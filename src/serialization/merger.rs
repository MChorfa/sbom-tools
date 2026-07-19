//! SBOM merging.
//!
//! Combines multiple SBOMs into a single document, deduplicating
//! components based on configurable strategies.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::ValueExt;

/// Errors that can occur during SBOM merging
#[derive(Debug, thiserror::Error)]
pub enum MergeError {
    /// The two SBOMs are different formats (e.g., CycloneDX and SPDX)
    #[error("cannot merge CycloneDX and SPDX SBOMs — both must be the same format")]
    FormatMismatch,
    /// The two SBOMs are incompatible SPDX versions
    #[error("cannot merge SPDX 3.0 and SPDX 2.x SBOMs")]
    SpdxVersionMismatch,
    /// JSON serialization/deserialization error
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Configuration for SBOM merging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeConfig {
    /// Deduplication strategy
    pub dedup_strategy: DeduplicationStrategy,
}

impl Default for MergeConfig {
    fn default() -> Self {
        Self {
            dedup_strategy: DeduplicationStrategy::Name,
        }
    }
}

/// Strategy for deduplicating components during merge
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum DeduplicationStrategy {
    /// Deduplicate by package name + version
    #[default]
    Name,
    /// Deduplicate by PURL (exact match)
    Purl,
    /// Keep all components (no dedup)
    None,
}

/// Merge two SBOM JSON documents into one.
///
/// The primary SBOM provides the document metadata; components from both
/// are merged with deduplication.
///
/// Both SBOMs must be the same format (CycloneDX or SPDX).
///
/// # Errors
///
/// Returns error if the SBOMs are different formats or JSON parsing fails.
pub fn merge_sbom_json(
    primary_json: &str,
    secondary_json: &str,
    config: &MergeConfig,
) -> Result<String, MergeError> {
    let mut primary: Value = serde_json::from_str(primary_json)?;
    let secondary: Value = serde_json::from_str(secondary_json)?;

    let primary_is_cdx = primary.get("bomFormat").is_some();
    let secondary_is_cdx = secondary.get("bomFormat").is_some();
    let primary_is_spdx3 = primary.get("@context").is_some();
    let secondary_is_spdx3 = secondary.get("@context").is_some();

    // Verify same format family
    if primary_is_cdx != secondary_is_cdx {
        return Err(MergeError::FormatMismatch);
    }

    // SPDX 2.x and SPDX 3.0 are incompatible in BOTH directions. The old
    // check only caught SPDX3-primary + SPDX2-secondary; the reverse silently
    // emitted the primary unchanged.
    if primary_is_spdx3 != secondary_is_spdx3 {
        return Err(MergeError::SpdxVersionMismatch);
    }

    if primary_is_cdx {
        merge_cyclonedx(&mut primary, &secondary, config)?;
    } else if primary_is_spdx3 {
        merge_spdx3(&mut primary, &secondary, config)?;
    } else {
        merge_spdx2(&mut primary, &secondary, config)?;
    }

    Ok(serde_json::to_string_pretty(&primary)?)
}

fn merge_cyclonedx(
    primary: &mut Value,
    secondary: &Value,
    config: &MergeConfig,
) -> Result<(), MergeError> {
    // The primary may legitimately lack a `components` array (metadata-only
    // shell document): create it from the secondary rather than silently
    // dropping every secondary component.
    if let Some(s_comps) = secondary.get("components").and_then(Value::as_array)
        && let Some(p_comps) = ensure_array(primary, "components")
    {
        if config.dedup_strategy == DeduplicationStrategy::None {
            // No deduplication — keep all components
            for comp in s_comps {
                p_comps.push(comp.clone());
            }
        } else {
            // Build dedup set from primary
            let mut seen = build_seen_set(p_comps, config);

            // Add non-duplicate components from secondary
            for comp in s_comps {
                let key = component_key(comp, config);
                if seen.insert(key) {
                    p_comps.push(comp.clone());
                }
            }
        }
    }

    // Merge dependencies
    if let Some(s_deps) = secondary.get("dependencies").and_then(Value::as_array)
        && let Some(p_deps) = ensure_array(primary, "dependencies")
    {
        let existing_refs: HashSet<String> = p_deps
            .iter()
            .filter_map(|d| d.get("ref").and_then(Value::as_str).map(String::from))
            .collect();

        for dep in s_deps {
            let dep_ref = dep.str_field("ref");
            if !existing_refs.contains(dep_ref) {
                p_deps.push(dep.clone());
            }
        }
    }

    // Merge vulnerabilities, deduplicating by id (affects refs are unioned)
    merge_vulnerabilities(primary, secondary);

    Ok(())
}

/// Get a mutable reference to `primary[field]` as an array, creating an empty
/// array when the field is absent. Returns `None` only when `primary` is not
/// an object or the existing field is not an array.
fn ensure_array<'a>(primary: &'a mut Value, field: &str) -> Option<&'a mut Vec<Value>> {
    primary.as_object_mut().and_then(|o| {
        o.entry(field)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
    })
}

/// Merge the secondary's `vulnerabilities` into the primary, deduplicating by
/// vulnerability id. When both documents carry the same id, the entries are
/// merged by unioning `affects` refs (the primary's entry wins for every
/// other field). Entries without an id cannot be identified and are appended.
fn merge_vulnerabilities(primary: &mut Value, secondary: &Value) {
    let Some(s_vulns) = secondary.get("vulnerabilities").and_then(Value::as_array) else {
        return;
    };
    if s_vulns.is_empty() {
        return;
    }
    let Some(p_vulns) = ensure_array(primary, "vulnerabilities") else {
        return;
    };

    let mut index_by_id: HashMap<String, usize> = p_vulns
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            v.get("id")
                .and_then(Value::as_str)
                .map(|id| (id.to_string(), i))
        })
        .collect();

    for vuln in s_vulns {
        let id = vuln.str_field("id");
        if id.is_empty() {
            p_vulns.push(vuln.clone());
            continue;
        }
        if let Some(&i) = index_by_id.get(id) {
            // Union affects refs into the primary's entry.
            let Some(s_affects) = vuln.get("affects").and_then(Value::as_array) else {
                continue;
            };
            let Some(existing) = p_vulns[i].as_object_mut() else {
                continue;
            };
            let existing_refs: HashSet<String> = existing
                .get("affects")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|a| a.get("ref").and_then(Value::as_str))
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let to_add: Vec<Value> = s_affects
                .iter()
                .filter(|a| {
                    a.get("ref")
                        .and_then(Value::as_str)
                        .is_none_or(|r| !existing_refs.contains(r))
                })
                .cloned()
                .collect();
            if !to_add.is_empty()
                && let Some(affects) = existing
                    .entry("affects")
                    .or_insert_with(|| Value::Array(Vec::new()))
                    .as_array_mut()
            {
                affects.extend(to_add);
            }
        } else {
            index_by_id.insert(id.to_string(), p_vulns.len());
            p_vulns.push(vuln.clone());
        }
    }
}

/// Merge the secondary's SPDX `relationships` into the primary, deduplicating
/// by the `(relationshipType, spdxElementId, relatedSpdxElement)` triple.
fn merge_relationships(primary: &mut Value, secondary: &Value) {
    let Some(s_rels) = secondary.get("relationships").and_then(Value::as_array) else {
        return;
    };
    if s_rels.is_empty() {
        return;
    }
    let Some(p_rels) = ensure_array(primary, "relationships") else {
        return;
    };

    fn rel_key(rel: &Value) -> (String, String, String) {
        (
            rel.str_field("relationshipType").to_string(),
            rel.str_field("spdxElementId").to_string(),
            rel.str_field("relatedSpdxElement").to_string(),
        )
    }

    let mut seen: HashSet<(String, String, String)> = p_rels.iter().map(rel_key).collect();
    for rel in s_rels {
        if seen.insert(rel_key(rel)) {
            p_rels.push(rel.clone());
        }
    }
}

fn merge_spdx3(
    primary: &mut Value,
    secondary: &Value,
    config: &MergeConfig,
) -> Result<(), MergeError> {
    let primary_key = if primary.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };

    let secondary_key = if secondary.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };
    let secondary_elements = secondary.get(secondary_key).and_then(Value::as_array);

    if let Some(s_elems) = secondary_elements
        && let Some(p_elems) = ensure_array(primary, primary_key)
    {
        let mut seen: HashSet<String> = p_elems
            .iter()
            .filter_map(|e| e.get("spdxId").and_then(Value::as_str).map(String::from))
            .collect();

        for elem in s_elems {
            let spdx_id = elem.str_field("spdxId");

            // For packages, apply dedup logic
            let elem_type = elem.str_field("type");
            if elem_type.contains("Package") || elem_type.contains("package") {
                let key = component_key(elem, config);
                if !seen.insert(key) {
                    continue;
                }
            } else if !seen.insert(spdx_id.to_string()) {
                continue;
            }

            p_elems.push(elem.clone());
        }
    }

    Ok(())
}

fn merge_spdx2(
    primary: &mut Value,
    secondary: &Value,
    config: &MergeConfig,
) -> Result<(), MergeError> {
    // Merge packages (creating the array when the primary lacks one)
    if let Some(s_pkgs) = secondary.get("packages").and_then(Value::as_array)
        && let Some(p_pkgs) = ensure_array(primary, "packages")
    {
        if config.dedup_strategy == DeduplicationStrategy::None {
            for pkg in s_pkgs {
                p_pkgs.push(pkg.clone());
            }
        } else {
            let mut seen = build_seen_set(p_pkgs, config);
            for pkg in s_pkgs {
                let key = component_key(pkg, config);
                if seen.insert(key) {
                    p_pkgs.push(pkg.clone());
                }
            }
        }
    }

    // Merge relationships, deduplicating by (type, source, target)
    merge_relationships(primary, secondary);

    Ok(())
}

/// Build a set of dedup keys from existing components
fn build_seen_set(components: &[Value], config: &MergeConfig) -> HashSet<String> {
    components
        .iter()
        .map(|c| component_key(c, config))
        .collect()
}

/// Generate a deduplication key for a component
fn component_key(comp: &Value, config: &MergeConfig) -> String {
    match config.dedup_strategy {
        DeduplicationStrategy::Purl => {
            // Try purl field directly
            if let Some(purl) = comp.get("purl").and_then(Value::as_str) {
                return purl.to_string();
            }
            // Try externalReferences for PURL
            if let Some(refs) = comp.get("externalReferences").and_then(Value::as_array) {
                for r in refs {
                    if r.get("type").and_then(Value::as_str) == Some("purl")
                        && let Some(url) = r.get("url").and_then(Value::as_str)
                    {
                        return url.to_string();
                    }
                }
            }
            // Fall back to name-version
            name_version_key(comp)
        }
        DeduplicationStrategy::Name | DeduplicationStrategy::None => name_version_key(comp),
    }
}

fn name_version_key(comp: &Value) -> String {
    // For cryptographic components, use OID as the dedup key if available
    if let Some(cp) = comp.get("cryptoProperties")
        && let Some(oid) = cp.get("oid").and_then(Value::as_str)
    {
        let asset_type = cp
            .get("assetType")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return format!("crypto:{asset_type}:{oid}");
    }
    let name = comp.str_field("name");
    let version = comp
        .get("version")
        .or_else(|| comp.get("versionInfo"))
        .and_then(Value::as_str)
        .unwrap_or("");
    format!("{name}@{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_cyclonedx_dedup() {
        let primary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"},
            {"name":"bar","version":"2.0"}
        ]}"#;

        let secondary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"},
            {"name":"baz","version":"3.0"}
        ]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), 3); // foo, bar, baz (foo deduped)
    }

    #[test]
    fn merge_different_formats_fails() {
        let cdx = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
        let spdx = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}"#;

        let result = merge_sbom_json(cdx, spdx, &MergeConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn merge_no_dedup() {
        let a = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"}
        ]}"#;
        let b = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"}
        ]}"#;

        let config = MergeConfig {
            dedup_strategy: DeduplicationStrategy::None,
        };
        let result = merge_sbom_json(a, b, &config).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let components = doc["components"].as_array().unwrap();
        // None strategy keeps all components, including duplicates
        assert_eq!(components.len(), 2);
    }

    /// A metadata-only primary (no `components` array) must still receive
    /// every secondary component.
    #[test]
    fn merge_creates_components_when_primary_lacks_array() {
        let primary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
            "metadata":{"component":{"type":"application","name":"shell"}}}"#;
        let secondary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"name":"foo","version":"1.0"},
            {"name":"bar","version":"2.0"}
        ]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let components = doc["components"].as_array().unwrap();
        assert_eq!(
            components.len(),
            2,
            "secondary components must not be dropped"
        );
    }

    /// SPDX 2.x primary + SPDX 3.0 secondary must error, exactly like the
    /// reverse direction (it previously emitted the primary unchanged).
    #[test]
    fn merge_spdx2_primary_spdx3_secondary_errors() {
        let spdx2 = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}"#;
        let spdx3 = r#"{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}"#;

        let result = merge_sbom_json(spdx2, spdx3, &MergeConfig::default());
        assert!(matches!(result, Err(MergeError::SpdxVersionMismatch)));

        // And the reverse direction still errors too.
        let result = merge_sbom_json(spdx3, spdx2, &MergeConfig::default());
        assert!(matches!(result, Err(MergeError::SpdxVersionMismatch)));
    }

    /// Overlapping vulnerabilities are deduplicated by id, with affects refs
    /// unioned into the primary's entry.
    #[test]
    fn merge_dedups_vulnerabilities_by_id_and_unions_affects() {
        let primary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
            "components":[{"bom-ref":"a","name":"a","version":"1.0"}],
            "vulnerabilities":[{"id":"CVE-1","description":"keep me","affects":[{"ref":"a"}]}]}"#;
        let secondary = r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
            "components":[{"bom-ref":"b","name":"b","version":"2.0"}],
            "vulnerabilities":[
                {"id":"CVE-1","description":"secondary copy","affects":[{"ref":"a"},{"ref":"b"}]},
                {"id":"CVE-2","affects":[{"ref":"b"}]}
            ]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let vulns = doc["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 2, "CVE-1 must not be duplicated");

        let cve1 = vulns.iter().find(|v| v["id"] == "CVE-1").unwrap();
        assert_eq!(cve1["description"], "keep me", "primary entry wins");
        let refs: Vec<&str> = cve1["affects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["ref"].as_str())
            .collect();
        assert_eq!(refs, vec!["a", "b"], "affects refs unioned without dupes");
    }

    /// Overlapping SPDX relationships are deduplicated by
    /// (type, source, target).
    #[test]
    fn merge_dedups_relationships_by_triple() {
        let primary = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
            "packages":[{"SPDXID":"SPDXRef-a","name":"a"}],
            "relationships":[
                {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-a"}
            ]}"#;
        let secondary = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
            "packages":[{"SPDXID":"SPDXRef-b","name":"b"}],
            "relationships":[
                {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-a"},
                {"spdxElementId":"SPDXRef-a","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-b"}
            ]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let rels = doc["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 2, "duplicate DESCRIBES must be dropped");
    }

    /// SPDX2 primary without a packages array still receives secondary packages.
    #[test]
    fn merge_spdx2_creates_packages_when_primary_lacks_array() {
        let primary = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT"}"#;
        let secondary = r#"{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
            "packages":[{"SPDXID":"SPDXRef-a","name":"a"}]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(doc["packages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn merge_crypto_oid_dedup() {
        let primary = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"name":"AES-256-GCM","type":"cryptographic-asset","cryptoProperties":{"assetType":"algorithm","oid":"2.16.840.1.101.3.4.1.46"}}
        ]}"#;

        let secondary = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"name":"AES-256-GCM-v2","type":"cryptographic-asset","cryptoProperties":{"assetType":"algorithm","oid":"2.16.840.1.101.3.4.1.46"}},
            {"name":"SHA-384","type":"cryptographic-asset","cryptoProperties":{"assetType":"algorithm","oid":"2.16.840.1.101.3.4.2.2"}}
        ]}"#;

        let result = merge_sbom_json(primary, secondary, &MergeConfig::default()).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let components = doc["components"].as_array().unwrap();
        // AES-256-GCM-v2 deduped by OID, SHA-384 added → 2 total
        assert_eq!(components.len(), 2);
    }
}
