//! SBOM tailoring / filtering.
//!
//! Removes components from an SBOM based on filter criteria,
//! preserving the original format structure.

use crate::model::{LicenseFamily, NormalizedSbom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

use super::ValueExt;

/// Configuration for SBOM tailoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailorConfig {
    /// Include only components matching these license families
    pub include_license_families: Vec<LicenseFamily>,
    /// Exclude components matching these ecosystems
    pub exclude_ecosystems: Vec<String>,
    /// Include only these component types (library, application, etc.)
    pub include_types: Vec<String>,
    /// Include only components matching this name pattern
    pub include_name_pattern: Option<String>,
    /// Include only these crypto asset types (algorithm, certificate, key, protocol)
    pub include_crypto_types: Vec<String>,
    /// Strip vulnerability data from output
    pub strip_vulns: bool,
    /// Strip extension/property data
    pub strip_extensions: bool,
}

/// Tailor (filter) an SBOM by removing components that don't match the criteria.
///
/// Operates on raw JSON to preserve original format structure.
///
/// # Errors
///
/// Returns error if JSON parsing fails.
pub fn tailor_sbom_json(
    raw_json: &str,
    sbom: &NormalizedSbom,
    config: &TailorConfig,
) -> anyhow::Result<String> {
    let mut doc: Value = serde_json::from_str(raw_json)?;

    // Canonical identities (bom-ref / SPDXID / spdxId via format_id, plus
    // purl) of components to remove. NEVER bare names: a same-named component
    // from another ecosystem must survive (e.g. excluding foo@npm must keep
    // foo@pypi).
    let mut removal = RemovalSet::default();

    for comp in sbom.components.values() {
        let mut keep = true;

        // Filter by license family
        if !config.include_license_families.is_empty() {
            let family = comp
                .licenses
                .declared
                .first()
                .map(|l| l.family())
                .unwrap_or(LicenseFamily::Other);
            if !config.include_license_families.contains(&family) {
                keep = false;
            }
        }

        // Filter by ecosystem
        if !config.exclude_ecosystems.is_empty()
            && let Some(eco) = &comp.ecosystem
        {
            let eco_str = format!("{eco:?}").to_lowercase();
            if config
                .exclude_ecosystems
                .iter()
                .any(|e| e.to_lowercase() == eco_str)
            {
                keep = false;
            }
        }

        // Filter by component type: accept CycloneDX spec values
        // ("cryptographic-asset", "machine-learning-model", ...) as well as
        // the internal Debug spellings, case-insensitively.
        if !config.include_types.is_empty() {
            let comp_type = normalize_type_token(&comp.component_type.to_string());
            if !config
                .include_types
                .iter()
                .any(|t| normalize_type_token(t) == comp_type)
            {
                keep = false;
            }
        }

        // Filter by name pattern (glob when the pattern contains `*`,
        // substring otherwise)
        if let Some(pattern) = &config.include_name_pattern
            && !name_matches_pattern(&comp.name, pattern)
        {
            keep = false;
        }

        // Filter by crypto asset type
        if !config.include_crypto_types.is_empty() {
            if let Some(cp) = &comp.crypto_properties {
                let asset_str = cp.asset_type.to_string().to_lowercase();
                if !config
                    .include_crypto_types
                    .iter()
                    .any(|t| t.to_lowercase() == asset_str)
                {
                    keep = false;
                }
            } else {
                // No crypto properties — exclude if we're filtering by crypto type
                keep = false;
            }
        }

        if !keep {
            removal.add(comp);
        }
    }

    // Prune from CycloneDX
    if doc.get("bomFormat").is_some() {
        prune_cyclonedx(&mut doc, &removal, config);
    } else if doc.get("@context").is_some() {
        prune_spdx3(&mut doc, &removal, config);
    } else {
        prune_spdx2(&mut doc, &removal, config);
    }

    Ok(serde_json::to_string_pretty(&doc)?)
}

/// Identities of components selected for removal.
///
/// Matching is by canonical identity (format-native id via `format_id`, or
/// purl) — never bare name alone. A name-based fallback exists ONLY for model
/// components that carry no distinguishing identity at all, and it is applied
/// only to raw components that also lack canonical identifiers, so a
/// same-named component from another ecosystem is never removed collaterally.
#[derive(Default)]
struct RemovalSet {
    /// bom-ref / SPDXID / spdxId (format_id) and purl values
    ids: HashSet<String>,
    /// Names of removed components with no identity beyond their name
    name_fallback: HashSet<String>,
}

impl RemovalSet {
    fn add(&mut self, comp: &crate::model::Component) {
        if !comp.identifiers.format_id.is_empty() {
            self.ids.insert(comp.identifiers.format_id.clone());
        }
        if let Some(purl) = &comp.identifiers.purl {
            self.ids.insert(purl.clone());
        }
        // Parsers fall back to the bare name for format_id when the source
        // has no native id; only such identity-poor components may use the
        // name fallback.
        if comp.identifiers.purl.is_none()
            && (comp.identifiers.format_id.is_empty() || comp.identifiers.format_id == comp.name)
        {
            self.name_fallback.insert(comp.name.clone());
        }
    }

    /// Does this raw CycloneDX component match a removed identity?
    fn matches_cyclonedx(&self, comp: &Value) -> bool {
        let bom_ref = comp.str_field("bom-ref");
        let purl = comp.str_field("purl");
        (!bom_ref.is_empty() && self.ids.contains(bom_ref))
            || (!purl.is_empty() && self.ids.contains(purl))
            || (bom_ref.is_empty()
                && purl.is_empty()
                && self.name_fallback.contains(comp.str_field("name")))
    }

    /// Does this raw SPDX 2.x package match a removed identity?
    fn matches_spdx2(&self, pkg: &Value) -> bool {
        let spdx_id = pkg.str_field("SPDXID");
        (!spdx_id.is_empty() && self.ids.contains(spdx_id))
            || (spdx_id.is_empty() && self.name_fallback.contains(pkg.str_field("name")))
    }

    /// Does this raw SPDX 3.0 element match a removed identity?
    fn matches_spdx3(&self, elem: &Value) -> bool {
        let spdx_id = elem.str_field("spdxId");
        (!spdx_id.is_empty() && self.ids.contains(spdx_id))
            || (spdx_id.is_empty() && self.name_fallback.contains(elem.str_field("name")))
    }

    /// Does a dependency/relationship reference point at a removed identity?
    fn matches_ref(&self, reference: &str) -> bool {
        !reference.is_empty() && self.ids.contains(reference)
    }
}

/// Match a component name against an `--include-name` pattern.
///
/// A pattern containing `*` uses glob semantics (each `*` matches any run of
/// characters, anchored at both ends); without `*` it is a plain substring
/// match. Both are case-insensitive. The literal-`*` substring matching this
/// replaces made the documented `--include-name "my-org/*"` example keep 0
/// components.
fn name_matches_pattern(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();

    if !pattern.contains('*') {
        return name.contains(&pattern);
    }

    let segments: Vec<&str> = pattern.split('*').collect();
    let last = segments.len() - 1;
    let mut pos = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        if i == 0 {
            // No leading `*`: segment is anchored at the start.
            if !name.starts_with(seg) {
                return false;
            }
            pos = seg.len();
        } else if i == last {
            // No trailing `*`: segment is anchored at the end (and must not
            // overlap already-consumed input).
            if !name.ends_with(seg) || name.len() - seg.len() < pos {
                return false;
            }
            pos = name.len();
        } else {
            // Interior segment: first occurrence at or after `pos`.
            match name[pos..].find(seg) {
                Some(idx) => pos = pos + idx + seg.len(),
                None => return false,
            }
        }
    }
    true
}

/// Normalize a component-type token so CycloneDX spec values
/// ("machine-learning-model"), internal Debug spellings
/// ("MachineLearningModel"), and the model's Display strings all compare
/// equal. `cryptographic-asset` (the CycloneDX 1.6 spec value) maps to the
/// internal `cryptographic`.
fn normalize_type_token(token: &str) -> String {
    let normalized: String = token
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .collect::<String>()
        .to_lowercase();
    if normalized == "cryptographicasset" {
        "cryptographic".to_string()
    } else {
        normalized
    }
}

fn prune_cyclonedx(doc: &mut Value, removal: &RemovalSet, config: &TailorConfig) {
    // Remove components
    if let Some(components) = doc.get_mut("components").and_then(Value::as_array_mut) {
        components.retain(|comp| !removal.matches_cyclonedx(comp));
    }

    // Remove corresponding dependency entries
    if let Some(deps) = doc.get_mut("dependencies").and_then(Value::as_array_mut) {
        deps.retain(|dep| !removal.matches_ref(dep.str_field("ref")));

        // Also remove from dependsOn arrays
        for dep in deps.iter_mut() {
            if let Some(depends_on) = dep.get_mut("dependsOn").and_then(Value::as_array_mut) {
                depends_on.retain(|d| !removal.matches_ref(d.as_str().unwrap_or("")));
            }
        }
    }

    // Strip vulnerabilities if requested
    if config.strip_vulns {
        doc.as_object_mut().map(|o| o.remove("vulnerabilities"));
    }

    // Strip extensions/properties if requested
    if config.strip_extensions
        && let Some(components) = doc.get_mut("components").and_then(Value::as_array_mut)
    {
        for comp in components {
            comp.as_object_mut().map(|o| o.remove("properties"));
        }
    }
}

fn prune_spdx3(doc: &mut Value, removal: &RemovalSet, config: &TailorConfig) {
    let key = if doc.get("element").is_some() {
        "element"
    } else {
        "@graph"
    };
    let elements = doc.get_mut(key).and_then(Value::as_array_mut);

    if let Some(elems) = elements {
        elems.retain(|elem| {
            let elem_type = elem.str_field("type");

            // Only filter software packages, keep relationships and other elements
            if !elem_type.contains("Package") && !elem_type.contains("package") {
                // If stripping vulns, also remove vulnerability elements
                if config.strip_vulns && elem_type.contains("Vulnerability") {
                    return false;
                }
                return true;
            }

            !removal.matches_spdx3(elem)
        });
    }
}

fn prune_spdx2(doc: &mut Value, removal: &RemovalSet, config: &TailorConfig) {
    // Remove packages
    if let Some(packages) = doc.get_mut("packages").and_then(Value::as_array_mut) {
        packages.retain(|pkg| !removal.matches_spdx2(pkg));
    }

    // Remove relationships referencing removed packages
    if let Some(rels) = doc.get_mut("relationships").and_then(Value::as_array_mut) {
        rels.retain(|rel| {
            let elem = rel
                .get("spdxElementId")
                .and_then(Value::as_str)
                .unwrap_or("");
            let related = rel
                .get("relatedSpdxElement")
                .and_then(Value::as_str)
                .unwrap_or("");
            !removal.matches_ref(elem) && !removal.matches_ref(related)
        });
    }

    // SPDX 2.x has no native vulnerability field; this tool's enricher
    // records vulnerabilities as annotations shaped
    // `annotator: "Tool: sbom-tools"` + `comment: "Vulnerability <id>: ..."`.
    // Strip exactly that class — deleting the whole `annotations` array
    // destroyed unrelated data (e.g. human REVIEW notes).
    if config.strip_vulns
        && let Some(annots) = doc.get_mut("annotations").and_then(Value::as_array_mut)
    {
        annots.retain(|annotation| {
            !(annotation.str_field("annotator") == "Tool: sbom-tools"
                && annotation
                    .str_field("comment")
                    .starts_with("Vulnerability "))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;

    #[test]
    fn tailor_by_name_pattern() {
        let raw = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"bom-ref":"id-keep","name":"keep-me","version":"1.0"},
            {"bom-ref":"id-remove","name":"remove-me","version":"2.0"}
        ]}"#;

        let mut sbom = NormalizedSbom::default();
        let keep = Component::new("keep-me".to_string(), "id-keep".to_string());
        let remove = Component::new("remove-me".to_string(), "id-remove".to_string());
        sbom.components.insert(keep.canonical_id.clone(), keep);
        sbom.components.insert(remove.canonical_id.clone(), remove);

        let config = TailorConfig {
            include_name_pattern: Some("keep".to_string()),
            ..Default::default()
        };

        let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
        assert!(result.contains("keep-me"));
        assert!(!result.contains("remove-me"));
    }

    #[test]
    fn strip_vulns() {
        let raw = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"vulnerabilities":[{"id":"CVE-1"}]}"#;
        let sbom = NormalizedSbom::default();
        let config = TailorConfig {
            strip_vulns: true,
            ..Default::default()
        };

        let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
        assert!(!result.contains("vulnerabilities"));
    }

    /// Excluding an ecosystem must remove only that ecosystem's component,
    /// never a same-named component from another ecosystem.
    #[test]
    fn exclude_ecosystem_keeps_same_name_other_ecosystem() {
        use crate::model::Ecosystem;

        let raw = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
            {"bom-ref":"foo-npm","name":"foo","version":"1.0","purl":"pkg:npm/foo@1.0"},
            {"bom-ref":"foo-pypi","name":"foo","version":"2.0","purl":"pkg:pypi/foo@2.0"}
        ]}"#;

        let mut sbom = NormalizedSbom::default();
        let mut foo_npm = Component::new("foo".to_string(), "foo-npm".to_string())
            .with_purl("pkg:npm/foo@1.0".to_string());
        foo_npm.ecosystem = Some(Ecosystem::Npm);
        let mut foo_pypi = Component::new("foo".to_string(), "foo-pypi".to_string())
            .with_purl("pkg:pypi/foo@2.0".to_string());
        foo_pypi.ecosystem = Some(Ecosystem::PyPi);
        sbom.components
            .insert(foo_npm.canonical_id.clone(), foo_npm);
        sbom.components
            .insert(foo_pypi.canonical_id.clone(), foo_pypi);

        let config = TailorConfig {
            exclude_ecosystems: vec!["npm".to_string()],
            ..Default::default()
        };

        let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let kept: Vec<&str> = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["purl"].as_str())
            .collect();
        assert_eq!(
            kept,
            vec!["pkg:pypi/foo@2.0"],
            "foo@pypi must survive excluding npm"
        );
    }

    /// The documented `--include-name "my-org/*"` example must keep matching
    /// components (previously the `*` was matched literally, keeping 0).
    #[test]
    fn include_name_glob_pattern() {
        assert!(name_matches_pattern("my-org/pkg-a", "my-org/*"));
        assert!(name_matches_pattern("my-org/pkg-b", "MY-ORG/*"));
        assert!(!name_matches_pattern("other/pkg-c", "my-org/*"));
        assert!(name_matches_pattern("libfoo-core", "*foo*"));
        assert!(name_matches_pattern("foo-middle-bar", "foo*bar"));
        assert!(!name_matches_pattern("foo-middle-baz", "foo*bar"));
        assert!(!name_matches_pattern("xfoobar", "foo*bar"));
        // Overlap guard: prefix and suffix may not share characters.
        assert!(!name_matches_pattern("foob", "foo*ob"));
        // No `*` keeps plain substring semantics.
        assert!(name_matches_pattern("my-org/pkg-a", "org/pkg"));
        assert!(!name_matches_pattern("my-org/pkg-a", "other"));
    }

    /// `--include-types` must accept CycloneDX spec values case-insensitively
    /// while the internal Debug spellings keep working.
    #[test]
    fn include_types_accepts_spec_and_debug_spellings() {
        use crate::model::ComponentType;

        let raw = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"bom-ref":"lib1","name":"libfoo","version":"1.0"},
            {"bom-ref":"mlm","name":"bert-base","version":"1.0"}
        ]}"#;

        let mut sbom = NormalizedSbom::default();
        let lib = Component::new("libfoo".to_string(), "lib1".to_string());
        let mut mlm = Component::new("bert-base".to_string(), "mlm".to_string());
        mlm.component_type = ComponentType::MachineLearningModel;
        sbom.components.insert(lib.canonical_id.clone(), lib);
        sbom.components.insert(mlm.canonical_id.clone(), mlm);

        for spelling in ["machine-learning-model", "MachineLearningModel"] {
            let config = TailorConfig {
                include_types: vec![spelling.to_string()],
                ..Default::default()
            };
            let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
            let doc: Value = serde_json::from_str(&result).unwrap();
            let kept: Vec<&str> = doc["components"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|c| c["name"].as_str())
                .collect();
            assert_eq!(kept, vec!["bert-base"], "spelling {spelling} must match");
        }

        // cryptographic-asset (spec) maps to the internal cryptographic
        assert_eq!(normalize_type_token("cryptographic-asset"), "cryptographic");
        assert_eq!(normalize_type_token("Cryptographic"), "cryptographic");
    }

    /// `--strip-vulns` on SPDX 2.x must remove only this tool's
    /// vulnerability-shaped annotations, keeping human REVIEW notes.
    #[test]
    fn strip_vulns_spdx2_keeps_non_vuln_annotations() {
        let raw = r#"{
            "spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT",
            "packages":[{"SPDXID":"SPDXRef-a","name":"a"}],
            "annotations":[
                {"annotator":"Person: Jane Reviewer","annotationType":"REVIEW",
                 "comment":"Manually reviewed licensing"},
                {"annotator":"Tool: sbom-tools","annotationType":"REVIEW",
                 "comment":"Vulnerability CVE-2024-0001: A bad bug"}
            ]
        }"#;
        let sbom = NormalizedSbom::default();
        let config = TailorConfig {
            strip_vulns: true,
            ..Default::default()
        };

        let result = tailor_sbom_json(raw, &sbom, &config).unwrap();
        let doc: Value = serde_json::from_str(&result).unwrap();
        let annots = doc["annotations"].as_array().unwrap();
        assert_eq!(annots.len(), 1, "only the vuln annotation is removed");
        assert_eq!(annots[0]["annotator"], "Person: Jane Reviewer");
    }
}
