//! CSAF v2.0 (ISO/IEC 20153:2025) document parser.
//!
//! CSAF (Common Security Advisory Framework) is the OASIS-published advisory
//! format named in CRA prEN 40000-1-3 [RLS-2-RQ-03-RE]. Red Hat, Cisco,
//! Siemens, Bosch, and other large vendors publish CSAF advisories that
//! include VEX-style product status information.
//!
//! This module parses the VEX-relevant subset of a CSAF document:
//! `vulnerabilities[].product_status.{known_affected,known_not_affected,
//! fixed,first_fixed,under_investigation,recommended,last_affected}` arrays
//! resolved against `product_tree.full_product_names[].product_identification_helper.purl`.
//!
//! Other CSAF sections (notes, threats, references, document-level metadata)
//! are accepted-but-ignored — VexEnricher only consumes status information.
//!
//! See <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html>.

use crate::model::{VexState, VexStatus};
use serde::Deserialize;
use std::collections::HashMap;

use super::openvex::VexParseError;

// ============================================================================
// CSAF serde structs (minimal, VEX-focused subset)
// ============================================================================

/// Top-level CSAF v2.0 document.
#[derive(Debug, Deserialize)]
struct CsafDocument {
    document: CsafHeader,
    #[serde(default)]
    product_tree: Option<CsafProductTree>,
    #[serde(default)]
    vulnerabilities: Vec<CsafVulnerability>,
}

#[derive(Debug, Deserialize)]
struct CsafHeader {
    csaf_version: String,
    /// `csaf_security_advisory` / `csaf_vex` / etc. — accepted but currently
    /// unused; we ingest VEX-relevant status from any CSAF v2.x category.
    #[serde(default)]
    #[allow(dead_code)]
    category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CsafProductTree {
    #[serde(default)]
    full_product_names: Vec<CsafProduct>,
    /// Some publishers nest products in `branches[]` rather than at the top
    /// level. Branches can recurse — flattened during parsing.
    #[serde(default)]
    branches: Vec<CsafBranch>,
    /// Relationships pair a product_id with another (e.g., "is_installed_on").
    /// We treat the relationship's `full_product_name` as a regular product.
    #[serde(default)]
    relationships: Vec<CsafRelationship>,
}

#[derive(Debug, Deserialize, Clone)]
struct CsafProduct {
    product_id: String,
    /// Display name — captured for forward compatibility (e.g., relationship
    /// summaries) but not used by the VEX lookup.
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    product_identification_helper: Option<CsafProductHelper>,
}

#[derive(Debug, Deserialize, Clone)]
struct CsafProductHelper {
    #[serde(default)]
    purl: Option<String>,
    /// CPE (`cpe22Type`/`cpe23Type`) — accepted-but-unused for now; PURL is
    /// the only identifier we propagate to VexStatus lookup keys.
    #[serde(default)]
    #[allow(dead_code)]
    cpe: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CsafBranch {
    #[serde(default)]
    product: Option<CsafProduct>,
    #[serde(default)]
    branches: Vec<CsafBranch>,
}

#[derive(Debug, Deserialize)]
struct CsafRelationship {
    #[serde(default)]
    full_product_name: Option<CsafProduct>,
}

#[derive(Debug, Deserialize)]
struct CsafVulnerability {
    /// CVE identifier (preferred). Falls back to `ids[].text` when absent.
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    ids: Vec<CsafVulnId>,
    #[serde(default)]
    product_status: Option<CsafProductStatus>,
}

#[derive(Debug, Deserialize)]
struct CsafVulnId {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CsafProductStatus {
    #[serde(default)]
    known_affected: Vec<String>,
    #[serde(default)]
    known_not_affected: Vec<String>,
    #[serde(default)]
    fixed: Vec<String>,
    #[serde(default)]
    first_fixed: Vec<String>,
    #[serde(default)]
    under_investigation: Vec<String>,
    #[serde(default)]
    recommended: Vec<String>,
    #[serde(default)]
    last_affected: Vec<String>,
}

// ============================================================================
// Parsing functions
// ============================================================================

/// Quick peek to decide whether `content` is a CSAF v2.0 document. Looks
/// for `document.csaf_version` starting with `"2."` and a `vulnerabilities`
/// or `product_tree` block. Tolerant of extra/missing fields.
pub(crate) fn is_csaf(content: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return false;
    };
    let Some(obj) = value.as_object() else {
        return false;
    };
    let has_csaf_version = obj
        .get("document")
        .and_then(|d| d.as_object())
        .and_then(|d| d.get("csaf_version"))
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.starts_with("2."));
    let has_vex_payload = obj.get("vulnerabilities").is_some() || obj.get("product_tree").is_some();
    has_csaf_version && has_vex_payload
}

/// Parse a CSAF v2.0 document and return VEX-relevant status entries.
///
/// Resolves `product_id` references against `product_tree.full_product_names`
/// (and recursively-flattened `branches[].product`) to PURL strings. Entries
/// without a PURL are emitted as unscoped (`vuln_id` only) so that fuzzy
/// product matching can still apply.
pub(crate) fn parse_csaf(content: &str) -> Result<CsafVexResult, VexParseError> {
    let doc: CsafDocument = serde_json::from_str(content)?;
    if !doc.document.csaf_version.starts_with("2.") {
        return Err(VexParseError::InvalidDocument(format!(
            "unsupported CSAF version {} (expected 2.x)",
            doc.document.csaf_version
        )));
    }

    let product_lookup = build_product_lookup(doc.product_tree.as_ref());

    let mut scoped: HashMap<(String, String), VexStatus> = HashMap::new();
    let mut unscoped: HashMap<String, VexStatus> = HashMap::new();
    let mut statements_parsed = 0;

    for vuln in &doc.vulnerabilities {
        let Some(vuln_id) = pick_vuln_id(vuln) else {
            continue;
        };
        let Some(status) = vuln.product_status.as_ref() else {
            continue;
        };

        let mut apply = |product_ids: &[String], state: VexState| {
            for pid in product_ids {
                statements_parsed += 1;
                let vex_status = VexStatus::new(state.clone());
                if let Some(purl) = product_lookup.get(pid).cloned() {
                    scoped.insert((vuln_id.clone(), purl), vex_status);
                } else {
                    // No PURL available — emit as unscoped fallback.
                    // Later identical vuln_ids overwrite, which matches the
                    // OpenVEX/CDX path's "later wins" semantics.
                    unscoped.insert(vuln_id.clone(), vex_status);
                }
            }
        };

        apply(&status.known_affected, VexState::Affected);
        apply(&status.known_not_affected, VexState::NotAffected);
        apply(&status.fixed, VexState::Fixed);
        apply(&status.first_fixed, VexState::Fixed);
        apply(&status.under_investigation, VexState::UnderInvestigation);
        apply(&status.recommended, VexState::Affected); // "recommended" upgrade
        apply(&status.last_affected, VexState::Fixed); // last vuln cycle, fixed in newer
    }

    Ok(CsafVexResult {
        scoped,
        unscoped,
        statements_parsed,
    })
}

#[derive(Debug)]
pub(crate) struct CsafVexResult {
    /// `(vuln_id, purl)` → status for product-scoped entries.
    pub scoped: HashMap<(String, String), VexStatus>,
    /// `vuln_id` → status for entries without a resolvable PURL.
    pub unscoped: HashMap<String, VexStatus>,
    pub statements_parsed: usize,
}

// ============================================================================
// Helpers
// ============================================================================

fn pick_vuln_id(vuln: &CsafVulnerability) -> Option<String> {
    if let Some(cve) = vuln.cve.as_deref() {
        if !cve.is_empty() {
            return Some(cve.to_string());
        }
    }
    vuln.ids
        .iter()
        .find_map(|i| i.text.clone().filter(|s| !s.is_empty()))
}

/// Flatten `product_tree.full_product_names` + recursive `branches[].product`
/// + `relationships[].full_product_name` into a `product_id → PURL` map.
fn build_product_lookup(tree: Option<&CsafProductTree>) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let Some(tree) = tree else {
        return out;
    };
    for p in &tree.full_product_names {
        record_product(p, &mut out);
    }
    for b in &tree.branches {
        walk_branch(b, &mut out);
    }
    for r in &tree.relationships {
        if let Some(p) = r.full_product_name.as_ref() {
            record_product(p, &mut out);
        }
    }
    out
}

fn walk_branch(b: &CsafBranch, out: &mut HashMap<String, String>) {
    if let Some(p) = b.product.as_ref() {
        record_product(p, out);
    }
    for inner in &b.branches {
        walk_branch(inner, out);
    }
}

fn record_product(p: &CsafProduct, out: &mut HashMap<String, String>) {
    if let Some(helper) = p.product_identification_helper.as_ref()
        && let Some(purl) = helper.purl.as_deref()
        && !purl.is_empty()
    {
        out.insert(p.product_id.clone(), purl.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CSAF: &str = r#"{
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "publisher": { "category": "vendor", "name": "Example" },
            "title": "Example advisory",
            "tracking": { "id": "EX-2024-001" }
        },
        "product_tree": {
            "full_product_names": [
                {
                    "product_id": "CSAFPID-001",
                    "name": "ExampleApp 1.0",
                    "product_identification_helper": {
                        "purl": "pkg:cargo/example-app@1.0"
                    }
                },
                {
                    "product_id": "CSAFPID-002",
                    "name": "ExampleApp 1.1",
                    "product_identification_helper": {
                        "purl": "pkg:cargo/example-app@1.1"
                    }
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2024-12345",
                "product_status": {
                    "known_affected": ["CSAFPID-001"],
                    "fixed": ["CSAFPID-002"]
                }
            }
        ]
    }"#;

    #[test]
    fn detects_csaf_document() {
        assert!(is_csaf(MINIMAL_CSAF));
    }

    #[test]
    fn does_not_misdetect_openvex() {
        let openvex = r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}"#;
        assert!(!is_csaf(openvex));
    }

    #[test]
    fn does_not_misdetect_cyclonedx() {
        let cdx = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#;
        assert!(!is_csaf(cdx));
    }

    #[test]
    fn parses_known_affected_and_fixed() {
        let result = parse_csaf(MINIMAL_CSAF).unwrap();
        assert_eq!(result.statements_parsed, 2);

        let affected = result
            .scoped
            .get(&(
                "CVE-2024-12345".to_string(),
                "pkg:cargo/example-app@1.0".to_string(),
            ))
            .expect("affected entry");
        assert_eq!(affected.status, VexState::Affected);

        let fixed = result
            .scoped
            .get(&(
                "CVE-2024-12345".to_string(),
                "pkg:cargo/example-app@1.1".to_string(),
            ))
            .expect("fixed entry");
        assert_eq!(fixed.status, VexState::Fixed);
    }

    #[test]
    fn rejects_non_csaf_2() {
        let bad = r#"{
            "document": {"csaf_version": "1.5", "category": "x", "publisher":{"category":"vendor","name":"X"}, "title":"x", "tracking":{"id":"x"}},
            "vulnerabilities": []
        }"#;
        let err = parse_csaf(bad).unwrap_err();
        assert!(matches!(err, VexParseError::InvalidDocument(_)));
    }

    #[test]
    fn handles_branches_recursively() {
        let csaf = r#"{
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "publisher": {"category":"vendor","name":"X"},
                "title": "x",
                "tracking": {"id":"x"}
            },
            "product_tree": {
                "branches": [
                    {
                        "branches": [
                            {
                                "product": {
                                    "product_id": "DEEP-1",
                                    "name": "deep",
                                    "product_identification_helper": {
                                        "purl": "pkg:cargo/deep@1.0"
                                    }
                                }
                            }
                        ]
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-99999",
                    "product_status": { "known_affected": ["DEEP-1"] }
                }
            ]
        }"#;
        let result = parse_csaf(csaf).unwrap();
        assert!(result.scoped.contains_key(&(
            "CVE-2024-99999".to_string(),
            "pkg:cargo/deep@1.0".to_string()
        )));
    }

    #[test]
    fn missing_purl_falls_back_to_unscoped() {
        let csaf = r#"{
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "publisher": {"category":"vendor","name":"X"},
                "title": "x",
                "tracking": {"id":"x"}
            },
            "product_tree": {
                "full_product_names": [
                    { "product_id": "P1", "name": "x" }
                ]
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-77777",
                    "product_status": { "known_affected": ["P1"] }
                }
            ]
        }"#;
        let result = parse_csaf(csaf).unwrap();
        assert!(result.scoped.is_empty());
        assert_eq!(
            result
                .unscoped
                .get("CVE-2024-77777")
                .map(|v| v.status.clone()),
            Some(VexState::Affected)
        );
    }

    #[test]
    fn falls_back_from_cve_to_ids_text() {
        let csaf = r#"{
            "document": {
                "category": "csaf_security_advisory",
                "csaf_version": "2.0",
                "publisher": {"category":"vendor","name":"X"},
                "title": "x",
                "tracking": {"id":"x"}
            },
            "product_tree": {
                "full_product_names": [
                    {
                        "product_id": "P1",
                        "name": "x",
                        "product_identification_helper": {"purl": "pkg:cargo/p@1"}
                    }
                ]
            },
            "vulnerabilities": [
                {
                    "ids": [{"system_name":"GHSA","text":"GHSA-aaaa-bbbb-cccc"}],
                    "product_status": { "known_affected": ["P1"] }
                }
            ]
        }"#;
        let result = parse_csaf(csaf).unwrap();
        assert!(result.scoped.contains_key(&(
            "GHSA-aaaa-bbbb-cccc".to_string(),
            "pkg:cargo/p@1".to_string()
        )));
    }
}
