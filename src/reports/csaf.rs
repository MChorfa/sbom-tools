//! CSAF v2.0 (ISO/IEC 20153:2025) advisory emitter.
//!
//! Produces a valid CSAF VEX document from an SBOM whose components carry
//! `VexStatus` values (typically applied by `VexEnricher`). Closes the
//! round-trip with [`crate::enrichment::vex::csaf`]: ingest a CSAF
//! advisory → enrich SBOM → emit CSAF that yields the same VEX states
//! when re-ingested.
//!
//! Mapping internal model → CSAF v2.0:
//!
//! - One product entry per SBOM component that carries a PURL (resolved
//!   to `product_tree.full_product_names[].product_identification_helper.purl`).
//! - One vulnerability entry per CVE/identifier; `product_status` lists
//!   reflect the corresponding `VexState`:
//!     - `Affected` → `known_affected`
//!     - `NotAffected` → `known_not_affected`
//!     - `Fixed` → `fixed`
//!     - `UnderInvestigation` → `under_investigation`
//!
//! See <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html>.

use crate::model::{NormalizedSbom, VexState};
use serde::Serialize;
use std::collections::BTreeMap;

use super::ReportError;

/// Configuration for the CSAF emitter. Operators that don't supply a
/// publisher / title fall back to sbom-tools defaults so the output is
/// still a valid CSAF document.
#[derive(Debug, Clone)]
pub struct CsafEmitOptions {
    pub document_id: Option<String>,
    pub publisher_name: Option<String>,
    pub publisher_namespace: Option<String>,
    pub publisher_category: Option<String>,
    pub title: Option<String>,
    pub category: Option<String>,
}

impl Default for CsafEmitOptions {
    fn default() -> Self {
        Self {
            document_id: None,
            publisher_name: None,
            publisher_namespace: None,
            publisher_category: None,
            title: None,
            category: None,
        }
    }
}

/// Emit a CSAF v2.0 VEX document from `sbom` as pretty-printed JSON.
pub fn emit_csaf(
    sbom: &NormalizedSbom,
    options: &CsafEmitOptions,
) -> Result<String, ReportError> {
    let doc = build_csaf_document(sbom, options);
    serde_json::to_string_pretty(&doc)
        .map_err(|e| ReportError::SerializationError(e.to_string()))
}

fn build_csaf_document(sbom: &NormalizedSbom, opt: &CsafEmitOptions) -> CsafDocOut {
    let now_rfc3339 = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    // Build product_tree and a (component_id) → product_id index.
    let mut product_index: BTreeMap<String, String> = BTreeMap::new();
    let mut full_product_names: Vec<CsafProductOut> = Vec::new();

    let mut counter: usize = 0;
    for (id, comp) in &sbom.components {
        let Some(purl) = comp.identifiers.purl.as_ref() else {
            continue;
        };
        counter += 1;
        let pid = format!("CSAFPID-{counter:04}");
        let display = match comp.version.as_deref() {
            Some(v) => format!("{} {}", comp.name, v),
            None => comp.name.clone(),
        };
        full_product_names.push(CsafProductOut {
            product_id: pid.clone(),
            name: display,
            product_identification_helper: Some(CsafProductHelperOut {
                purl: Some(purl.clone()),
            }),
        });
        product_index.insert(id.value().to_string(), pid);
    }

    // Group vulnerability statuses by (vuln_id) → buckets.
    let mut buckets: BTreeMap<String, ProductStatusBuckets> = BTreeMap::new();
    for (id, comp) in &sbom.components {
        let Some(pid) = product_index.get(id.value()) else {
            continue;
        };
        for vuln in &comp.vulnerabilities {
            let Some(vex) = vuln.vex_status.as_ref() else {
                continue;
            };
            let entry = buckets.entry(vuln.id.clone()).or_default();
            match vex.status {
                VexState::Affected => entry.known_affected.push(pid.clone()),
                VexState::NotAffected => entry.known_not_affected.push(pid.clone()),
                VexState::Fixed => entry.fixed.push(pid.clone()),
                VexState::UnderInvestigation => entry.under_investigation.push(pid.clone()),
            }
        }
    }

    let vulnerabilities: Vec<CsafVulnOut> = buckets
        .into_iter()
        .map(|(vuln_id, status)| {
            let (cve, ids) = if vuln_id.starts_with("CVE-") {
                (Some(vuln_id), Vec::new())
            } else {
                (
                    None,
                    vec![CsafVulnIdOut {
                        system_name: identifier_system(&vuln_id).to_string(),
                        text: vuln_id,
                    }],
                )
            };
            CsafVulnOut {
                cve,
                ids,
                product_status: status.into_serializable(),
            }
        })
        .collect();

    let publisher_name = opt
        .publisher_name
        .clone()
        .or_else(|| {
            sbom.document
                .creators
                .iter()
                .find(|c| matches!(c.creator_type, crate::model::CreatorType::Organization))
                .map(|c| c.name.clone())
        })
        .unwrap_or_else(|| "sbom-tools".to_string());

    let title = opt.title.clone().unwrap_or_else(|| {
        let primary = sbom
            .document
            .name
            .clone()
            .or_else(|| sbom.primary_component_id.as_ref().map(|c| c.value().to_string()))
            .unwrap_or_else(|| "SBOM".to_string());
        format!("VEX advisory for {primary}")
    });

    let document_id = opt.document_id.clone().unwrap_or_else(|| {
        format!("sbom-tools-vex-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"))
    });

    CsafDocOut {
        document: CsafHeaderOut {
            csaf_version: "2.0".to_string(),
            category: opt
                .category
                .clone()
                .unwrap_or_else(|| "csaf_vex".to_string()),
            publisher: CsafPublisherOut {
                category: opt
                    .publisher_category
                    .clone()
                    .unwrap_or_else(|| "vendor".to_string()),
                name: publisher_name,
                namespace: opt
                    .publisher_namespace
                    .clone()
                    .unwrap_or_else(|| "https://example.invalid".to_string()),
            },
            title,
            tracking: CsafTrackingOut {
                id: document_id,
                version: "1".to_string(),
                status: "final".to_string(),
                initial_release_date: now_rfc3339.clone(),
                current_release_date: now_rfc3339.clone(),
                revision_history: vec![CsafRevisionOut {
                    number: "1".to_string(),
                    date: now_rfc3339.clone(),
                    summary: "Initial publication".to_string(),
                }],
                generator: CsafGeneratorOut {
                    engine: CsafEngineOut {
                        name: "sbom-tools".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    },
                },
            },
        },
        product_tree: CsafProductTreeOut {
            full_product_names,
        },
        vulnerabilities,
    }
}

fn identifier_system(id: &str) -> &'static str {
    if id.starts_with("GHSA-") {
        "GHSA"
    } else if id.starts_with("RUSTSEC-") {
        "RUSTSEC"
    } else if id.starts_with("OSV-") {
        "OSV"
    } else if id.starts_with("CVE-") {
        "CVE"
    } else {
        "vendor"
    }
}

#[derive(Default)]
struct ProductStatusBuckets {
    known_affected: Vec<String>,
    known_not_affected: Vec<String>,
    fixed: Vec<String>,
    under_investigation: Vec<String>,
}

impl ProductStatusBuckets {
    fn into_serializable(self) -> CsafProductStatusOut {
        CsafProductStatusOut {
            known_affected: self.known_affected,
            known_not_affected: self.known_not_affected,
            fixed: self.fixed,
            under_investigation: self.under_investigation,
        }
    }
}

// ============================================================================
// CSAF v2.0 serde structs (output side)
// ============================================================================

#[derive(Serialize)]
struct CsafDocOut {
    document: CsafHeaderOut,
    product_tree: CsafProductTreeOut,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<CsafVulnOut>,
}

#[derive(Serialize)]
struct CsafHeaderOut {
    category: String,
    csaf_version: String,
    publisher: CsafPublisherOut,
    title: String,
    tracking: CsafTrackingOut,
}

#[derive(Serialize)]
struct CsafPublisherOut {
    category: String,
    name: String,
    namespace: String,
}

#[derive(Serialize)]
struct CsafTrackingOut {
    id: String,
    initial_release_date: String,
    current_release_date: String,
    version: String,
    status: String,
    revision_history: Vec<CsafRevisionOut>,
    generator: CsafGeneratorOut,
}

#[derive(Serialize)]
struct CsafRevisionOut {
    number: String,
    date: String,
    summary: String,
}

#[derive(Serialize)]
struct CsafGeneratorOut {
    engine: CsafEngineOut,
}

#[derive(Serialize)]
struct CsafEngineOut {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct CsafProductTreeOut {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    full_product_names: Vec<CsafProductOut>,
}

#[derive(Serialize)]
struct CsafProductOut {
    product_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_identification_helper: Option<CsafProductHelperOut>,
}

#[derive(Serialize)]
struct CsafProductHelperOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
}

#[derive(Serialize)]
struct CsafVulnOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    cve: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ids: Vec<CsafVulnIdOut>,
    product_status: CsafProductStatusOut,
}

#[derive(Serialize)]
struct CsafVulnIdOut {
    system_name: String,
    text: String,
}

#[derive(Serialize)]
struct CsafProductStatusOut {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    known_affected: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    known_not_affected: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fixed: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    under_investigation: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Component, NormalizedSbom, VexStatus, VulnerabilityRef, VulnerabilitySource,
    };

    fn sbom_with(purl: &str, name: &str, vuln: &str, state: VexState) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new(name.to_string(), name.to_string());
        c.identifiers.purl = Some(purl.to_string());
        let mut v = VulnerabilityRef::new(vuln.to_string(), VulnerabilitySource::Cve);
        v.vex_status = Some(VexStatus::new(state));
        c.vulnerabilities.push(v);
        sbom.add_component(c);
        sbom
    }

    #[test]
    fn emit_minimal_csaf_document() {
        let sbom = sbom_with(
            "pkg:cargo/example@1.0.0",
            "example",
            "CVE-2024-12345",
            VexState::Affected,
        );
        let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).expect("emit");
        let json: serde_json::Value = serde_json::from_str(&csaf).expect("valid JSON");
        assert_eq!(json["document"]["csaf_version"], "2.0");
        assert_eq!(json["document"]["category"], "csaf_vex");
        let products = json["product_tree"]["full_product_names"]
            .as_array()
            .unwrap();
        assert_eq!(products.len(), 1);
        assert_eq!(
            products[0]["product_identification_helper"]["purl"],
            "pkg:cargo/example@1.0.0"
        );
        let vulns = json["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["cve"], "CVE-2024-12345");
        let affected = vulns[0]["product_status"]["known_affected"]
            .as_array()
            .unwrap();
        assert_eq!(affected.len(), 1);
    }

    #[test]
    fn emit_groups_states_by_product_status() {
        let mut sbom = NormalizedSbom::default();
        for (i, state) in [
            VexState::Affected,
            VexState::NotAffected,
            VexState::Fixed,
            VexState::UnderInvestigation,
        ]
        .iter()
        .enumerate()
        {
            let mut c =
                Component::new(format!("c{i}"), format!("c{i}@1.0"));
            c.identifiers.purl = Some(format!("pkg:cargo/c{i}@1.0"));
            let mut v =
                VulnerabilityRef::new("CVE-2024-99999".to_string(), VulnerabilitySource::Cve);
            v.vex_status = Some(VexStatus::new(state.clone()));
            c.vulnerabilities.push(v);
            sbom.add_component(c);
        }
        let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).expect("emit");
        let json: serde_json::Value = serde_json::from_str(&csaf).unwrap();
        let status = &json["vulnerabilities"][0]["product_status"];
        assert_eq!(status["known_affected"].as_array().unwrap().len(), 1);
        assert_eq!(status["known_not_affected"].as_array().unwrap().len(), 1);
        assert_eq!(status["fixed"].as_array().unwrap().len(), 1);
        assert_eq!(status["under_investigation"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn emit_uses_ids_for_non_cve_identifiers() {
        let sbom = sbom_with(
            "pkg:cargo/example@1.0.0",
            "example",
            "GHSA-aaaa-bbbb-cccc",
            VexState::Affected,
        );
        // The internal model defaults VulnerabilityRef::new to CVE source,
        // but emit logic keys off the `vuln_id` string itself (CVE prefix).
        let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).expect("emit");
        let json: serde_json::Value = serde_json::from_str(&csaf).unwrap();
        let vuln = &json["vulnerabilities"][0];
        assert!(vuln["cve"].is_null(), "non-CVE id must not surface as cve");
        let ids = vuln["ids"].as_array().unwrap();
        assert_eq!(ids[0]["system_name"], "GHSA");
        assert_eq!(ids[0]["text"], "GHSA-aaaa-bbbb-cccc");
    }

    #[test]
    fn emit_skips_components_without_purl() {
        let mut sbom = NormalizedSbom::default();
        let mut c = Component::new("noident".to_string(), "noident".to_string());
        let mut v =
            VulnerabilityRef::new("CVE-2024-12345".to_string(), VulnerabilitySource::Cve);
        v.vex_status = Some(VexStatus::new(VexState::Affected));
        c.vulnerabilities.push(v);
        sbom.add_component(c);

        let csaf = emit_csaf(&sbom, &CsafEmitOptions::default()).expect("emit");
        let json: serde_json::Value = serde_json::from_str(&csaf).unwrap();
        assert!(
            json["product_tree"]["full_product_names"]
                .as_array()
                .map_or(true, |a| a.is_empty()),
            "components without PURL must not appear in product_tree"
        );
        // No products → no product_status entries → no vulnerabilities surfaced
        assert!(
            json["vulnerabilities"]
                .as_array()
                .map_or(true, |a| a.is_empty())
        );
    }
}
