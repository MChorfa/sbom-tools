//! sbomqs-compatible score emission ("sbomqs-compat" interoperability view).
//!
//! Recomputes interlynk-io/sbomqs **legacy (v1) engine** feature scores from
//! the normalized SBOM and emits them in the exact JSON shape of
//! `sbomqs score --json` (pkg/reporter/json.go struct tags), so users can put
//! this tool's output side by side with sbomqs output. Parity target:
//! **sbomqs v2.0.11** — every formula below was pinned against the fetched
//! v2.0.11 sources (`pkg/scorer/{criteria,semantic,quality,ntia,structural,`
//! `sharing,scores,score}.go`, `pkg/sbom/{sbom,cdx,spdx}.go`,
//! `pkg/licenses/{license,embed_licenses}.go`, `pkg/reporter/json.go`).
//!
//! This is a presentation layer only: nothing here changes scoring weights,
//! metrics, or compliance checks, and nothing here reads
//! [`crate::quality::QualityReport`] — in particular never its
//! `overall_score`. The 0-100 pipeline and the sbomqs 0-10 model use
//! different category taxonomies, different weights, and different
//! missing-data semantics (N/A renormalization vs ignored-in-denominator),
//! so dividing the 0-100 score by 10 is **not** an sbomqs-comparable number.
//! Per-feature recomputation, as done here, is the only honest comparison.
//!
//! # Aggregation (verbatim sbomqs semantics)
//!
//! * Feature scores are floats in `[0, 10]`; `max_score` is always `10`.
//! * `avg_score = sum(score of non-ignored entries) / count(ALL entries,`
//!   `ignored included)` — the verbatim `scores.go AvgScore()` formula,
//!   quirk included (ignored entries stay in the denominator).
//! * Grades use the sbomqs `ToGrade` brackets **A ≥ 9.0, B ≥ 8.0, C ≥ 7.0,
//!   D ≥ 5.0, F otherwise** — NOT this repo's `QualityGrade` brackets
//!   (A ≥ 90 … D ≥ 60 on 0-100), whose D/F cut lines differ. Grades are
//!   therefore never copied from a `QualityReport`; they are recomputed here.
//!
//! # Exact vs approximate vs not-computable
//!
//! Feature-by-feature fidelity against sbomqs v2.0.11 (see
//! `docs/STANDARDS_VERSIONS.md`, "sbomqs interoperability" for the full
//! user-facing table):
//!
//! * **Exact** (same observable behaviour for any document both tools parse):
//!   `sbom_spec`, `sbom_spec_version`, `sbom_parsable` (with the documented
//!   asymmetry that this pipeline only ever scores documents it parsed, while
//!   sbomqs can score an unparsable file 0), `comp_with_name`,
//!   `comp_with_version`, `comp_with_uniq_ids`, `comp_with_checksums`,
//!   `comp_with_licenses`, `comp_with_any_vuln_lookup_id`,
//!   `comp_with_multi_vuln_lookup_id`, `sbom_authors`, `sbom_dependencies`,
//!   `sbom_with_primary_component`.
//! * **Approximate** (model keeps less than sbomqs reads; direction of the
//!   possible drift documented on each evaluator): `sbom_file_format`
//!   (detected from the raw document text), `sbom_creation_timestamp`
//!   (epoch sentinel for missing/invalid timestamps),
//!   `sbom_required_fields` (SPDX `downloadLocation` / CDX `bomFormat` and
//!   dependency-ref checks are not modeled), `comp_with_supplier` (SPDX
//!   originator fallback approximated via the author field),
//!   `comp_valid_licenses` / `comp_with_deprecated_licenses` /
//!   `comp_with_restrictive_licenses` (license-expression tokenization and
//!   SPDX-list flags via the `spdx` crate instead of sbomqs' embedded
//!   list + AboutCode overlay), `comp_with_primary_purpose` (typed
//!   `ComponentType` loses the raw purpose string and defaults to Library),
//!   `sbom_with_creator_and_version` (tool version recovered heuristically
//!   from the normalized creator name), `sbom_sharable` (see below).
//! * **Not computable → `ignored: true`**: when the original document text is
//!   not provided (library callers), `sbom_file_format` and `sbom_sharable`
//!   are emitted with `ignored: true` and a reason — never silently dropped
//!   (dropping would inflate `avg_score` through the denominator) and never
//!   fabricated as 0 or 10. Ignored entries still count in the denominator,
//!   exactly as sbomqs treats a disabled check.
//!
//! # Known upstream quirks replicated or documented
//!
//! * `sbom_sharable`: sbomqs v2.0.11's vendored SPDX license list
//!   (`pkg/licenses/files/licenses_spdx.json`) carries **no** `isFreeAnyUse`
//!   flags, so every SPDX-listed document license (including `CC0-1.0`)
//!   counts as not-free and the check scores 0.0 for essentially every real
//!   document. This emitter replicates that (score 0.0, not ignored, when
//!   the raw document is available). The only inputs sbomqs scores 10 are
//!   document licenses absent from the SPDX list but present in its
//!   AboutCode data with a "Public Domain" category — that data is not
//!   embedded here, so such documents (rare) would diverge; the description
//!   discloses this.
//! * `sbom_with_creator_and_version` divides by the tool count; with zero
//!   tools Go computes `0.0/0.0 = NaN`, which sbomqs' `setScore` coerces to
//!   `0.0`. Replicated as a plain 0.0.
//! * `sbom_required_fields` is NOT binary: `docOK && all pkgs OK → 10.0`;
//!   `docOK && partial pkgs → (10 + 10·have/total)/2` (e.g. 7.5; and 5.0 for
//!   a docOK document with zero components); `!docOK → 0.0` regardless of
//!   package fields (the `(0+10)/2` branch in sbomqs is immediately
//!   overwritten with 0.0 — quirk preserved).
//! * Component-list checks on a zero-component SBOM emit score 0.0 with
//!   `ignored: true` ("N/A (no components)") and stay in the denominator.
//! * `comp_valid_licenses` is a mean over ALL components of per-component
//!   ratios `(spdx-listed / total licenses) · 10`, with license-less
//!   components contributing 0 — not `10·have/total`. Only SPDX-list
//!   membership counts (sbomqs `l.Spdx()`); `LicenseRef-*` and other custom
//!   ids do NOT count in the v1 engine.
//! * `comp_with_deprecated_licenses` / `comp_with_restrictive_licenses` are
//!   inverted proportionals `10·(total−affected)/total`, and score 0.0 with
//!   "no licenses found" when the whole SBOM has no licenses.
//!
//! # Component enumeration parity
//!
//! sbomqs enumerates SPDX *packages* (files/snippets live in a separate
//! list) and CycloneDX components including `metadata.component` (services
//! are not components). The normalized model folds SPDX files/snippets and
//! CycloneDX services into `components`, so this module filters them back
//! out: SPDX components typed `File` and CycloneDX components typed
//! `Other("service")` are excluded from every per-component denominator and
//! from `num_components`. (Side effect: an SPDX *package* whose
//! `primaryPackagePurpose` is SOURCE/ARCHIVE/FILE is also excluded, because
//! the typed model collapses those purposes into `ComponentType::File`.)

use crate::model::{Component, ComponentType, CreatorType, NormalizedSbom, SbomFormat};
use serde::{Deserialize, Serialize};

/// sbomqs release every formula in this module was verified against.
pub const SBOMQS_PARITY_TARGET: &str = "v2.0.11";

/// sbomqs scorer engine version (`pkg/scorer/scorer.go EngineVersion`) whose
/// behaviour this emitter models.
pub const SBOMQS_ENGINE_VERSION: &str = "7";

// Exact sbomqs v1 category strings (pkg/scorer/criteria.go) — downstream
// dashboards bucket on these byte-for-byte.
const CAT_NTIA: &str = "NTIA-minimum-elements";
const CAT_SEMANTIC: &str = "Semantic";
const CAT_QUALITY: &str = "Quality";
const CAT_SHARING: &str = "Sharing";
const CAT_STRUCTURAL: &str = "Structural";

/// Category emission order matches the sbomqs v1 default run
/// (criteria.go registration order with the bsi category-profiles filtered
/// out): NTIA, Semantic, Quality, Sharing, Structural.
pub const CATEGORY_ORDER: [&str; 5] = [
    CAT_NTIA,
    CAT_SEMANTIC,
    CAT_QUALITY,
    CAT_SHARING,
    CAT_STRUCTURAL,
];

// Recognition tables, verbatim from sbomqs v2.0.11 pkg/sbom/{cdx,spdx}.go.
const CDX_SPEC_VERSIONS: &[&str] = &["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"];
const SPDX_SPEC_VERSIONS: &[&str] = &["2.1", "2.2", "2.3"];
const CDX_FILE_FORMATS: &[&str] = &["json", "xml"];
const SPDX_FILE_FORMATS: &[&str] = &["json", "yaml", "rdf", "tag-value"];
const CDX_PRIMARY_PURPOSES: &[&str] = &[
    "application",
    "framework",
    "library",
    "container",
    "operating-system",
    "device",
    "firmware",
    "file",
];
const SPDX_PRIMARY_PURPOSES: &[&str] = &[
    "application",
    "framework",
    "library",
    "container",
    "operating-system",
    "device",
    "firmware",
    "source",
    "archive",
    "file",
    "install",
    "other",
];

const NO_COMPONENTS_DESC: &str = "N/A (no components)";

// ---------------------------------------------------------------------------
// JSON schema — field names/types mirror sbomqs pkg/reporter/json.go exactly.
// ---------------------------------------------------------------------------

/// One entry of the `scores` array (`pkg/reporter/json.go` `score`).
#[derive(Debug, Clone, Serialize)]
pub struct SbomqsScoreEntry {
    /// Exact sbomqs v1 category string (see [`CATEGORY_ORDER`]).
    pub category: String,
    /// Exact sbomqs feature key (e.g. `comp_with_name`).
    pub feature: String,
    /// Feature score in `[0, 10]`.
    pub score: f64,
    /// Always `10.0` (sbomqs `MAX_SCORE`).
    pub max_score: f64,
    /// Human-readable description; for `ignored: true` entries this states
    /// why sbom-tools cannot compute the feature.
    pub description: String,
    /// Entry excluded from the `avg_score` numerator but NOT the denominator
    /// (verbatim sbomqs `AvgScore` semantics).
    pub ignored: bool,
}

/// Per-file block (`pkg/reporter/json.go` `file`).
#[derive(Debug, Clone, Serialize)]
pub struct SbomqsFileReport {
    pub file_name: String,
    /// `"cyclonedx"` or `"spdx"` (sbomqs spec-type strings).
    pub spec: String,
    pub spec_version: String,
    /// `"json"`, `"xml"`, `"yaml"`, `"rdf"`, `"tag-value"` or `"unknown"`.
    pub file_format: String,
    /// `sum(non-ignored scores) / count(all scores)` — verbatim `AvgScore`.
    pub avg_score: f64,
    /// Size of the sbomqs-visible component set (SPDX file/snippet
    /// components and CycloneDX service components excluded — see module
    /// docs on component enumeration parity).
    pub num_components: usize,
    /// RFC 3339 creation timestamp, or `""` when the document has none
    /// (parsers substitute an epoch sentinel for missing timestamps).
    pub creation_time: String,
    pub gen_tool_name: String,
    pub gen_tool_version: String,
    pub scores: Vec<SbomqsScoreEntry>,
}

/// `creation_info` block. Honest identity: names this tool, never the
/// sbomqs binary, so divergent scores cannot be mis-attributed to Interlynk.
#[derive(Debug, Clone, Serialize)]
pub struct SbomqsCreationInfo {
    pub name: String,
    pub version: String,
    pub scoring_engine_version: String,
    pub vendor: String,
}

/// Top-level report (`pkg/reporter/json.go` `jsonReport`).
#[derive(Debug, Clone, Serialize)]
pub struct SbomqsReport {
    pub run_id: String,
    pub timestamp: String,
    pub creation_info: SbomqsCreationInfo,
    pub files: Vec<SbomqsFileReport>,
}

/// Input for the compat emitter.
///
/// `raw_content` is the original (pre-parse) document text. When present,
/// `sbom_file_format` and `sbom_sharable` are computed from it; when absent
/// those two features are emitted with `ignored: true` and a reason.
pub struct SbomqsCompatInput<'a> {
    pub sbom: &'a NormalizedSbom,
    /// File name reported as `file_name` (sbomqs reports the CLI input path).
    pub file_name: &'a str,
    pub raw_content: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the full sbomqs-shaped report for one SBOM.
#[must_use]
pub fn build_report(input: &SbomqsCompatInput<'_>) -> SbomqsReport {
    let scores = compute_scores(input);
    let avg = avg_score(&scores);
    let facts = input
        .raw_content
        .map(|raw| extract_raw_facts(raw, &input.sbom.document.format));
    let comps = compat_components(input.sbom);
    let (tool_name, tool_version) = first_tool_name_version(input.sbom);

    let doc = &input.sbom.document;
    let file = SbomqsFileReport {
        file_name: input.file_name.to_string(),
        spec: spec_type_string(&doc.format).to_string(),
        spec_version: doc.spec_version.clone(),
        file_format: facts
            .as_ref()
            .map_or("unknown", |f| f.file_format)
            .to_string(),
        avg_score: avg,
        num_components: comps.len(),
        creation_time: if doc.has_known_timestamp() {
            doc.created
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        } else {
            String::new()
        },
        gen_tool_name: tool_name,
        gen_tool_version: tool_version,
        scores,
    };

    SbomqsReport {
        run_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        creation_info: SbomqsCreationInfo {
            name: "sbom-tools".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            scoring_engine_version: format!(
                "sbomqs-compat-v1 (parity target sbomqs {SBOMQS_PARITY_TARGET} engine {SBOMQS_ENGINE_VERSION}; sbom-tools engine {})",
                crate::quality::SCORING_ENGINE_VERSION
            ),
            vendor: "sbom-tools project".to_string(),
        },
        files: vec![file],
    }
}

/// Render the report as pretty-printed JSON (the `-o sbomqs-json` payload).
#[must_use]
pub fn render_json(input: &SbomqsCompatInput<'_>) -> String {
    serde_json::to_string_pretty(&build_report(input)).unwrap_or_else(|_| "{}".to_string())
}

/// Per-category rollup for the human summary table.
///
/// sbomqs' v1 engine has no per-category aggregate of its own; this applies
/// the same `AvgScore` formula scoped to one category (what
/// `sbomqs score --category X` would report as its average), which keeps the
/// numbers comparable.
#[derive(Debug, Clone)]
pub struct CategoryRollup {
    /// Exact sbomqs category string.
    pub category: &'static str,
    /// `None` when every feature in the category is `ignored` (not
    /// computable from this model) — rendered as `n/a` plus the reason.
    pub score: Option<f64>,
    /// Reason for `score == None` (first ignored feature's description).
    pub reason: Option<String>,
}

/// Compute per-category rollups in sbomqs emission order.
#[must_use]
pub fn category_rollups(scores: &[SbomqsScoreEntry]) -> Vec<CategoryRollup> {
    CATEGORY_ORDER
        .iter()
        .map(|cat| {
            let entries: Vec<&SbomqsScoreEntry> =
                scores.iter().filter(|s| s.category == *cat).collect();
            let all_ignored = !entries.is_empty() && entries.iter().all(|s| s.ignored);
            if all_ignored {
                CategoryRollup {
                    category: cat,
                    score: None,
                    reason: entries.first().map(|s| s.description.clone()),
                }
            } else {
                let sum: f64 = entries.iter().filter(|s| !s.ignored).map(|s| s.score).sum();
                #[allow(clippy::cast_precision_loss)]
                let count = entries.len() as f64;
                CategoryRollup {
                    category: cat,
                    score: Some(if entries.is_empty() { 0.0 } else { sum / count }),
                    reason: None,
                }
            }
        })
        .collect()
}

/// Render the compact sbomqs-comparable table appended to the human summary.
#[must_use]
pub fn render_summary_table(input: &SbomqsCompatInput<'_>) -> String {
    let scores = compute_scores(input);
    let avg = avg_score(&scores);
    let rollups = category_rollups(&scores);

    let mut lines = Vec::new();
    lines.push(format!(
        "sbomqs-Comparable Scores (sbomqs {SBOMQS_PARITY_TARGET} score model, 0-10):"
    ));
    for rollup in rollups {
        match rollup.score {
            Some(score) => lines.push(format!("  {:<22} {:>4.1}/10", rollup.category, score)),
            None => lines.push(format!(
                "  {:<22}  n/a  ({})",
                rollup.category,
                rollup
                    .reason
                    .unwrap_or_else(|| "not computable".to_string())
            )),
        }
    }
    lines.push(format!(
        "  {:<22} {:>4.1}/10  (sbomqs grade: {})",
        "avg_score",
        avg,
        sbomqs_grade(avg)
    ));
    lines
        .push("  Recomputed per-feature from the SBOM with sbomqs' formulas — NOT the".to_string());
    lines.push("  0-100 score above divided by 10 (the scales are not convertible).".to_string());
    lines.push("  Full detail: --output sbomqs-json".to_string());
    lines.join("\n")
}

/// sbomqs grade brackets (`ToGrade`, source-verified; the sbomqs docs page
/// claiming A=8.0-10.0 is stale): A ≥ 9.0, B ≥ 8.0, C ≥ 7.0, D ≥ 5.0, else F.
#[must_use]
pub fn sbomqs_grade(avg: f64) -> &'static str {
    if avg >= 9.0 {
        "A"
    } else if avg >= 8.0 {
        "B"
    } else if avg >= 7.0 {
        "C"
    } else if avg >= 5.0 {
        "D"
    } else {
        "F"
    }
}

/// Verbatim sbomqs `AvgScore`: non-ignored scores summed, divided by the
/// count of ALL entries (ignored ones stay in the denominator).
#[must_use]
pub fn avg_score(scores: &[SbomqsScoreEntry]) -> f64 {
    if scores.is_empty() {
        return 0.0;
    }
    let sum: f64 = scores.iter().filter(|s| !s.ignored).map(|s| s.score).sum();
    #[allow(clippy::cast_precision_loss)]
    let count = scores.len() as f64;
    sum / count
}

/// Compute all 23 v1 default-profile feature scores in sbomqs order.
#[must_use]
pub fn compute_scores(input: &SbomqsCompatInput<'_>) -> Vec<SbomqsScoreEntry> {
    let sbom = input.sbom;
    let comps = compat_components(sbom);
    let facts = input
        .raw_content
        .map(|raw| extract_raw_facts(raw, &sbom.document.format));
    let tokens: Vec<Vec<LicenseToken>> =
        comps.iter().map(|c| component_license_tokens(c)).collect();

    let mut scores = Vec::with_capacity(23);

    // --- NTIA-minimum-elements -------------------------------------------
    scores.push(proportional(
        CAT_NTIA,
        "comp_with_name",
        count_by(&comps, |c| !c.name.trim().is_empty()),
        comps.len(),
        "have names",
    ));
    scores.push(proportional(
        CAT_NTIA,
        "comp_with_version",
        count_by(&comps, |c| {
            c.version.as_deref().is_some_and(|v| !v.trim().is_empty())
        }),
        comps.len(),
        "have versions",
    ));
    // NTIA uniq-ids = compWithUniqIDCheck semantics: a non-empty LOCAL id
    // (bom-ref / SPDXID), NOT purl/cpe presence (that is the BSI variant).
    scores.push(proportional(
        CAT_NTIA,
        "comp_with_uniq_ids",
        count_by(&comps, |c| !c.identifiers.format_id.trim().is_empty()),
        comps.len(),
        "have unique ID's",
    ));
    scores.push(proportional(
        CAT_NTIA,
        "comp_with_supplier",
        count_by(&comps, |c| has_supplier(c, &sbom.document.format)),
        comps.len(),
        "have supplier names",
    ));
    scores.push(timestamp_check(sbom));
    scores.push(authors_check(sbom));
    scores.push(dependencies_check(sbom));

    // --- Semantic ---------------------------------------------------------
    scores.push(required_fields_check(sbom, &comps, facts.as_ref()));
    scores.push(proportional(
        CAT_SEMANTIC,
        "comp_with_licenses",
        tokens.iter().filter(|t| !t.is_empty()).count(),
        comps.len(),
        "have licenses",
    ));
    scores.push(proportional(
        CAT_SEMANTIC,
        "comp_with_checksums",
        count_by(&comps, |c| !c.hashes.is_empty()),
        comps.len(),
        "have checksums",
    ));

    // --- Quality ----------------------------------------------------------
    scores.push(valid_licenses_check(&comps, &tokens));
    scores.push(primary_purpose_check(&comps, &sbom.document.format));
    scores.push(inverted_license_check(
        "comp_with_deprecated_licenses",
        &comps,
        &tokens,
        |t| t.deprecated,
        "have deprecated licenses",
    ));
    scores.push(inverted_license_check(
        "comp_with_restrictive_licenses",
        &comps,
        &tokens,
        |t| t.restrictive,
        "have restricted licenses",
    ));
    scores.push(proportional(
        CAT_QUALITY,
        "comp_with_any_vuln_lookup_id",
        count_by(&comps, |c| has_purl(c) || has_cpe(c)),
        comps.len(),
        "components have any lookup id",
    ));
    scores.push(proportional(
        CAT_QUALITY,
        "comp_with_multi_vuln_lookup_id",
        count_by(&comps, |c| has_purl(c) && has_cpe(c)),
        comps.len(),
        "components have multiple lookup id",
    ));
    scores.push(creator_and_version_check(sbom));
    scores.push(primary_component_check(sbom));

    // --- Sharing ----------------------------------------------------------
    scores.push(sharable_check(facts.as_ref()));

    // --- Structural -------------------------------------------------------
    scores.push(spec_check(sbom));
    scores.push(spec_version_check(sbom));
    scores.push(file_format_check(sbom, facts.as_ref()));
    scores.push(SbomqsScoreEntry {
        category: CAT_STRUCTURAL.to_string(),
        feature: "sbom_parsable".to_string(),
        score: 10.0,
        max_score: 10.0,
        description: "provided sbom is parsable (this pipeline only scores documents it \
                      successfully parsed; sbomqs can additionally score an unparsable file 0)"
            .to_string(),
        ignored: false,
    });

    scores
}

// ---------------------------------------------------------------------------
// Component enumeration
// ---------------------------------------------------------------------------

/// The sbomqs-visible component set (see module docs): SPDX file/snippet
/// components and CycloneDX service components are excluded.
fn compat_components(sbom: &NormalizedSbom) -> Vec<&Component> {
    sbom.components
        .values()
        .filter(|c| match sbom.document.format {
            SbomFormat::Spdx => c.component_type != ComponentType::File,
            SbomFormat::CycloneDx => {
                !matches!(&c.component_type, ComponentType::Other(s) if s == "service")
            }
        })
        .collect()
}

fn count_by(comps: &[&Component], pred: impl Fn(&Component) -> bool) -> usize {
    comps.iter().filter(|c| pred(c)).count()
}

fn has_purl(c: &Component) -> bool {
    c.identifiers
        .purl
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty())
}

fn has_cpe(c: &Component) -> bool {
    c.identifiers.cpe.iter().any(|c| !c.trim().is_empty())
}

/// Supplier presence. sbomqs falls back to the SPDX originator when the
/// supplier is absent; this model maps the SPDX originator into
/// `Component.author`, so for SPDX documents the author field is accepted as
/// the fallback (approximate).
fn has_supplier(c: &Component, format: &SbomFormat) -> bool {
    let supplier = c
        .supplier
        .as_ref()
        .is_some_and(|s| !s.name.trim().is_empty());
    match format {
        SbomFormat::Spdx => supplier || c.author.as_deref().is_some_and(|a| !a.trim().is_empty()),
        SbomFormat::CycloneDx => supplier,
    }
}

// ---------------------------------------------------------------------------
// Shared score constructors
// ---------------------------------------------------------------------------

fn zero_components_entry(category: &str, feature: &str) -> SbomqsScoreEntry {
    SbomqsScoreEntry {
        category: category.to_string(),
        feature: feature.to_string(),
        score: 0.0,
        max_score: 10.0,
        description: NO_COMPONENTS_DESC.to_string(),
        ignored: true,
    }
}

/// sbomqs proportional component-list score: `10 · have/total`; a
/// zero-component SBOM emits `0.0` + `ignored: true` (and stays in the
/// `avg_score` denominator). The v1 engine has no 9.9 cap (that cap is
/// v2-only).
fn proportional(
    category: &str,
    feature: &str,
    have: usize,
    total: usize,
    what: &str,
) -> SbomqsScoreEntry {
    if total == 0 {
        return zero_components_entry(category, feature);
    }
    #[allow(clippy::cast_precision_loss)]
    let score = (have as f64 / total as f64) * 10.0;
    SbomqsScoreEntry {
        category: category.to_string(),
        feature: feature.to_string(),
        score,
        max_score: 10.0,
        description: format!("{have}/{total} {what}"),
        ignored: false,
    }
}

// ---------------------------------------------------------------------------
// Document-level evaluators
// ---------------------------------------------------------------------------

/// `sbom_creation_timestamp` — approximate: parsers substitute an epoch
/// sentinel for missing/unparseable timestamps, so "no timestamp" and "a
/// timestamp sbomqs would reject as malformed" both score 0 here; a document
/// genuinely claiming 1970-01-01T00:00:00Z also reads as missing.
fn timestamp_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    let doc = &sbom.document;
    let (score, description) = if doc.has_known_timestamp() {
        (
            10.0,
            format!(
                "doc has creation timestamp {}",
                doc.created
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
        )
    } else {
        (
            0.0,
            "doc has no (or an unparseable) creation timestamp".to_string(),
        )
    };
    SbomqsScoreEntry {
        category: CAT_NTIA.to_string(),
        feature: "sbom_creation_timestamp".to_string(),
        score,
        max_score: 10.0,
        description,
        ignored: false,
    }
}

/// `sbom_authors` — sbomqs counts authors (persons/organizations) PLUS
/// tools; the normalized `creators` list carries all three, so any creator
/// scores 10 (exact).
fn authors_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    let total = sbom.document.creators.len();
    SbomqsScoreEntry {
        category: CAT_NTIA.to_string(),
        feature: "sbom_authors".to_string(),
        score: if total > 0 { 10.0 } else { 0.0 },
        max_score: 10.0,
        description: format!("doc has {total} authors"),
        ignored: false,
    }
}

/// `sbom_dependencies` — binary on the PRIMARY component's direct
/// dependencies (verbatim `sbomWithDepedenciesCheck`), not on arbitrary
/// dependency edges.
fn dependencies_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    let total = sbom.primary_component_id.as_ref().map_or(0, |primary| {
        sbom.edges.iter().filter(|e| &e.from == primary).count()
    });
    SbomqsScoreEntry {
        category: CAT_NTIA.to_string(),
        feature: "sbom_dependencies".to_string(),
        score: if total > 0 { 10.0 } else { 0.0 },
        max_score: 10.0,
        description: format!("primary comp has {total} dependencies"),
        ignored: false,
    }
}

/// `sbom_required_fields` — the blended doc+package formula (see module
/// docs). Doc-level checks are approximated where the model keeps less than
/// sbomqs reads:
///
/// * CycloneDX docOK ≈ `specVersion` present && document `version ≥ 1`
///   (`bomFormat` presence and per-dependency `ref` checks are not modeled;
///   both are enforced by this repo's parser for JSON, so drift is towards
///   sbomqs scoring lower on malformed documents this parser rejects).
/// * SPDX docOK ≈ version/name/namespace/creators/timestamp present, plus
///   `dataLicense` presence read from the raw document when available
///   (assumed present otherwise); `SPDXID` presence is implied by parse.
/// * CycloneDX pkgOK ≈ name present (`type` is schema-required);
///   SPDX pkgOK ≈ name + SPDXID present (`downloadLocation` and
///   `packageVerificationCode` are not modeled — drift towards scoring
///   HIGHER than sbomqs on packages missing those).
fn required_fields_check(
    sbom: &NormalizedSbom,
    comps: &[&Component],
    facts: Option<&RawFacts>,
) -> SbomqsScoreEntry {
    let doc = &sbom.document;
    let doc_ok = match doc.format {
        SbomFormat::CycloneDx => {
            !doc.spec_version.trim().is_empty() && doc.doc_version.unwrap_or(0) >= 1
        }
        SbomFormat::Spdx => {
            !doc.spec_version.trim().is_empty()
                && doc.name.as_deref().is_some_and(|n| !n.trim().is_empty())
                && doc
                    .serial_number
                    .as_deref()
                    .is_some_and(|n| !n.trim().is_empty())
                && !doc.creators.is_empty()
                && doc.has_known_timestamp()
                && facts.is_none_or(|f| f.has_data_license)
        }
    };

    let total = comps.len();
    let ok = count_by(comps, |c| match doc.format {
        SbomFormat::CycloneDx => !c.name.trim().is_empty(),
        SbomFormat::Spdx => !c.name.trim().is_empty() && !c.identifiers.format_id.trim().is_empty(),
    });
    let pkgs_ok = total > 0 && ok == total;

    // Verbatim sbomWithRequiredFieldCheck shape, quirk preserved: !docOK
    // scores 0.0 no matter how complete the packages are.
    let score = if !doc_ok {
        0.0
    } else if pkgs_ok {
        10.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let pkg_score = if total > 0 {
            (ok as f64 / total as f64) * 10.0
        } else {
            0.0
        };
        (10.0 + pkg_score) / 2.0
    };

    SbomqsScoreEntry {
        category: CAT_SEMANTIC.to_string(),
        feature: "sbom_required_fields".to_string(),
        score,
        max_score: 10.0,
        description: format!("Doc Fields:{doc_ok} Pkg Fields:{pkgs_ok}"),
        ignored: false,
    }
}

/// `sbom_with_creator_and_version` — tools with both a name and a version,
/// over the tool count. Approximate: the normalized model folds the tool
/// version into the creator name (CycloneDX: `"name version"`; SPDX keeps
/// the raw `name-version` string), so the version is recovered
/// heuristically: the last space- or hyphen-separated token counts as a
/// version when it contains a digit — the same heuristic sbomqs itself
/// applies to SPDX tool strings. Zero tools replicate sbomqs' `0/0 → NaN →
/// setScore → 0.0` coercion as a plain 0.0.
fn creator_and_version_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    let tools: Vec<&crate::model::Creator> = sbom
        .document
        .creators
        .iter()
        .filter(|c| c.creator_type == CreatorType::Tool)
        .collect();
    let with_version = tools
        .iter()
        .filter(|t| {
            let (name, version) = split_tool_name_version(&t.name);
            !name.is_empty() && !version.is_empty()
        })
        .count();
    #[allow(clippy::cast_precision_loss)]
    let score = if tools.is_empty() {
        // Go: 0.0/0.0 = NaN, coerced to 0.0 by sbomqs setScore.
        0.0
    } else {
        (with_version as f64 / tools.len() as f64) * 10.0
    };
    SbomqsScoreEntry {
        category: CAT_QUALITY.to_string(),
        feature: "sbom_with_creator_and_version".to_string(),
        score,
        max_score: 10.0,
        description: format!(
            "{with_version}/{} tools have creator and version",
            tools.len()
        ),
        ignored: false,
    }
}

fn primary_component_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    let present = sbom.primary_component_id.is_some();
    SbomqsScoreEntry {
        category: CAT_QUALITY.to_string(),
        feature: "sbom_with_primary_component".to_string(),
        score: if present { 10.0 } else { 0.0 },
        max_score: 10.0,
        description: if present {
            "primary component found".to_string()
        } else {
            "no primary component found".to_string()
        },
        ignored: false,
    }
}

/// `sbom_sharable` — quirk-faithful to sbomqs v2.0.11 (see module docs):
/// its vendored SPDX list has no `isFreeAnyUse` flags, so every SPDX-listed
/// document license counts non-free and the check scores 0.0 for
/// essentially every real document; a missing document license also scores
/// 0.0. Emitted as a real (non-ignored) 0.0 whenever the raw document was
/// provided; `ignored: true` is reserved for the tool-limitation case where
/// the raw document is unavailable.
fn sharable_check(facts: Option<&RawFacts>) -> SbomqsScoreEntry {
    match facts {
        Some(f) => SbomqsScoreEntry {
            category: CAT_SHARING.to_string(),
            feature: "sbom_sharable".to_string(),
            score: 0.0,
            max_score: 10.0,
            description: format!(
                "doc has a sharable license free 0 :: of {} (sbomqs {SBOMQS_PARITY_TARGET}'s \
                 vendored SPDX list carries no isFreeAnyUse flags, so every SPDX-listed data \
                 license — including CC0-1.0 — scores non-free; only AboutCode \
                 'Public Domain'-category ids not on the SPDX list would score 10 there)",
                f.doc_license_count
            ),
            ignored: false,
        },
        None => SbomqsScoreEntry {
            category: CAT_SHARING.to_string(),
            feature: "sbom_sharable".to_string(),
            score: 0.0,
            max_score: 10.0,
            description: "sbom-tools cannot compute this without the original document text \
                          (document data license is not retained in the normalized model); \
                          entry emitted as ignored and still counted in the avg_score \
                          denominator, exactly as sbomqs treats a disabled check"
                .to_string(),
            ignored: true,
        },
    }
}

// ---------------------------------------------------------------------------
// Structural evaluators
// ---------------------------------------------------------------------------

fn spec_type_string(format: &SbomFormat) -> &'static str {
    match format {
        SbomFormat::CycloneDx => "cyclonedx",
        SbomFormat::Spdx => "spdx",
    }
}

fn spec_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    // Both normalized formats are sbomqs-supported specs, so any parsed
    // document scores 10 (exact).
    SbomqsScoreEntry {
        category: CAT_STRUCTURAL.to_string(),
        feature: "sbom_spec".to_string(),
        score: 10.0,
        max_score: 10.0,
        description: format!(
            "provided sbom is in a supported sbom format of spdx,cyclonedx (detected: {})",
            spec_type_string(&sbom.document.format)
        ),
        ignored: false,
    }
}

fn spec_version_check(sbom: &NormalizedSbom) -> SbomqsScoreEntry {
    let doc = &sbom.document;
    let versions: &[&str] = match doc.format {
        SbomFormat::CycloneDx => CDX_SPEC_VERSIONS,
        SbomFormat::Spdx => SPDX_SPEC_VERSIONS,
    };
    let recognized = versions.contains(&doc.spec_version.trim());
    SbomqsScoreEntry {
        category: CAT_STRUCTURAL.to_string(),
        feature: "sbom_spec_version".to_string(),
        score: if recognized { 10.0 } else { 0.0 },
        max_score: 10.0,
        description: format!(
            "spec version {} against sbomqs-supported versions: {}",
            doc.spec_version,
            versions.join(",")
        ),
        ignored: false,
    }
}

/// `sbom_file_format` — detected from the raw document text (JSON/XML/
/// tag-value/YAML) and matched against the serializations sbomqs recognizes
/// per spec (CycloneDX: json,xml; SPDX: json,yaml,rdf,tag-value). Without
/// the raw text the serialization is not retained in the normalized model,
/// so the entry is `ignored: true` with a reason.
fn file_format_check(sbom: &NormalizedSbom, facts: Option<&RawFacts>) -> SbomqsScoreEntry {
    let formats: &[&str] = match sbom.document.format {
        SbomFormat::CycloneDx => CDX_FILE_FORMATS,
        SbomFormat::Spdx => SPDX_FILE_FORMATS,
    };
    match facts {
        Some(f) => {
            let recognized = formats.contains(&f.file_format);
            SbomqsScoreEntry {
                category: CAT_STRUCTURAL.to_string(),
                feature: "sbom_file_format".to_string(),
                score: if recognized { 10.0 } else { 0.0 },
                max_score: 10.0,
                description: format!(
                    "detected file format {} against sbomqs-supported formats: {}",
                    f.file_format,
                    formats.join(",")
                ),
                ignored: false,
            }
        }
        None => SbomqsScoreEntry {
            category: CAT_STRUCTURAL.to_string(),
            feature: "sbom_file_format".to_string(),
            score: 0.0,
            max_score: 10.0,
            description: format!(
                "sbom-tools cannot compute this without the original document text (the \
                 serialization format is not retained in the normalized model; sbomqs scores \
                 10 when the file format is one of: {}); entry emitted as ignored and still \
                 counted in the avg_score denominator",
                formats.join(",")
            ),
            ignored: true,
        },
    }
}

// ---------------------------------------------------------------------------
// License evaluators
// ---------------------------------------------------------------------------

/// One license "token", mirroring one `licenses.License` object sbomqs
/// derives from an expression via `LookupExpression` (which splits an SPDX
/// expression into individual ids and classifies each).
#[derive(Debug, Clone, Copy)]
struct LicenseToken {
    /// Equivalent of sbomqs `l.Spdx()`: the id is on the SPDX license list.
    listed: bool,
    /// SPDX-list deprecated flag (`isDeprecatedLicenseId`).
    deprecated: bool,
    /// Approximation of sbomqs `l.Restrictive()` (AboutCode category
    /// containing "copyleft"/"restricted") via the `spdx` crate's copyleft
    /// flag.
    restrictive: bool,
}

/// Split one license expression into tokens.
///
/// Mirrors sbomqs `LookupExpression`: `NONE`/`NOASSERTION`/empty yield no
/// tokens; ids are extracted from the expression and each is classified;
/// an id not on the SPDX list becomes a "custom" token (not listed, never
/// deprecated/restrictive). Differences (documented approximations): the
/// exception id after `WITH` is dropped rather than looked up, and
/// AboutCode-sourced classification is not available.
fn expression_tokens(expr: &str) -> Vec<LicenseToken> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower == "none" || lower == "noassertion" {
        return Vec::new();
    }

    let mut tokens = Vec::new();
    let mut skip_next = false; // the token after WITH is an exception id
    for tok in trimmed
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|t| !t.is_empty())
    {
        if tok == "AND" || tok == "OR" {
            continue;
        }
        if tok == "WITH" {
            skip_next = true;
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        let id = spdx::license_id(tok).or_else(|| spdx::license_id(tok.trim_end_matches('+')));
        tokens.push(id.map_or(
            LicenseToken {
                listed: false,
                deprecated: false,
                restrictive: false,
            },
            |id| LicenseToken {
                listed: true,
                deprecated: id.is_deprecated(),
                restrictive: id.is_copyleft(),
            },
        ));
    }
    if tokens.is_empty() {
        // Unparseable expression: sbomqs turns the whole expression into a
        // single custom license.
        tokens.push(LicenseToken {
            listed: false,
            deprecated: false,
            restrictive: false,
        });
    }
    tokens
}

fn component_license_tokens(comp: &Component) -> Vec<LicenseToken> {
    comp.licenses
        .all_licenses()
        .into_iter()
        .flat_map(|l| expression_tokens(&l.expression))
        .collect()
}

/// `comp_valid_licenses` — verbatim shape: mean over ALL components of
/// per-component ratios `(listed/total)·10`, license-less components
/// contributing 0. Only SPDX-list membership counts (v1 `l.Spdx()`), so
/// `LicenseRef-*` and other custom ids never count.
fn valid_licenses_check(comps: &[&Component], tokens: &[Vec<LicenseToken>]) -> SbomqsScoreEntry {
    if comps.is_empty() {
        return zero_components_entry(CAT_QUALITY, "comp_valid_licenses");
    }
    let mut total_score = 0.0;
    let mut with_valid = 0usize;
    for toks in tokens {
        if toks.is_empty() {
            continue;
        }
        let listed = toks.iter().filter(|t| t.listed).count();
        if listed == 0 {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let ratio = (listed as f64 / toks.len() as f64) * 10.0;
        total_score += ratio;
        with_valid += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let score = total_score / comps.len() as f64;
    SbomqsScoreEntry {
        category: CAT_QUALITY.to_string(),
        feature: "comp_valid_licenses".to_string(),
        score,
        max_score: 10.0,
        description: format!("{with_valid}/{} components with valid license", comps.len()),
        ignored: false,
    }
}

/// `comp_with_primary_purpose` — the purpose must be non-blank AND one of
/// the values sbomqs recognizes for the spec. Approximate: the typed
/// `ComponentType` defaults to Library when the source document declared no
/// type/purpose, which over-counts (sbomqs would see an empty purpose).
fn primary_purpose_check(comps: &[&Component], format: &SbomFormat) -> SbomqsScoreEntry {
    if comps.is_empty() {
        return zero_components_entry(CAT_QUALITY, "comp_with_primary_purpose");
    }
    let supported: &[&str] = match format {
        SbomFormat::CycloneDx => CDX_PRIMARY_PURPOSES,
        SbomFormat::Spdx => SPDX_PRIMARY_PURPOSES,
    };
    let with_purpose = comps
        .iter()
        .filter(|c| {
            let purpose = c.component_type.to_string().to_lowercase();
            !purpose.trim().is_empty() && supported.contains(&purpose.as_str())
        })
        .count();
    proportional(
        CAT_QUALITY,
        "comp_with_primary_purpose",
        with_purpose,
        comps.len(),
        "components have primary purpose specified",
    )
}

/// Inverted proportional license checks
/// (`comp_with_deprecated_licenses` / `comp_with_restrictive_licenses`):
/// `10·(total−affected)/total`, and a plain 0.0 with "no licenses found"
/// when the whole SBOM carries no licenses.
fn inverted_license_check(
    feature: &str,
    comps: &[&Component],
    tokens: &[Vec<LicenseToken>],
    flag: impl Fn(&LicenseToken) -> bool,
    what: &str,
) -> SbomqsScoreEntry {
    if comps.is_empty() {
        return zero_components_entry(CAT_QUALITY, feature);
    }
    let total_licenses: usize = tokens.iter().map(Vec::len).sum();
    if total_licenses == 0 {
        return SbomqsScoreEntry {
            category: CAT_QUALITY.to_string(),
            feature: feature.to_string(),
            score: 0.0,
            max_score: 10.0,
            description: "no licenses found".to_string(),
            ignored: false,
        };
    }
    let affected = tokens.iter().filter(|toks| toks.iter().any(&flag)).count();
    #[allow(clippy::cast_precision_loss)]
    let score = ((comps.len() - affected) as f64 / comps.len() as f64) * 10.0;
    SbomqsScoreEntry {
        category: CAT_QUALITY.to_string(),
        feature: feature.to_string(),
        score,
        max_score: 10.0,
        description: format!("{affected}/{} components {what}", comps.len()),
        ignored: false,
    }
}

// ---------------------------------------------------------------------------
// Raw-document facts (file format detection, document data license)
// ---------------------------------------------------------------------------

struct RawFacts {
    /// Detected serialization: "json", "xml", "yaml", "tag-value" or
    /// "unknown".
    file_format: &'static str,
    /// Number of document-level license entries (CycloneDX
    /// `metadata.licenses` entries / 1 when an SPDX `dataLicense` is
    /// present). Description-only.
    doc_license_count: usize,
    /// SPDX `dataLicense` present (used by `sbom_required_fields`).
    has_data_license: bool,
}

fn detect_file_format(raw: &str, format: &SbomFormat) -> &'static str {
    let trimmed = raw.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        return "json";
    }
    if trimmed.starts_with('<') {
        return "xml";
    }
    match format {
        SbomFormat::Spdx => {
            if raw
                .lines()
                .any(|l| l.trim_start().starts_with("SPDXVersion:"))
            {
                "tag-value"
            } else if raw.contains("spdxVersion") {
                "yaml"
            } else {
                "unknown"
            }
        }
        SbomFormat::CycloneDx => "unknown",
    }
}

fn extract_raw_facts(raw: &str, format: &SbomFormat) -> RawFacts {
    let file_format = detect_file_format(raw, format);
    match format {
        SbomFormat::Spdx => {
            let has = match file_format {
                "json" => {
                    #[derive(Deserialize)]
                    #[serde(rename_all = "camelCase")]
                    struct SpdxDataLicense {
                        data_license: Option<String>,
                    }
                    serde_json::from_str::<SpdxDataLicense>(raw)
                        .ok()
                        .and_then(|d| d.data_license)
                        .is_some_and(|l| !l.trim().is_empty())
                }
                "tag-value" => raw.lines().any(|l| {
                    l.trim_start()
                        .strip_prefix("DataLicense:")
                        .is_some_and(|v| !v.trim().is_empty())
                }),
                // XML / YAML / unknown: substring heuristic.
                _ => raw.contains("dataLicense") || raw.contains("DataLicense"),
            };
            RawFacts {
                file_format,
                doc_license_count: usize::from(has),
                has_data_license: has,
            }
        }
        SbomFormat::CycloneDx => {
            let count = if file_format == "json" {
                #[derive(Deserialize)]
                struct CdxMetadata {
                    licenses: Option<Vec<serde_json::Value>>,
                }
                #[derive(Deserialize)]
                struct CdxDoc {
                    metadata: Option<CdxMetadata>,
                }
                serde_json::from_str::<CdxDoc>(raw)
                    .ok()
                    .and_then(|d| d.metadata)
                    .and_then(|m| m.licenses)
                    .map_or(0, |l| l.len())
            } else {
                0
            };
            RawFacts {
                file_format,
                doc_license_count: count,
                // dataLicense is an SPDX concept; irrelevant for CycloneDX
                // docOK, which never consults it.
                has_data_license: true,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tool name/version split
// ---------------------------------------------------------------------------

/// Recover a (name, version) pair from a normalized tool-creator name.
///
/// The CycloneDX parser concatenates `"name version"`; SPDX creators keep
/// the raw `name-version` string. A trailing token only counts as a version
/// when it contains a digit — the same heuristic sbomqs applies to SPDX
/// tool strings (`extractVersion` in pkg/sbom/spdx.go).
fn split_tool_name_version(raw_name: &str) -> (&str, &str) {
    let name = raw_name.trim();
    if let Some((n, v)) = name.rsplit_once(' ')
        && v.chars().any(|c| c.is_ascii_digit())
    {
        return (n.trim_end(), v);
    }
    if let Some((n, v)) = name.rsplit_once('-')
        && v.chars().any(|c| c.is_ascii_digit())
    {
        return (n, v);
    }
    (name, "")
}

/// First Tool creator's (name, version) for the `gen_tool_name` /
/// `gen_tool_version` fields (sbomqs uses the first tool).
fn first_tool_name_version(sbom: &NormalizedSbom) -> (String, String) {
    sbom.document
        .creators
        .iter()
        .find(|c| c.creator_type == CreatorType::Tool)
        .map_or_else(
            || (String::new(), String::new()),
            |t| {
                let (name, version) = split_tool_name_version(&t.name);
                (name.to_string(), version.to_string())
            },
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::float_cmp)]

    use super::*;
    use crate::model::{
        Component, ComponentType, Creator, CreatorType, DependencyEdge, DependencyType,
        DocumentMetadata, Hash, HashAlgorithm, LicenseExpression, Organization,
    };

    const EPS: f64 = 1e-9;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < EPS
    }

    fn score<'a>(scores: &'a [SbomqsScoreEntry], feature: &str) -> &'a SbomqsScoreEntry {
        scores
            .iter()
            .find(|s| s.feature == feature)
            .unwrap_or_else(|| panic!("missing feature {feature}"))
    }

    /// Three-component CycloneDX fixture with hand-computable expectations.
    fn cdx_fixture() -> NormalizedSbom {
        let mut doc = DocumentMetadata {
            spec_version: "1.5".to_string(),
            format_version: "1.5".to_string(),
            doc_version: Some(1),
            ..DocumentMetadata::default()
        };
        doc.creators.push(Creator {
            creator_type: CreatorType::Tool,
            name: "syft 1.0.0".to_string(),
            email: None,
        });
        doc.creators.push(Creator {
            creator_type: CreatorType::Person,
            name: "Alice".to_string(),
            email: None,
        });
        let mut sbom = NormalizedSbom::new(doc);

        // comp1: fully populated; licenses MIT + "MIT OR FooBar"
        // (tokens: MIT listed, MIT listed, FooBar custom → ratio 2/3).
        let mut c1 = Component::new("pkg-a".to_string(), "ref-a".to_string())
            .with_version("1.0.0".to_string());
        c1.component_type = ComponentType::Application;
        c1.identifiers.purl = Some("pkg:npm/pkg-a@1.0.0".to_string());
        c1.identifiers
            .cpe
            .push("cpe:2.3:a:acme:pkg-a:1.0.0:*:*:*:*:*:*:*".to_string());
        c1.licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        c1.licenses
            .add_declared(LicenseExpression::new("MIT OR FooBar".to_string()));
        c1.supplier = Some(Organization::new("Acme".to_string()));
        c1.hashes
            .push(Hash::new(HashAlgorithm::Sha256, "a".repeat(64)));

        // comp2: no version/purl/cpe; deprecated+copyleft license GPL-2.0.
        let mut c2 = Component::new("pkg-b".to_string(), "ref-b".to_string());
        c2.licenses
            .add_declared(LicenseExpression::new("GPL-2.0".to_string()));

        // comp3: empty name, ML type (not an sbomqs CDX purpose), nothing else.
        let mut c3 = Component::new(String::new(), "ref-c".to_string());
        c3.component_type = ComponentType::MachineLearningModel;

        let primary = c1.canonical_id.clone();
        let dep = c2.canonical_id.clone();
        sbom.add_component(c1);
        sbom.add_component(c2);
        sbom.add_component(c3);
        sbom.set_primary_component(primary.clone());
        sbom.add_edge(DependencyEdge::new(primary, dep, DependencyType::DependsOn));
        sbom
    }

    const CDX_RAW: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
        "metadata":{"licenses":[{"license":{"id":"CC0-1.0"}}]},"components":[]}"#;

    fn fixture_scores(raw: Option<&str>) -> Vec<SbomqsScoreEntry> {
        let sbom = cdx_fixture();
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "app.cdx.json",
            raw_content: raw,
        };
        compute_scores(&input)
    }

    #[test]
    fn emits_all_23_default_features_with_exact_categories() {
        let scores = fixture_scores(Some(CDX_RAW));
        assert_eq!(scores.len(), 23);
        for s in &scores {
            assert!(
                CATEGORY_ORDER.contains(&s.category.as_str()),
                "unexpected category {}",
                s.category
            );
            assert_eq!(s.max_score, 10.0);
            assert!(
                (0.0..=10.0).contains(&s.score),
                "{} out of range",
                s.feature
            );
        }
        // Category strings byte-for-byte.
        assert!(scores.iter().any(|s| s.category == "NTIA-minimum-elements"));
        assert!(scores.iter().any(|s| s.category == "Structural"));
    }

    #[test]
    fn proportional_ntia_features_hand_computed() {
        let scores = fixture_scores(Some(CDX_RAW));
        // 2 of 3 components have a name.
        assert!(approx(score(&scores, "comp_with_name").score, 20.0 / 3.0));
        // 1 of 3 has a version.
        assert!(approx(
            score(&scores, "comp_with_version").score,
            10.0 / 3.0
        ));
        // All 3 carry a local id (bom-ref) — NTIA uniq-ids is local-id, not purl/cpe.
        assert!(approx(score(&scores, "comp_with_uniq_ids").score, 10.0));
        // 1 of 3 has a supplier.
        assert!(approx(
            score(&scores, "comp_with_supplier").score,
            10.0 / 3.0
        ));
        // Primary component has one direct dependency → binary 10.
        assert!(approx(score(&scores, "sbom_dependencies").score, 10.0));
        assert!(approx(score(&scores, "sbom_authors").score, 10.0));
    }

    #[test]
    fn required_fields_is_fractionally_blended_not_binary() {
        let scores = fixture_scores(Some(CDX_RAW));
        // docOK (specVersion + doc version 1) and 2/3 packages OK
        // → (10 + 10·2/3)/2 = 8.333… — the corrected blended formula.
        let entry = score(&scores, "sbom_required_fields");
        assert!(approx(entry.score, (10.0 + 20.0 / 3.0) / 2.0));
        assert_eq!(entry.description, "Doc Fields:true Pkg Fields:false");
        assert!(!entry.ignored);
    }

    #[test]
    fn required_fields_doc_not_ok_scores_zero_regardless_of_packages() {
        // Quirk preserved: !docOK → 0.0 even with perfect packages.
        let mut sbom = cdx_fixture();
        sbom.document.doc_version = None; // sbomqs: doc.Version < 1 → docOK false
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "x",
            raw_content: Some(CDX_RAW),
        };
        let scores = compute_scores(&input);
        assert!(approx(score(&scores, "sbom_required_fields").score, 0.0));
    }

    #[test]
    fn valid_licenses_is_ratio_mean_over_all_components() {
        let scores = fixture_scores(Some(CDX_RAW));
        // comp1 tokens: MIT, MIT, FooBar → 2/3 → 6.666…
        // comp2 tokens: GPL-2.0 (listed) → 10
        // comp3: no licenses → 0
        // mean over 3 comps: (20/3 + 10 + 0)/3 = 50/9 = 5.555…
        assert!(approx(
            score(&scores, "comp_valid_licenses").score,
            50.0 / 9.0
        ));
    }

    #[test]
    fn deprecated_and_restrictive_are_inverted_proportionals() {
        let scores = fixture_scores(Some(CDX_RAW));
        // Only comp2 (GPL-2.0: deprecated AND copyleft) is affected:
        // (3-1)/3 · 10 = 6.666…
        assert!(approx(
            score(&scores, "comp_with_deprecated_licenses").score,
            20.0 / 3.0
        ));
        assert!(approx(
            score(&scores, "comp_with_restrictive_licenses").score,
            20.0 / 3.0
        ));
    }

    #[test]
    fn primary_purpose_gates_on_sbomqs_purpose_list() {
        let scores = fixture_scores(Some(CDX_RAW));
        // application ✓, library (default) ✓, machine-learning-model is NOT
        // in sbomqs' CycloneDX purpose list → 2/3.
        assert!(approx(
            score(&scores, "comp_with_primary_purpose").score,
            20.0 / 3.0
        ));
    }

    #[test]
    fn lookup_id_features_hand_computed() {
        let scores = fixture_scores(Some(CDX_RAW));
        assert!(approx(
            score(&scores, "comp_with_any_vuln_lookup_id").score,
            10.0 / 3.0
        ));
        assert!(approx(
            score(&scores, "comp_with_multi_vuln_lookup_id").score,
            10.0 / 3.0
        ));
    }

    #[test]
    fn creator_and_version_uses_digit_heuristic_and_zero_tools_scores_zero() {
        let scores = fixture_scores(Some(CDX_RAW));
        // "syft 1.0.0" → name "syft", version "1.0.0" → 1/1.
        assert!(approx(
            score(&scores, "sbom_with_creator_and_version").score,
            10.0
        ));

        // Zero tools: sbomqs computes 0/0 = NaN, coerced to 0.0.
        let mut sbom = cdx_fixture();
        sbom.document
            .creators
            .retain(|c| c.creator_type != CreatorType::Tool);
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "x",
            raw_content: Some(CDX_RAW),
        };
        let scores = compute_scores(&input);
        let entry = score(&scores, "sbom_with_creator_and_version");
        assert!(approx(entry.score, 0.0));
        assert!(!entry.ignored);
    }

    #[test]
    fn sharable_replicates_v2_0_11_no_free_flags_quirk() {
        let scores = fixture_scores(Some(CDX_RAW));
        let entry = score(&scores, "sbom_sharable");
        // Even a CC0-1.0 document license scores 0.0 in sbomqs v2.0.11
        // (vendored list carries no isFreeAnyUse flags) — not ignored.
        assert!(approx(entry.score, 0.0));
        assert!(!entry.ignored);
        assert!(entry.description.contains("free 0 :: of 1"));
    }

    #[test]
    fn structural_scores_with_raw_json() {
        let scores = fixture_scores(Some(CDX_RAW));
        assert!(approx(score(&scores, "sbom_spec").score, 10.0));
        assert!(approx(score(&scores, "sbom_spec_version").score, 10.0));
        assert!(approx(score(&scores, "sbom_file_format").score, 10.0));
        assert!(approx(score(&scores, "sbom_parsable").score, 10.0));
    }

    #[test]
    fn unrecognized_spec_version_scores_zero() {
        let mut sbom = cdx_fixture();
        sbom.document.spec_version = "3.0".to_string(); // not a CDX version
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "x",
            raw_content: Some(CDX_RAW),
        };
        let scores = compute_scores(&input);
        assert!(approx(score(&scores, "sbom_spec_version").score, 0.0));
    }

    #[test]
    fn missing_raw_content_emits_ignored_with_reason_never_fabricated() {
        let scores = fixture_scores(None);
        for feature in ["sbom_file_format", "sbom_sharable"] {
            let entry = score(&scores, feature);
            assert!(entry.ignored, "{feature} must be ignored without raw text");
            assert!(
                entry.description.contains("cannot compute"),
                "{feature} must carry a reason: {}",
                entry.description
            );
        }
        // Still 23 entries: ignored features stay in the array (and the
        // avg_score denominator) — never silently dropped.
        assert_eq!(scores.len(), 23);
    }

    #[test]
    fn avg_score_is_sum_of_non_ignored_over_count_of_all() {
        let scores = fixture_scores(None);
        let expected: f64 = scores
            .iter()
            .filter(|s| !s.ignored)
            .map(|s| s.score)
            .sum::<f64>()
            / scores.len() as f64;
        assert!(approx(avg_score(&scores), expected));

        // Hand-check the quirk with a tiny synthetic list: one ignored entry
        // keeps the denominator at 3.
        let synthetic = vec![
            SbomqsScoreEntry {
                category: CAT_NTIA.to_string(),
                feature: "a".to_string(),
                score: 10.0,
                max_score: 10.0,
                description: String::new(),
                ignored: false,
            },
            SbomqsScoreEntry {
                category: CAT_NTIA.to_string(),
                feature: "b".to_string(),
                score: 5.0,
                max_score: 10.0,
                description: String::new(),
                ignored: false,
            },
            SbomqsScoreEntry {
                category: CAT_NTIA.to_string(),
                feature: "c".to_string(),
                score: 10.0,
                max_score: 10.0,
                description: String::new(),
                ignored: true,
            },
        ];
        assert!(approx(avg_score(&synthetic), 15.0 / 3.0));
    }

    #[test]
    fn zero_component_sbom_marks_component_checks_ignored_in_denominator() {
        let sbom = NormalizedSbom::new(DocumentMetadata {
            spec_version: "1.5".to_string(),
            doc_version: Some(1),
            ..DocumentMetadata::default()
        });
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "empty.cdx.json",
            raw_content: Some(r#"{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}"#),
        };
        let scores = compute_scores(&input);
        assert_eq!(scores.len(), 23);
        let ignored: Vec<&str> = scores
            .iter()
            .filter(|s| s.ignored)
            .map(|s| s.feature.as_str())
            .collect();
        // All 12 component-list checks are ignored with the sbomqs N/A text.
        assert_eq!(ignored.len(), 12);
        for feature in [
            "comp_with_name",
            "comp_valid_licenses",
            "comp_with_checksums",
        ] {
            let entry = score(&scores, feature);
            assert!(entry.ignored);
            assert_eq!(entry.description, NO_COMPONENTS_DESC);
            assert!(approx(entry.score, 0.0));
        }
        // docOK with zero components → (10 + 0)/2 = 5.0 (verbatim quirk).
        assert!(approx(score(&scores, "sbom_required_fields").score, 5.0));
    }

    #[test]
    fn grade_brackets_match_sbomqs_source_not_repo_grades() {
        assert_eq!(sbomqs_grade(9.0), "A");
        assert_eq!(sbomqs_grade(8.999), "B");
        assert_eq!(sbomqs_grade(8.0), "B");
        assert_eq!(sbomqs_grade(7.0), "C");
        assert_eq!(sbomqs_grade(6.9), "D");
        assert_eq!(sbomqs_grade(5.0), "D");
        // The repo's 0-100 QualityGrade would call 55/100 an F only below 60;
        // sbomqs' D bracket reaches down to 5.0 — 4.9 is an F here.
        assert_eq!(sbomqs_grade(4.9), "F");
    }

    #[test]
    fn json_report_matches_sbomqs_field_names_and_identity() {
        let sbom = cdx_fixture();
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "app.cdx.json",
            raw_content: Some(CDX_RAW),
        };
        let json = render_json(&input);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Top level: exact sbomqs pkg/reporter/json.go keys.
        for key in ["run_id", "timestamp", "creation_info", "files"] {
            assert!(value.get(key).is_some(), "missing top-level key {key}");
        }
        let ci = &value["creation_info"];
        for key in ["name", "version", "scoring_engine_version", "vendor"] {
            assert!(ci.get(key).is_some(), "missing creation_info key {key}");
        }
        // Honest identity — never impersonate the sbomqs binary.
        assert_eq!(ci["name"], "sbom-tools");
        assert!(
            ci["scoring_engine_version"]
                .as_str()
                .unwrap()
                .contains("sbomqs-compat"),
        );

        let file = &value["files"][0];
        for key in [
            "file_name",
            "spec",
            "spec_version",
            "file_format",
            "avg_score",
            "num_components",
            "creation_time",
            "gen_tool_name",
            "gen_tool_version",
            "scores",
        ] {
            assert!(file.get(key).is_some(), "missing file key {key}");
        }
        assert_eq!(file["spec"], "cyclonedx");
        assert_eq!(file["spec_version"], "1.5");
        assert_eq!(file["file_format"], "json");
        assert_eq!(file["num_components"], 3);
        assert_eq!(file["gen_tool_name"], "syft");
        assert_eq!(file["gen_tool_version"], "1.0.0");

        let entries = file["scores"].as_array().unwrap();
        assert_eq!(entries.len(), 23);
        for entry in entries {
            for key in [
                "category",
                "feature",
                "score",
                "max_score",
                "description",
                "ignored",
            ] {
                assert!(entry.get(key).is_some(), "missing score key {key}");
            }
            assert_eq!(entry["max_score"], 10.0);
        }

        // avg_score in the report equals the verbatim formula over entries.
        let sum: f64 = entries
            .iter()
            .filter(|e| !e["ignored"].as_bool().unwrap())
            .map(|e| e["score"].as_f64().unwrap())
            .sum();
        let expected = sum / entries.len() as f64;
        assert!(approx(file["avg_score"].as_f64().unwrap(), expected));
    }

    #[test]
    fn summary_table_shows_categories_grade_and_non_convertibility_note() {
        let sbom = cdx_fixture();
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "app.cdx.json",
            raw_content: Some(CDX_RAW),
        };
        let table = render_summary_table(&input);
        for cat in CATEGORY_ORDER {
            assert!(table.contains(cat), "table must list category {cat}");
        }
        assert!(table.contains("avg_score"));
        assert!(table.contains("sbomqs grade:"));
        assert!(table.contains("not convertible"));
        assert!(table.contains("sbomqs-json"));
    }

    #[test]
    fn summary_table_renders_null_category_with_reason_without_raw() {
        // Sharing's only feature is ignored without the raw document, so the
        // whole category renders as n/a + reason (null-with-reason contract).
        let sbom = cdx_fixture();
        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "app.cdx.json",
            raw_content: None,
        };
        let scores = compute_scores(&input);
        let rollups = category_rollups(&scores);
        let sharing = rollups.iter().find(|r| r.category == CAT_SHARING).unwrap();
        assert!(sharing.score.is_none());
        assert!(
            sharing
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("cannot compute"))
        );

        let table = render_summary_table(&input);
        assert!(table.contains("n/a"));
    }

    #[test]
    fn expression_tokens_mirror_lookup_expression_semantics() {
        assert!(expression_tokens("NOASSERTION").is_empty());
        assert!(expression_tokens("NONE").is_empty());
        assert!(expression_tokens("").is_empty());

        let toks = expression_tokens("MIT OR FooBar");
        assert_eq!(toks.len(), 2);
        assert!(toks[0].listed && !toks[1].listed);

        // WITH-exception: exception id dropped (documented approximation).
        let toks = expression_tokens("Apache-2.0 WITH LLVM-exception");
        assert_eq!(toks.len(), 1);
        assert!(toks[0].listed);

        // Deprecated '+' form stays deprecated.
        let toks = expression_tokens("GPL-2.0+");
        assert_eq!(toks.len(), 1);
        assert!(toks[0].listed && toks[0].deprecated);
    }

    #[test]
    fn spdx_file_components_are_excluded_from_denominators() {
        let mut doc = DocumentMetadata::default();
        doc.format = SbomFormat::Spdx;
        doc.spec_version = "2.3".to_string();
        let mut sbom = NormalizedSbom::new(doc);
        let pkg = Component::new("pkg".to_string(), "SPDXRef-pkg".to_string())
            .with_version("1.0".to_string());
        let mut file = Component::new("a.c".to_string(), "SPDXRef-file".to_string());
        file.component_type = ComponentType::File;
        sbom.add_component(pkg);
        sbom.add_component(file);

        let input = SbomqsCompatInput {
            sbom: &sbom,
            file_name: "doc.spdx.json",
            raw_content: None,
        };
        let scores = compute_scores(&input);
        // Only the package counts: 1/1 has a version.
        assert!(approx(score(&scores, "comp_with_version").score, 10.0));
        let report = build_report(&input);
        assert_eq!(report.files[0].num_components, 1);
    }

    #[test]
    fn file_format_detection_covers_json_xml_tag_value() {
        assert_eq!(
            detect_file_format("  {\"a\":1}", &SbomFormat::CycloneDx),
            "json"
        );
        assert_eq!(detect_file_format("<bom/>", &SbomFormat::CycloneDx), "xml");
        assert_eq!(
            detect_file_format(
                "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0",
                &SbomFormat::Spdx
            ),
            "tag-value"
        );
        assert_eq!(
            detect_file_format("hello", &SbomFormat::CycloneDx),
            "unknown"
        );
    }
}
