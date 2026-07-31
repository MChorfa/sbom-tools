//! CLI-level and cross-format tests for the sbomqs interoperability view
//! (`quality -o sbomqs-json` and the sbomqs table in the human summary).
//!
//! Parity target: interlynk-io/sbomqs v2.0.11 — the JSON must match the
//! `sbomqs score --json` schema (pkg/reporter/json.go) field-for-field, the
//! category strings must match pkg/scorer/criteria.go byte-for-byte, and
//! `avg_score` must obey the verbatim `AvgScore` formula
//! (sum of non-ignored scores / count of ALL scores, ignored included).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn base_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbom-tools"));
    cmd.arg("--no-color");
    cmd.env("RUST_LOG", "error");
    cmd.env("RUST_LOG_STYLE", "never");
    cmd
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be utf-8")
}

fn json_stdout(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout should be utf-8");
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout must be JSON: {e}\n{stdout}"))
}

/// Exact sbomqs v1 category strings (pkg/scorer/criteria.go).
const SBOMQS_CATEGORIES: [&str; 5] = [
    "Structural",
    "NTIA-minimum-elements",
    "Semantic",
    "Quality",
    "Sharing",
];

#[test]
fn cli_quality_sbomqs_json_matches_sbomqs_score_report_schema() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
        .args(["-o", "sbomqs-json"])
        .output()
        .expect("quality command should run");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let value = json_stdout(&output);

    // Top level (pkg/reporter/json.go jsonReport).
    for key in ["run_id", "timestamp", "creation_info", "files"] {
        assert!(value.get(key).is_some(), "missing top-level key {key}");
    }
    let ci = &value["creation_info"];
    for key in ["name", "version", "scoring_engine_version", "vendor"] {
        assert!(ci.get(key).is_some(), "missing creation_info key {key}");
    }
    // Honest identity: identifies sbom-tools, never impersonates sbomqs.
    assert_eq!(ci["name"], "sbom-tools");
    assert_eq!(ci["vendor"], "sbom-tools project");
    assert!(
        ci["scoring_engine_version"]
            .as_str()
            .is_some_and(|v| v.contains("sbomqs-compat")),
        "scoring_engine_version must carry the compat tag"
    );

    // Per-file block (pkg/reporter/json.go file).
    let files = value["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1);
    let file = &files[0];
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
    assert_eq!(file["gen_tool_name"], "test-generator");
    assert_eq!(file["gen_tool_version"], "1.0.0");
    assert_eq!(file["creation_time"], "2026-01-04T12:00:00Z");

    // Per-score entries (pkg/reporter/json.go score) — 23 v1 default
    // features, exact category strings, max_score always 10.
    let scores = file["scores"].as_array().expect("scores array");
    assert_eq!(scores.len(), 23, "23 v1 default-profile features expected");
    for entry in scores {
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
        let category = entry["category"].as_str().expect("category string");
        assert!(
            SBOMQS_CATEGORIES.contains(&category),
            "unexpected category {category}"
        );
        assert_eq!(entry["max_score"], 10.0);
        let score = entry["score"].as_f64().expect("score number");
        assert!((0.0..=10.0).contains(&score));
    }

    // Verbatim AvgScore: sum(non-ignored) / count(ALL, ignored included).
    let sum: f64 = scores
        .iter()
        .filter(|e| !e["ignored"].as_bool().expect("ignored bool"))
        .map(|e| e["score"].as_f64().expect("score"))
        .sum();
    #[allow(clippy::cast_precision_loss)]
    let expected = sum / scores.len() as f64;
    let avg = file["avg_score"].as_f64().expect("avg_score number");
    assert!(
        (avg - expected).abs() < 1e-9,
        "avg_score {avg} must equal sum(non-ignored)/count(all) = {expected}"
    );
}

#[test]
fn cli_quality_sbomqs_json_spdx_document() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("spdx/minimal.spdx.json"))
        .args(["-o", "sbomqs-json"])
        .output()
        .expect("quality command should run");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let value = json_stdout(&output);
    let file = &value["files"][0];
    assert_eq!(file["spec"], "spdx");
    assert_eq!(file["spec_version"], "2.3");
    assert_eq!(file["file_format"], "json");
    // SPDX tool creator "Tool: test-generator-1.0.0" splits on the last
    // hyphen-with-digit, mirroring sbomqs' extractVersion heuristic.
    assert_eq!(file["gen_tool_name"], "test-generator");
    assert_eq!(file["gen_tool_version"], "1.0.0");
    // Both packages carry name/version/SPDXID → exact 10s.
    let scores = file["scores"].as_array().expect("scores array");
    let get = |feature: &str| {
        scores
            .iter()
            .find(|s| s["feature"] == feature)
            .unwrap_or_else(|| panic!("missing feature {feature}"))
    };
    assert_eq!(get("comp_with_name")["score"], 10.0);
    assert_eq!(get("comp_with_version")["score"], 10.0);
    assert_eq!(get("comp_with_uniq_ids")["score"], 10.0);
    // sbomqs v2.0.11 quirk replicated: even a CC0-1.0 dataLicense scores
    // 0.0 on sbom_sharable (vendored list has no isFreeAnyUse flags) — a
    // real 0.0, not an ignored entry, because the raw document is available.
    let sharable = get("sbom_sharable");
    assert_eq!(sharable["score"], 0.0);
    assert_eq!(sharable["ignored"], false);
}

#[test]
fn cli_quality_summary_appends_sbomqs_table() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
        .args(["-o", "summary"])
        .output()
        .expect("quality command should run");
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout utf-8");
    assert!(
        stdout.contains("sbomqs-Comparable Scores"),
        "summary must contain the sbomqs table:\n{stdout}"
    );
    for category in SBOMQS_CATEGORIES {
        assert!(
            stdout.contains(category),
            "summary sbomqs table must list category {category}:\n{stdout}"
        );
    }
    assert!(stdout.contains("sbomqs grade:"));
    // The comparability guard note: the 0-10 numbers are recomputed
    // per-feature, never the 0-100 score divided by 10.
    assert!(stdout.contains("not convertible"));
}

#[test]
fn cli_quality_help_documents_sbomqs_json_format() {
    let output = base_command()
        .args(["quality", "--help"])
        .output()
        .expect("quality --help should run");
    let help = String::from_utf8(output.stdout.clone()).expect("stdout utf-8");
    assert!(
        help.contains("sbomqs-json"),
        "quality --help must document the sbomqs-json format:\n{help}"
    );
}
