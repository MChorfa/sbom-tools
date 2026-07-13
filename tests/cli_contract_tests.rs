//! CLI contract tests: per-command exit codes, typed value-enum parse
//! validation, and NDJSON output wiring.

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

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout should be utf-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr should be utf-8")
}

#[test]
fn validate_fail_on_warning_returns_exit_code_2() {
    // ntia-warnings-only.cdx.json has 0 NTIA errors but dependency-coverage
    // warnings (sparse graph), so --fail-on-warning must exit with code 2.
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
        .args(["--standard", "ntia", "--summary", "--fail-on-warning"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

#[test]
fn validate_without_fail_on_warning_returns_exit_code_0_when_warnings_only() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
        .args(["--standard", "ntia", "--summary"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn validate_with_errors_returns_exit_code_1() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .args(["--standard", "ntia", "--summary"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn quality_below_min_score_returns_exit_code_1() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--min-score", "100", "-o", "json"])
        .output()
        .expect("quality command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn quality_meeting_min_score_returns_exit_code_0() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--min-score", "0", "-o", "json"])
        .output()
        .expect("quality command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn query_no_match_returns_exit_code_1() {
    let output = base_command()
        .arg("query")
        .arg("zzz-no-such-component-zzz")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("query command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
}

#[test]
fn query_match_returns_exit_code_0() {
    let output = base_command()
        .arg("query")
        .arg("lodash")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("query command should run");

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn invalid_fuzzy_preset_is_rejected_at_parse() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--fuzzy-preset", "not-a-preset"])
        .output()
        .expect("diff command should run");

    // clap exits with code 2 on argument parse errors.
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-preset'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("possible values"),
        "stderr should list the valid presets (did-you-mean hint): {err}"
    );
}

#[test]
fn invalid_merge_dedup_strategy_is_rejected_at_parse() {
    let output = base_command()
        .arg("merge")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--dedup", "not-a-strategy"])
        .output()
        .expect("merge command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-strategy'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("name") && err.contains("purl"),
        "stderr should list valid dedup strategies: {err}"
    );
}

#[test]
fn diff_ndjson_output_emits_one_json_object_per_line() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "ndjson"])
        .output()
        .expect("diff command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);

    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 2, "expected multiple NDJSON lines: {text}");

    // Every non-empty line must be a standalone JSON object.
    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line is not valid json: {line}: {e}"));
        assert!(
            value.is_object(),
            "each NDJSON line should be an object: {line}"
        );
    }

    // The first record is the metadata header; a summary record follows.
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first line json");
    assert_eq!(first["type"], "metadata");
    assert!(
        lines
            .iter()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .any(|v| v["type"] == "summary"),
        "expected a summary NDJSON record: {text}"
    );
}

// ---------------------------------------------------------------------------
// Typed --standard / --profile parsing (P2-D CLI & config coherence)
// ---------------------------------------------------------------------------

/// Every canonical `--standard` value must be enumerated in `validate --help`
/// (clap generates the list from the ValueEnum, so this guards the wiring).
#[test]
fn validate_help_enumerates_every_canonical_standard() {
    let output = base_command()
        .args(["validate", "--help"])
        .output()
        .expect("validate --help should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let help = stdout(&output);
    for canonical in [
        "ntia",
        "fda",
        "cra",
        "cra-phase1",
        "ssdf",
        "eo14028",
        "cnsa2",
        "pqc",
        "bsi",
        "oss-steward",
        "eucc",
        "ai-act",
        "bsi-ai",
    ] {
        assert!(
            help.contains(canonical),
            "validate --help must list standard '{canonical}':\n{help}"
        );
    }
}

/// Every canonical `--profile` value must be enumerated in `quality --help`.
#[test]
fn quality_help_enumerates_every_canonical_profile() {
    let output = base_command()
        .args(["quality", "--help"])
        .output()
        .expect("quality --help should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let help = stdout(&output);
    for canonical in [
        "minimal",
        "standard",
        "security",
        "license-compliance",
        "cra",
        "bsi",
        "comprehensive",
        "cbom",
        "ai-readiness",
    ] {
        assert!(
            help.contains(canonical),
            "quality --help must list profile '{canonical}':\n{help}"
        );
    }
}

#[test]
fn invalid_standard_is_rejected_at_parse_with_possible_values() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "not-a-standard"])
        .output()
        .expect("validate command should run");

    // clap exits with code 2 on argument parse errors.
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-standard'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("possible values"),
        "stderr should list valid standards: {err}"
    );
}

#[test]
fn invalid_profile_is_rejected_at_parse_with_possible_values() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "not-a-profile"])
        .output()
        .expect("quality command should run");

    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let err = stderr(&output);
    assert!(
        err.contains("invalid value 'not-a-profile'"),
        "stderr should explain the invalid value: {err}"
    );
    assert!(
        err.contains("possible values"),
        "stderr should list valid profiles: {err}"
    );
}

/// CraPhase1 is reachable from the CLI: `--standard cra-phase1` selects the
/// Phase 1 (2026) profile, while plain `cra` keeps meaning Phase 2 (2027).
#[test]
fn validate_standard_cra_phase1_is_reachable_and_cra_means_phase2() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra-phase1,cra", "--summary"])
        .output()
        .expect("validate command should run");

    // Exit code depends on the fixture's compliance; only the parse/report
    // wiring is asserted here.
    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    let standards: Vec<String> = json
        .as_array()
        .expect("multi-standard summary array")
        .iter()
        .map(|s| s["standard"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        standards.iter().any(|s| s.contains("Phase 1")),
        "cra-phase1 must select the Phase 1 profile: {standards:?}"
    );
    assert!(
        standards.iter().any(|s| s.contains("Phase 2")),
        "plain cra must keep meaning Phase 2: {standards:?}"
    );
}

/// Alias spellings and case-insensitivity work end-to-end through clap.
#[test]
fn validate_standard_aliases_parse_through_clap() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "NIST-SSDF,cra-2026,Tr03183", "--summary"])
        .output()
        .expect("validate command should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    assert_eq!(
        json.as_array().map(Vec::len),
        Some(3),
        "three aliased standards must produce three results: {json}"
    );
}

// ---------------------------------------------------------------------------
// Unsupported (command, format) combinations are rejected, not substituted
// ---------------------------------------------------------------------------

#[test]
fn diff_rejects_oscal_json_output() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "oscal-json"])
        .output()
        .expect("diff command should run");

    assert!(
        !output.status.success(),
        "diff -o oscal-json must fail instead of emitting plain JSON"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools diff`"),
        "stderr should name the unsupported combination: {err}"
    );
}

#[test]
fn view_rejects_oscal_json_output() {
    let output = base_command()
        .arg("view")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "oscal-json"])
        .output()
        .expect("view command should run");

    assert!(
        !output.status.success(),
        "view -o oscal-json must fail instead of emitting plain JSON"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools view`"),
        "stderr should name the unsupported combination: {err}"
    );
}

#[test]
fn validate_rejects_html_output_and_lists_supported_formats() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "ntia", "-o", "html"])
        .output()
        .expect("validate command should run");

    assert!(
        !output.status.success(),
        "validate -o html must fail instead of silently emitting text"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools validate`"),
        "stderr should name the unsupported combination: {err}"
    );
    assert!(
        err.contains("oscal-json"),
        "stderr should list the formats validate does support: {err}"
    );
}

#[test]
fn quality_rejects_oscal_json_output() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "oscal-json"])
        .output()
        .expect("quality command should run");

    assert!(
        !output.status.success(),
        "quality -o oscal-json must fail instead of silently emitting text"
    );
    let err = stderr(&output);
    assert!(
        err.contains("not supported by `sbom-tools quality`"),
        "stderr should name the unsupported combination: {err}"
    );
}

// ---------------------------------------------------------------------------
// Explicit --cra-sidecar failures are hard errors; sidecar typos are named
// ---------------------------------------------------------------------------

#[test]
fn quality_explicit_missing_sidecar_is_hard_error() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("demo-new.cdx.json"))
        .args([
            "--profile",
            "cra",
            "--cra-sidecar",
            "/nonexistent/side.cra.json",
        ])
        .output()
        .expect("quality command should run");

    assert!(
        !output.status.success(),
        "an explicitly passed broken sidecar must abort quality"
    );
    assert!(
        stderr(&output).contains("Failed to load CRA sidecar"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn view_explicit_missing_sidecar_is_hard_error() {
    let output = base_command()
        .arg("view")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json", "--cra-sidecar", "/nonexistent/side.cra.json"])
        .output()
        .expect("view command should run");

    assert!(
        !output.status.success(),
        "an explicitly passed broken sidecar must abort view"
    );
    assert!(
        stderr(&output).contains("Failed to load CRA sidecar"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn validate_sidecar_with_snake_case_typo_names_key_and_hints_camel_case() {
    let dir = tempfile::tempdir().expect("temp dir");
    let sidecar = dir.path().join("typo.cra.json");
    std::fs::write(&sidecar, r#"{"security_contact": "security@example.com"}"#)
        .expect("write sidecar");

    let output = base_command()
        .arg("validate")
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra", "--summary"])
        .arg("--cra-sidecar")
        .arg(&sidecar)
        .output()
        .expect("validate command should run");

    assert!(
        !output.status.success(),
        "a typo'd sidecar key must fail loudly instead of deserializing to all-None"
    );
    let err = stderr(&output);
    assert!(
        err.contains("security_contact"),
        "error must name the offending key: {err}"
    );
    assert!(
        err.contains("camelCase"),
        "error must hint at camelCase keys: {err}"
    );
}
