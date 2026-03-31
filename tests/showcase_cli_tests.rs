use sbom_tools::config::DiffConfigBuilder;
use sbom_tools::diff::DependencyChangeType;
use sbom_tools::parsers::parse_sbom;
use sbom_tools::pipeline::compute_diff;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture_path(name: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

fn sbom_tools_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbom-tools"))
}

fn base_command() -> Command {
    let mut cmd = Command::new(sbom_tools_bin());
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

fn json_stdout(output: &Output) -> serde_json::Value {
    let text = stdout(output);
    let start = text
        .find(|ch| ['{', '['].contains(&ch))
        .expect("stdout should contain a JSON object or array");

    serde_json::from_str(&text[start..]).expect("stdout payload should be valid json")
}

#[test]
fn cli_diff_summary_supports_match_explanations_and_threshold_recommendation() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args([
            "--explain-matches",
            "--recommend-threshold",
            "-o",
            "summary",
        ])
        .output()
        .expect("diff command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("=== Match Explanations ==="));
    assert!(text.contains("=== Threshold Recommendation ==="));
    assert!(text.contains("SBOM Diff Summary"));
}

#[test]
fn cli_diff_json_reports_supply_chain_attack_examples() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("showcase/supply-chain-baseline.cdx.json"))
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("diff command should run");

    assert!(output.status.success(), "{}", stderr(&output));

    let json = json_stdout(&output);

    let added = json["reports"]["components"]["added"]
        .as_array()
        .expect("added component array");
    let modified = json["reports"]["components"]["modified"]
        .as_array()
        .expect("modified component array");
    let introduced = json["reports"]["vulnerabilities"]["introduced"]
        .as_array()
        .expect("introduced vulnerabilities array");

    assert!(
        added.iter().any(|c| c["name"] == "axios-builder"),
        "axios-builder should be reported as added: {added:?}"
    );
    assert!(
        added.iter().any(|c| c["name"] == "vllm-plugins"),
        "vllm-plugins should be reported as added: {added:?}"
    );
    assert!(
        modified.iter().any(|c| {
            c["name"] == "lodash" && c["old_version"] == "4.17.21" && c["new_version"] == "4.17.15"
        }),
        "lodash downgrade should be reported as modified: {modified:?}"
    );
    assert_eq!(json["summary"]["vulnerabilities"]["introduced"], 3);
    assert!(
        introduced.iter().any(|v| v["id"] == "MAL-2025-190832"),
        "axios malicious advisory should be present"
    );
    assert!(
        introduced.iter().any(|v| v["id"] == "MAL-2026-844"),
        "vllm malicious advisory should be present"
    );
}

#[test]
fn cli_query_detects_recent_supply_chain_examples() {
    let axios_output = base_command()
        .arg("query")
        .args(["--affected-by", "MAL-2025-190832", "-o", "json"])
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .output()
        .expect("query command should run");

    assert!(axios_output.status.success(), "{}", stderr(&axios_output));
    let axios_json = json_stdout(&axios_output);
    assert_eq!(axios_json["matches"].as_array().unwrap().len(), 1);
    assert_eq!(axios_json["matches"][0]["name"], "axios-builder");

    let vllm_output = base_command()
        .arg("query")
        .args(["--affected-by", "MAL-2026-844", "-o", "json"])
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .output()
        .expect("query command should run");

    assert!(vllm_output.status.success(), "{}", stderr(&vllm_output));
    let vllm_json = json_stdout(&vllm_output);
    assert_eq!(vllm_json["matches"].as_array().unwrap().len(), 1);
    assert_eq!(vllm_json["matches"][0]["name"], "vllm-plugins");
}

#[test]
fn cli_view_filters_supply_chain_findings_by_severity() {
    let output = base_command()
        .arg("view")
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .args(["--vulnerable-only", "--severity", "high", "-o", "json"])
        .output()
        .expect("view command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);

    let components = json["components"].as_array().expect("component array");
    assert_eq!(components.len(), 2);
    assert!(
        components.iter().any(|c| c["name"] == "axios-builder"),
        "expected axios-builder in filtered view output"
    );
    assert!(
        components.iter().any(|c| c["name"] == "vllm-plugins"),
        "expected vllm-plugins in filtered view output"
    );
}

#[test]
fn cli_vex_status_reports_partial_coverage_for_supply_chain_incident() {
    let output = base_command()
        .arg("vex")
        .arg("status")
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .arg("--vex")
        .arg(fixture_path("showcase/supply-chain-vex.openvex.json"))
        .args(["-o", "json"])
        .output()
        .expect("vex status command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);

    assert_eq!(json["total_vulnerabilities"], 3);
    assert_eq!(json["with_vex"], 2);
    assert_eq!(json["without_vex"], 1);
    assert!(
        json["gaps"]
            .as_array()
            .expect("gaps array")
            .iter()
            .any(|g| g["id"] == "MAL-2026-844"),
        "expected MAL-2026-844 to remain as a VEX gap"
    );
}

#[test]
fn cli_diff_fail_on_vex_gap_returns_exit_code_4() {
    let output = base_command()
        .arg("diff")
        .arg(fixture_path("showcase/supply-chain-baseline.cdx.json"))
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .arg("--vex")
        .arg(fixture_path("showcase/supply-chain-vex.openvex.json"))
        .args(["--fail-on-vex-gap", "-o", "json"])
        .output()
        .expect("diff command should run");

    assert_eq!(output.status.code(), Some(4), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("VEX gap"),
        "stderr should explain the VEX gap: {}",
        stderr(&output)
    );
}

#[test]
fn cli_diff_multi_showcases_portfolio_comparison() {
    let output = base_command()
        .arg("diff-multi")
        .arg(fixture_path("showcase/fleet-v1.cdx.json"))
        .arg(fixture_path("showcase/fleet-v2.cdx.json"))
        .arg(fixture_path("showcase/fleet-v3.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("diff-multi command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);

    assert_eq!(json["comparisons"].as_array().unwrap().len(), 2);
    assert!(
        json["summary"]["universal_components"]
            .as_array()
            .map_or(false, |items| !items.is_empty()),
        "expected universal components in diff-multi summary"
    );
    assert!(
        json["summary"]["inconsistent_components"]
            .as_array()
            .map_or(false, |items| !items.is_empty()),
        "expected inconsistent components in diff-multi summary"
    );
}

#[test]
fn cli_timeline_showcases_release_evolution() {
    let output = base_command()
        .arg("timeline")
        .arg(fixture_path("showcase/fleet-v1.cdx.json"))
        .arg(fixture_path("showcase/fleet-v2.cdx.json"))
        .arg(fixture_path("showcase/fleet-v3.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("timeline command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);

    assert_eq!(json["sboms"].as_array().unwrap().len(), 3);
    assert_eq!(json["incremental_diffs"].as_array().unwrap().len(), 2);
    assert_eq!(json["cumulative_from_first"].as_array().unwrap().len(), 2);
}

#[test]
fn cli_matrix_showcases_similarity_and_clustering() {
    let output = base_command()
        .arg("matrix")
        .arg(fixture_path("showcase/fleet-v1.cdx.json"))
        .arg(fixture_path("showcase/fleet-v2.cdx.json"))
        .arg(fixture_path("showcase/fleet-v3.cdx.json"))
        .args(["--cluster-threshold", "0.7", "-o", "json"])
        .output()
        .expect("matrix command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);

    assert_eq!(json["sboms"].as_array().unwrap().len(), 3);
    assert!(json.get("similarity_scores").is_some());
}

#[test]
fn cli_quality_security_profile_outputs_machine_readable_report() {
    let output = base_command()
        .arg("quality")
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .args([
            "--profile",
            "security",
            "--recommendations",
            "--metrics",
            "-o",
            "json",
        ])
        .output()
        .expect("quality command should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let json = json_stdout(&output);

    assert_eq!(json["profile"], "security");
    assert!(json["report"]["overall_score"].is_number());
    assert!(json["report"]["recommendations"].is_array());
}

#[test]
fn cli_validate_summary_outputs_multi_standard_json() {
    let output = base_command()
        .arg("validate")
        .arg(fixture_path("showcase/supply-chain-incident.cdx.json"))
        .args(["--standard", "ntia,cra", "--summary"])
        .output()
        .expect("validate command should run");

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let json = json_stdout(&output);
    let summaries = json.as_array().expect("multi-standard summary array");
    assert_eq!(summaries.len(), 2);
    assert!(
        summaries
            .iter()
            .any(|s| s["standard"] == "NTIA Minimum Elements")
    );
    assert!(
        summaries
            .iter()
            .any(|s| s["standard"] == "EU CRA Phase 2 (2029)")
    );
}

#[test]
fn cli_license_check_flags_agpl_and_propagation_risks() {
    let output = base_command()
        .arg("license-check")
        .arg(fixture_path("showcase/license-risk.cdx.json"))
        .args(["--strict", "--check-propagation"])
        .output()
        .expect("license-check command should run");

    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("AGPL-3.0-only"));
    assert!(text.contains("License Propagation Risks"));
}

#[test]
fn library_graph_diff_detects_reparenting_and_depth_changes() {
    let old_path = fixture_path("showcase/graph-baseline.cdx.json");
    let new_path = fixture_path("showcase/graph-reorg.cdx.json");
    let old = parse_sbom(&old_path).expect("old graph fixture should parse");
    let new = parse_sbom(&new_path).expect("new graph fixture should parse");

    let config = DiffConfigBuilder::new()
        .old_path(old_path)
        .new_path(new_path)
        .graph_diff(true)
        .build()
        .expect("graph diff config should build");

    let result = compute_diff(&config, &old, &new).expect("graph diff should succeed");
    let summary = result
        .graph_summary
        .expect("graph summary should be present");

    assert!(summary.reparented > 0, "expected reparented graph changes");
    assert!(
        summary.depth_changed > 0,
        "expected depth-change graph changes"
    );
    assert!(
        result
            .graph_changes
            .iter()
            .any(|c| matches!(c.change, DependencyChangeType::Reparented { .. })),
        "expected at least one reparented graph change"
    );
    assert!(
        result
            .graph_changes
            .iter()
            .any(|c| matches!(c.change, DependencyChangeType::DepthChanged { .. })),
        "expected at least one depth-changed graph change"
    );
}
