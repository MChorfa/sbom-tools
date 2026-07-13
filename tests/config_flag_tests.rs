//! End-to-end tests for the global `--config` / `--no-config` flags and the
//! `config check` action. Exercises the real binary via `CARGO_BIN_EXE` so the
//! full clap -> EffectiveConfig -> per-command seeding path is covered.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

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

/// Write a config file inside a fresh temp dir and return its path.
fn write_config(contents: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join(".sbom-tools.yaml");
    std::fs::write(&path, contents).expect("write config");
    (dir, path)
}

#[test]
fn config_file_output_format_takes_effect_on_diff() {
    // The non-TTY auto default is `summary`, so a config value of `Json` is
    // observable: it can only come from the config file.
    let (_dir, cfg) = write_config("output:\n  format: Json\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "diff"])
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .output()
        .expect("diff should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.trim_start().starts_with('{'),
        "config output.format=Json should produce JSON, got:\n{text}"
    );
}

#[test]
fn explicit_cli_flag_overrides_config_file_value() {
    // File says Json, but an explicit `-o summary` on the CLI must win.
    let (_dir, cfg) = write_config("output:\n  format: Json\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "diff"])
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "summary"])
        .output()
        .expect("diff should run");

    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("SBOM Diff Summary"),
        "explicit -o summary should override config Json, got:\n{text}"
    );
    assert!(
        !text.trim_start().starts_with('{'),
        "output should not be JSON when -o summary is passed"
    );
}

#[test]
fn config_file_fail_on_change_changes_exit_code() {
    // demo-old vs demo-new differ, so `fail_on_change: true` from the file must
    // flip the exit code from 0 to 1.
    let (_dir, cfg) = write_config("behavior:\n  fail_on_change: true\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "diff"])
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "summary"])
        .output()
        .expect("diff should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "config fail_on_change should yield exit 1; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn no_config_ignores_discovered_file() {
    // A `.sbom-tools.yaml` sits in the cwd with fail_on_change: true. Running
    // with --no-config must skip discovery entirely, so the differing diff
    // still exits 0.
    let (dir, cfg) = write_config("behavior:\n  fail_on_change: true\n");

    let output = base_command()
        .arg("--no-config")
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "summary"])
        .current_dir(dir.path())
        .output()
        .expect("diff should run");
    let _ = &cfg;

    assert_eq!(
        output.status.code(),
        Some(0),
        "--no-config should ignore the .sbom-tools.yaml in cwd; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn discovered_config_in_cwd_applies_without_explicit_flag() {
    // Sanity check the discovery path (no --config): a fail_on_change file in
    // the cwd must flip the exit code to 1.
    let (dir, cfg) = write_config("behavior:\n  fail_on_change: true\n");

    let output = base_command()
        .arg("diff")
        .arg(fixture_path("demo-old.cdx.json"))
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "summary"])
        .current_dir(dir.path())
        .output()
        .expect("diff should run");
    let _ = &cfg;

    assert_eq!(
        output.status.code(),
        Some(1),
        "discovered config fail_on_change should yield exit 1; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn config_check_prints_and_validates_effective_config() {
    let (_dir, cfg) = write_config("matching:\n  fuzzy_preset: strict\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "config", "check"])
        .output()
        .expect("config check should run");

    assert!(output.status.success(), "{}", stderr(&output));
    // The validated source is reported on stderr, the merged YAML on stdout.
    assert!(
        stderr(&output).contains("Valid."),
        "config check should report validity; stderr:\n{}",
        stderr(&output)
    );
    let text = stdout(&output);
    assert!(
        text.contains("fuzzy_preset: strict"),
        "config check should print the merged config; got:\n{text}"
    );
}

#[test]
fn config_check_rejects_invalid_config() {
    // threshold out of range -> validation failure -> non-zero exit.
    let (_dir, cfg) = write_config("matching:\n  threshold: 5.0\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "config", "check"])
        .output()
        .expect("config check should run");

    assert!(
        !output.status.success(),
        "invalid config should fail config check"
    );
    assert!(
        stderr(&output).contains("matching.threshold"),
        "error should name the offending field; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn explicit_missing_config_path_is_an_error() {
    let output = base_command()
        .args([
            "--config",
            "/nonexistent/sbom-tools.yaml",
            "config",
            "check",
        ])
        .output()
        .expect("command should run");

    assert!(
        !output.status.success(),
        "a missing explicit --config path should be a hard error"
    );
    assert!(
        stderr(&output).contains("not found"),
        "stderr should explain the missing file; got:\n{}",
        stderr(&output)
    );
}

// ---------------------------------------------------------------------------
// `compliance:` config section (validate / quality defaults)
// ---------------------------------------------------------------------------

#[test]
fn config_compliance_standards_takes_effect_on_validate() {
    // Default standard is ntia; a config value of [cra] is observable in the
    // summary JSON's "standard" field.
    let (_dir, cfg) = write_config("compliance:\n  standards: [cra]\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "validate"])
        .arg(fixture_path("demo-new.cdx.json"))
        .arg("--summary")
        .output()
        .expect("validate should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    assert!(
        json["standard"]
            .as_str()
            .unwrap_or_default()
            .contains("CRA"),
        "config compliance.standards=[cra] should select CRA, got: {json}"
    );
}

#[test]
fn explicit_standard_flag_overrides_config_compliance_standards() {
    let (_dir, cfg) = write_config("compliance:\n  standards: [cra]\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "validate"])
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "ntia", "--summary"])
        .output()
        .expect("validate should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("summary should be JSON");
    assert_eq!(
        json["standard"], "NTIA Minimum Elements",
        "explicit --standard ntia must override the config file: {json}"
    );
}

#[test]
fn config_compliance_profile_takes_effect_on_quality() {
    // Config profile accepts the same aliases as the CLI flag.
    let (_dir, cfg) = write_config("compliance:\n  profile: cyber-resilience\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "quality"])
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("quality should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("quality output should be JSON");
    assert_eq!(
        json["profile"], "cra",
        "config compliance.profile=cyber-resilience should select the cra profile: {json}"
    );
}

#[test]
fn explicit_profile_flag_overrides_config_compliance_profile() {
    let (_dir, cfg) = write_config("compliance:\n  profile: cra\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "quality"])
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--profile", "security", "-o", "json"])
        .output()
        .expect("quality should run");

    let json: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("quality output should be JSON");
    assert_eq!(
        json["profile"], "security",
        "explicit --profile security must override the config file: {json}"
    );
}

#[test]
fn config_compliance_min_score_gates_quality_exit_code() {
    // No CLI --min-score; the config's min_score: 100 must flip the exit code.
    let (_dir, cfg) = write_config("compliance:\n  min_score: 100\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "quality"])
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["-o", "json"])
        .output()
        .expect("quality should run");

    assert_eq!(
        output.status.code(),
        Some(1),
        "config compliance.min_score=100 must gate the exit code; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn config_compliance_fail_on_warning_takes_effect_on_validate() {
    // ntia-warnings-only has warnings but no errors, so exit code 2 can only
    // come from the config's fail_on_warning.
    let (_dir, cfg) = write_config("compliance:\n  fail_on_warning: true\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "validate"])
        .arg(fixture_path("cyclonedx/ntia-warnings-only.cdx.json"))
        .args(["--standard", "ntia", "--summary"])
        .output()
        .expect("validate should run");

    assert_eq!(
        output.status.code(),
        Some(2),
        "config compliance.fail_on_warning must flip the exit code; stderr:\n{}",
        stderr(&output)
    );
}

#[test]
fn invalid_compliance_section_fails_config_check_with_field_name() {
    let (_dir, cfg) =
        write_config("compliance:\n  standards: [not-a-standard]\n  profile: bogus\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "config", "check"])
        .output()
        .expect("config check should run");

    assert!(
        !output.status.success(),
        "invalid compliance section should fail config check"
    );
    let err = stderr(&output);
    assert!(
        err.contains("compliance.standards[0]") && err.contains("compliance.profile"),
        "error should name the offending fields; stderr:\n{err}"
    );
}

#[test]
fn config_compliance_cra_sidecar_is_explicit_and_hard_errors_when_broken() {
    // A sidecar configured in the file is treated like an explicit flag: a
    // broken path aborts the command instead of being silently ignored.
    let (_dir, cfg) = write_config("compliance:\n  cra_sidecar: /nonexistent/side.cra.json\n");

    let output = base_command()
        .args(["--config", cfg.to_str().unwrap(), "validate"])
        .arg(fixture_path("demo-new.cdx.json"))
        .args(["--standard", "cra", "--summary"])
        .output()
        .expect("validate should run");

    assert!(
        !output.status.success(),
        "a configured broken sidecar must abort validate"
    );
    assert!(
        stderr(&output).contains("Failed to load CRA sidecar"),
        "{}",
        stderr(&output)
    );
}
