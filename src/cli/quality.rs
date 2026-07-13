//! Quality command handler.
//!
//! Implements the `quality` subcommand for assessing SBOM quality.

use crate::config::EnrichmentConfig;
use crate::pipeline::{OutputTarget, exit_codes, parse_sbom_with_context, write_output};
use crate::quality::{
    QualityGrade, QualityReport, QualityScorer, ScoringProfile, ViolationSeverity,
};
use crate::reports::ReportFormat;
use anyhow::Result;
use serde_json::json;
use std::path::PathBuf;

/// Output formats the `quality` command has a real renderer for.
/// `auto`/`summary` render the plain-text report; JSON and SARIF are
/// dedicated emitters. All other [`ReportFormat`] values are rejected up
/// front instead of silently falling back to text.
pub const QUALITY_OUTPUT_FORMATS: &[ReportFormat] = &[
    ReportFormat::Auto,
    ReportFormat::Summary,
    ReportFormat::Json,
    ReportFormat::Sarif,
];

/// Quality command configuration
pub struct QualityConfig {
    pub sbom_path: PathBuf,
    pub profile: ScoringProfile,
    pub output: ReportFormat,
    pub output_file: Option<PathBuf>,
    pub show_recommendations: bool,
    pub show_metrics: bool,
    pub min_score: Option<f32>,
    /// Exit non-zero when the compliance verdict is non-compliant (opt-in;
    /// the default gate is `--min-score` only, so existing scripts are
    /// unaffected).
    pub fail_on_noncompliant: bool,
    pub no_color: bool,
    /// Optional CRA sidecar metadata path (auto-discovered next to the SBOM
    /// when None). Supplements the embedded compliance check used by the
    /// `cra` scoring profile.
    pub cra_sidecar_path: Option<PathBuf>,
    /// CRA Annex III/IV product class (CLI string form). Sidecar value wins.
    pub cra_product_class: Option<String>,
    /// Enrichment configuration (OSV / KEV / EOL / staleness / VEX). When any
    /// source is enabled the SBOM is enriched before scoring so the
    /// Lifecycle / `VulnDocs` categories reflect live data.
    pub enrichment: EnrichmentConfig,
}

/// Run the quality command, returning the desired exit code.
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::too_many_arguments)]
pub fn run_quality(
    sbom_path: PathBuf,
    profile: ScoringProfile,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    show_recommendations: bool,
    show_metrics: bool,
    min_score: Option<f32>,
    fail_on_noncompliant: bool,
    no_color: bool,
    cra_sidecar_path: Option<PathBuf>,
    cra_product_class: Option<String>,
    enrichment: EnrichmentConfig,
) -> Result<i32> {
    let config = QualityConfig {
        sbom_path,
        profile,
        output,
        output_file,
        show_recommendations,
        show_metrics,
        min_score,
        fail_on_noncompliant,
        no_color,
        cra_sidecar_path,
        cra_product_class,
        enrichment,
    };

    run_quality_impl(config)
}

fn run_quality_impl(config: QualityConfig) -> Result<i32> {
    super::ensure_output_format_supported("quality", config.output, QUALITY_OUTPUT_FORMATS)?;

    #[cfg_attr(not(feature = "enrichment"), allow(unused_mut))]
    let mut parsed = parse_sbom_with_context(&config.sbom_path, false)?;

    // Enrich before scoring so Lifecycle (staleness/EOL) and VulnDocs (OSV/KEV)
    // categories reflect live data rather than only the static SBOM contents.
    #[cfg(feature = "enrichment")]
    {
        let any_enrichment = config.enrichment.enabled
            || config.enrichment.enable_eol
            || config.enrichment.enable_kev
            || config.enrichment.enable_epss
            || config.enrichment.enable_staleness
            || config.enrichment.enable_huggingface
            || !config.enrichment.vex_paths.is_empty();
        if any_enrichment {
            let stats =
                crate::pipeline::enrich_sbom_full(parsed.sbom_mut(), &config.enrichment, false);
            for warning in &stats.warnings {
                tracing::warn!("{warning}");
            }
        }
    }

    let profile = config.profile;

    tracing::info!("Running quality assessment with {:?} profile", profile);

    // Honour explicit --cra-sidecar (hard error when broken); otherwise
    // auto-discover next to the SBOM (best-effort).
    let sidecar = super::load_cra_sidecar(config.cra_sidecar_path.as_deref(), &config.sbom_path)?;
    let cli_class = config
        .cra_product_class
        .as_deref()
        .and_then(crate::model::CraProductClass::parse_cli);
    let sidecar_class = sidecar.as_ref().and_then(|s| s.product_class);
    if let (Some(cli), Some(side)) = (cli_class, sidecar_class)
        && cli != side
    {
        tracing::warn!(
            "CRA product class mismatch: --cra-product-class={} but sidecar says {}; using sidecar.",
            cli.label(),
            side.label()
        );
    }
    let effective_class = sidecar_class.or(cli_class);

    let mut scorer = QualityScorer::new(profile);
    if let Some(sc) = sidecar {
        scorer = scorer.with_cra_sidecar(sc);
    }
    if let Some(c) = effective_class {
        scorer = scorer.with_cra_product_class(c);
    }
    let report = scorer.score(parsed.sbom());

    // Build output based on format
    let output_text = match config.output {
        ReportFormat::Json => format_quality_json(&report, &config),
        ReportFormat::Sarif => format_quality_sarif(&report, &config),
        _ => format_quality_report(&report, &config),
    };

    // Write output
    let output_target = OutputTarget::from_option(config.output_file);
    write_output(&output_text, &output_target, false)?;

    // Check minimum score threshold. An N/A AI-readiness report (no ML components)
    // has no meaningful score, so it must not trip the threshold gate.
    let ai_not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);
    if let Some(threshold) = config.min_score
        && !ai_not_applicable
        && report.overall_score < threshold
    {
        tracing::error!(
            "Quality score {:.1} is below minimum threshold {:.1}",
            report.overall_score,
            threshold
        );
        return Ok(exit_codes::QUALITY_BELOW_THRESHOLD);
    }

    // Opt-in: fail the command when the compliance verdict is non-compliant,
    // so the printed "NON-COMPLIANT" cannot be paired with a success exit.
    // Off by default, so `quality --min-score` keeps its score-only contract.
    if config.fail_on_noncompliant && !report.compliance.is_compliant {
        tracing::error!(
            "SBOM is non-compliant with {} ({} error(s))",
            report.compliance.level.name(),
            report.compliance.error_count
        );
        return Ok(exit_codes::COMPLIANCE_ERRORS);
    }

    Ok(exit_codes::SUCCESS)
}

/// Format quality report as JSON
fn format_quality_json(report: &QualityReport, config: &QualityConfig) -> String {
    let not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);

    // Serialize the report, then for an N/A AI-readiness result replace the
    // overall_score/grade so machine consumers don't read a 0.0 / "F" as a real
    // failing score (the standard 8-category pipeline did not run).
    let mut report_value = serde_json::to_value(report).unwrap_or_default();
    if not_applicable && let Some(obj) = report_value.as_object_mut() {
        obj.insert("overall_score".to_string(), serde_json::Value::Null);
        obj.insert(
            "grade".to_string(),
            serde_json::Value::String("N/A".to_string()),
        );
    }

    let output = json!({
        "tool": "sbom-tools",
        "version": env!("CARGO_PKG_VERSION"),
        "sbom": config.sbom_path.file_name().unwrap_or_default().to_string_lossy(),
        "profile": config.profile.to_string(),
        "applicable": !not_applicable,
        "report": report_value,
    });
    serde_json::to_string_pretty(&output).unwrap_or_default()
}

/// Format quality report as SARIF 2.1.0
fn format_quality_sarif(report: &QualityReport, config: &QualityConfig) -> String {
    // AI-readiness uses a dedicated SBOM-AIBOM-* SARIF rule family (one result per
    // failing model-card check), with a rule table and run-level properties.
    if report.profile == ScoringProfile::AiReadiness
        && let Some(metrics) = report.ai_readiness_metrics.as_ref()
    {
        let na = metrics.is_not_applicable();
        let score = if na { None } else { Some(report.overall_score) };
        let grade = if na { "N/A" } else { report.grade.letter() };
        return crate::reports::generate_ai_readiness_sarif(
            metrics,
            &config
                .sbom_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            &config.profile.to_string(),
            score,
            grade,
        )
        .unwrap_or_else(|_| {
            serde_json::to_string_pretty(&serde_json::json!({ "runs": [] })).unwrap_or_default()
        });
    }

    let not_applicable = report
        .ai_readiness_metrics
        .as_ref()
        .is_some_and(crate::quality::AiReadinessMetrics::is_not_applicable);
    let mut results = Vec::new();

    // Add compliance violations as SARIF results
    for violation in &report.compliance.violations {
        let level = match violation.severity {
            ViolationSeverity::Error => "error",
            ViolationSeverity::Warning => "warning",
            ViolationSeverity::Info => "note",
        };
        results.push(json!({
            "ruleId": format!("QUALITY-{}", violation.category.name().to_uppercase().replace(' ', "-")),
            "level": level,
            "message": { "text": violation.message },
            "properties": {
                "requirement": violation.requirement,
                "category": violation.category.name(),
                "remediation": violation.remediation_guidance(),
                "element": violation.element,
            }
        }));
    }

    // Add recommendations as informational results
    for rec in &report.recommendations {
        let level = match rec.priority {
            1 => "error",
            2 => "warning",
            _ => "note",
        };
        results.push(json!({
            "ruleId": format!("QUALITY-REC-{}", rec.category.name().to_uppercase().replace(' ', "-")),
            "level": level,
            "message": {
                "text": format!("{} ({} affected, +{:.1} impact)", rec.message, rec.affected_count, rec.impact)
            },
            "properties": {
                "priority": rec.priority,
                "category": rec.category.name(),
                "affected_count": rec.affected_count,
                "impact": rec.impact,
            }
        }));
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sbom-tools",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/anthropics/sbom-tools",
                }
            },
            "results": results,
            "properties": {
                "sbom": config.sbom_path.file_name().unwrap_or_default().to_string_lossy(),
                "profile": config.profile.to_string(),
                "applicable": !not_applicable,
                "overall_score": if not_applicable { serde_json::Value::Null } else { json!(report.overall_score) },
                "grade": if not_applicable { "N/A" } else { report.grade.letter() },
                "compliant": report.compliance.is_compliant,
            }
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// Format quality report for output
fn format_quality_report(report: &QualityReport, config: &QualityConfig) -> String {
    let mut lines = Vec::new();
    let use_color = !config.no_color && std::env::var("NO_COLOR").is_err();

    // AI-readiness uses a dedicated report layout (per-check pass/fail, not the
    // standard 8 category scores).
    if report.profile == ScoringProfile::AiReadiness {
        return format_ai_readiness_report(report, config, use_color);
    }

    // Color codes
    let (grade_color, reset) = if use_color {
        let color = match report.grade {
            QualityGrade::A | QualityGrade::B => "\x1b[32m", // Green
            QualityGrade::C | QualityGrade::D => "\x1b[33m", // Yellow
            QualityGrade::F => "\x1b[31m",                   // Red
        };
        (color, "\x1b[0m")
    } else {
        ("", "")
    };

    // Header
    lines.push(format!(
        "SBOM Quality Report: {}",
        config
            .sbom_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    ));
    lines.push(format!("Profile: {}", config.profile));
    lines.push(String::new());

    // Overall score
    lines.push(format!(
        "Overall Score: {}{:.1}/100 (Grade: {}){}",
        grade_color,
        report.overall_score,
        report.grade.letter(),
        reset
    ));
    lines.push(String::new());

    // Category scores
    lines.push("Category Scores:".to_string());
    lines.push(format!(
        "  Completeness:    {:.1}/100",
        report.completeness_score
    ));
    lines.push(format!(
        "  Identifiers:     {:.1}/100",
        report.identifier_score
    ));
    lines.push(format!(
        "  Licenses:        {:.1}/100",
        report.license_score
    ));
    lines.push(match report.vulnerability_score {
        Some(score) => format!("  Vulnerabilities: {score:.1}/100"),
        None => "  Vulnerabilities: N/A".to_string(),
    });
    lines.push(format!(
        "  Dependencies:    {:.1}/100",
        report.dependency_score
    ));
    lines.push(String::new());

    // Compliance status
    let compliance_status = if report.compliance.is_compliant {
        format!(
            "{}COMPLIANT{}",
            if use_color { "\x1b[32m" } else { "" },
            reset
        )
    } else {
        format!(
            "{}NON-COMPLIANT{}",
            if use_color { "\x1b[31m" } else { "" },
            reset
        )
    };
    lines.push(format!(
        "Compliance ({}): {} ({} errors, {} warnings)",
        report.compliance.level.name(),
        compliance_status,
        report.compliance.error_count,
        report.compliance.warning_count
    ));
    lines.push(String::new());

    // Detailed metrics
    if config.show_metrics {
        lines.push("Detailed Metrics:".to_string());
        lines.push(format!(
            "  Total Components: {}",
            report.completeness_metrics.total_components
        ));
        lines.push(format!(
            "  With Version:     {:.1}%",
            report.completeness_metrics.components_with_version
        ));
        lines.push(format!(
            "  With PURL:        {:.1}%",
            report.completeness_metrics.components_with_purl
        ));
        lines.push(format!(
            "  With License:     {:.1}%",
            report.completeness_metrics.components_with_licenses
        ));
        lines.push(format!(
            "  With Supplier:    {:.1}%",
            report.completeness_metrics.components_with_supplier
        ));
        lines.push(format!(
            "  With Hashes:      {:.1}%",
            report.completeness_metrics.components_with_hashes
        ));
        lines.push(String::new());

        lines.push("  Identifier Quality:".to_string());
        lines.push(format!(
            "    Valid PURLs:    {}",
            report.identifier_metrics.valid_purls
        ));
        lines.push(format!(
            "    Valid CPEs:     {}",
            report.identifier_metrics.valid_cpes
        ));
        lines.push(format!(
            "    Missing IDs:    {}",
            report.identifier_metrics.missing_all_identifiers
        ));
        lines.push(format!(
            "    Ecosystems:     {}",
            report.identifier_metrics.ecosystems.join(", ")
        ));
        lines.push(String::new());

        lines.push("  Dependency Graph:".to_string());
        lines.push(format!(
            "    Total Edges:    {}",
            report.dependency_metrics.total_dependencies
        ));
        lines.push(format!(
            "    Orphan Nodes:   {}",
            report.dependency_metrics.orphan_components
        ));
        // Software complexity index
        if let Some(simplicity) = report.dependency_metrics.software_complexity_index {
            let level = report
                .dependency_metrics
                .complexity_level
                .as_ref()
                .map_or("N/A", |l| l.label());
            lines.push(format!("    Complexity:     {simplicity:.0}/100 ({level})"));
            if let Some(ref f) = report.dependency_metrics.complexity_factors {
                lines.push(format!(
                    "      Volume: {:.2}  Depth: {:.2}  Fanout: {:.2}  Cycles: {:.2}  Fragmentation: {:.2}",
                    f.dependency_volume, f.normalized_depth, f.fanout_concentration, f.cycle_ratio, f.fragmentation
                ));
            }
        } else {
            lines.push("    Complexity:     N/A (graph analysis skipped)".to_string());
        }
        lines.push(String::new());
    }

    // Recommendations
    if config.show_recommendations && !report.recommendations.is_empty() {
        lines.push("Recommendations:".to_string());
        for rec in report.recommendations.iter().take(10) {
            let priority_indicator = if use_color {
                match rec.priority {
                    1 => "\x1b[31m[P1]\x1b[0m",
                    2 => "\x1b[33m[P2]\x1b[0m",
                    3 => "\x1b[34m[P3]\x1b[0m",
                    _ => "[P4+]",
                }
            } else {
                match rec.priority {
                    1 => "[P1]",
                    2 => "[P2]",
                    3 => "[P3]",
                    _ => "[P4+]",
                }
            };
            lines.push(format!(
                "  {} {} ({} affected, +{:.1} impact)",
                priority_indicator, rec.message, rec.affected_count, rec.impact
            ));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Render the AI-readiness profile as a per-check pass/fail report.
fn format_ai_readiness_report(
    report: &QualityReport,
    config: &QualityConfig,
    use_color: bool,
) -> String {
    let mut lines = Vec::new();
    let Some(metrics) = report.ai_readiness_metrics.as_ref() else {
        return String::new();
    };
    let reset = if use_color { "\x1b[0m" } else { "" };

    lines.push(format!(
        "SBOM Quality Report: {}",
        config
            .sbom_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
    ));
    lines.push(format!("Profile: {}", config.profile));
    lines.push(String::new());

    if metrics.is_not_applicable() {
        let muted = if use_color { "\x1b[33m" } else { "" };
        lines.push(format!("Overall Score: {muted}N/A{reset}"));
        lines.push(
            metrics
                .na_reason
                .clone()
                .unwrap_or_else(|| "AI readiness is not applicable for this SBOM".to_string()),
        );
        return lines.join("\n");
    }

    let grade_color = if use_color {
        match report.grade {
            QualityGrade::A | QualityGrade::B => "\x1b[32m",
            QualityGrade::C | QualityGrade::D => "\x1b[33m",
            QualityGrade::F => "\x1b[31m",
        }
    } else {
        ""
    };
    lines.push(format!(
        "Overall Score: {}{:.1}/100 (Grade: {}){}",
        grade_color,
        report.overall_score,
        report.grade.letter(),
        reset
    ));
    lines.push(format!(
        "ML Components: {} total, {} fully documented",
        metrics.ml_component_count, metrics.components_fully_documented
    ));
    lines.push(String::new());
    lines.push("AI Readiness Checks:".to_string());

    for check in &metrics.checks {
        let status = if check.passed { "PASS" } else { "FAIL" };
        let status_color = if use_color {
            if check.passed { "\x1b[32m" } else { "\x1b[31m" }
        } else {
            ""
        };
        lines.push(format!(
            "  {}{}{} {} ({:.0}%)",
            status_color,
            status,
            reset,
            check.id,
            check.weight * 100.0
        ));
        lines.push(format!("    {}", check.name));
        if config.show_metrics
            && let Some(detail) = &check.detail
        {
            lines.push(format!("    {detail}"));
        }
    }
    lines.push(String::new());

    if config.show_recommendations && !report.recommendations.is_empty() {
        lines.push("Recommendations:".to_string());
        for rec in report.recommendations.iter().take(10) {
            lines.push(format!(
                "  [P{}] {} ({} affected, +{:.1} impact)",
                rec.priority, rec.message, rec.affected_count, rec.impact
            ));
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Component, ComponentType, DocumentMetadata, MlModelInfo, NormalizedSbom};

    /// Contract test: every documented `--profile` spelling parses to the
    /// right profile through the single shared parser (clap uses the same
    /// name/alias table).
    #[test]
    fn every_documented_profile_alias_parses() {
        let table: &[(&str, ScoringProfile)] = &[
            ("minimal", ScoringProfile::Minimal),
            ("standard", ScoringProfile::Standard),
            ("security", ScoringProfile::Security),
            ("license-compliance", ScoringProfile::LicenseCompliance),
            ("license", ScoringProfile::LicenseCompliance),
            ("cra", ScoringProfile::Cra),
            ("cyber-resilience", ScoringProfile::Cra),
            ("bsi", ScoringProfile::BsiTr03183_2),
            ("tr-03183", ScoringProfile::BsiTr03183_2),
            ("tr03183", ScoringProfile::BsiTr03183_2),
            ("bsi-tr-03183-2", ScoringProfile::BsiTr03183_2),
            ("comprehensive", ScoringProfile::Comprehensive),
            ("full", ScoringProfile::Comprehensive),
            ("cbom", ScoringProfile::Cbom),
            ("cryptographic", ScoringProfile::Cbom),
            ("ai-readiness", ScoringProfile::AiReadiness),
            ("ai_readiness", ScoringProfile::AiReadiness),
        ];
        for (spelling, expected) in table {
            let parsed: ScoringProfile = spelling
                .parse()
                .unwrap_or_else(|e| panic!("'{spelling}' must parse: {e}"));
            assert_eq!(parsed, *expected, "'{spelling}' mapped to wrong profile");
        }
    }

    #[test]
    fn profile_parse_is_case_insensitive_and_rejects_unknown() {
        assert_eq!(
            "MINIMAL".parse::<ScoringProfile>().unwrap(),
            ScoringProfile::Minimal
        );
        assert_eq!(
            "Standard".parse::<ScoringProfile>().unwrap(),
            ScoringProfile::Standard
        );
        let err = "invalid".parse::<ScoringProfile>().unwrap_err();
        assert!(err.contains("Valid values"));
        assert!(err.contains("license-compliance"));
    }

    #[test]
    fn rejects_unsupported_output_format_before_reading_sbom() {
        // html/markdown/csv/oscal-json used to fall through to the text
        // renderer; they must now fail fast (before the SBOM is read — the
        // path here does not exist).
        for format in [
            ReportFormat::Html,
            ReportFormat::Markdown,
            ReportFormat::Csv,
            ReportFormat::OscalJson,
            ReportFormat::Ndjson,
            ReportFormat::Table,
            ReportFormat::SideBySide,
            ReportFormat::Tui,
        ] {
            let err = run_quality(
                PathBuf::from("/nonexistent/never-read.cdx.json"),
                ScoringProfile::Standard,
                format,
                None,
                false,
                false,
                None,
                false,
                true,
                None,
                None,
                EnrichmentConfig::default(),
            )
            .expect_err("unsupported format must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("not supported by `sbom-tools quality`"),
                "unexpected error for {format}: {msg}"
            );
            assert!(
                msg.contains("sarif") && msg.contains("json"),
                "error must list the supported formats: {msg}"
            );
        }
    }

    #[test]
    fn explicit_missing_sidecar_is_a_hard_error() {
        // An explicitly passed --cra-sidecar that fails to load used to be
        // silently ignored (`.ok()`); it must now abort the command.
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        let err = run_quality(
            sbom_path,
            ScoringProfile::Cra,
            ReportFormat::Summary,
            None,
            false,
            false,
            None,
            false,
            true,
            Some(dir.path().join("missing.cra.json")),
            None,
            EnrichmentConfig::default(),
        )
        .expect_err("broken explicit sidecar must be a hard error");
        assert!(err.to_string().contains("Failed to load CRA sidecar"));
    }

    #[test]
    fn auto_discovered_broken_sidecar_soft_fails() {
        // Without an explicit path, a broken adjacent sidecar must not abort
        // the command (best-effort discovery logs a warning instead).
        let dir = tempfile::tempdir().unwrap();
        let sbom_path = dir.path().join("app.cdx.json");
        std::fs::write(
            &sbom_path,
            r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("app.cra.json"), "{ not json").unwrap();
        let code = run_quality(
            sbom_path,
            ScoringProfile::Cra,
            ReportFormat::Json,
            Some(dir.path().join("out.json")),
            false,
            false,
            None,
            false,
            true,
            None,
            None,
            EnrichmentConfig::default(),
        )
        .expect("auto-discovery must soft-fail on a broken sidecar");
        assert_eq!(code, exit_codes::SUCCESS);
    }

    fn ai_config(output: ReportFormat, min_score: Option<f32>) -> QualityConfig {
        QualityConfig {
            sbom_path: PathBuf::from("model.cdx.json"),
            profile: ScoringProfile::AiReadiness,
            output,
            output_file: None,
            show_recommendations: true,
            show_metrics: true,
            min_score,
            fail_on_noncompliant: false,
            no_color: true,
            cra_sidecar_path: None,
            cra_product_class: None,
            enrichment: EnrichmentConfig::default(),
        }
    }

    fn fully_documented_ml_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        let mut component = Component::new("bert-base".to_string(), "ml-model-1".to_string())
            .with_version("1.0.0".to_string());
        component.component_type = ComponentType::MachineLearningModel;
        component.ml_model = Some(MlModelInfo {
            architecture_family: Some("transformer".to_string()),
            training_datasets: vec![crate::model::DatasetRef {
                reference: None,
                name: Some("dataset".to_string()),
                purl: None,
            }],
            energy_kwh_training: Some(20.0),
            model_card_url: Some("https://example.test/model-card".to_string()),
            limitations: Some("Only validated for English text".to_string()),
            ..MlModelInfo::default()
        });
        // A weight hash satisfies the AI-010 integrity check.
        component.hashes.push(crate::model::Hash::new(
            crate::model::HashAlgorithm::Sha256,
            "d".repeat(64),
        ));
        component.extensions.raw = Some(json!({
            "mlModel": { "modelCard": {
                "quantitativeAnalysis": { "performanceMetrics": [{ "type": "accuracy", "value": 0.97 }] },
                "considerations": {
                    "fairnessConsiderations": ["Reviewed"],
                    "useCases": ["Classification"],
                    "ethicalConsiderations": ["Human review required"]
                }
            }}
        }));
        sbom.add_component(component);
        sbom
    }

    #[test]
    fn test_format_quality_report_ai_readiness_shows_checks() {
        let sbom = fully_documented_ml_sbom();
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let output = format_quality_report(&report, &ai_config(ReportFormat::Summary, None));
        assert!(output.contains("AI Readiness Checks:"));
        assert!(output.contains("PASS AI-001"));
        assert!(!output.contains("Category Scores:"));
    }

    #[test]
    fn test_format_quality_report_ai_readiness_na_shows_na() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let output = format_quality_report(&report, &ai_config(ReportFormat::Summary, Some(70.0)));
        assert!(output.contains("Overall Score: N/A"));
        assert!(output.contains("No machine-learning-model components found"));
    }

    #[test]
    fn test_format_quality_json_ai_readiness_na_is_not_misleading() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let out = format_quality_json(&report, &ai_config(ReportFormat::Json, None));
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        // N/A must not serialize as a real 0.0 / "F" score.
        assert_eq!(value["applicable"], json!(false));
        assert!(value["report"]["overall_score"].is_null());
        assert_eq!(value["report"]["grade"], json!("N/A"));
    }

    #[test]
    fn test_format_quality_sarif_ai_readiness_na_is_not_misleading() {
        let sbom = NormalizedSbom::new(DocumentMetadata::default());
        let report = QualityScorer::new(ScoringProfile::AiReadiness).score(&sbom);
        let out = format_quality_sarif(&report, &ai_config(ReportFormat::Sarif, None));
        let value: serde_json::Value = serde_json::from_str(&out).expect("valid SARIF JSON");
        let run = &value["runs"][0];
        let props = &run["properties"];
        assert_eq!(props["applicable"], json!(false));
        assert!(props["overall_score"].is_null());
        assert_eq!(props["grade"], json!("N/A"));
        // The dedicated SBOM-AIBOM-* rule family is now emitted (was absent before),
        // and N/A yields no findings.
        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert!(
            rules.iter().any(|r| r["id"] == json!("SBOM-AIBOM-001")),
            "expected SBOM-AIBOM rule table"
        );
        assert!(run["results"].as_array().expect("results array").is_empty());
    }
}
