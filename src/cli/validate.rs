//! Validate command handler.
//!
//! Implements the `validate` subcommand for validating SBOMs against compliance standards.

use crate::model::NormalizedSbom;
use crate::pipeline::{OutputTarget, exit_codes, parse_sbom_with_context, write_output};
use crate::quality::{ComplianceChecker, ComplianceLevel, ComplianceResult, ViolationSeverity};
use crate::reports::{ReportFormat, generate_compliance_sarif};
use anyhow::{Result, bail};
use std::path::PathBuf;

/// Run the validate command, returning the desired exit code.
///
/// # Exit codes
/// - [`exit_codes::SUCCESS`] (0): compliant (no errors; no warnings when
///   `--fail-on-warning` is set)
/// - [`exit_codes::COMPLIANCE_ERRORS`] (1): one or more compliance errors found
/// - [`exit_codes::COMPLIANCE_WARNINGS`] (2): warnings found with
///   `--fail-on-warning`
///
/// The caller is responsible for calling `std::process::exit()` with the
/// returned code when it is non-zero.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn run_validate(
    sbom_path: PathBuf,
    standard: String,
    output: ReportFormat,
    output_file: Option<PathBuf>,
    fail_on_warning: bool,
    summary: bool,
    cra_sidecar_path: Option<PathBuf>,
    cra_product_class: Option<String>,
) -> Result<i32> {
    let parsed = parse_sbom_with_context(&sbom_path, false)?;

    // Load CRA sidecar — explicit flag wins, otherwise auto-discover next to the SBOM
    let cra_sidecar = match cra_sidecar_path {
        Some(p) => Some(
            crate::model::CraSidecarMetadata::from_file(&p).map_err(|e| {
                anyhow::anyhow!("Failed to load CRA sidecar from {}: {e}", p.display())
            })?,
        ),
        None => crate::model::CraSidecarMetadata::find_for_sbom(&sbom_path),
    };

    // Resolve effective product class: sidecar wins; otherwise CLI flag.
    // Mismatch between explicit CLI flag and sidecar is reported as a Warning
    // on stderr (not turned into a Violation — sidecar is authoritative).
    let cli_class = cra_product_class
        .as_deref()
        .and_then(crate::model::CraProductClass::parse_cli);
    let sidecar_class = cra_sidecar.as_ref().and_then(|s| s.product_class);
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

    let standards: Vec<&str> = standard.split(',').map(str::trim).collect();
    let mut results = Vec::new();

    for std_name in &standards {
        let result = match std_name.to_lowercase().as_str() {
            "ntia" => ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(parsed.sbom()),
            "fda" => ComplianceChecker::new(ComplianceLevel::FdaMedicalDevice).check(parsed.sbom()),
            "cra" => {
                let mut checker = ComplianceChecker::new(ComplianceLevel::CraPhase2);
                if let Some(sc) = cra_sidecar.clone() {
                    checker = checker.with_sidecar(sc);
                }
                if let Some(c) = effective_class {
                    checker = checker.with_product_class(c);
                }
                checker.check(parsed.sbom())
            }
            "ssdf" | "nist-ssdf" | "nist_ssdf" => {
                ComplianceChecker::new(ComplianceLevel::NistSsdf).check(parsed.sbom())
            }
            "eo14028" | "eo-14028" | "eo_14028" => {
                ComplianceChecker::new(ComplianceLevel::Eo14028).check(parsed.sbom())
            }
            "cnsa2" | "cnsa-2" | "cnsa_2" | "cnsa2.0" => {
                ComplianceChecker::new(ComplianceLevel::Cnsa2).check(parsed.sbom())
            }
            "pqc" | "nist-pqc" | "nist_pqc" => {
                ComplianceChecker::new(ComplianceLevel::NistPqc).check(parsed.sbom())
            }
            "bsi" | "tr-03183" | "tr03183" | "bsi-tr-03183-2" => {
                ComplianceChecker::new(ComplianceLevel::BsiTr03183_2).check(parsed.sbom())
            }
            "oss-steward" | "cra-oss-steward" | "cra-oss" | "cra-art24" | "art24" => {
                let mut checker = ComplianceChecker::new(ComplianceLevel::CraOssSteward);
                if let Some(sc) = cra_sidecar.clone() {
                    checker = checker.with_sidecar(sc);
                }
                checker.check(parsed.sbom())
            }
            "eucc" | "eucc-substantial" | "common-criteria" => {
                let mut checker = ComplianceChecker::new(ComplianceLevel::EuccSubstantial);
                if let Some(sc) = cra_sidecar.clone() {
                    checker = checker.with_sidecar(sc);
                }
                checker.check(parsed.sbom())
            }
            "ai-act" | "ai_act" | "aiact" | "eu-ai-act" => {
                // The sidecar carries the is_high_risk_ai flag, which escalates
                // Annex IV readiness findings — attach it when present.
                let mut checker = ComplianceChecker::new(ComplianceLevel::EuAiAct);
                if let Some(sc) = cra_sidecar.clone() {
                    checker = checker.with_sidecar(sc);
                }
                checker.check(parsed.sbom())
            }
            "bsi-ai" | "bsi_ai" | "bsiai" | "sbom-for-ai" | "ai-bom" => {
                ComplianceChecker::new(ComplianceLevel::BsiSbomForAi).check(parsed.sbom())
            }
            _ => {
                bail!(
                    "Unknown validation standard: {std_name}. \
                    Valid options: ntia, fda, cra, ssdf, eo14028, cnsa2, pqc, bsi, oss-steward, eucc, ai-act, bsi-ai"
                );
            }
        };
        results.push(result);
    }

    if results.len() == 1 {
        let result = &results[0];
        if summary {
            write_compliance_summary(result, output_file)?;
        } else {
            write_compliance_output(result, output, output_file)?;
        }

        if result.error_count > 0 {
            return Ok(exit_codes::COMPLIANCE_ERRORS);
        }
        if fail_on_warning && result.warning_count > 0 {
            return Ok(exit_codes::COMPLIANCE_WARNINGS);
        }
    } else {
        // Multi-standard: merge results for output
        if summary {
            write_multi_compliance_summary(&results, output_file)?;
        } else {
            write_multi_compliance_output(&results, output, output_file)?;
        }

        let has_errors = results.iter().any(|r| r.error_count > 0);
        let has_warnings = results.iter().any(|r| r.warning_count > 0);
        if has_errors {
            return Ok(exit_codes::COMPLIANCE_ERRORS);
        }
        if fail_on_warning && has_warnings {
            return Ok(exit_codes::COMPLIANCE_WARNINGS);
        }
    }

    Ok(exit_codes::SUCCESS)
}

fn write_compliance_output(
    result: &ComplianceResult,
    output: ReportFormat,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);

    let content = match output {
        ReportFormat::Json => serde_json::to_string_pretty(result)
            .map_err(|e| anyhow::anyhow!("Failed to serialize compliance JSON: {e}"))?,
        ReportFormat::Sarif => generate_compliance_sarif(result)?,
        ReportFormat::OscalJson => {
            crate::reports::oscal::generate_assessment_results(std::slice::from_ref(result))?
        }
        _ => format_compliance_text(result),
    };

    write_output(&content, &target, false)?;
    Ok(())
}

/// Compact summary for CI badge generation
#[derive(serde::Serialize)]
struct ComplianceSummary {
    standard: String,
    /// Whether the standard actually evaluated the SBOM. When false,
    /// `compliant` is the documented always-true N/A contract and `score`
    /// is null — dashboards must not read either as a pass.
    applicable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_applicable_reason: Option<String>,
    compliant: bool,
    score: Option<u8>,
    errors: usize,
    warnings: usize,
    info: usize,
}

fn compliance_summary(result: &ComplianceResult) -> ComplianceSummary {
    let not_applicable_reason = match &result.applicability {
        crate::quality::Applicability::NotApplicable(reason) => Some(reason.clone()),
        crate::quality::Applicability::Applicable => None,
    };
    ComplianceSummary {
        standard: result.level.name().to_string(),
        applicable: result.is_applicable(),
        not_applicable_reason,
        compliant: result.is_compliant,
        score: result.score(),
        errors: result.error_count,
        warnings: result.warning_count,
        info: result.info_count,
    }
}

fn write_compliance_summary(result: &ComplianceResult, output_file: Option<PathBuf>) -> Result<()> {
    let target = OutputTarget::from_option(output_file);
    let summary = compliance_summary(result);
    let content = serde_json::to_string(&summary)
        .map_err(|e| anyhow::anyhow!("Failed to serialize summary: {e}"))?;
    write_output(&content, &target, false)?;
    Ok(())
}

fn write_multi_compliance_output(
    results: &[ComplianceResult],
    output: ReportFormat,
    output_file: Option<PathBuf>,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);

    let content = match output {
        ReportFormat::Json => serde_json::to_string_pretty(results)
            .map_err(|e| anyhow::anyhow!("Failed to serialize compliance JSON: {e}"))?,
        ReportFormat::Sarif => crate::reports::generate_multi_compliance_sarif(results)?,
        ReportFormat::OscalJson => crate::reports::oscal::generate_assessment_results(results)?,
        _ => {
            let mut parts = Vec::new();
            for result in results {
                parts.push(format_compliance_text(result));
            }
            parts.join("\n---\n\n")
        }
    };

    write_output(&content, &target, false)?;
    Ok(())
}

fn write_multi_compliance_summary(
    results: &[ComplianceResult],
    output_file: Option<PathBuf>,
) -> Result<()> {
    let target = OutputTarget::from_option(output_file);
    let summaries: Vec<ComplianceSummary> = results.iter().map(compliance_summary).collect();

    let content = serde_json::to_string(&summaries)
        .map_err(|e| anyhow::anyhow!("Failed to serialize multi-standard summary: {e}"))?;
    write_output(&content, &target, false)?;
    Ok(())
}

fn format_compliance_text(result: &ComplianceResult) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Compliance ({})", result.level.name()));
    if let crate::quality::Applicability::NotApplicable(reason) = &result.applicability {
        lines.push(format!("Status: NOT APPLICABLE — {reason}"));
    } else {
        lines.push(format!(
            "Status: {} ({} errors, {} warnings, {} info)",
            if result.is_compliant {
                "COMPLIANT"
            } else {
                "NON-COMPLIANT"
            },
            result.error_count,
            result.warning_count,
            result.info_count
        ));
    }
    lines.push(String::new());

    if result.violations.is_empty() {
        lines.push("No violations found.".to_string());
        return lines.join("\n");
    }

    for v in &result.violations {
        let severity = match v.severity {
            ViolationSeverity::Error => "ERROR",
            ViolationSeverity::Warning => "WARN",
            ViolationSeverity::Info => "INFO",
        };
        let element = v.element.as_deref().unwrap_or("-");
        lines.push(format!(
            "[{}] {} | {} | {}",
            severity,
            v.category.name(),
            v.requirement,
            element
        ));
        lines.push(format!("  {}", v.message));
    }

    lines.join("\n")
}

/// Run the engine's NtiaMinimum check and print a compact PASSED/FAILED
/// summary. Used by `view --validate-ntia`; gating errors are listed,
/// warnings go to the log.
pub fn print_ntia_validation(sbom: &NormalizedSbom) {
    let result = ComplianceChecker::new(ComplianceLevel::NtiaMinimum).check(sbom);
    for v in result.violations_by_severity(ViolationSeverity::Warning) {
        tracing::warn!("{}", v.message);
    }
    if result.is_compliant {
        tracing::info!("SBOM passes NTIA minimum elements validation");
        println!("NTIA Validation: PASSED");
    } else {
        tracing::warn!("SBOM has {} NTIA validation errors", result.error_count);
        println!("NTIA Validation: FAILED");
        for v in result.violations_by_severity(ViolationSeverity::Error) {
            println!("  - {}", v.message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_ntia_validation_does_not_panic_on_empty_sbom() {
        print_ntia_validation(&NormalizedSbom::default());
    }
}
