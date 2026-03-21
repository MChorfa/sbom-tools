//! Severity utilities for vulnerability display and comparison.

use crate::model::{Severity, VulnerabilityRef};

/// Get numeric order for Severity enum (higher = more severe).
#[inline]
#[must_use]
pub const fn severity_enum_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info | Severity::None | Severity::Unknown => 0,
    }
}

/// Get the maximum severity from a list of vulnerabilities.
///
/// Uses the explicit `severity` field when available, falling back to
/// deriving severity from the highest CVSS base score via
/// [`Severity::from_cvss`]. This ensures vulnerabilities that only have
/// CVSS scores (no categorical severity) are still represented in the badge.
#[must_use]
pub fn max_severity_from_vulns(vulns: &[VulnerabilityRef]) -> Option<String> {
    vulns
        .iter()
        .filter_map(effective_severity)
        .max_by(|a, b| severity_enum_order(a).cmp(&severity_enum_order(b)))
        .map(|s| s.to_string().to_lowercase())
}

/// Get the effective severity for a vulnerability: explicit severity field,
/// or derived from the highest CVSS base score.
fn effective_severity(v: &VulnerabilityRef) -> Option<Severity> {
    if let Some(sev) = &v.severity {
        return Some(sev.clone());
    }
    // Derive from highest CVSS score
    v.cvss
        .iter()
        .map(|c| c.base_score)
        .reduce(f32::max)
        .map(Severity::from_cvss)
}

/// Check if a Severity enum matches a target string (case-insensitive).
#[inline]
#[must_use]
pub fn severity_matches(severity: Option<&Severity>, target: &str) -> bool {
    severity.is_some_and(|s| s.to_string().eq_ignore_ascii_case(target))
}

/// Categorize severity into buckets for grouping.
/// Returns: "critical", "high", "medium", "low", or "clean"
#[must_use]
pub fn severity_category(vulns: &[VulnerabilityRef]) -> &'static str {
    if vulns.is_empty() {
        return "clean";
    }

    let max = vulns
        .iter()
        .filter_map(|v| effective_severity(v).map(|s| severity_enum_order(&s)))
        .max()
        .unwrap_or(0);

    match max {
        4 => "critical",
        3 => "high",
        2 => "medium",
        // Unknown/Info/None severity with vulnerabilities -> treat as low
        _ => "low",
    }
}
