//! Generation honesty report.
//!
//! Everything the generator could not determine is recorded here instead of
//! being fabricated into the BOM, alongside risk observations about the model
//! artifacts themselves. Rendered to stderr by the CLI (like the emit
//! fidelity report) so piped SBOM output stays clean.

use std::fmt::Write as _;

use super::description::FactSource;

/// A fact the generator wanted but could not derive.
#[derive(Debug, Clone)]
pub struct KnownUnknown {
    /// The AIBOM field/fact that is missing (e.g. `license`).
    pub field: String,
    /// Why it is missing and how the operator can supply it.
    pub why: String,
}

/// A risk observation about the model artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RiskFlag {
    /// Pickle-container weights (`.bin`/`.pt`/`.ckpt`) — arbitrary code
    /// execution on deserialization.
    PickleWeights(String),
    /// Repo ships Python code that `trust_remote_code=True` would execute.
    CustomCode(String),
    /// No license could be determined.
    MissingLicense,
    /// The revision is not pinned to a commit sha.
    UnpinnedRevision,
    /// The Hub reports the model as gated; file-level access may differ.
    GatedModel(String),
}

impl RiskFlag {
    fn render(&self) -> String {
        match self {
            Self::PickleWeights(file) => format!(
                "pickle-container weights ({file}): deserialization executes arbitrary code; \
                 prefer the safetensors artifacts"
            ),
            Self::CustomCode(file) => format!(
                "repo ships executable Python ({file}): loading with trust_remote_code=True \
                 runs this code"
            ),
            Self::MissingLicense => {
                "no license declared anywhere in the model metadata".to_string()
            }
            Self::UnpinnedRevision => {
                "revision is not a pinned commit sha; the BOM describes a moving target"
                    .to_string()
            }
            Self::GatedModel(mode) => {
                format!("model is gated ({mode}); reproduce-verification requires accepted access")
            }
        }
    }
}

/// Coverage, provenance, and known-unknowns for one generation run.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GenerationReport {
    /// Model id (or directory name) the report describes.
    pub subject: String,
    /// Total files inventoried.
    pub file_count: usize,
    /// Weight files inventoried.
    pub weight_file_count: usize,
    /// Files carrying a SHA-256.
    pub hashed_count: usize,
    /// Hashes computed locally vs declared by the Hub.
    pub computed_hashes: usize,
    /// Hub-declared hashes.
    pub hub_declared_hashes: usize,
    /// Facts the generator could not derive.
    pub known_unknowns: Vec<KnownUnknown>,
    /// Risk observations.
    pub risks: Vec<RiskFlag>,
}

impl GenerationReport {
    /// Record a missing fact.
    pub fn unknown(&mut self, field: impl Into<String>, why: impl Into<String>) {
        self.known_unknowns.push(KnownUnknown {
            field: field.into(),
            why: why.into(),
        });
    }

    /// Record a risk observation (deduplicated).
    pub fn risk(&mut self, risk: RiskFlag) {
        if !self.risks.contains(&risk) {
            self.risks.push(risk);
        }
    }

    /// Count a hash by its source.
    pub fn count_hash(&mut self, source: FactSource) {
        self.hashed_count += 1;
        match source {
            FactSource::Computed => self.computed_hashes += 1,
            FactSource::HubDeclared => self.hub_declared_hashes += 1,
        }
    }

    /// Render the report for stderr.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "AI-BOM generation report — {}", self.subject);
        let _ = writeln!(
            out,
            "  files: {} inventoried, {} weight file(s), {} hashed \
             ({} computed locally, {} hub-declared)",
            self.file_count,
            self.weight_file_count,
            self.hashed_count,
            self.computed_hashes,
            self.hub_declared_hashes
        );
        if !self.risks.is_empty() {
            let _ = writeln!(out, "  risks:");
            for risk in &self.risks {
                let _ = writeln!(out, "    ! {}", risk.render());
            }
        }
        if !self.known_unknowns.is_empty() {
            let _ = writeln!(out, "  known unknowns (not fabricated):");
            for ku in &self.known_unknowns {
                let _ = writeln!(out, "    ? {}: {}", ku.field, ku.why);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_lists_risks_and_unknowns() {
        let mut report = GenerationReport {
            subject: "org/model".into(),
            file_count: 4,
            weight_file_count: 2,
            ..GenerationReport::default()
        };
        report.count_hash(FactSource::Computed);
        report.count_hash(FactSource::HubDeclared);
        report.risk(RiskFlag::MissingLicense);
        report.risk(RiskFlag::MissingLicense); // deduped
        report.unknown("energy", "model card declares no training energy");

        let rendered = report.render();
        assert!(rendered.contains("org/model"));
        assert!(rendered.contains("1 computed locally, 1 hub-declared"));
        assert_eq!(rendered.matches("no license declared").count(), 1);
        assert!(rendered.contains("? energy"));
    }
}
