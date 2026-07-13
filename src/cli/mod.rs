//! CLI command handlers.
//!
//! This module provides testable command handlers that are invoked by main.rs.
//! Each handler implements the business logic for a specific CLI subcommand.

#[cfg(feature = "enrichment")]
mod cache;
mod convert;
mod cra_docs;
mod cra_standards_watch;
mod diff;
#[cfg(feature = "enrichment")]
mod enrich;
mod license_check;
mod merge;
mod multi;
mod quality;
mod query;
mod tailor;
mod validate;
mod verify;
mod vex;
mod view;
mod watch;

#[cfg(feature = "enrichment")]
pub use cache::{CacheAction, run_cache};
pub use convert::run_convert;
pub use cra_docs::run_cra_docs;
pub use cra_standards_watch::{
    OnlineProbe, TrackedStandard, WatchOutputFormat, cra_catalogue, probe_cra_standards,
    run_cra_standards_watch,
};
pub use diff::run_diff;
#[cfg(feature = "enrichment")]
pub use enrich::run_enrich;
pub use license_check::run_license_check;
pub use merge::run_merge;
pub use multi::{run_diff_multi, run_matrix, run_timeline};
pub use quality::run_quality;
pub use query::{QueryFilter, run_query};
pub use tailor::run_tailor;
pub use validate::run_validate;
pub use verify::{VerifyAction, run_verify};
pub use vex::{VexAction, VexExportFormat, run_vex};
pub use view::run_view;
pub use watch::run_watch;

// Re-export config types used by handlers
pub use crate::config::{DiffConfig, ViewConfig};

/// Reject an output format the given command has no real renderer for.
///
/// Each command handler declares the formats it genuinely supports and calls
/// this before doing any work, so an unsupported `(command, format)` pair
/// fails with a clear error instead of silently substituting another format
/// (e.g. `validate -o html` used to fall through to the plain-text renderer,
/// and `diff -o oscal-json` used to emit plain JSON).
pub(crate) fn ensure_output_format_supported(
    command: &str,
    requested: crate::reports::ReportFormat,
    supported: &[crate::reports::ReportFormat],
) -> anyhow::Result<()> {
    if supported.contains(&requested) {
        return Ok(());
    }
    anyhow::bail!(
        "output format '{requested}' is not supported by `sbom-tools {command}`; \
         supported formats: {}",
        supported
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Resolve the CRA sidecar for a command.
///
/// An **explicitly** requested sidecar (CLI flag or config file) that fails
/// to load is a hard error — the user asked for that metadata, so silently
/// scoring without it would misreport compliance. Auto-discovery (no explicit
/// path) stays best-effort: `find_for_sbom` logs a warning for a discovered-
/// but-broken candidate and returns `None`.
pub(crate) fn load_cra_sidecar(
    explicit: Option<&std::path::Path>,
    sbom_path: &std::path::Path,
) -> anyhow::Result<Option<crate::model::CraSidecarMetadata>> {
    match explicit {
        Some(p) => crate::model::CraSidecarMetadata::from_file(p)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("Failed to load CRA sidecar from {}: {e}", p.display())),
        None => Ok(crate::model::CraSidecarMetadata::find_for_sbom(sbom_path)),
    }
}
