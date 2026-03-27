//! Shared enrichment pipeline for all commands.
//!
//! Composes OSV, EOL, and VEX enrichment into a single function call,
//! deduplicating logic previously inlined in `cli/diff.rs` and `cli/view.rs`.

use crate::config::EnrichmentConfig;
use crate::model::NormalizedSbom;

/// Aggregated enrichment statistics across all enrichment sources.
#[derive(Debug, Default, Clone)]
pub struct AggregatedEnrichmentStats {
    /// OSV vulnerability enrichment stats
    #[cfg(feature = "enrichment")]
    pub osv: Option<crate::enrichment::EnrichmentStats>,
    /// End-of-life enrichment stats
    #[cfg(feature = "enrichment")]
    pub eol: Option<crate::enrichment::EolEnrichmentStats>,
    /// VEX enrichment stats
    #[cfg(feature = "enrichment")]
    pub vex: Option<crate::enrichment::VexEnrichmentStats>,
    /// Warnings for display (non-fatal enrichment failures)
    pub warnings: Vec<String>,
}

impl AggregatedEnrichmentStats {
    /// Extract the OSV `EnrichmentStats` if available (for backwards compat with TUI).
    #[cfg(feature = "enrichment")]
    #[must_use]
    pub fn osv_stats(&self) -> Option<crate::enrichment::EnrichmentStats> {
        self.osv.clone()
    }

    /// Whether any enrichment was actually performed.
    #[must_use]
    pub fn any_enrichment(&self) -> bool {
        #[cfg(feature = "enrichment")]
        {
            self.osv.is_some() || self.eol.is_some() || self.vex.is_some()
        }
        #[cfg(not(feature = "enrichment"))]
        {
            false
        }
    }
}

/// Enrich a single SBOM with all configured enrichment sources.
///
/// Non-fatal: individual enrichment failures are captured as warnings,
/// not propagated as errors. Returns stats for display in TUI/reports.
#[cfg(feature = "enrichment")]
pub fn enrich_sbom_full(
    sbom: &mut NormalizedSbom,
    config: &EnrichmentConfig,
    quiet: bool,
) -> AggregatedEnrichmentStats {
    let mut stats = AggregatedEnrichmentStats::default();

    // 1. OSV vulnerability enrichment
    if config.enabled {
        let osv_config = super::build_enrichment_config(config);
        match super::enrich_sbom(sbom, &osv_config, quiet) {
            Some(s) => stats.osv = Some(s),
            None => stats
                .warnings
                .push("OSV vulnerability enrichment failed".into()),
        }
    }

    // 2. EOL detection
    if config.enable_eol {
        let eol_config = crate::enrichment::EolClientConfig {
            cache_dir: config
                .cache_dir
                .clone()
                .unwrap_or_else(super::dirs::eol_cache_dir),
            cache_ttl: std::time::Duration::from_secs(config.cache_ttl_hours * 3600),
            bypass_cache: config.bypass_cache,
            timeout: std::time::Duration::from_secs(config.timeout_secs),
            ..Default::default()
        };
        match super::enrich_eol(sbom, &eol_config, quiet) {
            Some(s) => stats.eol = Some(s),
            None => stats.warnings.push("EOL enrichment failed".into()),
        }
    }

    // 3. VEX overlay
    if !config.vex_paths.is_empty() {
        match super::enrich_vex(sbom, &config.vex_paths, quiet) {
            Some(s) => stats.vex = Some(s),
            None => stats.warnings.push("VEX enrichment failed".into()),
        }
    }

    stats
}

/// Enrich multiple SBOMs with all configured enrichment sources.
///
/// Returns per-SBOM stats in the same order as the input slice.
#[cfg(feature = "enrichment")]
pub fn enrich_sboms(
    sboms: &mut [NormalizedSbom],
    config: &EnrichmentConfig,
    quiet: bool,
) -> Vec<AggregatedEnrichmentStats> {
    sboms
        .iter_mut()
        .map(|sbom| enrich_sbom_full(sbom, config, quiet))
        .collect()
}

/// No-op enrichment when the `enrichment` feature is disabled.
#[cfg(not(feature = "enrichment"))]
pub fn enrich_sbom_full(
    _sbom: &mut NormalizedSbom,
    config: &EnrichmentConfig,
    _quiet: bool,
) -> AggregatedEnrichmentStats {
    let mut stats = AggregatedEnrichmentStats::default();
    if config.enabled {
        stats.warnings.push(
            "Enrichment requested but the 'enrichment' feature is not enabled. \
             Rebuild with: cargo build --features enrichment"
                .into(),
        );
    }
    stats
}

/// No-op batch enrichment when the `enrichment` feature is disabled.
#[cfg(not(feature = "enrichment"))]
pub fn enrich_sboms(
    sboms: &mut [NormalizedSbom],
    config: &EnrichmentConfig,
    quiet: bool,
) -> Vec<AggregatedEnrichmentStats> {
    sboms
        .iter_mut()
        .map(|sbom| enrich_sbom_full(sbom, config, quiet))
        .collect()
}
