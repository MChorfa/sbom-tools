//! Configuration types for the diff engine.

use crate::matching::CrossEcosystemConfig;

/// Configuration for large SBOM optimization.
#[derive(Debug, Clone)]
pub struct LargeSbomConfig {
    /// Minimum component count to enable LSH-based matching
    pub lsh_threshold: usize,
    /// Cross-ecosystem matching configuration
    pub cross_ecosystem: CrossEcosystemConfig,
    /// Per-component candidate budget, same value on both sides of the
    /// `lsh_threshold` size gate. Above the gate it bounds the TOTAL across
    /// all strategies (index + LSH + cross-ecosystem); below the gate it
    /// bounds the index candidates (cross-ecosystem candidates there are
    /// budgeted separately by `CrossEcosystemConfig::max_candidates`)
    pub max_candidates: usize,
}

impl Default for LargeSbomConfig {
    fn default() -> Self {
        Self {
            lsh_threshold: 500,
            cross_ecosystem: CrossEcosystemConfig::default(),
            // Matches the budget the sub-threshold path has always used, so
            // candidate volume no longer jumps ~3.5x (50 -> up to 175) when
            // an SBOM crosses the size gate (candidates are quality-ranked,
            // so the marginal recall of slots 51..100 is negligible next to
            // their cost).
            max_candidates: 50,
        }
    }
}

impl LargeSbomConfig {
    /// Check if cross-ecosystem matching is enabled.
    #[must_use]
    pub const fn enable_cross_ecosystem(&self) -> bool {
        self.cross_ecosystem.enabled
    }

    /// Aggressive optimization for very large SBOMs (1000+)
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            lsh_threshold: 300,
            cross_ecosystem: CrossEcosystemConfig::default(),
            max_candidates: 25,
        }
    }

    /// Conservative settings (for accuracy over speed)
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            lsh_threshold: 1000,
            cross_ecosystem: CrossEcosystemConfig::disabled(),
            max_candidates: 150,
        }
    }
}
