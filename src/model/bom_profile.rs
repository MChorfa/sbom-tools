//! BOM profile detection and configuration.
//!
//! Determines the type of Bill of Materials (SBOM, CBOM, etc.) and provides
//! profile-specific defaults for quality scoring, compliance standards, and
//! TUI tab selection.

use super::metadata::ComponentType;
use super::sbom::NormalizedSbom;
use serde::{Deserialize, Serialize};

/// BOM profile — determines mode-specific behavior across TUI and CLI.
///
/// Auto-detected from SBOM content or overridden via `--bom-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum BomProfile {
    /// Standard Software Bill of Materials
    #[default]
    Sbom,
    /// Cryptographic Bill of Materials (CycloneDX 1.6+ cryptoProperties)
    Cbom,
    // Future: AiBom, Hbom
}

impl BomProfile {
    /// Auto-detect the BOM profile from SBOM content.
    ///
    /// Classifies as CBOM when >50% of components are `ComponentType::Cryptographic`
    /// and there are at least 3 crypto components.
    #[must_use]
    pub fn detect(sbom: &NormalizedSbom) -> Self {
        let total = sbom.components.len();
        if total == 0 {
            return Self::Sbom;
        }

        let crypto_count = sbom
            .components
            .values()
            .filter(|c| c.component_type == ComponentType::Cryptographic)
            .count();

        if crypto_count >= 3 && crypto_count * 2 > total {
            Self::Cbom
        } else {
            Self::Sbom
        }
    }

    /// Human-readable label for display.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sbom => "SBOM",
            Self::Cbom => "CBOM",
        }
    }

    /// Parse from a string (CLI `--bom-type` flag).
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sbom" => Some(Self::Sbom),
            "cbom" => Some(Self::Cbom),
            _ => None,
        }
    }
}

impl std::fmt::Display for BomProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Component;

    #[test]
    fn test_detect_sbom_empty() {
        let sbom = NormalizedSbom::default();
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_sbom_no_crypto() {
        let mut sbom = NormalizedSbom::default();
        for i in 0..10 {
            let c = Component::new(format!("lib-{i}"), format!("lib-{i}@1.0"));
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_cbom_majority_crypto() {
        let mut sbom = NormalizedSbom::default();
        // 2 software + 5 crypto = 71% crypto → CBOM
        for i in 0..2 {
            let c = Component::new(format!("app-{i}"), format!("app-{i}@1.0"));
            sbom.add_component(c);
        }
        for i in 0..5 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Cbom);
    }

    #[test]
    fn test_detect_sbom_minority_crypto() {
        let mut sbom = NormalizedSbom::default();
        // 8 software + 3 crypto = 27% crypto → SBOM (below 50%)
        for i in 0..8 {
            let c = Component::new(format!("lib-{i}"), format!("lib-{i}@1.0"));
            sbom.add_component(c);
        }
        for i in 0..3 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_detect_cbom_needs_minimum_3() {
        let mut sbom = NormalizedSbom::default();
        // 2 crypto only but < 3 minimum → SBOM
        for i in 0..2 {
            let mut c = Component::new(format!("algo-{i}"), format!("algo-{i}@1.0"));
            c.component_type = ComponentType::Cryptographic;
            sbom.add_component(c);
        }
        assert_eq!(BomProfile::detect(&sbom), BomProfile::Sbom);
    }

    #[test]
    fn test_from_str_opt() {
        assert_eq!(BomProfile::from_str_opt("sbom"), Some(BomProfile::Sbom));
        assert_eq!(BomProfile::from_str_opt("CBOM"), Some(BomProfile::Cbom));
        assert_eq!(BomProfile::from_str_opt("cbom"), Some(BomProfile::Cbom));
        assert_eq!(BomProfile::from_str_opt("hbom"), None);
    }

    #[test]
    fn test_label() {
        assert_eq!(BomProfile::Sbom.label(), "SBOM");
        assert_eq!(BomProfile::Cbom.label(), "CBOM");
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", BomProfile::Sbom), "SBOM");
        assert_eq!(format!("{}", BomProfile::Cbom), "CBOM");
    }
}
