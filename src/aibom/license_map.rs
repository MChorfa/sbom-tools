//! Hugging Face license-tag → SPDX mapping.
//!
//! HF frontmatter `license:` values are Hub tags, not SPDX ids. Many map
//! cleanly (`apache-2.0` → `Apache-2.0`); model-specific licenses (`llama3.1`,
//! `gemma`, the OpenRAIL family) have no SPDX id and become *named* licenses;
//! `other` uses the card's `license_name`/`license_link`. An absent tag is
//! never defaulted — the caller records it as a known-unknown.

use crate::model::LicenseExpression;

/// Outcome of mapping an HF license tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedLicense {
    /// A valid SPDX id/expression.
    Spdx(String),
    /// A known non-SPDX license kept as a named license (emitted as
    /// `{license: {name}}`), with an optional reference URL.
    Named {
        /// Display name.
        name: String,
        /// License text URL, when known.
        url: Option<String>,
    },
}

impl MappedLicense {
    /// Convert into a [`LicenseExpression`] for the canonical model.
    #[must_use]
    pub fn into_expression(self) -> LicenseExpression {
        match self {
            Self::Spdx(id) => LicenseExpression::from_spdx_id(&id),
            Self::Named { name, .. } => LicenseExpression::new(name),
        }
    }

    /// The license URL, when the mapping carries one.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Spdx(_) => None,
            Self::Named { url, .. } => url.as_deref(),
        }
    }
}

/// Direct HF-tag → SPDX-id table for tags whose SPDX equivalent is exact.
/// GNU family tags map to `-only` — HF's bare `gpl-3.0` tag does not express
/// or-later, and `-only` is the conservative reading.
const SPDX_TABLE: &[(&str, &str)] = &[
    ("apache-2.0", "Apache-2.0"),
    ("mit", "MIT"),
    ("bsd", "BSD-3-Clause"),
    ("bsd-2-clause", "BSD-2-Clause"),
    ("bsd-3-clause", "BSD-3-Clause"),
    ("bsd-3-clause-clear", "BSD-3-Clause-Clear"),
    ("isc", "ISC"),
    ("zlib", "Zlib"),
    ("unlicense", "Unlicense"),
    ("wtfpl", "WTFPL"),
    ("postgresql", "PostgreSQL"),
    ("ncsa", "NCSA"),
    ("osl-3.0", "OSL-3.0"),
    ("afl-3.0", "AFL-3.0"),
    ("artistic-2.0", "Artistic-2.0"),
    ("bsl-1.0", "BSL-1.0"),
    ("cc0-1.0", "CC0-1.0"),
    ("cc-by-2.0", "CC-BY-2.0"),
    ("cc-by-2.5", "CC-BY-2.5"),
    ("cc-by-3.0", "CC-BY-3.0"),
    ("cc-by-4.0", "CC-BY-4.0"),
    ("cc-by-sa-3.0", "CC-BY-SA-3.0"),
    ("cc-by-sa-4.0", "CC-BY-SA-4.0"),
    ("cc-by-nc-2.0", "CC-BY-NC-2.0"),
    ("cc-by-nc-3.0", "CC-BY-NC-3.0"),
    ("cc-by-nc-4.0", "CC-BY-NC-4.0"),
    ("cc-by-nd-4.0", "CC-BY-ND-4.0"),
    ("cc-by-nc-nd-3.0", "CC-BY-NC-ND-3.0"),
    ("cc-by-nc-nd-4.0", "CC-BY-NC-ND-4.0"),
    ("cc-by-nc-sa-2.0", "CC-BY-NC-SA-2.0"),
    ("cc-by-nc-sa-3.0", "CC-BY-NC-SA-3.0"),
    ("cc-by-nc-sa-4.0", "CC-BY-NC-SA-4.0"),
    ("cdla-permissive-1.0", "CDLA-Permissive-1.0"),
    ("cdla-permissive-2.0", "CDLA-Permissive-2.0"),
    ("cdla-sharing-1.0", "CDLA-Sharing-1.0"),
    ("odc-by", "ODC-By-1.0"),
    ("odbl", "ODbL-1.0"),
    ("pddl", "PDDL-1.0"),
    ("gpl-2.0", "GPL-2.0-only"),
    ("gpl-3.0", "GPL-3.0-only"),
    ("agpl-3.0", "AGPL-3.0-only"),
    ("lgpl-2.1", "LGPL-2.1-only"),
    ("lgpl-3.0", "LGPL-3.0-only"),
    ("gfdl", "GFDL-1.3-only"),
    ("mpl-2.0", "MPL-2.0"),
    ("epl-1.0", "EPL-1.0"),
    ("epl-2.0", "EPL-2.0"),
    ("ecl-2.0", "ECL-2.0"),
    ("eupl-1.1", "EUPL-1.1"),
    ("eupl-1.2", "EUPL-1.2"),
    ("etalab-2.0", "etalab-2.0"),
    ("lppl-1.3c", "LPPL-1.3c"),
    ("ms-pl", "MS-PL"),
    ("ofl-1.1", "OFL-1.1"),
    ("c-uda", "C-UDA-1.0"),
];

/// Known model-specific / community licenses without an SPDX id, with their
/// canonical license-text URLs where stable.
const NAMED_TABLE: &[(&str, &str, Option<&str>)] = &[
    (
        "llama2",
        "Llama 2 Community License",
        Some("https://ai.meta.com/llama/license/"),
    ),
    (
        "llama3",
        "Llama 3 Community License",
        Some("https://www.llama.com/llama3/license/"),
    ),
    (
        "llama3.1",
        "Llama 3.1 Community License",
        Some("https://www.llama.com/llama3_1/license/"),
    ),
    (
        "llama3.2",
        "Llama 3.2 Community License",
        Some("https://www.llama.com/llama3_2/license/"),
    ),
    (
        "llama3.3",
        "Llama 3.3 Community License",
        Some("https://www.llama.com/llama3_3/license/"),
    ),
    (
        "llama4",
        "Llama 4 Community License",
        Some("https://www.llama.com/llama4/license/"),
    ),
    (
        "gemma",
        "Gemma Terms of Use",
        Some("https://ai.google.dev/gemma/terms"),
    ),
    ("openrail", "OpenRAIL", None),
    ("openrail++", "OpenRAIL++", None),
    ("creativeml-openrail-m", "CreativeML OpenRAIL-M", None),
    ("bigscience-openrail-m", "BigScience OpenRAIL-M", None),
    ("bigcode-openrail-m", "BigCode OpenRAIL-M", None),
    ("bigscience-bloom-rail-1.0", "BigScience BLOOM RAIL 1.0", None),
    ("deepfloyd-if-license", "DeepFloyd IF License", None),
    (
        "fair-noncommercial-research-license",
        "FAIR Noncommercial Research License",
        None,
    ),
    ("apple-ascl", "Apple Sample Code License", None),
    ("apple-amlr", "Apple Model License for Research", None),
    ("intel-research", "Intel Research Use License", None),
    ("h-research", "H Company Research License", None),
];

/// Map an HF license tag to a license expression.
///
/// `license_name`/`license_link` come from the card and apply when the tag is
/// `other`. Returns `None` for the `unknown` tag (no license information —
/// the caller records a known-unknown, same as an absent tag).
#[must_use]
pub fn map_hf_license(
    tag: &str,
    license_name: Option<&str>,
    license_link: Option<&str>,
) -> Option<MappedLicense> {
    let tag = tag.trim().to_lowercase();
    if tag.is_empty() || tag == "unknown" {
        return None;
    }

    if tag == "other" {
        // A custom license: usable only when the card names it.
        let name = license_name?.trim();
        if name.is_empty() {
            return None;
        }
        return Some(MappedLicense::Named {
            name: name.to_string(),
            url: license_link.map(str::to_string),
        });
    }

    if let Some((_, spdx)) = SPDX_TABLE.iter().find(|(hf, _)| *hf == tag) {
        return Some(MappedLicense::Spdx((*spdx).to_string()));
    }
    if let Some((_, name, url)) = NAMED_TABLE.iter().find(|(hf, _, _)| *hf == tag) {
        return Some(MappedLicense::Named {
            name: (*name).to_string(),
            url: url.map(str::to_string),
        });
    }

    // Unrecognized tag: if it happens to be a valid SPDX expression keep it
    // as such (cards sometimes write real SPDX ids); otherwise keep the tag
    // as a named license so the declaration is preserved verbatim.
    let expr = LicenseExpression::new(tag.clone());
    if expr.is_valid_spdx {
        Some(MappedLicense::Spdx(tag))
    } else {
        Some(MappedLicense::Named {
            name: tag,
            url: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_spdx_tags() {
        assert_eq!(
            map_hf_license("apache-2.0", None, None),
            Some(MappedLicense::Spdx("Apache-2.0".into()))
        );
        assert_eq!(
            map_hf_license("MIT", None, None),
            Some(MappedLicense::Spdx("MIT".into()))
        );
        assert_eq!(
            map_hf_license("gpl-3.0", None, None),
            Some(MappedLicense::Spdx("GPL-3.0-only".into()))
        );
    }

    #[test]
    fn model_specific_licenses_are_named() {
        let mapped = map_hf_license("llama3.1", None, None).unwrap();
        assert!(matches!(
            &mapped,
            MappedLicense::Named { name, .. } if name.contains("Llama 3.1")
        ));
        assert!(mapped.url().is_some());
    }

    #[test]
    fn other_requires_license_name() {
        assert_eq!(map_hf_license("other", None, None), None);
        let mapped =
            map_hf_license("other", Some("Acme Model License"), Some("https://a.test/l")).unwrap();
        assert_eq!(
            mapped,
            MappedLicense::Named {
                name: "Acme Model License".into(),
                url: Some("https://a.test/l".into())
            }
        );
    }

    #[test]
    fn unknown_and_empty_are_none() {
        assert_eq!(map_hf_license("unknown", None, None), None);
        assert_eq!(map_hf_license("  ", None, None), None);
    }

    #[test]
    fn unrecognized_tag_preserved_as_named() {
        let mapped = map_hf_license("my-house-license", None, None).unwrap();
        assert!(matches!(mapped, MappedLicense::Named { name, .. } if name == "my-house-license"));
    }

    #[test]
    fn spdx_expressions_survive_validation() {
        for (_, spdx) in SPDX_TABLE {
            assert!(
                LicenseExpression::from_spdx_id(spdx).is_valid_spdx,
                "{spdx} must be a valid SPDX id"
            );
        }
    }
}
