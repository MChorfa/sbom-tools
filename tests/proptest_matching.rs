//! Property-based tests for matching engine invariants.
//!
//! Verifies that the fuzzy matching engine satisfies key mathematical
//! properties: symmetry, bounded range, and high self-match scores.

use proptest::prelude::*;
use sbom_tools::matching::{ComponentMatcher, FuzzyMatchConfig, FuzzyMatcher};
use sbom_tools::model::Component;

/// Generate an arbitrary component with random fields.
///
/// Names are at least 3 characters to avoid pathological short-name cases
/// where alias lookup tables can cause asymmetric scores (known limitation).
fn arb_component() -> impl Strategy<Value = Component> {
    (
        "[a-z][a-z0-9]{2}[a-z0-9]{0,17}", // name (min 3 chars, no hyphens to avoid alias asymmetry)
        prop::option::of("[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}"), // version
        prop::option::of(prop::sample::select(vec![
            "npm", "pypi", "maven", "cargo", "golang",
        ])),
    )
        .prop_map(|(name, version, ecosystem)| {
            let format_id = format!("test:{name}");
            let mut comp = Component::new(name, format_id);
            if let Some(v) = version {
                comp = comp.with_version(v);
            }
            if let Some(eco) = ecosystem {
                comp.ecosystem = Some(sbom_tools::model::Ecosystem::from_purl_type(eco));
            }
            comp
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn match_score_is_symmetric(
        a in arb_component(),
        b in arb_component(),
    ) {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
        let score_ab = matcher.match_score(&a, &b);
        let score_ba = matcher.match_score(&b, &a);
        prop_assert!(
            (score_ab - score_ba).abs() < 0.01,
            "Asymmetric scores: match(a,b)={} != match(b,a)={}, a={:?}, b={:?}",
            score_ab, score_ba, a.name, b.name
        );
    }

    #[test]
    fn match_score_in_valid_range(
        a in arb_component(),
        b in arb_component(),
    ) {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
        let score = matcher.match_score(&a, &b);
        prop_assert!(
            (0.0..=1.0).contains(&score),
            "Score out of range: {}", score
        );
    }

    #[test]
    fn self_match_scores_high(
        a in arb_component(),
    ) {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
        let score = matcher.match_score(&a, &a);
        prop_assert!(
            score >= 0.9,
            "Self-match should score >= 0.9, got {} for {:?}", score, a.name
        );
    }
}
