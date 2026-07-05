//! Rule engine integration for the diff engine.

use crate::matching::RuleEngine;
use crate::model::{CanonicalId, NormalizedSbom};
use indexmap::IndexMap;
use std::collections::HashMap;

/// Result of applying matching rules.
pub struct RuleApplicationResult {
    pub old_filtered: NormalizedSbom,
    pub new_filtered: NormalizedSbom,
    pub old_canonical: HashMap<CanonicalId, CanonicalId>,
    pub new_canonical: HashMap<CanonicalId, CanonicalId>,
    pub rules_count: usize,
}

/// Apply matching rules and return filtered SBOMs with canonical mappings.
pub fn apply_rules(
    rule_engine: Option<&RuleEngine>,
    old: &NormalizedSbom,
    new: &NormalizedSbom,
) -> Option<RuleApplicationResult> {
    let engine = rule_engine?;

    let old_result = engine.apply(&old.components);
    let new_result = engine.apply(&new.components);

    // Filter out excluded components
    let old_components: IndexMap<_, _> = old
        .components
        .iter()
        .filter(|(id, _)| !old_result.excluded.contains(*id))
        .map(|(id, c)| (id.clone(), c.clone()))
        .collect();
    let new_components: IndexMap<_, _> = new
        .components
        .iter()
        .filter(|(id, _)| !new_result.excluded.contains(*id))
        .map(|(id, c)| (id.clone(), c.clone()))
        .collect();

    // Create filtered SBOMs. Edges referencing an excluded component go
    // with it — leaving them in produced dependency/graph changes for
    // components the user explicitly excluded.
    let mut old_filtered = old.clone();
    old_filtered.components = old_components;
    old_filtered
        .edges
        .retain(|e| !old_result.excluded.contains(&e.from) && !old_result.excluded.contains(&e.to));
    let mut new_filtered = new.clone();
    new_filtered.components = new_components;
    new_filtered
        .edges
        .retain(|e| !new_result.excluded.contains(&e.from) && !new_result.excluded.contains(&e.to));

    // Count applied rules
    let rules_count = old_result.applied_rules.len() + new_result.applied_rules.len();

    Some(RuleApplicationResult {
        old_filtered,
        new_filtered,
        old_canonical: old_result.canonical_map,
        new_canonical: new_result.canonical_map,
        rules_count,
    })
}

// NOTE: there is deliberately no post-match "remap to canonical IDs" step.
// Equivalence canonical IDs exist only as identity BRIDGES during matching
// (see `match_components`' equivalence phase): every ID in the match result
// must remain a REAL component ID, because the change computers look those
// IDs up in the SBOM component maps. The old remap_match_result rewrote
// match keys into versionless canonical-PURL space, so every downstream
// lookup missed — matched components were re-reported as Added and removed
// components vanished from the diff entirely.
