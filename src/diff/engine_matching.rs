//! Component matching logic for the diff engine.
//!
//! This module contains the matching algorithms used to pair components
//! between old and new SBOMs.

use crate::matching::{
    BatchCandidateConfig, BatchCandidateGenerator, ComponentIndex, ComponentMatcher,
    CrossEcosystemDb,
};
use crate::model::{CanonicalId, NormalizedSbom};
use std::collections::{HashMap, HashSet};

use super::engine_config::LargeSbomConfig;

/// Simple result of component matching (`old_id` -> Option<`new_id`>).
pub type MatchResult = HashMap<CanonicalId, Option<CanonicalId>>;

/// Real component ID -> equivalence canonical ID (from matching rules).
pub type CanonicalMap = HashMap<CanonicalId, CanonicalId>;

/// Rich result of component matching with score information.
///
/// This struct provides both the match mappings and the scores for each matched pair,
/// which is needed for reliable `match_info` population.
#[derive(Debug, Clone)]
pub struct ComponentMatchResult {
    /// Map from `old_id` -> Option<`new_id`>
    pub matches: MatchResult,
    /// Score for each matched pair (`old_id`, `new_id`) -> score
    pub pairs: HashMap<(CanonicalId, CanonicalId), f64>,
}

impl ComponentMatchResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            matches: HashMap::new(),
            pairs: HashMap::new(),
        }
    }
}

impl Default for ComponentMatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Matches components between old and new SBOMs.
///
/// Uses 1:1 exclusive matching to ensure each new component is matched to at most
/// one old component. This prevents multiple old components from matching the same
/// new component, which could cause confusing diff results.
///
/// Returns a `ComponentMatchResult` containing both the match mappings and scores
/// for each matched pair.
pub fn match_components(
    old: &NormalizedSbom,
    new: &NormalizedSbom,
    matcher: &dyn ComponentMatcher,
    large_sbom_config: &LargeSbomConfig,
    equivalences: Option<(&CanonicalMap, &CanonicalMap)>,
) -> ComponentMatchResult {
    let _span = tracing::info_span!(
        "diff_engine::match_components",
        old_count = old.component_count(),
        new_count = new.component_count(),
    )
    .entered();

    let mut result = ComponentMatchResult::new();
    let mut used_new_ids: HashSet<CanonicalId> = HashSet::new();

    // Phase 1: Exact matches by canonical ID (fast, highest priority)
    for old_id in old.components.keys() {
        if new.components.contains_key(old_id) {
            let id = old_id.clone();
            result.pairs.insert((id.clone(), id.clone()), 1.0);
            result.matches.insert(id.clone(), Some(id.clone()));
            used_new_ids.insert(id);
        }
    }

    let unmatched_old: Vec<_> = old
        .components
        .keys()
        .filter(|id| !result.matches.contains_key(*id))
        .collect();

    // Phase 1.5: equivalence-rule identity bridges. Two REAL component IDs
    // mapping to the same canonical ID are declared identical by a user
    // rule, so they become score-1.0 candidate edges — resolved 1:1 by the
    // assignment below (several aliases collapsing onto one canonical
    // compete, and the loser is honestly reported removed instead of
    // silently overwriting the winner). Canonical IDs never leak into the
    // match result: the change computers look every ID up in the SBOM maps.
    let mut equivalence_candidates: Vec<(CanonicalId, CanonicalId, f64)> = Vec::new();
    if let Some((old_canonical, new_canonical)) = equivalences {
        let mut new_by_canonical: HashMap<&CanonicalId, Vec<&CanonicalId>> = HashMap::new();
        for (new_id, canonical) in new_canonical {
            if !used_new_ids.contains(new_id) && new.components.contains_key(new_id) {
                new_by_canonical.entry(canonical).or_default().push(new_id);
            }
        }
        for old_id in &unmatched_old {
            if let Some(canonical) = old_canonical.get(*old_id)
                && let Some(new_ids) = new_by_canonical.get(canonical)
            {
                for new_id in new_ids {
                    equivalence_candidates.push(((*old_id).clone(), (*new_id).clone(), 1.0));
                }
            }
        }
        // Deterministic candidate order regardless of HashMap iteration.
        equivalence_candidates.sort_by(|a, b| {
            a.0.value()
                .cmp(b.0.value())
                .then_with(|| a.1.value().cmp(b.1.value()))
        });
    }

    // Determine if we should use enhanced matching for large SBOMs
    let total_components = old.component_count().max(new.component_count());
    let use_batch_generator = total_components >= large_sbom_config.lsh_threshold;

    // Phase 2 & 3: Collect candidates (strategy depends on SBOM size)
    let mut candidates: Vec<(CanonicalId, CanonicalId, f64)> = if use_batch_generator {
        match_with_batch_generator(
            old,
            new,
            &unmatched_old,
            &used_new_ids,
            matcher,
            large_sbom_config,
        )
    } else {
        match_with_component_index(
            old,
            new,
            &unmatched_old,
            &used_new_ids,
            matcher,
            large_sbom_config,
        )
    };
    candidates.extend(equivalence_candidates);

    // Phase 4: Optimal assignment over the sparse candidate edge list
    // (duplicate (old, new) edges collapse to the highest score inside).
    let assignment = sparse_assignment(&candidates);

    // Apply assignment results
    for (old_id, new_id, score) in assignment {
        if used_new_ids.insert(new_id.clone()) {
            result.pairs.insert((old_id.clone(), new_id.clone()), score);
            result.matches.insert(old_id, Some(new_id));
        }
    }

    // Phase 6: Mark remaining unmatched old components as removed (None)
    for old_id in old.components.keys() {
        if !result.matches.contains_key(old_id) {
            result.matches.insert(old_id.clone(), None);
        }
    }

    result
}

/// Use `BatchCandidateGenerator` (LSH + cross-ecosystem) for large SBOMs.
fn match_with_batch_generator(
    old: &NormalizedSbom,
    new: &NormalizedSbom,
    unmatched_old: &[&CanonicalId],
    used_new_ids: &HashSet<CanonicalId>,
    matcher: &dyn ComponentMatcher,
    large_sbom_config: &LargeSbomConfig,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    use rayon::prelude::*;

    // The acceptance gate honors the MATCHER's threshold, so custom
    // ComponentMatcher implementations are no longer silently gated by the
    // fuzzy config they do not use (identical for the default FuzzyMatcher,
    // whose threshold() returns the fuzzy-config value).
    let threshold = matcher.threshold();

    // Build batch candidate generator for the new SBOM
    let batch_config = BatchCandidateConfig {
        max_candidates: large_sbom_config.max_candidates,
        max_length_diff: 10,
        lsh_threshold: large_sbom_config.lsh_threshold,
        enable_cross_ecosystem: large_sbom_config.cross_ecosystem.enabled,
    };
    let generator = BatchCandidateGenerator::build(new, batch_config);

    // Collect source components for batch processing
    let sources: Vec<_> = unmatched_old
        .iter()
        .filter_map(|id| old.components.get(*id).map(|comp| (*id, comp)))
        .collect();

    // Use parallel processing for large batches
    let parallel_threshold = 50;
    if sources.len() > parallel_threshold {
        sources
            .par_iter()
            .flat_map(|(old_id, old_comp)| {
                let batch_result = generator.find_candidates(old_id, old_comp);

                // Combine all candidate sources
                let mut all_candidates = batch_result.index_candidates;
                all_candidates.extend(batch_result.lsh_candidates);
                all_candidates.extend(batch_result.cross_ecosystem_candidates);

                all_candidates
                    .iter()
                    .filter(|new_id| !used_new_ids.contains(*new_id))
                    .filter_map(|new_id| {
                        new.components.get(new_id).and_then(|new_comp| {
                            let score = matcher.match_score(old_comp, new_comp);
                            if score >= threshold {
                                Some(((*old_id).clone(), new_id.clone(), score))
                            } else {
                                None
                            }
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    } else {
        let mut candidates = Vec::new();
        for (old_id, old_comp) in sources {
            let batch_result = generator.find_candidates(old_id, old_comp);

            // Combine all candidate sources
            let mut all_candidates = batch_result.index_candidates;
            all_candidates.extend(batch_result.lsh_candidates);
            all_candidates.extend(batch_result.cross_ecosystem_candidates);

            for new_id in all_candidates {
                if used_new_ids.contains(&new_id) {
                    continue;
                }
                if let Some(new_comp) = new.components.get(&new_id) {
                    let score = matcher.match_score(old_comp, new_comp);
                    if score >= threshold {
                        candidates.push((old_id.clone(), new_id, score));
                    }
                }
            }
        }
        candidates
    }
}

/// Use standard `ComponentIndex` for smaller SBOMs.
///
/// Also includes cross-ecosystem matching when enabled, with score penalty applied.
fn match_with_component_index(
    old: &NormalizedSbom,
    new: &NormalizedSbom,
    unmatched_old: &[&CanonicalId],
    used_new_ids: &HashSet<CanonicalId>,
    matcher: &dyn ComponentMatcher,
    large_sbom_config: &LargeSbomConfig,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    use rayon::prelude::*;

    // See match_with_batch_generator: gate on the matcher's own threshold.
    let threshold = matcher.threshold();

    let new_index = ComponentIndex::build(new);
    let old_index = ComponentIndex::build(old);

    // Build cross-ecosystem DB if enabled
    let cross_eco_db = if large_sbom_config.cross_ecosystem.enabled {
        Some(CrossEcosystemDb::default())
    } else {
        None
    };

    // Build ecosystem index for cross-ecosystem lookups
    let new_by_ecosystem: HashMap<_, Vec<_>> = if cross_eco_db.is_some() {
        let mut map: HashMap<crate::model::Ecosystem, Vec<_>> = HashMap::new();
        for (id, comp) in &new.components {
            if let Some(eco) = &comp.ecosystem {
                map.entry(eco.clone()).or_default().push((id.clone(), comp));
            }
        }
        map
    } else {
        HashMap::new()
    };

    // Honor the configured per-source candidate budget on this side of the
    // lsh_threshold gate too, so match quality doesn't jump when an SBOM
    // crosses the size boundary (this was previously hardcoded to 50 while
    // the batch path used the config value).
    let max_candidates = large_sbom_config.max_candidates;
    let max_length_diff = 10;
    let parallel_threshold = 50;
    let cross_eco_config = &large_sbom_config.cross_ecosystem;

    if unmatched_old.len() > parallel_threshold {
        unmatched_old
            .par_iter()
            .flat_map(|old_id| {
                let old_entry = old_index.get_entry(old_id);
                let old_comp = old.components.get(*old_id);

                match (old_entry, old_comp) {
                    (Some(entry), Some(old_comp)) => {
                        // Same-ecosystem candidates (primary)
                        let candidate_ids = new_index.find_candidates(
                            old_id,
                            entry,
                            max_candidates,
                            max_length_diff,
                        );

                        let mut results: Vec<_> = candidate_ids
                            .iter()
                            .filter(|new_id| !used_new_ids.contains(*new_id))
                            .filter_map(|new_id| {
                                new.components.get(new_id).and_then(|new_comp| {
                                    let score = matcher.match_score(old_comp, new_comp);
                                    if score >= threshold {
                                        Some(((*old_id).clone(), new_id.clone(), score))
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect();

                        // Cross-ecosystem candidates (policy applied by the matcher)
                        if let (Some(db), Some(old_eco)) = (&cross_eco_db, &old_comp.ecosystem) {
                            let cross_matches = find_cross_ecosystem_candidates(
                                old_id,
                                old_comp,
                                old_eco,
                                db,
                                &new_by_ecosystem,
                                used_new_ids,
                                matcher,
                                cross_eco_config,
                                threshold,
                            );
                            results.extend(cross_matches);
                        }

                        results
                    }
                    _ => Vec::new(),
                }
            })
            .collect()
    } else {
        let mut candidates = Vec::new();
        for old_id in unmatched_old {
            if let (Some(old_entry), Some(old_comp)) =
                (old_index.get_entry(old_id), old.components.get(*old_id))
            {
                // Same-ecosystem candidates (primary)
                let candidate_ids =
                    new_index.find_candidates(old_id, old_entry, max_candidates, max_length_diff);

                for new_id in candidate_ids {
                    if used_new_ids.contains(&new_id) {
                        continue;
                    }
                    if let Some(new_comp) = new.components.get(&new_id) {
                        let score = matcher.match_score(old_comp, new_comp);
                        if score >= threshold {
                            candidates.push(((*old_id).clone(), new_id, score));
                        }
                    }
                }

                // Cross-ecosystem candidates (policy applied by the matcher)
                if let (Some(db), Some(old_eco)) = (&cross_eco_db, &old_comp.ecosystem) {
                    let cross_matches = find_cross_ecosystem_candidates(
                        old_id,
                        old_comp,
                        old_eco,
                        db,
                        &new_by_ecosystem,
                        used_new_ids,
                        matcher,
                        cross_eco_config,
                        threshold,
                    );
                    candidates.extend(cross_matches);
                }
            }
        }
        candidates
    }
}

/// Find cross-ecosystem candidates for a component.
///
/// Pure candidate GENERATION: looks up the component in the cross-ecosystem
/// DB and finds equivalent packages in other ecosystems within the new SBOM.
/// The match policy — penalty, min-score floor, verified-only, DB gating —
/// lives inside the matcher's `match_score` (see `FuzzyMatcher::score_pair`),
/// so candidates from this path score identically to the same pairs surfaced
/// by any other strategy. Candidates are gated at the same fuzzy threshold as
/// every other candidate source.
#[allow(clippy::too_many_arguments)]
fn find_cross_ecosystem_candidates(
    old_id: &CanonicalId,
    old_comp: &crate::model::Component,
    old_eco: &crate::model::Ecosystem,
    db: &CrossEcosystemDb,
    new_by_ecosystem: &HashMap<
        crate::model::Ecosystem,
        Vec<(CanonicalId, &crate::model::Component)>,
    >,
    used_new_ids: &HashSet<CanonicalId>,
    matcher: &dyn ComponentMatcher,
    config: &crate::matching::CrossEcosystemConfig,
    threshold: f64,
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    let mut results = Vec::new();

    // Find equivalent packages in other ecosystems
    let equivalents = db.find_equivalents(old_eco, &old_comp.name);

    for equiv in equivalents {
        // Cheap pre-filter; the matcher enforces this too
        if config.verified_only && !equiv.verified {
            continue;
        }

        // Look for components in the target ecosystem
        if let Some(target_comps) = new_by_ecosystem.get(&equiv.target_ecosystem) {
            let mut count = 0;
            for (new_id, new_comp) in target_comps {
                if count >= config.max_candidates {
                    break;
                }
                if used_new_ids.contains(new_id) {
                    continue;
                }

                // Check if names match the cross-ecosystem mapping
                if new_comp.name.eq_ignore_ascii_case(&equiv.target_name) {
                    let score = matcher.match_score(old_comp, new_comp);
                    if score >= threshold {
                        results.push((old_id.clone(), new_id.clone(), score));
                        count += 1;
                    }
                }
            }
        }
    }

    results
}

/// Cost matrix scaling factor: float scores in `[0, 1]` are mapped to integer
/// costs so the solver can use exact comparisons (no float epsilon issues).
const ASSIGNMENT_COST_SCALE: i64 = 1_000_000;

/// Sparse assignment over the candidate edge list via successive shortest
/// augmenting paths (Dijkstra with reduced costs / dual potentials).
///
/// Solves maximum-weight bipartite matching without materializing a dense n×n
/// matrix: the graph is stored as per-source adjacency lists of the actual
/// candidate edges, so both memory and time scale with the number of candidate
/// edges (bounded by the configured per-source candidate budget), not with
/// the product of the two SBOM sizes.
///
/// Each real edge has non-negative integer cost `SCALE − score·SCALE` (lower =
/// better match), and every source additionally gets a dummy "leave unmatched"
/// object of cost `SCALE` (= score 0). The result is therefore a min-cost
/// **perfect** matching over non-negative costs — a setting where Dijkstra with
/// potentials is exact — and a source prefers a real object precisely when its
/// score is positive, recovering max-weight behavior. Re-routing existing
/// matches along augmenting paths is what makes this globally optimal rather
/// than greedy.
///
/// Determinism: old/new IDs are indexed in sorted value order (preserving
/// #218's ordering invariant), adjacency lists are object-index sorted, and
/// path-search ties break by smaller object index, so repeated runs over
/// identical input produce identical output.
fn sparse_assignment(
    candidates: &[(CanonicalId, CanonicalId, f64)],
) -> Vec<(CanonicalId, CanonicalId, f64)> {
    // Stable, sorted index spaces for old and new IDs so tie-breaking is
    // reproducible across runs (keeps #218's determinism guarantee).
    let old_ids = sorted_unique_ids(candidates.iter().map(|(o, _, _)| o));
    let new_ids = sorted_unique_ids(candidates.iter().map(|(_, n, _)| n));

    let old_idx: HashMap<&CanonicalId, usize> =
        old_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();
    let new_idx: HashMap<&CanonicalId, usize> =
        new_ids.iter().enumerate().map(|(i, id)| (id, i)).collect();

    let num_old = old_ids.len();
    let num_real = new_ids.len();
    // One dummy object per source (indices num_real..num_real+num_old) lets a
    // source stay unmatched at cost SCALE without breaking the perfect-matching
    // formulation. Dummy `num_real + i` is reachable only from source `i`.
    let num_obj = num_real + num_old;

    // Per-source adjacency: (object index, non-negative integer cost). Duplicate
    // (old, new) edges collapse to the lowest cost (= highest score). Edges are
    // object-index sorted so the search is deterministic regardless of HashMap
    // iteration order.
    let mut adjacency: Vec<Vec<(usize, i64)>> = vec![Vec::new(); num_old];
    {
        let mut edge_best: HashMap<(usize, usize), i64> = HashMap::new();
        for (old_id, new_id, score) in candidates {
            if let (Some(&oi), Some(&ni)) = (old_idx.get(old_id), new_idx.get(new_id)) {
                let clamped = score.clamp(0.0, 1.0);
                let cost = ASSIGNMENT_COST_SCALE - (clamped * ASSIGNMENT_COST_SCALE as f64) as i64;
                let entry = edge_best.entry((oi, ni)).or_insert(i64::MAX);
                if cost < *entry {
                    *entry = cost;
                }
            }
        }
        for ((oi, ni), cost) in edge_best {
            adjacency[oi].push((ni, cost));
        }
        for (src, edges) in adjacency.iter_mut().enumerate() {
            // Dummy object for this source: cost SCALE == score 0.
            edges.push((num_real + src, ASSIGNMENT_COST_SCALE));
            edges.sort_by_key(|&(obj, _)| obj);
        }
    }

    // Matching state: object -> source, source -> object.
    let mut object_owner: Vec<Option<usize>> = vec![None; num_obj];
    let mut source_obj: Vec<Option<usize>> = vec![None; num_old];
    // Raw cost of each matched source's matched edge, so extending a path
    // through an owner is O(1) instead of a linear adjacency scan.
    let mut source_matched_cost: Vec<i64> = vec![0; num_old];
    // Dual potentials for reduced-cost Dijkstra (keeps reduced edge costs ≥ 0).
    let mut potential: Vec<i64> = vec![0; num_obj];

    // Per-augmentation scratch reused across iterations. `touched` records which
    // objects had their dist set this round, so reset and the potential update
    // run over only the reachable objects — keeping cost proportional to the
    // candidate edges, not to num_obj.
    let mut dist: Vec<i64> = vec![i64::MAX; num_obj];
    let mut src_for_obj: Vec<Option<usize>> = vec![None; num_obj];
    let mut edge_cost_for_obj: Vec<i64> = vec![0; num_obj];
    let mut visited: Vec<bool> = vec![false; num_obj];
    let mut touched: Vec<usize> = Vec::new();
    let mut heap: std::collections::BinaryHeap<std::cmp::Reverse<(i64, usize)>> =
        std::collections::BinaryHeap::new();

    // Augment one source at a time, in sorted order, via the shortest
    // alternating path to a free object. Every source can always reach its own
    // free dummy, so each augmentation succeeds.
    for start in 0..num_old {
        for &obj in &touched {
            dist[obj] = i64::MAX;
            src_for_obj[obj] = None;
            visited[obj] = false;
        }
        touched.clear();
        heap.clear();

        // Seed: relax the free start source's own edges.
        for &(obj, cost) in &adjacency[start] {
            let reduced = cost - potential[obj];
            if reduced < dist[obj] {
                if dist[obj] == i64::MAX {
                    touched.push(obj);
                }
                dist[obj] = reduced;
                src_for_obj[obj] = Some(start);
                edge_cost_for_obj[obj] = cost;
                heap.push(std::cmp::Reverse((reduced, obj)));
            }
        }

        let mut found_obj: Option<usize> = None;

        // Dijkstra with lazy deletion: pop the closest unsettled object; stale
        // entries (superseded by a later, cheaper relaxation) are skipped.
        // Ties break by smaller object index via the (dist, obj) ordering,
        // which keeps the search deterministic.
        while let Some(std::cmp::Reverse((d, obj))) = heap.pop() {
            if visited[obj] || d > dist[obj] {
                continue;
            }
            visited[obj] = true;

            match object_owner[obj] {
                None => {
                    // Free object reached: this is the shortest augmenting path.
                    found_obj = Some(obj);
                    break;
                }
                Some(owner) => {
                    // Object is taken. Extend the path through its owner: the
                    // owner gives up `obj` (subtract that edge's reduced cost)
                    // and bids on each of its other objects.
                    let owner_obj_reduced = source_matched_cost[owner] - potential[obj];
                    for &(obj2, cost) in &adjacency[owner] {
                        if visited[obj2] {
                            continue;
                        }
                        let reduced = cost - potential[obj2];
                        let nd = dist[obj] - owner_obj_reduced + reduced;
                        if nd < dist[obj2] {
                            if dist[obj2] == i64::MAX {
                                touched.push(obj2);
                            }
                            dist[obj2] = nd;
                            src_for_obj[obj2] = Some(owner);
                            edge_cost_for_obj[obj2] = cost;
                            heap.push(std::cmp::Reverse((nd, obj2)));
                        }
                    }
                }
            }
        }

        // Dual update: shift each settled object's potential by how much
        // closer it was than the augmenting path's endpoint, so all reduced
        // costs stay ≥ 0 for the next round. The −path_len term is essential:
        // adding dist[obj] alone inflates potentials, hands negative reduced
        // costs to sources matched outside the settled set, and lets a later
        // search settle objects in the wrong order — producing suboptimal
        // matchings (see `potential_update_regression`).
        if let Some(found) = found_obj {
            let path_len = dist[found];
            for &obj in &touched {
                if visited[obj] {
                    potential[obj] += dist[obj] - path_len;
                }
            }
        }

        // Augment: walk the alternating path back to `start`, flipping matches.
        if let Some(mut obj) = found_obj {
            loop {
                let src = src_for_obj[obj].expect("path object has a source");
                let prev_obj = source_obj[src];
                object_owner[obj] = Some(src);
                source_obj[src] = Some(obj);
                source_matched_cost[src] = edge_cost_for_obj[obj];
                match prev_obj {
                    Some(p) => obj = p,
                    None => break,
                }
            }
        }
    }

    // Cost lookup for materializing the final scores (real edges only).
    let edge_cost: HashMap<(usize, usize), i64> = adjacency
        .iter()
        .enumerate()
        .flat_map(|(src, edges)| {
            edges
                .iter()
                .filter(move |(obj, _)| *obj < num_real)
                .map(move |&(obj, cost)| ((src, obj), cost))
        })
        .collect();

    let mut result = Vec::new();
    for (src, obj) in source_obj.iter().enumerate() {
        if let Some(obj) = obj
            && *obj < num_real
            && let Some(&cost) = edge_cost.get(&(src, *obj))
        {
            let score = (ASSIGNMENT_COST_SCALE - cost) as f64 / ASSIGNMENT_COST_SCALE as f64;
            if score > 0.0 {
                result.push((old_ids[src].clone(), new_ids[*obj].clone(), score));
            }
        }
    }
    result
}

/// Collect a sorted, de-duplicated list of IDs in value order.
fn sorted_unique_ids<'a, I>(ids: I) -> Vec<CanonicalId>
where
    I: Iterator<Item = &'a CanonicalId>,
{
    let set: HashSet<&CanonicalId> = ids.collect();
    let mut ids: Vec<CanonicalId> = set.into_iter().cloned().collect();
    ids.sort_by(|a, b| a.value().cmp(b.value()));
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(s: &str) -> CanonicalId {
        CanonicalId::from_format_id(s)
    }

    /// Total score of an assignment, for comparing solver output against the
    /// known optimum.
    fn total_score(assignment: &[(CanonicalId, CanonicalId, f64)]) -> f64 {
        assignment.iter().map(|(_, _, s)| s).sum()
    }

    #[test]
    fn empty_candidates_yield_empty_assignment() {
        assert!(sparse_assignment(&[]).is_empty());
    }

    #[test]
    fn sparse_assignment_is_one_to_one() {
        // Two sources both prefer the same object; solver must split them.
        let candidates = vec![
            (cid("o1"), cid("n1"), 0.9),
            (cid("o1"), cid("n2"), 0.6),
            (cid("o2"), cid("n1"), 0.8),
            (cid("o2"), cid("n2"), 0.5),
        ];
        let result = sparse_assignment(&candidates);

        let old_used: HashSet<_> = result.iter().map(|(o, _, _)| o.clone()).collect();
        let new_used: HashSet<_> = result.iter().map(|(_, n, _)| n.clone()).collect();
        assert_eq!(
            old_used.len(),
            result.len(),
            "each old id used at most once"
        );
        assert_eq!(
            new_used.len(),
            result.len(),
            "each new id used at most once"
        );
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn sparse_assignment_finds_global_optimum_over_greedy_trap() {
        // Greedy by score would take (o1,n1)=0.95 first, forcing o2->n2=0.10
        // (total 1.05). The optimal assignment is o1->n2=0.80, o2->n1=0.90
        // (total 1.70). The solver must find the optimum, not the greedy pick.
        let candidates = vec![
            (cid("o1"), cid("n1"), 0.95),
            (cid("o1"), cid("n2"), 0.80),
            (cid("o2"), cid("n1"), 0.90),
            (cid("o2"), cid("n2"), 0.10),
        ];
        let result = sparse_assignment(&candidates);

        assert!(
            (total_score(&result) - 1.70).abs() < 1e-9,
            "expected optimal total 1.70, got {} from {:?}",
            total_score(&result),
            result
        );
    }

    #[test]
    fn sparse_assignment_handles_more_sources_than_objects() {
        // Three sources, two objects: one source must remain unassigned.
        let candidates = vec![
            (cid("o1"), cid("n1"), 0.9),
            (cid("o2"), cid("n1"), 0.7),
            (cid("o2"), cid("n2"), 0.6),
            (cid("o3"), cid("n2"), 0.8),
        ];
        let result = sparse_assignment(&candidates);

        // At most two matches (two objects), all distinct objects.
        assert!(result.len() <= 2);
        let new_used: HashSet<_> = result.iter().map(|(_, n, _)| n.clone()).collect();
        assert_eq!(new_used.len(), result.len());
        // Optimum is o1->n1 (0.9) + o3->n2 (0.8) = 1.7.
        assert!(
            (total_score(&result) - 1.70).abs() < 1e-9,
            "expected optimal total 1.70, got {}",
            total_score(&result)
        );
    }

    /// Deterministic xorshift PRNG so the sweep below needs no external deps
    /// and reproduces identically on every run.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Exhaustive maximum-total-score matching over integer micro-scores — the
    /// reference optimum the solver must reach on small instances.
    fn brute_force_optimum(num_old: usize, edges: &[(usize, usize, i64)]) -> i64 {
        fn rec(src: usize, num_old: usize, adj: &[Vec<(usize, i64)>], used: &mut u64) -> i64 {
            if src == num_old {
                return 0;
            }
            let mut best = rec(src + 1, num_old, adj, used);
            for &(obj, s) in &adj[src] {
                if *used & (1 << obj) == 0 {
                    *used |= 1 << obj;
                    best = best.max(s + rec(src + 1, num_old, adj, used));
                    *used &= !(1 << obj);
                }
            }
            best
        }
        let mut adj = vec![Vec::new(); num_old];
        for &(o, n, s) in edges {
            adj[o].push((n, s));
        }
        rec(0, num_old, &adj, &mut 0)
    }

    /// Regression: the pre-fix potential update (`potential[obj] += dist[obj]`
    /// without subtracting the augmenting-path length) broke the reduced-cost
    /// invariant on this instance and returned total 1.660456 instead of the
    /// optimum 1.717704 (o0→n2 + o1→n0 + o3→n1, o2 unmatched).
    #[test]
    fn potential_update_regression() {
        let candidates = vec![
            (cid("o0"), cid("n1"), 0.723_401),
            (cid("o0"), cid("n2"), 0.922_365),
            (cid("o1"), cid("n0"), 0.482_754),
            (cid("o1"), cid("n2"), 0.937_055),
            (cid("o2"), cid("n2"), 0.427_613),
            (cid("o3"), cid("n1"), 0.312_585),
            (cid("o3"), cid("n2"), 0.006_082),
        ];
        let result = sparse_assignment(&candidates);

        assert!(
            (total_score(&result) - 1.717_704).abs() < 1e-6,
            "expected optimal total 1.717704, got {} from {:?}",
            total_score(&result),
            result
        );
    }

    /// The solver must match the brute-force optimum on every random small
    /// instance. Scores are quantized through the solver's own i64 scaling so
    /// the totals compare exactly, with no float tolerance.
    #[test]
    fn sparse_assignment_matches_brute_force_on_random_instances() {
        for num_old in 2..=6usize {
            for num_new in 2..=6usize {
                for rep in 0..40u64 {
                    let seed = 0x9E37_79B9 ^ ((num_old as u64) << 32) ^ ((num_new as u64) << 16) ^ rep;
                    let mut rng = XorShift(seed.max(1));

                    let mut candidates = Vec::new();
                    let mut edges = Vec::new();
                    for o in 0..num_old {
                        for n in 0..num_new {
                            if rng.below(10) < 6 {
                                let micro = 1_000 + rng.below(999_001) as i64;
                                let score = micro as f64 / ASSIGNMENT_COST_SCALE as f64;
                                // Quantize exactly the way the solver does, so
                                // brute force optimizes the identical objective.
                                let qmicro =
                                    (score * ASSIGNMENT_COST_SCALE as f64) as i64;
                                candidates.push((
                                    cid(&format!("o{o:02}")),
                                    cid(&format!("n{n:02}")),
                                    score,
                                ));
                                edges.push((o, n, qmicro));
                            }
                        }
                    }

                    let result = sparse_assignment(&candidates);
                    let solver_micro = (total_score(&result)
                        * ASSIGNMENT_COST_SCALE as f64)
                        .round() as i64;
                    let optimum = brute_force_optimum(num_old, &edges);

                    assert_eq!(
                        solver_micro, optimum,
                        "suboptimal assignment for seed {seed} \
                         (num_old={num_old}, num_new={num_new}): \
                         solver total {solver_micro} vs optimum {optimum}; \
                         edges: {edges:?}"
                    );
                }
            }
        }
    }

    /// Regression for the score-tier inversion at assignment level: with
    /// convention names sharing long prefixes/suffixes, near-miss neighbors
    /// used to outscore exact-name twins (0.95 fuzzy vs 0.90 ecosystem-rule),
    /// and the optimal assignment paired 6/6 components with the WRONG
    /// neighbor. Exact-name pairs now score 1.0 and non-identical names cap
    /// at 0.99, so identity must win.
    #[test]
    fn convention_named_components_match_their_exact_twins() {
        use crate::matching::FuzzyMatcher;
        use crate::model::{Component, DocumentMetadata, Ecosystem, NormalizedSbom};

        let build = |version: &str| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            for i in 1..=6 {
                let name = format!("comp{i:06}lib");
                let mut comp = Component::new(name.clone(), format!("pkg:npm/{name}@{version}"));
                comp.version = Some(version.to_string());
                comp.ecosystem = Some(Ecosystem::Npm);
                sbom.add_component(comp);
            }
            sbom
        };
        let old = build("1.0.0");
        let new = build("2.0.0");

        let matcher = FuzzyMatcher::new(crate::matching::FuzzyMatchConfig::default());
        let result = match_components(
            &old,
            &new,
            &matcher,
            &LargeSbomConfig::default(),
            None,
        );

        assert_eq!(result.matches.len(), 6);
        for (old_id, new_id) in &result.matches {
            let new_id = new_id
                .as_ref()
                .unwrap_or_else(|| panic!("{old_id:?} unmatched"));
            assert_eq!(
                old.components.get(old_id).map(|c| &c.name),
                new.components.get(new_id).map(|c| &c.name),
                "component must match its exact-name twin, not a neighbor"
            );
        }
    }

    /// Same-name packages from different ecosystems must degrade to
    /// added+removed, not merge: end-to-end guard for the npm/redis vs
    /// pypi/redis substitution scenario.
    #[test]
    fn cross_ecosystem_substitution_does_not_merge() {
        use crate::matching::FuzzyMatcher;
        use crate::model::{Component, DocumentMetadata, Ecosystem, NormalizedSbom};

        let build = |eco: Ecosystem, purl_type: &str, version: &str| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let mut comp = Component::new(
                "redis".to_string(),
                format!("pkg:{purl_type}/redis@{version}"),
            );
            comp.version = Some(version.to_string());
            comp.ecosystem = Some(eco);
            sbom.add_component(comp);
            sbom
        };
        let old = build(Ecosystem::Npm, "npm", "4.6.0");
        let new = build(Ecosystem::PyPi, "pypi", "5.0.0");

        let matcher = FuzzyMatcher::new(crate::matching::FuzzyMatchConfig::default());
        let result = match_components(
            &old,
            &new,
            &matcher,
            &LargeSbomConfig::default(),
            None,
        );

        let old_id = old.components.keys().next().unwrap();
        assert_eq!(
            result.matches.get(old_id),
            Some(&None),
            "npm/redis must be reported removed, not matched to pypi/redis"
        );
        assert!(result.pairs.is_empty());
    }

    /// Build an SBOM of 560 fuzzy-matchable components (distinct syllable
    /// names, versioned canonical IDs so nothing exact-matches across sides).
    fn parity_sbom(version: &str) -> crate::model::NormalizedSbom {
        use crate::model::{Component, DocumentMetadata, Ecosystem, NormalizedSbom};

        const A: [&str; 14] = [
            "alor", "brev", "cind", "dulm", "evar", "fost", "grin", "hulp", "ivex", "jorm",
            "kral", "lund", "merv", "nixo",
        ];
        const B: [&str; 8] = ["bem", "tuk", "waz", "pol", "gus", "ryn", "sev", "dob"];
        const C: [&str; 5] = ["mint", "zorf", "kelp", "wund", "trax"];

        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for a in A {
            for b in B {
                for c in C {
                    let name = format!("{a}{b}{c}");
                    let mut comp =
                        Component::new(name.clone(), format!("pkg:npm/{name}@{version}"));
                    comp.version = Some(version.to_string());
                    comp.identifiers.purl = Some(format!("pkg:npm/{name}@{version}"));
                    comp.ecosystem = Some(Ecosystem::Npm);
                    sbom.add_component(comp);
                }
            }
        }
        sbom
    }

    /// Crossing the lsh_threshold size gate must not change match results:
    /// with a shared candidate budget the batch (LSH) path and the plain
    /// index path see the same ranked candidates, so a 560-component SBOM
    /// pair must match identically through both.
    #[test]
    fn batch_and_index_paths_produce_identical_matches() {
        use crate::matching::FuzzyMatcher;

        let old = parity_sbom("1.0.0");
        let new = parity_sbom("2.0.0");
        let matcher = FuzzyMatcher::new(crate::matching::FuzzyMatchConfig::default());

        // 560 components >= 500 threshold: batch/LSH path.
        let batch_cfg = LargeSbomConfig::default();
        assert!(old.component_count() >= batch_cfg.lsh_threshold);
        let via_batch = match_components(&old, &new, &matcher, &batch_cfg, None);

        // Same inputs with the gate pushed out of reach: plain index path.
        let index_cfg = LargeSbomConfig {
            lsh_threshold: 100_000,
            ..LargeSbomConfig::default()
        };
        let via_index = match_components(&old, &new, &matcher, &index_cfg, None);

        assert_eq!(
            via_batch.matches, via_index.matches,
            "match results must not depend on which side of the size gate ran"
        );

        // And the matching itself must be complete and correct: every old
        // component pairs with its same-named counterpart.
        assert_eq!(via_batch.matches.len(), old.component_count());
        for (old_id, new_id) in &via_batch.matches {
            let new_id = new_id
                .as_ref()
                .unwrap_or_else(|| panic!("{old_id:?} unmatched"));
            assert_eq!(
                old.components.get(old_id).map(|c| &c.name),
                new.components.get(new_id).map(|c| &c.name),
                "component matched to a different name"
            );
        }
    }

    #[test]
    fn sparse_assignment_is_deterministic() {
        // Symmetric scores create ties; output must be stable across runs and
        // independent of input edge order.
        let candidates = vec![
            (cid("a"), cid("x"), 0.5),
            (cid("a"), cid("y"), 0.5),
            (cid("b"), cid("x"), 0.5),
            (cid("b"), cid("y"), 0.5),
        ];
        let mut shuffled = candidates.clone();
        shuffled.reverse();

        let r1 = sparse_assignment(&candidates);
        let r2 = sparse_assignment(&candidates);
        let r3 = sparse_assignment(&shuffled);

        assert_eq!(r1, r2, "repeated runs must match");
        assert_eq!(r1, r3, "result must not depend on edge insertion order");
    }
}
