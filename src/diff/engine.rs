//! Semantic diff engine implementation.

use super::changes::{
    ComponentChangeComputer, DependencyChangeComputer, LicenseChangeComputer,
    VulnerabilityChangeComputer, compute_metadata_changes,
};
pub use super::engine_config::LargeSbomConfig;
use super::engine_matching::{ComponentMatchResult, match_components};
use super::engine_rules::apply_rules;
use super::incremental::ChangedSections;
use super::result::MatchMetrics;
use super::traits::ChangeComputer;
use super::{CostModel, DiffResult, GraphDiffConfig, MatchInfo, diff_dependency_graph};
use crate::error::SbomDiffError;
use crate::matching::{
    ComponentMatcher, FuzzyMatchConfig, FuzzyMatcher, RuleEngine,
};
use crate::model::NormalizedSbom;
use std::borrow::Cow;

/// Semantic diff engine for comparing SBOMs.
#[must_use]
pub struct DiffEngine {
    cost_model: CostModel,
    fuzzy_config: FuzzyMatchConfig,
    include_unchanged: bool,
    graph_diff_config: Option<GraphDiffConfig>,
    rule_engine: Option<RuleEngine>,
    custom_matcher: Option<Box<dyn ComponentMatcher>>,
    large_sbom_config: LargeSbomConfig,
}

impl DiffEngine {
    /// Create a new diff engine with default settings
    pub fn new() -> Self {
        Self {
            cost_model: CostModel::default(),
            fuzzy_config: FuzzyMatchConfig::balanced(),
            include_unchanged: false,
            graph_diff_config: None,
            rule_engine: None,
            custom_matcher: None,
            large_sbom_config: LargeSbomConfig::default(),
        }
    }

    /// Create a diff engine with a custom cost model
    pub const fn with_cost_model(mut self, cost_model: CostModel) -> Self {
        self.cost_model = cost_model;
        self
    }

    /// Set fuzzy matching configuration
    pub const fn with_fuzzy_config(mut self, config: FuzzyMatchConfig) -> Self {
        self.fuzzy_config = config;
        self
    }

    /// Include unchanged components in the result
    pub const fn include_unchanged(mut self, include: bool) -> Self {
        self.include_unchanged = include;
        self
    }

    /// Enable graph-aware diffing with the given configuration
    pub fn with_graph_diff(mut self, config: GraphDiffConfig) -> Self {
        self.graph_diff_config = Some(config);
        self
    }

    /// Set custom matching rules engine directly
    pub fn with_rule_engine(mut self, engine: RuleEngine) -> Self {
        self.rule_engine = Some(engine);
        self
    }

    /// Set a custom component matcher.
    pub fn with_matcher(mut self, matcher: Box<dyn ComponentMatcher>) -> Self {
        self.custom_matcher = Some(matcher);
        self
    }

    /// Configure large SBOM optimization settings.
    pub const fn with_large_sbom_config(mut self, config: LargeSbomConfig) -> Self {
        self.large_sbom_config = config;
        self
    }

    /// Get the large SBOM configuration.
    #[must_use]
    pub const fn large_sbom_config(&self) -> &LargeSbomConfig {
        &self.large_sbom_config
    }

    /// Check if a custom matcher is configured
    #[must_use]
    pub fn has_custom_matcher(&self) -> bool {
        self.custom_matcher.is_some()
    }

    /// Check if graph diffing is enabled
    #[must_use]
    pub const fn graph_diff_enabled(&self) -> bool {
        self.graph_diff_config.is_some()
    }

    /// Check if custom matching rules are configured
    #[must_use]
    pub const fn has_matching_rules(&self) -> bool {
        self.rule_engine.is_some()
    }

    /// Compare two SBOMs and return the diff result
    #[must_use = "diff result contains all changes and should not be discarded"]
    pub fn diff(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
    ) -> Result<DiffResult, SbomDiffError> {
        let _span = tracing::info_span!(
            "diff_engine::diff",
            old_components = old.component_count(),
            new_components = new.component_count(),
        )
        .entered();

        let mut result = DiffResult::new();

        // Quick check: if content hashes match, SBOMs are identical. With
        // --include-unchanged the caller asked for full inventory output, so
        // the shortcut would contradict the flag (identical SBOMs would be
        // the one case with NO inventory) — fall through instead.
        if old.content_hash == new.content_hash
            && old.content_hash != 0
            && !self.include_unchanged
        {
            result.semantic_score = PERCENT_MAX;
            return Ok(result);
        }

        // Apply custom matching rules if configured
        // Use Cow to avoid cloning SBOMs when no rules are applied
        let (old_filtered, new_filtered, canonical_maps) =
            if let Some(rule_result) = apply_rules(self.rule_engine.as_ref(), old, new) {
                result.rules_applied = rule_result.rules_count;
                (
                    Cow::Owned(rule_result.old_filtered),
                    Cow::Owned(rule_result.new_filtered),
                    Some((rule_result.old_canonical, rule_result.new_canonical)),
                )
            } else {
                (Cow::Borrowed(old), Cow::Borrowed(new), None)
            };

        // Build component mappings using the configured matcher; the matcher
        // carries the cross-ecosystem policy so every candidate source scores
        // uniformly.
        let default_matcher = FuzzyMatcher::new(self.fuzzy_config.clone())
            .with_cross_ecosystem(self.large_sbom_config.cross_ecosystem.clone());
        let matcher: &dyn ComponentMatcher = self
            .custom_matcher
            .as_ref()
            .map_or(&default_matcher as &dyn ComponentMatcher, |m| m.as_ref());

        // Equivalence canonical maps act as identity bridges INSIDE matching;
        // the result always carries real component IDs.
        let component_matches = match_components(
            &old_filtered,
            &new_filtered,
            matcher,
            &self.large_sbom_config,
            canonical_maps
                .as_ref()
                .map(|(old_map, new_map)| (old_map, new_map)),
        );

        // Compute all sections, then the derived outputs (metrics, graph
        // diff, score, summary) via the same routines the incremental path
        // uses — one implementation, so the two paths cannot drift.
        self.compute_sections(
            &old_filtered,
            &new_filtered,
            &component_matches,
            matcher,
            &ChangedSections::all_changed(),
            &mut result,
        );
        self.finalize_result(
            &old_filtered,
            &new_filtered,
            &component_matches,
            true,
            &mut result,
        );
        Ok(result)
    }

    /// Compute the selected change sections into `result`.
    ///
    /// The SINGLE implementation behind both the full path (`diff`, all
    /// sections) and the incremental path (`diff_sections`, dirty sections
    /// only) — hand-duplicating this orchestration is how the two paths
    /// previously drifted (the incremental path forgot match metrics and the
    /// graph diff).
    fn compute_sections(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        match_result: &ComponentMatchResult,
        matcher: &dyn ComponentMatcher,
        sections: &ChangedSections,
        result: &mut DiffResult,
    ) {
        if sections.components {
            let comp_computer = ComponentChangeComputer::new(self.cost_model.clone())
                .with_include_unchanged(self.include_unchanged);
            let comp_changes = comp_computer.compute(old, new, &match_result.matches);
            result.components.added = comp_changes.added;
            result.components.removed = comp_changes.removed;
            result.components.modified = comp_changes
                .modified
                .into_iter()
                .map(|mut change| {
                    // Add match explanation for modified components. Use
                    // stored canonical IDs directly instead of reconstructing
                    // from name+version. Unchanged inventory entries skip the
                    // enrichment — explaining a self-match is wasted work.
                    if change.change_type != crate::diff::ChangeType::Unchanged
                        && let (Some(old_id), Some(new_id)) =
                            (&change.old_canonical_id, &change.canonical_id)
                        && let (Some(old_comp), Some(new_comp)) =
                            (old.components.get(old_id), new.components.get(new_id))
                    {
                        let explanation = matcher.explain_match(old_comp, new_comp);
                        let mut match_info = MatchInfo::from_explanation(&explanation);

                        // Use the actual score from the matching phase if available
                        if let Some(&score) =
                            match_result.pairs.get(&(old_id.clone(), new_id.clone()))
                        {
                            match_info.score = score;
                        }

                        change = change.with_match_info(match_info);
                    }
                    change
                })
                .collect();
        }

        if sections.dependencies {
            let dep_computer = DependencyChangeComputer::new();
            let dep_changes = dep_computer.compute(old, new, &match_result.matches);
            result.dependencies.added = dep_changes.added;
            result.dependencies.removed = dep_changes.removed;
        }

        if sections.licenses {
            let lic_computer = LicenseChangeComputer::new();
            let lic_changes = lic_computer.compute(old, new, &match_result.matches);
            result.licenses.new_licenses = lic_changes.new_licenses;
            result.licenses.removed_licenses = lic_changes.removed_licenses;
            result.licenses.component_changes = lic_changes.component_changes;
        }

        if sections.vulnerabilities {
            let vuln_computer = VulnerabilityChangeComputer::new();
            let vuln_changes = vuln_computer.compute(old, new, &match_result.matches);
            result.vulnerabilities.introduced = vuln_changes.introduced;
            result.vulnerabilities.resolved = vuln_changes.resolved;
            result.vulnerabilities.persistent = vuln_changes.persistent;
            result.vulnerabilities.vex_changes = vuln_changes.vex_changes;
        }

        // Document-level metadata changes are cheap and not tracked by
        // `ChangedSections` — always recompute rather than risk serving a
        // stale cached vec when only the document header changed.
        result.metadata_changes = compute_metadata_changes(old, new);
    }

    /// Derived outputs recomputed on EVERY path: match metrics (from the
    /// always-recomputed matching), the graph diff when `refresh_graph`,
    /// the semantic score, and the summary.
    ///
    /// Score normalization convention: both paths normalize against the
    /// rule-FILTERED SBOMs (the content that was actually diffed), so a
    /// cache-warm incremental run scores identically to a cold full run.
    fn finalize_result(
        &self,
        old_filtered: &NormalizedSbom,
        new_filtered: &NormalizedSbom,
        match_result: &ComponentMatchResult,
        refresh_graph: bool,
        result: &mut DiffResult,
    ) {
        result.match_metrics =
            Some(self.compute_match_metrics(match_result, old_filtered, new_filtered, result));

        if refresh_graph && let Some(ref graph_config) = self.graph_diff_config {
            let (graph_changes, graph_summary) = diff_dependency_graph(
                old_filtered,
                new_filtered,
                &match_result.matches,
                graph_config,
            );
            result.graph_changes = graph_changes;
            result.graph_summary = Some(graph_summary);
        }

        result.semantic_score =
            self.compute_semantic_score(result, old_filtered, new_filtered);
        result.calculate_summary();
    }

    /// Match metrics for observability.
    fn compute_match_metrics(
        &self,
        match_result: &ComponentMatchResult,
        old_filtered: &NormalizedSbom,
        new_filtered: &NormalizedSbom,
        result: &DiffResult,
    ) -> MatchMetrics {
        // Sorted so float accumulation order (and thus the serialized
        // average) is identical across runs
        let mut scores: Vec<f64> = match_result.pairs.values().copied().collect();
        scores.sort_unstable_by(f64::total_cmp);
        // 0.995 sits strictly between the 0.99 non-identical-name cap and
        // the 1.0 identity tiers, so a capped near-miss never counts as
        // an exact match.
        let exact = scores.iter().filter(|&&s| s >= 0.995).count();
        let fuzzy = scores.len() - exact;
        let matched_count = scores.len();
        let unmatched_old = old_filtered.component_count().saturating_sub(matched_count);
        let unmatched_new = new_filtered.component_count().saturating_sub(matched_count);
        let avg = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        };
        let min = scores.iter().copied().fold(f64::INFINITY, f64::min);

        MatchMetrics {
            exact_matches: exact,
            fuzzy_matches: fuzzy,
            rule_matches: result.rules_applied,
            unmatched_old,
            unmatched_new,
            avg_match_score: avg,
            min_match_score: if min.is_infinite() { 0.0 } else { min },
        }
    }

    /// Diff only the specified sections, reusing cached results for unchanged sections.
    ///
    /// This enables true incremental diffing: when only some SBOM sections changed,
    /// we skip recomputing the unchanged sections and reuse them from the cached result.
    /// Component matching is always recomputed since it's needed by all section computers.
    ///
    /// Falls back to a full diff if no cached result is provided.
    pub(crate) fn diff_sections(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        sections: &ChangedSections,
        cached: &DiffResult,
    ) -> Result<DiffResult, SbomDiffError> {
        // Start with the cached result so unchanged sections are preserved
        let mut result = cached.clone();

        // Apply custom matching rules if configured
        let (old_filtered, new_filtered, canonical_maps) =
            if let Some(rule_result) = apply_rules(self.rule_engine.as_ref(), old, new) {
                result.rules_applied = rule_result.rules_count;
                (
                    Cow::Owned(rule_result.old_filtered),
                    Cow::Owned(rule_result.new_filtered),
                    Some((rule_result.old_canonical, rule_result.new_canonical)),
                )
            } else {
                (Cow::Borrowed(old), Cow::Borrowed(new), None)
            };

        // Always recompute matching — it's needed for any section computer
        let default_matcher = FuzzyMatcher::new(self.fuzzy_config.clone())
            .with_cross_ecosystem(self.large_sbom_config.cross_ecosystem.clone());
        let matcher: &dyn ComponentMatcher = self
            .custom_matcher
            .as_ref()
            .map_or(&default_matcher as &dyn ComponentMatcher, |m| m.as_ref());

        // Equivalence canonical maps act as identity bridges INSIDE matching;
        // the result always carries real component IDs.
        let component_matches = match_components(
            &old_filtered,
            &new_filtered,
            matcher,
            &self.large_sbom_config,
            canonical_maps
                .as_ref()
                .map(|(old_map, new_map)| (old_map, new_map)),
        );

        // Selectively recompute only the changed sections via the shared
        // implementation, then refresh every derived output.
        //
        // Widening rule: every section computer consumes the component
        // MATCHES, and matches are a function of component content — so any
        // component change can flip a match and with it the dependency,
        // license, and vulnerability diffs, even when those sections' own
        // hashes are clean (a rename spliced a stale empty dependency diff).
        // The vulnerability computer additionally reads component depths,
        // derived from the dependency graph, so edge changes rerun it too.
        // The only splice that survives a components-dirty diff is the
        // components section itself never being clean in that case — the
        // savings remain for edge-only changes (components and licenses
        // splice) and for pure metadata changes.
        let mut effective_sections = sections.clone();
        effective_sections.dependencies |= sections.components;
        effective_sections.licenses |= sections.components;
        effective_sections.vulnerabilities |= sections.dependencies || sections.components;
        self.compute_sections(
            &old_filtered,
            &new_filtered,
            &component_matches,
            matcher,
            &effective_sections,
            &mut result,
        );

        // The graph diff reads only components, edges, and matches — all
        // pinned by the components/dependencies section hashes — so the
        // spliced graph output is valid exactly when neither of those
        // sections changed. Match metrics, score, and summary are refreshed
        // unconditionally.
        let refresh_graph = sections.components || sections.dependencies;
        self.finalize_result(
            &old_filtered,
            &new_filtered,
            &component_matches,
            refresh_graph,
            &mut result,
        );
        Ok(result)
    }

    /// Compute the semantic score from a `DiffResult`.
    fn compute_semantic_score(
        &self,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
    ) -> f64 {
        // Unchanged inventory entries (--include-unchanged) live in the
        // modified stream but are not changes; scoring must ignore them or
        // the flag would alter the semantic score.
        let modified_count = result
            .components
            .modified
            .iter()
            .filter(|c| c.change_type != crate::diff::ChangeType::Unchanged)
            .count();
        let raw_cost = self.cost_model.calculate_semantic_score(
            result.components.added.len(),
            result.components.removed.len(),
            modified_count,
            result.licenses.component_changes.len(),
            result.vulnerabilities.introduced.len(),
            result.vulnerabilities.resolved.len(),
            result.dependencies.added.len(),
            result.dependencies.removed.len(),
        );

        self.normalize_semantic_score(raw_cost, result, old_sbom, new_sbom)
    }

    /// Normalize `raw_cost` to a 0–100 similarity percentage against an
    /// SBOM-derived upper-bound budget.
    ///
    /// For each cost axis we compute the worst-case contribution given the
    /// inputs (e.g. every component on both sides being added or removed) and
    /// sum them to form `total_budget`. The score is then
    /// `PERCENT_MAX * (1 - raw_cost / total_budget)`, clamped to `[0, PERCENT_MAX]`
    /// to defend against future cost-model changes where the bound might no
    /// longer dominate. When both SBOMs are empty the budget collapses to ~0
    /// and the function returns `PERCENT_MAX` (an empty diff is fully similar).
    ///
    /// Note: `modification_budget` uses the actual `modified.len()` rather
    /// than `min(old, new)`. The actual count is still a valid upper bound on
    /// `raw_modification_cost` (each modification contributes at most
    /// `max(version_major, license_changed)`), and using it keeps the per-axis
    /// scoring sensitive to the modifications that actually occurred.
    /// `vulnerability_resolved` is intentionally excluded from the budget: it
    /// is a reward (negative cost in `CostModel`), so it can only reduce
    /// `raw_cost`, never push it above the bound.
    fn normalize_semantic_score(
        &self,
        raw_cost: f64,
        result: &DiffResult,
        old_sbom: &NormalizedSbom,
        new_sbom: &NormalizedSbom,
    ) -> f64 {
        let component_budget = (old_sbom.component_count() + new_sbom.component_count()) as f64
            * f64::from(
                self.cost_model
                    .component_added
                    .max(self.cost_model.component_removed),
            );
        let dependency_budget = (old_sbom.edges.len() + new_sbom.edges.len()) as f64
            * f64::from(
                self.cost_model
                    .dependency_added
                    .max(self.cost_model.dependency_removed),
            );
        let vulnerability_budget = (old_sbom.vulnerability_counts().total()
            + new_sbom.vulnerability_counts().total()) as f64
            * f64::from(self.cost_model.vulnerability_introduced);
        // Excludes Unchanged inventory entries, mirroring compute_semantic_score.
        let modification_budget = result
            .components
            .modified
            .iter()
            .filter(|c| c.change_type != crate::diff::ChangeType::Unchanged)
            .count() as f64
            * f64::from(
                self.cost_model
                    .version_major
                    .max(self.cost_model.license_changed),
            );

        let total_budget =
            component_budget + dependency_budget + vulnerability_budget + modification_budget;

        if total_budget <= f64::EPSILON {
            return PERCENT_MAX;
        }

        (PERCENT_MAX * (1.0 - (raw_cost / total_budget))).clamp(0.0, PERCENT_MAX)
    }
}

/// Upper bound of the 0–100 similarity percentage emitted by
/// [`DiffEngine::normalize_semantic_score`].
const PERCENT_MAX: f64 = 100.0;

impl Default for DiffEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_diff() {
        let engine = DiffEngine::new();
        let sbom = NormalizedSbom::default();
        let result = engine.diff(&sbom, &sbom).expect("diff should succeed");
        assert!(!result.has_changes());
    }

    /// `--include-unchanged` was an end-to-end no-op: the flag is now
    /// honored (Unchanged entries appear) without perturbing summary counts
    /// or the semantic score.
    #[test]
    fn include_unchanged_emits_inventory_entries_without_changing_scores() {
        use crate::diff::ChangeType;
        use crate::model::{Component, DocumentMetadata};

        let build = |bump_app: bool| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            let app_version = if bump_app { "2.0.0" } else { "1.0.0" };
            for (name, version) in [
                ("app", app_version),
                ("stable-lib", "3.1.0"),
                ("other-lib", "0.9.0"),
            ] {
                let mut c =
                    Component::new(name.to_string(), format!("pkg:npm/{name}@{version}"));
                c.version = Some(version.to_string());
                c.calculate_content_hash();
                sbom.add_component(c);
            }
            sbom.calculate_content_hash();
            sbom
        };
        let old = build(false);
        let new = build(true);

        let without = DiffEngine::new().diff(&old, &new).expect("diff");
        let with = DiffEngine::new()
            .include_unchanged(true)
            .diff(&old, &new)
            .expect("diff");

        let unchanged: Vec<_> = with
            .components
            .modified
            .iter()
            .filter(|c| c.change_type == ChangeType::Unchanged)
            .collect();
        assert_eq!(
            unchanged.len(),
            2,
            "the two stable components must appear as Unchanged inventory entries"
        );
        assert!(unchanged.iter().all(|c| c.cost == 0));

        // Counts and scoring must be flag-invariant.
        assert_eq!(
            with.summary.components_modified,
            without.summary.components_modified
        );
        assert_eq!(with.summary.total_changes, without.summary.total_changes);
        assert!(
            (with.semantic_score - without.semantic_score).abs() < 1e-9,
            "the flag must not change the semantic score: {} vs {}",
            with.semantic_score,
            without.semantic_score
        );

        // Flag off: no Unchanged entries anywhere (default output unchanged).
        assert!(
            without
                .components
                .modified
                .iter()
                .all(|c| c.change_type != ChangeType::Unchanged)
        );

        // Inventory entries are not changes: has_changes() is flag-invariant.
        assert_eq!(with.has_changes(), without.has_changes());

        // Identical SBOMs with the flag on must still produce full inventory
        // (the identical-hash short-circuit would otherwise make "everything
        // unchanged" the one case with NO inventory).
        let identical = DiffEngine::new()
            .include_unchanged(true)
            .diff(&old, &old)
            .expect("diff");
        assert_eq!(
            identical
                .components
                .modified
                .iter()
                .filter(|c| c.change_type == ChangeType::Unchanged)
                .count(),
            3,
            "identical SBOMs must yield one Unchanged entry per component"
        );
        assert!(!identical.has_changes());
        assert!((identical.semantic_score - 100.0).abs() < 1e-9);
    }

    fn rules_component(name: &str, purl: &str, version: &str, id: &str) -> crate::model::Component {
        let mut c = crate::model::Component::new(name.to_string(), id.to_string());
        c.version = Some(version.to_string());
        c.identifiers.purl = Some(purl.to_string());
        c.calculate_content_hash();
        c
    }

    fn rules_sbom(comps: Vec<crate::model::Component>) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(crate::model::DocumentMetadata::default());
        for c in comps {
            sbom.add_component(c);
        }
        sbom.calculate_content_hash();
        sbom
    }

    fn equivalence_engine() -> DiffEngine {
        use crate::matching::{AliasPattern, EquivalenceGroup, MatchingRulesConfig};
        let rules = MatchingRulesConfig {
            equivalences: vec![EquivalenceGroup {
                name: Some("foo family".to_string()),
                canonical: "pkg:npm/foo".to_string(),
                aliases: vec![
                    AliasPattern::exact("pkg:npm/foo-fork"),
                    AliasPattern::exact("pkg:npm/foo-legacy"),
                ],
                version_sensitive: false,
            }],
            ..Default::default()
        };
        DiffEngine::new().with_rule_engine(RuleEngine::new(rules).expect("valid rules"))
    }

    /// Regression for the equivalence-remap corruption: the old
    /// remap_match_result rewrote match keys into versionless canonical-PURL
    /// space, so identical rule-matched components were re-reported as
    /// Added, removed components vanished, and alias collisions silently
    /// overwrote matches. Equivalences now bridge REAL ids during matching.
    #[test]
    fn equivalence_rules_bridge_matches_without_corrupting_the_diff() {
        // Case A: identical component matching the rule on both sides —
        // previously re-reported as Added.
        let old = rules_sbom(vec![rules_component("foo", "pkg:npm/foo", "1.0.0", "old-foo")]);
        let new = rules_sbom(vec![rules_component("foo", "pkg:npm/foo", "1.0.0", "new-foo")]);
        let result = equivalence_engine().diff(&old, &new).expect("diff");
        // (Document metadata legitimately differs between hand-built SBOMs;
        // the corruption under test was component-level.)
        assert_eq!(
            result.summary.components_added, 0,
            "identical rule-matched components were re-reported as Added: {:?}",
            result.summary
        );
        assert_eq!(result.summary.components_removed, 0);
        assert_eq!(result.summary.components_modified, 0);

        // Case B: alias -> canonical migration bridges into ONE modified
        // entry (real ids), not added+removed.
        let old = rules_sbom(vec![rules_component(
            "foo-fork",
            "pkg:npm/foo-fork",
            "1.0.0",
            "old-fork",
        )]);
        let new = rules_sbom(vec![rules_component("foo", "pkg:npm/foo", "1.0.0", "new-foo")]);
        let result = equivalence_engine().diff(&old, &new).expect("diff");
        assert_eq!(result.components.added.len(), 0, "must not report Added");
        assert_eq!(result.components.removed.len(), 0, "must not report Removed");
        assert_eq!(result.components.modified.len(), 1);
        assert!(
            result.components.modified[0]
                .field_changes
                .iter()
                .any(|f| f.field == "name"),
            "the migration must surface as a name change"
        );
        let bridge_score = result.components.modified[0]
            .match_info
            .as_ref()
            .expect("bridged pair carries match info")
            .score;
        assert!(
            (bridge_score - 1.0).abs() < 1e-9,
            "an equivalence bridge asserts identity: score must be 1.0, got {bridge_score}"
        );

        // Case C: removed rule-matched component must still be reported
        // (previously vanished entirely).
        let old = rules_sbom(vec![rules_component(
            "foo-fork",
            "pkg:npm/foo-fork",
            "1.0.0",
            "old-fork",
        )]);
        let new = rules_sbom(vec![]);
        let result = equivalence_engine().diff(&old, &new).expect("diff");
        assert_eq!(result.components.removed.len(), 1);
        assert_eq!(result.components.removed[0].name, "foo-fork");

        // Case D: two aliases collapsing onto one canonical compete 1:1 —
        // one matches, the loser is honestly reported removed (previously a
        // silent HashMap overwrite).
        let old = rules_sbom(vec![
            rules_component("foo-fork", "pkg:npm/foo-fork", "1.0.0", "old-fork"),
            rules_component("foo-legacy", "pkg:npm/foo-legacy", "1.0.0", "old-legacy"),
        ]);
        let new = rules_sbom(vec![rules_component("foo", "pkg:npm/foo", "1.0.0", "new-foo")]);
        let result = equivalence_engine().diff(&old, &new).expect("diff");
        assert_eq!(result.components.added.len(), 0);
        assert_eq!(result.components.modified.len(), 1);
        assert_eq!(
            result.components.removed.len(),
            1,
            "the losing alias must be reported removed, not silently dropped"
        );
    }

    /// Exclusion rules must take a component's edges with it — leaving them
    /// in produced dependency changes for explicitly excluded components.
    #[test]
    fn exclusion_rules_drop_edges_with_their_components() {
        use crate::matching::{ExclusionRule, MatchingRulesConfig};
        use crate::model::{DependencyEdge, DependencyType};

        let rules = MatchingRulesConfig {
            exclusions: vec![ExclusionRule::exact("pkg:npm/noise")],
            ..Default::default()
        };
        let engine =
            DiffEngine::new().with_rule_engine(RuleEngine::new(rules).expect("valid rules"));

        let build = |with_edge: bool| {
            let app = rules_component("app", "pkg:npm/app", "1.0.0", "app-ref");
            let noise = rules_component("noise", "pkg:npm/noise", "1.0.0", "noise-ref");
            let app_id = app.canonical_id.clone();
            let noise_id = noise.canonical_id.clone();
            let mut sbom = rules_sbom(vec![app, noise]);
            if with_edge {
                sbom.add_edge(DependencyEdge::new(
                    app_id,
                    noise_id,
                    DependencyType::DependsOn,
                ));
            }
            sbom.calculate_content_hash();
            sbom
        };

        // The only difference is an edge to the EXCLUDED component.
        let old = build(true);
        let new = build(false);
        let result = engine.diff(&old, &new).expect("diff");
        assert_eq!(
            result.dependencies.removed.len(),
            0,
            "edges of excluded components must not surface in the diff: {:?}",
            result.dependencies.removed
        );
        assert_eq!(result.dependencies.added.len(), 0);
    }

    /// version_sensitive equivalences bridge only matching versions — the
    /// flag was previously accepted from config and silently ignored, which
    /// became consequential once equivalences started working at all.
    #[test]
    fn version_sensitive_equivalences_bridge_only_matching_versions() {
        use crate::matching::{AliasPattern, EquivalenceGroup, MatchingRulesConfig};
        let engine = |sensitive: bool| {
            let rules = MatchingRulesConfig {
                equivalences: vec![EquivalenceGroup {
                    name: None,
                    canonical: "pkg:npm/foo".to_string(),
                    aliases: vec![AliasPattern::exact("pkg:npm/foo-fork")],
                    version_sensitive: sensitive,
                }],
                ..Default::default()
            };
            DiffEngine::new().with_rule_engine(RuleEngine::new(rules).expect("valid rules"))
        };

        let old = rules_sbom(vec![rules_component(
            "foo-fork",
            "pkg:npm/foo-fork",
            "1.0.0",
            "old-fork",
        )]);
        let new = rules_sbom(vec![rules_component("foo", "pkg:npm/foo", "2.0.0", "new-foo")]);

        // Version-insensitive: bridges across the version bump.
        let result = engine(false).diff(&old, &new).expect("diff");
        assert_eq!(result.components.modified.len(), 1);
        assert_eq!(result.components.added.len(), 0);

        // Version-sensitive: 1.0.0 and 2.0.0 do not bridge; names are too
        // different for fuzzy, so the diff is added + removed.
        let result = engine(true).diff(&old, &new).expect("diff");
        assert_eq!(result.components.modified.len(), 0);
        assert_eq!(result.components.added.len(), 1);
        assert_eq!(result.components.removed.len(), 1);

        // Version-sensitive with MATCHING versions still bridges.
        let new_same = rules_sbom(vec![rules_component(
            "foo",
            "pkg:npm/foo",
            "1.0.0",
            "new-foo-same",
        )]);
        let result = engine(true).diff(&old, &new_same).expect("diff");
        assert_eq!(result.components.modified.len(), 1);
        assert_eq!(result.components.added.len(), 0);
    }
}
