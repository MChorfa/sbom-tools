//! Fuzzy matching engine for cross-ecosystem package correlation.
//!
//! This module provides multi-tier matching strategies for correlating
//! components across different ecosystems and naming conventions.
//!
//! # Architecture
//!
//! The matching system is built on the [`ComponentMatcher`] trait, which
//! provides a pluggable interface for different matching strategies:
//!
//! - [`FuzzyMatcher`]: Multi-tier fuzzy matching (default)
//! - [`CompositeMatcher`]: Combines multiple matchers
//! - [`CachedMatcher`]: Wraps any matcher with caching
//!
//! # Example
//!
//! ```ignore
//! use sbom_tools::matching::{ComponentMatcher, FuzzyMatcher, FuzzyMatchConfig};
//!
//! // Use the trait for dependency injection
//! fn diff_with_matcher(matcher: &dyn ComponentMatcher) {
//!     let score = matcher.match_score(&comp_a, &comp_b);
//! }
//!
//! let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
//! diff_with_matcher(&matcher);
//! ```

pub mod adaptive;
mod aliases;
mod config;
pub mod cross_ecosystem;
pub mod custom_rules;
pub mod ecosystem_config;
pub mod index;
pub mod lsh;
mod purl;
pub mod rule_engine;
mod rules;
pub mod scoring;
pub mod string_similarity;
mod traits;

pub use adaptive::{
    AdaptiveMatching, AdaptiveMethod, AdaptiveThreshold, AdaptiveThresholdConfig,
    AdaptiveThresholdResult, ScoreStats,
};
pub use aliases::AliasTable;
pub use config::{CrossEcosystemConfig, FuzzyMatchConfig, MultiFieldWeights};
pub use cross_ecosystem::{CrossEcosystemDb, CrossEcosystemMatch, PackageFamily};
pub use custom_rules::{
    AliasPattern, EquivalenceGroup, ExclusionRule, MatchingRulesConfig, RulePrecedence,
    RulesSummary,
};
pub use ecosystem_config::{
    ConfigError, CustomEquivalence, CustomRules, EcosystemConfig, EcosystemRulesConfig,
    GlobalSettings, GroupMigration, ImportMapping, NormalizationConfig, PackageGroup,
    ScopeHandling, SecurityConfig, TyposquatEntry, VersionSpec, VersioningConfig,
};
pub use index::{
    BatchCandidateConfig, BatchCandidateGenerator, BatchCandidateResult, BatchCandidateStats,
    ComponentIndex, IndexStats, LazyComponentIndex, NormalizedEntry,
};
pub use lsh::{LshConfig, LshIndex, LshIndexStats, MinHashSignature};
pub use purl::PurlNormalizer;
pub use rule_engine::{AppliedRule, AppliedRuleType, RuleApplicationResult, RuleEngine};
pub use rules::EcosystemRules;
pub use scoring::{MultiFieldScoreResult, SemverParts};
pub use traits::{
    CacheConfig, CacheStats, CachedMatcher, ComponentMatcher, CompositeMatcher,
    CompositeMatcherBuilder, MatchExplanation, MatchMetadata, MatchResult, MatchTier,
    ScoreComponent,
};

use crate::model::Component;
use strsim::{jaro_winkler, levenshtein};

/// Score ceiling for pairs whose (lowercased) names differ.
///
/// Identical-name pairs score 1.0 through the tier-level name-identity
/// anchor (ecosystem-normalized or raw), which fires before fuzzy AND
/// multi-field scoring — so with this cap no near-miss neighbor can tie or
/// beat an exact-name counterpart in any scoring mode. Without it, a
/// one-character-different name plus the version boost reaches 1.0 and the
/// optimal assignment pairs components with the wrong neighbor instead of
/// their exact-name counterpart.
const NON_IDENTICAL_NAME_CAP: f64 = 0.99;

/// Fuzzy matcher for component correlation.
#[must_use]
pub struct FuzzyMatcher {
    config: FuzzyMatchConfig,
    alias_table: AliasTable,
    purl_normalizer: PurlNormalizer,
    ecosystem_rules: EcosystemRules,
    /// Cross-ecosystem match policy: components from known-different
    /// ecosystems only ever match through the curated equivalence DB, with
    /// `score_penalty` and `min_score` applied uniformly — regardless of
    /// which candidate-generation strategy surfaced the pair.
    cross_ecosystem: CrossEcosystemConfig,
    cross_ecosystem_db: Option<CrossEcosystemDb>,
}

impl FuzzyMatcher {
    /// Create a new fuzzy matcher with the given configuration.
    ///
    /// Cross-ecosystem policy defaults to [`CrossEcosystemConfig::default`]
    /// (enabled, builtin equivalence DB); override with
    /// [`with_cross_ecosystem`](Self::with_cross_ecosystem).
    pub fn new(config: FuzzyMatchConfig) -> Self {
        let cross_ecosystem = CrossEcosystemConfig::default();
        let cross_ecosystem_db = cross_ecosystem
            .enabled
            .then(CrossEcosystemDb::with_builtin_mappings);
        Self {
            config,
            alias_table: AliasTable::default(),
            purl_normalizer: PurlNormalizer::new(),
            ecosystem_rules: EcosystemRules::new(),
            cross_ecosystem,
            cross_ecosystem_db,
        }
    }

    /// Get the current configuration.
    #[must_use]
    pub const fn config(&self) -> &FuzzyMatchConfig {
        &self.config
    }

    /// Create a matcher with a custom alias table
    pub fn with_alias_table(mut self, table: AliasTable) -> Self {
        self.alias_table = table;
        self
    }

    /// Set the cross-ecosystem match policy (builds the builtin equivalence
    /// DB when enabled; a previously supplied custom DB is kept).
    pub fn with_cross_ecosystem(mut self, config: CrossEcosystemConfig) -> Self {
        if config.enabled && self.cross_ecosystem_db.is_none() {
            self.cross_ecosystem_db = Some(CrossEcosystemDb::with_builtin_mappings());
        }
        self.cross_ecosystem = config;
        self
    }

    /// Use a custom cross-ecosystem equivalence DB instead of the builtins.
    pub fn with_cross_ecosystem_db(mut self, db: CrossEcosystemDb) -> Self {
        self.cross_ecosystem_db = Some(db);
        self
    }

    /// Match two components and return a confidence score (0.0 - 1.0)
    #[must_use]
    pub fn match_components(&self, a: &Component, b: &Component) -> f64 {
        let scored = self.score_pair(a, b);
        match scored.outcome {
            // Identifier/identity/alias/cross-ecosystem tiers carry their own
            // acceptance criteria and bypass the fuzzy threshold.
            TierOutcome::ExactPurl
            | TierOutcome::Alias
            | TierOutcome::EcosystemRule
            | TierOutcome::NameIdentity
            | TierOutcome::CrossEcosystem { .. } => scored.score,
            TierOutcome::Fuzzy { .. } | TierOutcome::MultiField { .. } => {
                if scored.score >= self.config.threshold {
                    scored.score
                } else {
                    0.0
                }
            }
            TierOutcome::CrossEcosystemRejected { .. } => 0.0,
        }
    }

    /// The tiered scoring pipeline — the single source of truth behind
    /// [`match_score`](ComponentMatcher::match_score),
    /// [`match_detailed`](ComponentMatcher::match_detailed), and
    /// [`explain_match`](ComponentMatcher::explain_match), so the three views
    /// can never disagree about a pair.
    ///
    /// Tiers, in priority order:
    /// 1. Exact normalized PURL → 1.0
    /// 2. Cross-ecosystem gate: KNOWN-different ecosystems match only via
    ///    the curated equivalence DB, penalized and floored per config
    ///    (`Unknown`/`Generic` ecosystems don't engage the gate — a
    ///    non-canonical purl type from another tool is missing information,
    ///    not evidence of a different ecosystem)
    /// 3. Name identity: ecosystem-normalized equality (same ecosystem) or
    ///    case-insensitive raw equality → 1.0
    /// 4. Alias table (opt-in) → 0.95
    /// 5. Fuzzy / multi-field scoring, capped at
    ///    [`NON_IDENTICAL_NAME_CAP`] for differing names
    ///
    /// The returned score is the raw tier score; threshold gating is the
    /// caller's concern (fuzzy/multi-field tiers only).
    fn score_pair(&self, a: &Component, b: &Component) -> ScoredPair {
        // Tier 1: Exact PURL match
        if let (Some(purl_a), Some(purl_b)) = (&a.identifiers.purl, &b.identifiers.purl) {
            let norm_a = self.purl_normalizer.normalize(purl_a);
            let norm_b = self.purl_normalizer.normalize(purl_b);
            if norm_a == norm_b {
                return ScoredPair {
                    score: 1.0,
                    outcome: TierOutcome::ExactPurl,
                };
            }
        }

        let identical_names = a.name.to_lowercase() == b.name.to_lowercase();

        // Tier 2: cross-ecosystem gate. Same-name packages in different
        // ecosystems are usually DIFFERENT packages (npm/redis vs pypi/redis)
        // — hiding an ecosystem substitution as a version bump is the worst
        // failure mode for a supply-chain diff, so only curated equivalences
        // may cross this line, and they carry the configured penalty. The
        // gate requires BOTH ecosystems to be canonically known: an
        // Unknown("rubygems") from another tool's purl spelling vs RubyGems
        // is missing information, not a substitution.
        if let (Some(eco_a), Some(eco_b)) = (&a.ecosystem, &b.ecosystem)
            && eco_a != eco_b
            && is_known_ecosystem(eco_a)
            && is_known_ecosystem(eco_b)
        {
            if !self.cross_ecosystem.enabled {
                return ScoredPair::rejected(CrossEcoRejection::Disabled);
            }
            let Some(db) = &self.cross_ecosystem_db else {
                return ScoredPair::rejected(CrossEcoRejection::Disabled);
            };
            return match db.equivalence(eco_a, &a.name, eco_b, &b.name) {
                None => ScoredPair::rejected(CrossEcoRejection::NotEquivalent),
                Some(info) if self.cross_ecosystem.verified_only && !info.verified => {
                    ScoredPair::rejected(CrossEcoRejection::Unverified)
                }
                Some(info) => {
                    let base = self.fuzzy_or_multi_field(a, b, identical_names).score;
                    let penalized = (base - self.cross_ecosystem.score_penalty).max(0.0);
                    // `<= 0.0` matters: with a user-configured min_score of
                    // 0.0, a fully-penalized pair must still be a rejection,
                    // not a "matched at 0.0" that the three views would
                    // disagree about.
                    if penalized <= 0.0 || penalized < self.cross_ecosystem.min_score {
                        ScoredPair::rejected(CrossEcoRejection::BelowFloor { penalized })
                    } else {
                        ScoredPair {
                            score: penalized,
                            outcome: TierOutcome::CrossEcosystem {
                                base,
                                family: info.family_name,
                            },
                        }
                    }
                }
            };
        }

        // Tier 3: name identity — the strongest name evidence available, and
        // it must outrank the alias tier (0.95) and every fuzzy neighbor.
        // Scoring identity below 1.0 (the old flat 0.90) let near-miss fuzzy
        // neighbors (~0.95) outbid a component's own exact-name counterpart
        // in the assignment. The anchor is tier-level rather than inside the
        // fuzzy scorer so it holds in multi-field mode too.
        if self.config.use_ecosystem_rules && self.ecosystem_normalized_names_equal(a, b) {
            return ScoredPair {
                score: 1.0,
                outcome: TierOutcome::EcosystemRule,
            };
        }
        if identical_names {
            return ScoredPair {
                score: 1.0,
                outcome: TierOutcome::NameIdentity,
            };
        }

        // Tier 4: Alias table lookup (table is empty unless installed)
        if self.config.use_aliases && self.check_alias_match(a, b) {
            return ScoredPair {
                score: 0.95,
                outcome: TierOutcome::Alias,
            };
        }

        // Tier 5: fuzzy / multi-field scoring
        self.fuzzy_or_multi_field(a, b, identical_names)
    }

    /// Fuzzy or multi-field scoring (per config), with the non-identical-name
    /// cap applied.
    fn fuzzy_or_multi_field(
        &self,
        a: &Component,
        b: &Component,
        identical_names: bool,
    ) -> ScoredPair {
        if let Some(ref weights) = self.config.field_weights {
            let mut result = self.compute_multi_field_score(a, b, weights);
            let capped = !identical_names && result.total > NON_IDENTICAL_NAME_CAP;
            if capped {
                result.total = NON_IDENTICAL_NAME_CAP;
            }
            ScoredPair {
                score: result.total,
                outcome: TierOutcome::MultiField { result, capped },
            }
        } else {
            let breakdown = self.fuzzy_breakdown(a, b, identical_names);
            ScoredPair {
                score: breakdown.total,
                outcome: TierOutcome::Fuzzy { breakdown },
            }
        }
    }

    /// Check if components match via alias table
    fn check_alias_match(&self, a: &Component, b: &Component) -> bool {
        // The default table is empty; don't pay two Vec<String> allocations
        // per candidate pair to consult it.
        if self.alias_table.is_empty() {
            return false;
        }

        // Check if either component's name is an alias of the other
        let names_a = self.get_all_names(a);
        let names_b = self.get_all_names(b);

        for name_a in &names_a {
            if let Some(canonical) = self.alias_table.get_canonical(name_a) {
                for name_b in &names_b {
                    if self.alias_table.is_alias(&canonical, name_b) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Get all possible names for a component
    fn get_all_names(&self, comp: &Component) -> Vec<String> {
        let mut names = vec![comp.name.clone()];
        names.extend(comp.identifiers.aliases.clone());

        // Extract name from PURL if available
        if let Some(purl) = &comp.identifiers.purl
            && let Some(name) = self.extract_name_from_purl(purl)
        {
            names.push(name);
        }

        names
    }

    /// Extract the package name from a PURL
    fn extract_name_from_purl(&self, purl: &str) -> Option<String> {
        // pkg:type/namespace/name@version?qualifiers#subpath
        let without_pkg = purl.strip_prefix("pkg:")?;
        let parts: Vec<&str> = without_pkg.split('/').collect();

        if parts.len() >= 2 {
            let name_part = parts.last()?;
            // Remove version and qualifiers
            let name = name_part.split('@').next()?;
            Some(name.to_string())
        } else {
            None
        }
    }

    /// Check whether both components live in the same ecosystem and their
    /// names are equal after ecosystem-official normalization.
    fn ecosystem_normalized_names_equal(&self, a: &Component, b: &Component) -> bool {
        let (Some(ecosystem_a), Some(ecosystem_b)) = (a.ecosystem.as_ref(), b.ecosystem.as_ref())
        else {
            return false;
        };
        if ecosystem_a != ecosystem_b {
            return false;
        }
        self.ecosystem_rules.normalize_name(&a.name, ecosystem_a)
            == self.ecosystem_rules.normalize_name(&b.name, ecosystem_b)
    }

    /// Compute fuzzy string similarity score (uncapped; used as the name
    /// component of multi-field scoring).
    fn compute_fuzzy_score(&self, a: &Component, b: &Component) -> f64 {
        // Names being identical exempts a pair from the cap anyway, so the
        // uncapped total is what a raw-similarity consumer wants.
        self.fuzzy_breakdown(a, b, true).total
    }

    /// Fuzzy string similarity with the full component breakdown retained
    /// for explanations. Applies [`NON_IDENTICAL_NAME_CAP`] unless
    /// `identical_names`.
    fn fuzzy_breakdown(&self, a: &Component, b: &Component, identical_names: bool) -> FuzzyBreakdown {
        let name_a = a.name.to_lowercase();
        let name_b = b.name.to_lowercase();

        // Jaro-Winkler similarity
        let jw_score = jaro_winkler(&name_a, &name_b);

        // Normalized Levenshtein distance
        let max_len = name_a.len().max(name_b.len());
        let lev_distance = levenshtein(&name_a, &name_b);
        let lev_score = if max_len > 0 {
            1.0 - (lev_distance as f64 / max_len as f64)
        } else {
            1.0
        };

        // Token-based similarity (catches reordered names like "react-dom" vs "dom-react")
        let token_score = Self::compute_token_similarity(&name_a, &name_b);

        // Phonetic similarity (catches typos like "color" vs "colour")
        let phonetic_score = Self::compute_phonetic_similarity(&name_a, &name_b);

        // Weighted combination of character-based scores
        let char_score = jw_score.mul_add(
            self.config.jaro_winkler_weight,
            lev_score * self.config.levenshtein_weight,
        );

        // Use the MAXIMUM of character, token, and phonetic scores
        // This allows each method to catch different types of variations
        let combined = char_score.max(token_score).max(phonetic_score * 0.85);

        // Version-aware boost (semantic version similarity)
        let version_boost =
            Self::compute_version_similarity(a.version.as_ref(), b.version.as_ref());

        let uncapped = (combined + version_boost).min(1.0);
        let capped = !identical_names && uncapped > NON_IDENTICAL_NAME_CAP;
        let total = if capped {
            NON_IDENTICAL_NAME_CAP
        } else {
            uncapped
        };

        FuzzyBreakdown {
            jw_score,
            lev_score,
            lev_distance,
            max_len,
            token_score,
            phonetic_score,
            char_score,
            version_boost,
            capped,
            total,
        }
    }

    /// Compute token-based similarity using Jaccard index on name tokens.
    fn compute_token_similarity(name_a: &str, name_b: &str) -> f64 {
        string_similarity::compute_token_similarity(name_a, name_b)
    }

    /// Compute version similarity with semantic awareness.
    fn compute_version_similarity(va: Option<&String>, vb: Option<&String>) -> f64 {
        string_similarity::compute_version_similarity(va, vb)
    }

    /// Compute phonetic similarity using Soundex.
    #[must_use]
    pub fn compute_phonetic_similarity(name_a: &str, name_b: &str) -> f64 {
        string_similarity::compute_phonetic_similarity(name_a, name_b)
    }

    /// Compute multi-field weighted score.
    ///
    /// Combines scores from multiple component fields based on configured weights.
    #[must_use]
    pub fn compute_multi_field_score(
        &self,
        a: &Component,
        b: &Component,
        weights: &config::MultiFieldWeights,
    ) -> scoring::MultiFieldScoreResult {
        use std::collections::HashSet;

        let mut result = scoring::MultiFieldScoreResult::default();

        // 1. Name similarity (using fuzzy scoring). Note: the fuzzy score
        // includes the graduated version boost, so version evidence also
        // contributes here in addition to the weighted version field below —
        // long-standing behavior, kept for score stability.
        let name_score = self.compute_fuzzy_score(a, b);
        result.name_score = name_score;
        result.total += name_score * weights.name;

        // 2. Version match (graduated or binary scoring)
        let version_score = if weights.version_divergence_enabled {
            scoring::compute_version_divergence_score(&a.version, &b.version, weights)
        } else {
            // Legacy binary scoring
            match (&a.version, &b.version) {
                (Some(va), Some(vb)) if va == vb => 1.0,
                (None, None) => 0.5, // Both missing = neutral
                _ => 0.0,
            }
        };
        result.version_score = version_score;
        result.total += version_score * weights.version;

        // 3. Ecosystem match (exact match = 1.0, mismatch applies penalty)
        let (ecosystem_score, ecosystem_penalty) = match (&a.ecosystem, &b.ecosystem) {
            (Some(ea), Some(eb)) if ea == eb => (1.0, 0.0),
            (None, None) => (0.5, 0.0), // Both missing = neutral, no penalty
            (Some(_), Some(_)) => (0.0, weights.ecosystem_mismatch_penalty), // Different ecosystems = penalty
            _ => (0.0, 0.0), // One missing = no match but no penalty
        };
        result.ecosystem_score = ecosystem_score;
        result.total += ecosystem_score.mul_add(weights.ecosystem, ecosystem_penalty);

        // 4. License overlap (Jaccard similarity on declared licenses)
        let licenses_a: HashSet<_> = a
            .licenses
            .declared
            .iter()
            .map(|l| l.expression.as_str())
            .collect();
        let licenses_b: HashSet<_> = b
            .licenses
            .declared
            .iter()
            .map(|l| l.expression.as_str())
            .collect();
        let license_score = if licenses_a.is_empty() && licenses_b.is_empty() {
            0.5 // Both empty = neutral
        } else if licenses_a.is_empty() || licenses_b.is_empty() {
            0.0 // One empty = no match
        } else {
            let intersection = licenses_a.intersection(&licenses_b).count();
            let union = licenses_a.union(&licenses_b).count();
            if union > 0 {
                intersection as f64 / union as f64
            } else {
                0.0
            }
        };
        result.license_score = license_score;
        result.total += license_score * weights.licenses;

        // 5. Supplier match (exact match on supplier organization name)
        let supplier_score = match (&a.supplier, &b.supplier) {
            (Some(sa), Some(sb)) if sa.name.to_lowercase() == sb.name.to_lowercase() => 1.0,
            (None, None) => 0.5, // Both missing = neutral
            _ => 0.0,
        };
        result.supplier_score = supplier_score;
        result.total += supplier_score * weights.supplier;

        // 6. Group/namespace match
        let group_score = match (&a.group, &b.group) {
            (Some(ga), Some(gb)) if ga.to_lowercase() == gb.to_lowercase() => 1.0,
            (None, None) => 0.5, // Both missing = neutral
            _ => 0.0,
        };
        result.group_score = group_score;
        result.total += group_score * weights.group;

        // Clamp total to [0.0, 1.0] after penalty application
        result.total = result.total.clamp(0.0, 1.0);

        result
    }
}

impl Default for FuzzyMatcher {
    fn default() -> Self {
        Self::new(FuzzyMatchConfig::balanced())
    }
}

/// A scored pair plus which tier produced the score — enough to build the
/// detailed and explained views without re-deriving anything.
struct ScoredPair {
    score: f64,
    outcome: TierOutcome,
}

impl ScoredPair {
    const fn rejected(reason: CrossEcoRejection) -> Self {
        Self {
            score: 0.0,
            outcome: TierOutcome::CrossEcosystemRejected { reason },
        }
    }
}

/// Which tier of the scoring pipeline decided a pair's score.
enum TierOutcome {
    ExactPurl,
    Alias,
    EcosystemRule,
    /// Case-insensitive raw-name equality when ecosystems are not
    /// known-different (missing/Unknown ecosystem info on either side)
    NameIdentity,
    CrossEcosystem {
        /// Layer-four score before the cross-ecosystem penalty
        base: f64,
        /// Equivalence family that allowed the pair across the gate
        family: String,
    },
    CrossEcosystemRejected {
        reason: CrossEcoRejection,
    },
    Fuzzy {
        breakdown: FuzzyBreakdown,
    },
    MultiField {
        result: scoring::MultiFieldScoreResult,
        capped: bool,
    },
}

/// Why the cross-ecosystem gate rejected a pair.
enum CrossEcoRejection {
    Disabled,
    NotEquivalent,
    Unverified,
    BelowFloor { penalized: f64 },
}

/// Full fuzzy-scoring breakdown, retained for explanations.
struct FuzzyBreakdown {
    jw_score: f64,
    lev_score: f64,
    lev_distance: usize,
    max_len: usize,
    token_score: f64,
    phonetic_score: f64,
    char_score: f64,
    version_boost: f64,
    capped: bool,
    total: f64,
}

impl ComponentMatcher for FuzzyMatcher {
    fn match_score(&self, a: &Component, b: &Component) -> f64 {
        self.match_components(a, b)
    }

    fn match_detailed(&self, a: &Component, b: &Component) -> MatchResult {
        let scored = self.score_pair(a, b);
        match scored.outcome {
            TierOutcome::ExactPurl => MatchResult::with_metadata(
                scored.score,
                MatchTier::ExactIdentifier,
                MatchMetadata {
                    matched_fields: vec!["purl".to_string()],
                    normalization: Some("purl_normalized".to_string()),
                    rule_id: None,
                },
            ),
            TierOutcome::Alias => MatchResult::with_metadata(
                scored.score,
                MatchTier::Alias,
                MatchMetadata {
                    matched_fields: vec!["name".to_string()],
                    normalization: Some("alias_table".to_string()),
                    rule_id: None,
                },
            ),
            TierOutcome::EcosystemRule => MatchResult::with_metadata(
                scored.score,
                MatchTier::EcosystemRule,
                MatchMetadata {
                    matched_fields: vec!["name".to_string(), "ecosystem".to_string()],
                    normalization: Some("ecosystem_rules".to_string()),
                    rule_id: None,
                },
            ),
            TierOutcome::NameIdentity => MatchResult::with_metadata(
                scored.score,
                MatchTier::NameIdentity,
                MatchMetadata {
                    matched_fields: vec!["name".to_string()],
                    normalization: Some("case_insensitive_name".to_string()),
                    rule_id: None,
                },
            ),
            TierOutcome::CrossEcosystem { family, .. } => MatchResult::with_metadata(
                scored.score,
                MatchTier::CrossEcosystem,
                MatchMetadata {
                    matched_fields: vec!["name".to_string(), "ecosystem".to_string()],
                    normalization: Some("cross_ecosystem_db".to_string()),
                    rule_id: Some(family),
                },
            ),
            TierOutcome::Fuzzy { .. } if scored.score >= self.config.threshold => {
                MatchResult::with_metadata(
                    scored.score,
                    MatchTier::Fuzzy,
                    MatchMetadata {
                        matched_fields: vec!["name".to_string()],
                        normalization: Some("fuzzy_similarity".to_string()),
                        rule_id: None,
                    },
                )
            }
            TierOutcome::MultiField { .. } if scored.score >= self.config.threshold => {
                MatchResult::with_metadata(
                    scored.score,
                    MatchTier::Fuzzy,
                    MatchMetadata {
                        matched_fields: vec![
                            "name".to_string(),
                            "version".to_string(),
                            "ecosystem".to_string(),
                            "licenses".to_string(),
                            "supplier".to_string(),
                            "group".to_string(),
                        ],
                        normalization: Some("multi_field".to_string()),
                        rule_id: None,
                    },
                )
            }
            TierOutcome::Fuzzy { .. }
            | TierOutcome::MultiField { .. }
            | TierOutcome::CrossEcosystemRejected { .. } => MatchResult::no_match(),
        }
    }

    fn name(&self) -> &'static str {
        "FuzzyMatcher"
    }

    fn threshold(&self) -> f64 {
        self.config.threshold
    }

    fn explain_match(&self, a: &Component, b: &Component) -> MatchExplanation {
        let scored = self.score_pair(a, b);
        match scored.outcome {
            TierOutcome::ExactPurl => {
                let purl_a = a.identifiers.purl.as_deref().unwrap_or_default();
                let purl_b = b.identifiers.purl.as_deref().unwrap_or_default();
                MatchExplanation::matched(
                    MatchTier::ExactIdentifier,
                    scored.score,
                    format!("Exact PURL match: '{purl_a}' equals '{purl_b}' after normalization"),
                )
                .with_normalization("purl_normalized")
            }
            TierOutcome::Alias => MatchExplanation::matched(
                MatchTier::Alias,
                scored.score,
                format!(
                    "'{}' and '{}' are known aliases of the same package",
                    a.name, b.name
                ),
            )
            .with_normalization("alias_table"),
            TierOutcome::EcosystemRule => {
                let ecosystem = a
                    .ecosystem
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string);
                MatchExplanation::matched(
                    MatchTier::EcosystemRule,
                    scored.score,
                    format!(
                        "Names match after {} ecosystem normalization: '{}' -> '{}'",
                        ecosystem, a.name, b.name
                    ),
                )
                .with_normalization(format!("{ecosystem}_normalization"))
            }
            TierOutcome::NameIdentity => MatchExplanation::matched(
                MatchTier::NameIdentity,
                scored.score,
                format!("Identical component names: '{}'", a.name),
            )
            .with_normalization("case_insensitive_name"),
            TierOutcome::CrossEcosystem { base, family } => MatchExplanation::matched(
                MatchTier::CrossEcosystem,
                scored.score,
                format!(
                    "'{}' ({}) and '{}' ({}) are curated equivalents (family '{}'): base score {:.2} − {:.2} cross-ecosystem penalty",
                    a.name,
                    ecosystem_label(a),
                    b.name,
                    ecosystem_label(b),
                    family,
                    base,
                    self.cross_ecosystem.score_penalty,
                ),
            )
            .with_score_component(ScoreComponent {
                name: "Cross-ecosystem penalty".to_string(),
                weight: 1.0,
                raw_score: -self.cross_ecosystem.score_penalty,
                weighted_score: -self.cross_ecosystem.score_penalty,
                description: format!("applied to base score {base:.2}"),
            })
            .with_normalization("cross_ecosystem_db"),
            TierOutcome::CrossEcosystemRejected { reason } => {
                MatchExplanation::no_match(match reason {
                    CrossEcoRejection::Disabled => format!(
                        "'{}' ({}) and '{}' ({}) are from different ecosystems and cross-ecosystem matching is disabled",
                        a.name,
                        ecosystem_label(a),
                        b.name,
                        ecosystem_label(b),
                    ),
                    CrossEcoRejection::NotEquivalent => format!(
                        "'{}' ({}) and '{}' ({}) are from different ecosystems with no curated equivalence — same-name packages in different ecosystems are treated as different packages",
                        a.name,
                        ecosystem_label(a),
                        b.name,
                        ecosystem_label(b),
                    ),
                    CrossEcoRejection::Unverified => format!(
                        "'{}' and '{}' have an unverified cross-ecosystem equivalence and verified_only is set",
                        a.name, b.name,
                    ),
                    CrossEcoRejection::BelowFloor { penalized } => format!(
                        "cross-ecosystem score {:.2} below the configured floor {:.2} after the {:.2} penalty",
                        penalized, self.cross_ecosystem.min_score, self.cross_ecosystem.score_penalty,
                    ),
                })
            }
            TierOutcome::Fuzzy { breakdown } => {
                let is_match = scored.score >= self.config.threshold;
                let mut explanation = if is_match {
                    MatchExplanation::matched(
                        MatchTier::Fuzzy,
                        scored.score,
                        format!(
                            "Fuzzy match: '{}' ~ '{}' with {:.0}% similarity",
                            a.name,
                            b.name,
                            scored.score * 100.0
                        ),
                    )
                } else {
                    MatchExplanation::no_match(format!(
                        "Fuzzy similarity {:.2} below threshold {:.2}",
                        scored.score, self.config.threshold
                    ))
                };

                explanation = explanation
                    .with_score_component(ScoreComponent {
                        name: "Jaro-Winkler".to_string(),
                        weight: self.config.jaro_winkler_weight,
                        raw_score: breakdown.jw_score,
                        weighted_score: breakdown.jw_score * self.config.jaro_winkler_weight,
                        description: format!(
                            "'{}' vs '{}' = {:.2}",
                            a.name.to_lowercase(),
                            b.name.to_lowercase(),
                            breakdown.jw_score
                        ),
                    })
                    .with_score_component(ScoreComponent {
                        name: "Levenshtein".to_string(),
                        weight: self.config.levenshtein_weight,
                        raw_score: breakdown.lev_score,
                        weighted_score: breakdown.lev_score * self.config.levenshtein_weight,
                        description: format!(
                            "edit distance {} / max_len {} = {:.2}",
                            breakdown.lev_distance, breakdown.max_len, breakdown.lev_score
                        ),
                    })
                    .with_score_component(ScoreComponent {
                        name: "Token overlap".to_string(),
                        weight: 1.0,
                        raw_score: breakdown.token_score,
                        weighted_score: breakdown.token_score,
                        description: format!(
                            "Jaccard on name tokens = {:.2}; final = max(char blend {:.2}, token, phonetic × 0.85)",
                            breakdown.token_score, breakdown.char_score
                        ),
                    })
                    .with_score_component(ScoreComponent {
                        name: "Phonetic".to_string(),
                        weight: 0.85,
                        raw_score: breakdown.phonetic_score,
                        weighted_score: breakdown.phonetic_score * 0.85,
                        description: format!("Soundex similarity = {:.2}", breakdown.phonetic_score),
                    });

                if breakdown.version_boost > 0.0 {
                    explanation = explanation.with_score_component(ScoreComponent {
                        name: "Version boost".to_string(),
                        weight: 1.0,
                        raw_score: breakdown.version_boost,
                        weighted_score: breakdown.version_boost,
                        description: format!(
                            "graduated semver similarity: {:?} vs {:?}",
                            a.version, b.version
                        ),
                    });
                }

                if breakdown.capped {
                    explanation =
                        explanation.with_normalization("non_identical_name_cap_0.99");
                }

                explanation.with_normalization("lowercase")
            }
            TierOutcome::MultiField { result, capped } => {
                let is_match = scored.score >= self.config.threshold;
                let weights = self
                    .config
                    .field_weights
                    .as_ref()
                    .cloned()
                    .unwrap_or_default();
                let mut explanation = if is_match {
                    MatchExplanation::matched(
                        MatchTier::Fuzzy,
                        scored.score,
                        format!(
                            "Multi-field match: '{}' ~ '{}' scoring {:.0}% across name/version/ecosystem/licenses/supplier/group",
                            a.name,
                            b.name,
                            scored.score * 100.0
                        ),
                    )
                } else {
                    MatchExplanation::no_match(format!(
                        "Multi-field score {:.2} below threshold {:.2}",
                        scored.score, self.config.threshold
                    ))
                };

                for (name, weight, raw) in [
                    ("Name", weights.name, result.name_score),
                    ("Version", weights.version, result.version_score),
                    ("Ecosystem", weights.ecosystem, result.ecosystem_score),
                    ("Licenses", weights.licenses, result.license_score),
                    ("Supplier", weights.supplier, result.supplier_score),
                    ("Group", weights.group, result.group_score),
                ] {
                    explanation = explanation.with_score_component(ScoreComponent {
                        name: name.to_string(),
                        weight,
                        raw_score: raw,
                        weighted_score: raw * weight,
                        description: format!("{name} similarity = {raw:.2}"),
                    });
                }

                if capped {
                    explanation =
                        explanation.with_normalization("non_identical_name_cap_0.99");
                }

                explanation.with_normalization("multi_field")
            }
        }
    }
}

/// Ecosystem display label for explanation messages.
fn ecosystem_label(comp: &Component) -> String {
    comp.ecosystem
        .as_ref()
        .map_or_else(|| "unknown".to_string(), std::string::ToString::to_string)
}

/// Whether an ecosystem value is canonically known — `Unknown(_)` and
/// `Generic` carry no cross-ecosystem evidence and must not engage the gate.
const fn is_known_ecosystem(eco: &crate::model::Ecosystem) -> bool {
    !matches!(
        eco,
        crate::model::Ecosystem::Unknown(_) | crate::model::Ecosystem::Generic
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_purl_match() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.identifiers.purl = Some("pkg:npm/lodash@4.17.21".to_string());

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.identifiers.purl = Some("pkg:npm/lodash@4.17.21".to_string());

        assert_eq!(matcher.match_components(&a, &b), 1.0);
    }

    #[test]
    fn test_fuzzy_name_match() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        // Similar names should have some fuzzy match score
        let a = Component::new("lodash-es".to_string(), "comp-1".to_string());
        let b = Component::new("lodash".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        // With permissive threshold (0.70), similar names should match
        assert!(
            score >= 0.70,
            "lodash-es vs lodash should have score >= 0.70, got {}",
            score
        );
    }

    #[test]
    fn test_different_names_low_score() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::strict());

        let a = Component::new("react".to_string(), "comp-1".to_string());
        let b = Component::new("angular".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        assert!(
            score < 0.5,
            "react vs angular should have low score, got {}",
            score
        );
    }

    #[test]
    fn test_multi_field_weights_normalized() {
        let weights = config::MultiFieldWeights::balanced();
        assert!(
            weights.is_normalized(),
            "Balanced weights should be normalized"
        );

        let weights = config::MultiFieldWeights::name_focused();
        assert!(
            weights.is_normalized(),
            "Name-focused weights should be normalized"
        );

        let weights = config::MultiFieldWeights::security_focused();
        assert!(
            weights.is_normalized(),
            "Security-focused weights should be normalized"
        );
    }

    #[test]
    fn test_multi_field_scoring_same_component() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::balanced();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        // Identical component should score very high
        // Note: empty licenses/supplier/group get neutral 0.5 score, so total won't be 1.0
        let result = matcher.compute_multi_field_score(&a, &a, &weights);
        assert!(
            result.total > 0.90,
            "Same component should score > 0.90, got {}",
            result.total
        );
        assert_eq!(result.name_score, 1.0);
        assert_eq!(result.version_score, 1.0);
        assert_eq!(result.ecosystem_score, 1.0);
        // Empty fields get neutral 0.5 score
        assert_eq!(
            result.license_score, 0.5,
            "Empty licenses should be neutral"
        );
        assert_eq!(
            result.supplier_score, 0.5,
            "Empty supplier should be neutral"
        );
        assert_eq!(result.group_score, 0.5, "Empty group should be neutral");
    }

    #[test]
    fn test_multi_field_scoring_different_versions() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::balanced();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.version = Some("4.17.20".to_string()); // Different patch version
        b.ecosystem = Some(crate::model::Ecosystem::Npm);

        let result = matcher.compute_multi_field_score(&a, &b, &weights);

        // Name matches perfectly
        assert!(result.name_score > 0.9, "Name score should be > 0.9");

        // Graduated version scoring: same major.minor gives high score
        // 4.17.21 vs 4.17.20 = same major.minor, patch diff of 1
        // Expected: 0.8 - 0.01 * 1 = 0.79
        assert!(
            result.version_score > 0.7,
            "Same major.minor with patch diff should score high, got {}",
            result.version_score
        );

        // Ecosystem matches
        assert_eq!(
            result.ecosystem_score, 1.0,
            "Same ecosystem should score 1.0"
        );

        // Total should be high due to name, ecosystem, and graduated version score
        assert!(
            result.total > 0.8,
            "Total should be > 0.8, got {}",
            result.total
        );
    }

    #[test]
    fn test_multi_field_scoring_different_major_versions() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::balanced();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.version = Some("3.10.0".to_string()); // Different major version
        b.ecosystem = Some(crate::model::Ecosystem::Npm);

        let result = matcher.compute_multi_field_score(&a, &b, &weights);

        // Graduated version scoring: different major gives low score
        // 4 vs 3 = major diff of 1
        // Expected: 0.3 - 0.10 * 1 = 0.20
        assert!(
            result.version_score < 0.3,
            "Different major versions should score low, got {}",
            result.version_score
        );
    }

    #[test]
    fn test_multi_field_scoring_legacy_weights() {
        // Test that legacy weights disable graduated scoring
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());
        let weights = config::MultiFieldWeights::legacy();

        let mut a = Component::new("lodash".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());
        a.ecosystem = Some(crate::model::Ecosystem::Npm);

        let mut b = Component::new("lodash".to_string(), "comp-2".to_string());
        b.version = Some("4.17.20".to_string());
        b.ecosystem = Some(crate::model::Ecosystem::Npm);

        let result = matcher.compute_multi_field_score(&a, &b, &weights);

        // Legacy mode: binary version scoring (exact match or 0)
        assert_eq!(
            result.version_score, 0.0,
            "Legacy mode: different versions should score 0"
        );
    }

    #[test]
    fn test_multi_field_config_preset() {
        let config = FuzzyMatchConfig::from_preset("balanced-multi").unwrap();
        assert!(config.field_weights.is_some());

        let config = FuzzyMatchConfig::from_preset("strict_multi").unwrap();
        assert!(config.field_weights.is_some());
    }

    #[test]
    fn test_multi_field_score_result_summary() {
        let result = MultiFieldScoreResult {
            total: 0.85,
            name_score: 1.0,
            version_score: 0.0,
            ecosystem_score: 1.0,
            license_score: 0.5,
            supplier_score: 0.5,
            group_score: 0.5,
        };

        let summary = result.summary();
        assert!(summary.contains("0.85"));
        assert!(summary.contains("name: 1.00"));
    }

    #[test]
    fn test_token_similarity_exact() {
        let score = string_similarity::compute_token_similarity("react-dom", "react-dom");
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_token_similarity_reordered() {
        // Reordered tokens should have high similarity
        let score = string_similarity::compute_token_similarity("react-dom", "dom-react");
        assert_eq!(score, 1.0, "Reordered tokens should match perfectly");
    }

    #[test]
    fn test_token_similarity_partial() {
        // Partial token overlap
        let score = string_similarity::compute_token_similarity("react-dom-utils", "react-dom");
        // Jaccard: 2 common / 3 total = 0.667
        assert!(
            (score - 0.667).abs() < 0.01,
            "Partial overlap should be ~0.67, got {}",
            score
        );
    }

    #[test]
    fn test_token_similarity_different_delimiters() {
        // Different delimiters should still work
        let score =
            string_similarity::compute_token_similarity("my_package_name", "my-package-name");
        assert_eq!(score, 1.0, "Different delimiters should match");
    }

    #[test]
    fn test_token_similarity_no_overlap() {
        let score = string_similarity::compute_token_similarity("react", "angular");
        assert_eq!(score, 0.0, "No common tokens should score 0");
    }

    #[test]
    fn test_version_similarity_exact() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.2.3".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.10, "Exact version match should give max boost");
    }

    #[test]
    fn test_version_similarity_same_major_minor() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.2.4".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.07, "Same major.minor should give 0.07 boost");
    }

    #[test]
    fn test_version_similarity_same_major() {
        let v1 = "1.2.3".to_string();
        let v2 = "1.5.0".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.04, "Same major should give 0.04 boost");
    }

    #[test]
    fn test_version_similarity_different_major() {
        let v1 = "1.2.3".to_string();
        let v2 = "2.0.0".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.0, "Different major versions should give no boost");
    }

    #[test]
    fn test_version_similarity_prerelease() {
        // Handle prerelease versions like "1.2.3-beta"
        let v1 = "1.2.3-beta".to_string();
        let v2 = "1.2.4".to_string();
        let score = FuzzyMatcher::compute_version_similarity(Some(&v1), Some(&v2));
        assert_eq!(score, 0.07, "Prerelease should still match major.minor");
    }

    #[test]
    fn test_version_similarity_missing() {
        let v = "1.0.0".to_string();
        let score = FuzzyMatcher::compute_version_similarity(None, Some(&v));
        assert_eq!(score, 0.0, "Missing version should give no boost");

        let score = FuzzyMatcher::compute_version_similarity(None, None);
        assert_eq!(score, 0.0, "Both missing should give no boost");
    }

    #[test]
    fn test_fuzzy_match_with_reordered_tokens() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        let a = Component::new("react-dom".to_string(), "comp-1".to_string());
        let b = Component::new("dom-react".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        // Token similarity is 1.0, blended with character similarity
        assert!(
            score > 0.5,
            "Reordered names should still match, got {}",
            score
        );
    }

    #[test]
    fn test_fuzzy_match_version_boost() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        // Use slightly different names so we rely on fuzzy matching, not exact match
        let mut a = Component::new("lodash-utils".to_string(), "comp-1".to_string());
        a.version = Some("4.17.21".to_string());

        let mut b = Component::new("lodash-util".to_string(), "comp-2".to_string());
        b.version = Some("4.17.20".to_string()); // Same major.minor -> +0.07 boost

        let mut c = Component::new("lodash-util".to_string(), "comp-3".to_string());
        c.version = Some("5.0.0".to_string()); // Different major -> +0.0 boost

        let score_same_minor = matcher.match_components(&a, &b);
        let score_diff_major = matcher.match_components(&a, &c);

        // Both should match (fuzzy), but same_minor should have version boost
        assert!(score_same_minor > 0.0, "Same minor should match");
        assert!(score_diff_major > 0.0, "Different major should still match");
        assert!(
            score_same_minor > score_diff_major,
            "Same minor version should score higher: {} vs {}",
            score_same_minor,
            score_diff_major
        );
    }

    #[test]
    fn test_soundex_basic() {
        // Test basic Soundex encoding
        assert_eq!(string_similarity::soundex("Robert"), "R163");
        assert_eq!(string_similarity::soundex("Rupert"), "R163"); // Same as Robert
        assert_eq!(string_similarity::soundex("Smith"), "S530");
        assert_eq!(string_similarity::soundex("Smyth"), "S530"); // Same as Smith
    }

    #[test]
    fn test_soundex_empty() {
        assert_eq!(string_similarity::soundex(""), "");
        assert_eq!(string_similarity::soundex("123"), ""); // No letters
    }

    #[test]
    fn test_phonetic_similarity_exact() {
        let score = string_similarity::compute_phonetic_similarity("color", "colour");
        assert_eq!(score, 1.0, "color and colour should match phonetically");
    }

    #[test]
    fn test_phonetic_similarity_different() {
        let score = string_similarity::compute_phonetic_similarity("react", "angular");
        assert!(
            score < 0.5,
            "Different names should have low phonetic similarity"
        );
    }

    #[test]
    fn test_phonetic_similarity_compound() {
        // Test compound names where tokens match phonetically
        let score = string_similarity::compute_phonetic_similarity("json-parser", "jayson-parser");
        assert!(
            score > 0.5,
            "Similar sounding compound names should match: {}",
            score
        );
    }

    #[test]
    fn test_fuzzy_match_with_phonetic() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::permissive());

        let a = Component::new("color-utils".to_string(), "comp-1".to_string());
        let b = Component::new("colour-utils".to_string(), "comp-2".to_string());

        let score = matcher.match_components(&a, &b);
        assert!(
            score > 0.7,
            "Phonetically similar names should match: {}",
            score
        );
    }

    fn comp(name: &str, eco: Option<crate::model::Ecosystem>, version: &str) -> Component {
        let mut c = Component::new(name.to_string(), format!("test-{name}-{version}"));
        c.version = Some(version.to_string());
        c.ecosystem = eco;
        c
    }

    /// Regression for the score-tier inversion: an exact-name counterpart
    /// must strictly outscore every near-miss neighbor, otherwise the
    /// assignment pairs components with the wrong neighbor (reproduced 6/6
    /// on convention-named fixtures before the fix).
    #[test]
    fn exact_name_match_dominates_fuzzy_neighbors() {
        use crate::model::Ecosystem;
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        let old = comp("comp000001lib", Some(Ecosystem::Npm), "1.0.0");
        let twin = comp("comp000001lib", Some(Ecosystem::Npm), "2.0.0");
        let neighbor = comp("comp000002lib", Some(Ecosystem::Npm), "1.0.0");

        let twin_score = matcher.match_components(&old, &twin);
        let neighbor_score = matcher.match_components(&old, &neighbor);

        assert!(
            (twin_score - 1.0).abs() < 1e-9,
            "identical-name pair must score 1.0, got {twin_score}"
        );
        assert!(
            neighbor_score <= NON_IDENTICAL_NAME_CAP,
            "near-miss neighbor must be capped, got {neighbor_score}"
        );
        assert!(
            twin_score > neighbor_score,
            "exact-name counterpart must dominate: twin {twin_score} vs neighbor {neighbor_score}"
        );
    }

    /// The cap also holds when the version boost would have pushed a
    /// non-identical name to 1.0, and does not apply to identical names.
    #[test]
    fn non_identical_names_never_reach_one() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        // Same version -> +0.10 boost; uncapped this clamps to 1.0.
        let a = comp("libfoo-aaaa1", None, "1.0.0");
        let b = comp("libfoo-aaaa2", None, "1.0.0");
        let score = matcher.match_components(&a, &b);
        assert!(
            score > 0.0 && score <= NON_IDENTICAL_NAME_CAP,
            "boosted near-miss must stay below 1.0, got {score}"
        );

        // Identical names without ecosystems flow through the fuzzy tier
        // uncapped and reach 1.0.
        let c = comp("libfoo", None, "1.0.0");
        let d = comp("libfoo", None, "3.0.0");
        assert!((matcher.match_components(&c, &d) - 1.0).abs() < 1e-9);
    }

    /// Same-name packages in different ecosystems are DIFFERENT packages
    /// unless the curated DB says otherwise: npm/redis vs pypi/redis was
    /// previously merged at an unpenalized 1.0.
    #[test]
    fn same_name_different_ecosystem_does_not_match() {
        use crate::model::Ecosystem;
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        let a = comp("redis", Some(Ecosystem::Npm), "4.6.0");
        let b = comp("redis", Some(Ecosystem::PyPi), "5.0.0");

        assert_eq!(
            matcher.match_components(&a, &b),
            0.0,
            "npm/redis and pypi/redis must not merge"
        );
        let explanation = matcher.explain_match(&a, &b);
        assert!(!explanation.is_match);
        assert!(
            explanation.reason.contains("different ecosystems"),
            "rejection must be explained: {}",
            explanation.reason
        );
    }

    /// Curated equivalents cross the gate with the configured penalty and
    /// surface the CrossEcosystem tier.
    #[test]
    fn curated_cross_ecosystem_equivalents_match_with_penalty() {
        use crate::model::Ecosystem;
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        // "regex" is a builtin family spanning pypi and cargo.
        let a = comp("regex", Some(Ecosystem::PyPi), "2023.12.25");
        let b = comp("regex", Some(Ecosystem::Cargo), "1.10.2");

        let score = matcher.match_components(&a, &b);
        let expected = 1.0 - CrossEcosystemConfig::default().score_penalty;
        assert!(
            (score - expected).abs() < 1e-9,
            "expected penalized {expected}, got {score}"
        );

        let detailed = matcher.match_detailed(&a, &b);
        assert_eq!(detailed.tier, MatchTier::CrossEcosystem);
        let explanation = matcher.explain_match(&a, &b);
        assert!(explanation.is_match);
        assert_eq!(explanation.tier, MatchTier::CrossEcosystem);
    }

    /// verified_only rejects unverified families; disabling the policy
    /// rejects everything cross-ecosystem.
    #[test]
    fn cross_ecosystem_policy_knobs_are_honored() {
        use crate::model::Ecosystem;
        use cross_ecosystem::{CrossEcosystemDb, PackageFamily};

        let mut db = CrossEcosystemDb::new();
        db.add_family(
            PackageFamily::new("unverified-fam")
                .with_names(&Ecosystem::PyPi, &["fooberlib"])
                .with_names(&Ecosystem::Cargo, &["fooberlib"]),
        );

        let a = comp("fooberlib", Some(Ecosystem::PyPi), "1.0.0");
        let b = comp("fooberlib", Some(Ecosystem::Cargo), "1.0.0");

        let permissive_matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced())
            .with_cross_ecosystem_db(db.clone())
            .with_cross_ecosystem(CrossEcosystemConfig {
                verified_only: false,
                ..CrossEcosystemConfig::default()
            });
        assert!(permissive_matcher.match_components(&a, &b) > 0.0);

        let strict_matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced())
            .with_cross_ecosystem_db(db)
            .with_cross_ecosystem(CrossEcosystemConfig {
                verified_only: true,
                ..CrossEcosystemConfig::default()
            });
        assert_eq!(strict_matcher.match_components(&a, &b), 0.0);

        let disabled_matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced())
            .with_cross_ecosystem(CrossEcosystemConfig::disabled());
        assert_eq!(disabled_matcher.match_components(&a, &b), 0.0);
    }

    /// match_score, match_detailed, and explain_match must agree — a matched
    /// pair carrying a "no match" explanation was possible when the three
    /// methods used three different formulas.
    #[test]
    fn score_detailed_and_explanation_agree() {
        use crate::model::Ecosystem;

        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced())
            .with_alias_table(AliasTable::with_builtins());

        let pairs = [
            // token-reorder pair: matched via token similarity, previously
            // labeled no-match by explain_match's jw+lev-only formula
            (comp("react-dom", None, "18.0.0"), comp("dom-react", None, "18.0.0")),
            (comp("lodash", Some(Ecosystem::Npm), "4.0.0"), comp("lodash", Some(Ecosystem::Npm), "5.0.0")),
            (comp("redis", Some(Ecosystem::Npm), "4.0.0"), comp("redis", Some(Ecosystem::PyPi), "5.0.0")),
            (comp("regex", Some(Ecosystem::PyPi), "2023.1.1"), comp("regex", Some(Ecosystem::Cargo), "1.10.0")),
            (comp("PIL", None, "9.0.0"), comp("pillow", None, "10.0.0")),
            (comp("react", None, "18.0.0"), comp("angular", None, "17.0.0")),
            (comp("lodash-utils", None, "1.2.3"), comp("lodash-util", None, "1.2.4")),
        ];

        for (a, b) in &pairs {
            let score = matcher.match_components(a, b);
            let detailed = matcher.match_detailed(a, b);
            let explanation = matcher.explain_match(a, b);

            assert!(
                (score - detailed.score).abs() < 1e-9 || (score == 0.0 && !detailed.is_match()),
                "match_score {score} disagrees with match_detailed {} for '{}' vs '{}'",
                detailed.score,
                a.name,
                b.name
            );
            assert_eq!(
                score > 0.0,
                explanation.is_match,
                "match_score {score} disagrees with explanation '{}' for '{}' vs '{}'",
                explanation.reason,
                a.name,
                b.name
            );
            if explanation.is_match {
                assert!(
                    (score - explanation.score).abs() < 1e-9,
                    "explanation score {} != match score {score} for '{}' vs '{}'",
                    explanation.score,
                    a.name,
                    b.name
                );
            }
        }
    }

    /// Audit regression: a fully-penalized cross-ecosystem pair must be a
    /// rejection even when min_score is configured 0.0 — "matched at 0.0"
    /// made the three views disagree.
    #[test]
    fn fully_penalized_cross_ecosystem_pair_is_rejected() {
        use crate::model::Ecosystem;
        let matcher =
            FuzzyMatcher::new(FuzzyMatchConfig::balanced()).with_cross_ecosystem(
                CrossEcosystemConfig {
                    min_score: 0.0,
                    score_penalty: 1.0,
                    ..CrossEcosystemConfig::default()
                },
            );

        let a = comp("regex", Some(Ecosystem::PyPi), "2023.1.1");
        let b = comp("regex", Some(Ecosystem::Cargo), "1.10.0");

        assert_eq!(matcher.match_components(&a, &b), 0.0);
        let explanation = matcher.explain_match(&a, &b);
        assert!(
            !explanation.is_match,
            "a 0.0 score must never be explained as a match: {}",
            explanation.reason
        );
        assert!(!matcher.match_detailed(&a, &b).is_match());
    }

    /// Audit regression: the exact-name anchor must hold in MULTI-FIELD mode
    /// with missing ecosystem data — previously the twin scored below
    /// threshold there while a near-miss neighbor passed, reintroducing the
    /// wrong-neighbor inversion the rewrite exists to fix.
    #[test]
    fn multi_field_mode_keeps_exact_name_dominance() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced_multi_field());

        let old = comp("libfoo-aaaa1", None, "1.0.0");
        let twin = comp("libfoo-aaaa1", None, "2.0.0");
        let neighbor = comp("libfoo-aaaa2", None, "1.0.0");

        let twin_score = matcher.match_components(&old, &twin);
        let neighbor_score = matcher.match_components(&old, &neighbor);

        assert!(
            (twin_score - 1.0).abs() < 1e-9,
            "identity anchor must hold in multi-field mode, got {twin_score}"
        );
        assert!(
            twin_score > neighbor_score,
            "twin must dominate neighbor in multi-field mode: {twin_score} vs {neighbor_score}"
        );
    }

    /// Audit regression: Unknown/Generic ecosystems carry no cross-ecosystem
    /// evidence — a non-canonical purl-type spelling from another tool must
    /// not hard-reject an identical-name pair.
    #[test]
    fn unknown_ecosystem_does_not_engage_the_gate() {
        use crate::model::Ecosystem;
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced());

        let a = comp("rails", Some(Ecosystem::Unknown("rubygems".to_string())), "7.0.0");
        let b = comp("rails", Some(Ecosystem::RubyGems), "7.1.0");

        let score = matcher.match_components(&a, &b);
        assert!(
            (score - 1.0).abs() < 1e-9,
            "Unknown('rubygems') vs RubyGems with identical names must match, got {score}"
        );
        assert_eq!(matcher.match_detailed(&a, &b).tier, MatchTier::NameIdentity);
    }

    /// Identity must outrank the alias tier: an alias-listed name compared
    /// with itself is an identical-name pair (1.0), not an alias pair (0.95).
    #[test]
    fn identical_names_outrank_alias_tier() {
        let matcher = FuzzyMatcher::new(FuzzyMatchConfig::balanced())
            .with_alias_table(AliasTable::with_builtins());

        let a = comp("pillow", None, "9.0.0");
        let b = comp("pillow", None, "10.0.0");

        assert!(
            (matcher.match_components(&a, &b) - 1.0).abs() < 1e-9,
            "identical alias-listed names must hit the identity tier at 1.0"
        );
    }

    /// The use_aliases knob gates the alias tier (previously dead config).
    #[test]
    fn use_aliases_knob_gates_alias_tier() {
        let table = AliasTable::with_builtins();
        let a = comp("PIL", None, "9.0.0");
        let b = comp("pillow", None, "10.0.0");

        let enabled = FuzzyMatcher::new(FuzzyMatchConfig::balanced())
            .with_alias_table(table.clone());
        assert_eq!(
            enabled.match_components(&a, &b),
            0.95,
            "builtin alias PIL/pillow should match via alias tier"
        );

        let disabled = FuzzyMatcher::new(FuzzyMatchConfig {
            use_aliases: false,
            ..FuzzyMatchConfig::balanced()
        })
        .with_alias_table(table);
        assert!(
            disabled.match_components(&a, &b) < 0.95,
            "use_aliases=false must bypass the alias tier"
        );
    }

    /// The use_ecosystem_rules knob gates normalized-name equality
    /// (previously dead config). Identical raw names still match via fuzzy.
    #[test]
    fn use_ecosystem_rules_knob_gates_normalization() {
        use crate::model::Ecosystem;
        let a = comp("Python_Dateutil", Some(Ecosystem::PyPi), "2.8.0");
        let b = comp("python-dateutil", Some(Ecosystem::PyPi), "2.9.0");

        let enabled = FuzzyMatcher::new(FuzzyMatchConfig::balanced());
        assert!(
            (enabled.match_components(&a, &b) - 1.0).abs() < 1e-9,
            "ecosystem-normalized equal names must score 1.0"
        );

        let disabled = FuzzyMatcher::new(FuzzyMatchConfig {
            use_ecosystem_rules: false,
            ..FuzzyMatchConfig::balanced()
        });
        let score = disabled.match_components(&a, &b);
        assert!(
            score > 0.0 && score < 1.0,
            "knob off: normalization variants fall to capped fuzzy, got {score}"
        );
    }
}
