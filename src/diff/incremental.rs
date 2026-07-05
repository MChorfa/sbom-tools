//! Incremental diffing with result caching.
//!
//! This module provides caching and incremental computation for SBOM diffs,
//! dramatically improving performance when comparing related SBOMs (e.g.,
//! successive builds where only a few components change).
//!
//! # How It Works
//!
//! 1. **Content Hashing**: Each SBOM section (components, dependencies, licenses,
//!    vulnerabilities) has a separate content hash.
//! 2. **Change Detection**: Before recomputing, we check if each section changed.
//! 3. **Partial Recomputation**: Only sections that changed are recomputed.
//! 4. **Result Caching**: Full results are cached for exact SBOM pair matches.
//!
//! # Performance Gains
//!
//! - Exact cache hit: O(1) lookup
//! - Partial change: Only recompute changed sections (typically 10-50% of work)
//! - Cold start: Same as regular diff

use crate::diff::{DiffEngine, DiffResult};
use crate::error::SbomDiffError;
use crate::model::NormalizedSbom;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ============================================================================
// Cache Key Types
// ============================================================================

/// Key for full diff cache lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DiffCacheKey {
    /// Hash of the old SBOM
    pub old_hash: u64,
    /// Hash of the new SBOM
    pub new_hash: u64,
}

impl DiffCacheKey {
    /// Create a cache key from two SBOMs.
    #[must_use]
    pub const fn from_sboms(old: &NormalizedSbom, new: &NormalizedSbom) -> Self {
        Self {
            old_hash: old.content_hash,
            new_hash: new.content_hash,
        }
    }
}

/// Section-level hashes for incremental change detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHashes {
    /// Hash of all components
    pub components: u64,
    /// Hash of all dependency edges
    pub dependencies: u64,
    /// Hash of all licenses
    pub licenses: u64,
    /// Hash of all vulnerabilities
    pub vulnerabilities: u64,
}

impl SectionHashes {
    /// Compute section hashes for an SBOM.
    ///
    /// CORRECTNESS CONTRACT: each section hash must cover EVERY input its
    /// section computer reads — `diff_sections` splices the previous pair's
    /// section verbatim whenever a hash is unchanged, so an uncovered field
    /// silently serves a stale diff (a vulnerability moving between
    /// components and an edge scope flip both did exactly that). A hash that
    /// covers too much only costs a spurious recompute; one that covers too
    /// little is a correctness bug.
    ///
    /// Hashes are order-sensitive by design: reordering only ever produces a
    /// false "changed", which is safe.
    #[must_use]
    pub fn from_sbom(sbom: &NormalizedSbom) -> Self {
        use std::collections::hash_map::DefaultHasher;

        // Component hash
        let mut hasher = DefaultHasher::new();
        for (id, comp) in &sbom.components {
            id.hash(&mut hasher);
            comp.name.hash(&mut hasher);
            comp.version.hash(&mut hasher);
            comp.content_hash.hash(&mut hasher);
        }
        let components = hasher.finish();

        // Dependencies hash: every field of the DependencyChangeComputer's
        // edge key, including scope. Enums hash by discriminant (plus the
        // payload for `Other`) to keep the per-edge loop allocation-free.
        let mut hasher = DefaultHasher::new();
        for edge in &sbom.edges {
            edge.from.hash(&mut hasher);
            edge.to.hash(&mut hasher);
            std::mem::discriminant(&edge.relationship).hash(&mut hasher);
            if let crate::model::DependencyType::Other(other) = &edge.relationship {
                other.hash(&mut hasher);
            }
            edge.scope
                .as_ref()
                .map(std::mem::discriminant)
                .hash(&mut hasher);
        }
        let dependencies = hasher.finish();

        // Licenses hash: the LicenseChangeComputer attributes declared
        // licenses to their owning component, so the owner is part of the
        // section content — without it, a license moving between components
        // leaves the hash unchanged.
        let mut hasher = DefaultHasher::new();
        for (id, comp) in &sbom.components {
            for lic in &comp.licenses.declared {
                id.hash(&mut hasher);
                lic.expression.hash(&mut hasher);
            }
        }
        let licenses = hasher.finish();

        // Vulnerabilities hash: covers the fields VulnerabilityDetail and
        // VexStatusChange are built from — owning component, severity, CVSS,
        // KEV/EPSS, and the effective VEX source (per-vuln falling back to
        // per-component, mirroring VulnerabilityDetail::from_ref).
        //
        // Two inputs are deliberately covered elsewhere: component_depth
        // derives from edges + the component set, so the engine reruns the
        // vulnerability computer whenever the dependencies or components
        // sections are dirty; and the remaining textual detail fields
        // (source, CWEs, description, remediation, published, KEV dates) are
        // part of Component::content_hash, which feeds the components hash
        // above — the same rerun rule catches them.
        //
        // Enum fields hash by discriminant to keep this loop allocation-free.
        let mut hasher = DefaultHasher::new();
        for (id, comp) in &sbom.components {
            for vuln in &comp.vulnerabilities {
                id.hash(&mut hasher);
                vuln.id.hash(&mut hasher);
                vuln.severity
                    .as_ref()
                    .map(std::mem::discriminant)
                    .hash(&mut hasher);
                vuln.max_cvss_score().map(f32::to_bits).hash(&mut hasher);
                vuln.is_kev.hash(&mut hasher);
                vuln.epss_score.map(f64::to_bits).hash(&mut hasher);
                let vex = vuln.vex_status.as_ref().or(comp.vex_status.as_ref());
                vex.map(|v| std::mem::discriminant(&v.status)).hash(&mut hasher);
                vex.and_then(|v| v.justification.as_ref().map(std::mem::discriminant))
                    .hash(&mut hasher);
                vex.and_then(|v| v.impact_statement.as_deref())
                    .hash(&mut hasher);
            }
        }
        let vulnerabilities = hasher.finish();

        Self {
            components,
            dependencies,
            licenses,
            vulnerabilities,
        }
    }

    /// Check which sections differ between two hash sets.
    #[must_use]
    pub const fn changed_sections(&self, other: &Self) -> ChangedSections {
        ChangedSections {
            components: self.components != other.components,
            dependencies: self.dependencies != other.dependencies,
            licenses: self.licenses != other.licenses,
            vulnerabilities: self.vulnerabilities != other.vulnerabilities,
        }
    }
}

/// Indicates which sections changed between two SBOMs.
#[derive(Debug, Clone, Default)]
pub struct ChangedSections {
    pub components: bool,
    pub dependencies: bool,
    pub licenses: bool,
    pub vulnerabilities: bool,
}

impl ChangedSections {
    /// Create a `ChangedSections` with all sections marked as changed.
    #[must_use]
    pub const fn all_changed() -> Self {
        Self {
            components: true,
            dependencies: true,
            licenses: true,
            vulnerabilities: true,
        }
    }

    /// Check if any section changed.
    #[must_use]
    pub const fn any(&self) -> bool {
        self.components || self.dependencies || self.licenses || self.vulnerabilities
    }

    /// Check if all sections changed.
    #[must_use]
    pub const fn all(&self) -> bool {
        self.components && self.dependencies && self.licenses && self.vulnerabilities
    }

    /// Count how many sections changed.
    #[must_use]
    pub fn count(&self) -> usize {
        [
            self.components,
            self.dependencies,
            self.licenses,
            self.vulnerabilities,
        ]
        .iter()
        .filter(|&&b| b)
        .count()
    }
}

// ============================================================================
// Cached Entry
// ============================================================================

/// A cached diff result with metadata.
#[derive(Debug, Clone)]
pub struct CachedDiffResult {
    /// The diff result
    pub result: Arc<DiffResult>,
    /// When this was computed
    pub computed_at: Instant,
    /// Section hashes from old SBOM
    pub old_hashes: SectionHashes,
    /// Section hashes from new SBOM
    pub new_hashes: SectionHashes,
}

impl CachedDiffResult {
    /// Create a new cached result.
    #[must_use]
    pub fn new(
        result: Arc<DiffResult>,
        old_hashes: SectionHashes,
        new_hashes: SectionHashes,
    ) -> Self {
        Self {
            result,
            computed_at: Instant::now(),
            old_hashes,
            new_hashes,
        }
    }

    /// Check if this entry is still valid (not expired).
    #[must_use]
    pub fn is_valid(&self, ttl: Duration) -> bool {
        self.computed_at.elapsed() < ttl
    }

    /// Get age of this cache entry.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.computed_at.elapsed()
    }
}

// ============================================================================
// Diff Cache
// ============================================================================

/// Configuration for the diff cache.
#[derive(Debug, Clone)]
pub struct DiffCacheConfig {
    /// Maximum number of entries to cache
    pub max_entries: usize,
    /// Time-to-live for cache entries
    pub ttl: Duration,
}

impl Default for DiffCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100,
            ttl: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Thread-safe cache for diff results.
///
/// Supports both full result caching and incremental computation
/// when only some sections change.
pub struct DiffCache {
    /// Full result cache (keyed by SBOM pair hashes)
    cache: RwLock<HashMap<DiffCacheKey, CachedDiffResult>>,
    /// Configuration
    config: DiffCacheConfig,
    /// Statistics (atomics so lookups never take a write lock)
    stats: AtomicCacheStats,
}

/// Lock-free statistics storage; `get()` previously took the map's WRITE
/// lock (to bump a never-read per-entry hit counter) plus a stats write
/// lock, serializing all readers.
#[derive(Debug, Default)]
struct AtomicCacheStats {
    lookups: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    incremental_hits: AtomicU64,
    evictions: AtomicU64,
    time_saved_ms: AtomicU64,
}

impl AtomicCacheStats {
    fn snapshot(&self) -> CacheStats {
        CacheStats {
            lookups: self.lookups.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            incremental_hits: self.incremental_hits.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            time_saved_ms: self.time_saved_ms.load(Ordering::Relaxed),
        }
    }
}

/// Statistics for cache performance.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total cache lookups
    pub lookups: u64,
    /// Exact cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Incremental computations (partial cache hit)
    pub incremental_hits: u64,
    /// Entries evicted (capacity evictions plus bulk purges of expired
    /// entries at capacity, so a single put can add more than one)
    pub evictions: u64,
    /// Total computation time saved (estimated)
    pub time_saved_ms: u64,
}

impl CacheStats {
    /// Get the cache hit rate.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            (self.hits + self.incremental_hits) as f64 / self.lookups as f64
        }
    }
}

impl DiffCache {
    /// Create a new diff cache with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DiffCacheConfig::default())
    }

    /// Create a new diff cache with custom configuration.
    #[must_use]
    pub fn with_config(config: DiffCacheConfig) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            config,
            stats: AtomicCacheStats::default(),
        }
    }

    /// Look up a cached result.
    ///
    /// Returns `Some` if an exact match is found and still valid.
    pub fn get(&self, key: &DiffCacheKey) -> Option<Arc<DiffResult>> {
        let result = {
            let cache = self.cache.read().expect("cache lock poisoned");
            cache.get(key).and_then(|entry| {
                entry
                    .is_valid(self.config.ttl)
                    .then(|| Arc::clone(&entry.result))
            })
        };

        self.stats.lookups.fetch_add(1, Ordering::Relaxed);
        if let Some(ref result) = result {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            self.stats
                .time_saved_ms
                .fetch_add(Self::estimate_computation_time(result), Ordering::Relaxed);
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Store a result in the cache.
    pub fn put(
        &self,
        key: DiffCacheKey,
        result: Arc<DiffResult>,
        old_hashes: SectionHashes,
        new_hashes: SectionHashes,
    ) {
        let mut cache = self.cache.write().expect("cache lock poisoned");

        // Overwriting an existing key needs no capacity; previously it still
        // evicted an unrelated oldest entry first.
        if !cache.contains_key(&key) && cache.len() >= self.config.max_entries {
            // Expired entries occupy capacity but serve no one — drop them
            // before evicting live entries.
            let before = cache.len();
            cache.retain(|_, entry| entry.is_valid(self.config.ttl));
            let expired = before - cache.len();
            if expired > 0 {
                self.stats
                    .evictions
                    .fetch_add(expired as u64, Ordering::Relaxed);
            }

            while cache.len() >= self.config.max_entries {
                if let Some(oldest_key) = Self::find_oldest_entry(&cache) {
                    cache.remove(&oldest_key);
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                } else {
                    break;
                }
            }
        }

        cache.insert(key, CachedDiffResult::new(result, old_hashes, new_hashes));
    }

    /// Find the oldest cache entry.
    fn find_oldest_entry(cache: &HashMap<DiffCacheKey, CachedDiffResult>) -> Option<DiffCacheKey> {
        cache
            .iter()
            .max_by_key(|(_, entry)| entry.age())
            .map(|(key, _)| key.clone())
    }

    /// Estimate computation time based on result size.
    fn estimate_computation_time(result: &DiffResult) -> u64 {
        // Rough estimate: 1ms per 10 components
        let component_count = result.components.added.len()
            + result.components.removed.len()
            + result.components.modified.len();
        (component_count / 10).max(1) as u64
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        self.stats.snapshot()
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.clear();
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.read().expect("cache lock poisoned").len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.read().expect("cache lock poisoned").is_empty()
    }
}

impl Default for DiffCache {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Incremental Diff Engine
// ============================================================================

/// Metadata about the last diffed pair, used for incremental updates.
struct LastDiffMeta {
    /// Cache key of the last diffed pair
    key: DiffCacheKey,
    /// Section hashes from the last pair's old SBOM
    old_hashes: SectionHashes,
    /// Section hashes from the last pair's new SBOM
    new_hashes: SectionHashes,
}

/// A diff engine wrapper that supports incremental computation and caching.
///
/// Wraps the standard `DiffEngine` and adds:
/// - Result caching for repeated comparisons
/// - Section-level change detection
/// - Incremental recomputation for partial changes
pub struct IncrementalDiffEngine {
    /// The underlying diff engine
    engine: DiffEngine,
    /// Result cache
    cache: DiffCache,
    /// Track previous computation for incremental updates
    last_diff: RwLock<Option<LastDiffMeta>>,
}

impl IncrementalDiffEngine {
    /// Create a new incremental diff engine.
    #[must_use]
    pub fn new(engine: DiffEngine) -> Self {
        Self {
            engine,
            cache: DiffCache::new(),
            last_diff: RwLock::new(None),
        }
    }

    /// Create with custom cache configuration.
    #[must_use]
    pub fn with_cache_config(engine: DiffEngine, config: DiffCacheConfig) -> Self {
        Self {
            engine,
            cache: DiffCache::with_config(config),
            last_diff: RwLock::new(None),
        }
    }

    /// Perform a diff, using cache when possible.
    ///
    /// Returns the diff result and metadata about cache usage.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying diff computation fails.
    pub fn diff(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
    ) -> Result<IncrementalDiffResult, SbomDiffError> {
        let start = Instant::now();

        // Hand-built SBOMs carry content_hash == 0 (the documented "unset"
        // state the engine's identical-SBOM short-circuit also respects).
        // Every such pair would collide on the (0,0) cache key and be served
        // each other's cached results, and the last-pair splice base would be
        // unidentifiable — bypass the incremental machinery entirely.
        if old.content_hash == 0 || new.content_hash == 0 {
            let result = self.engine.diff(old, new)?;
            return Ok(IncrementalDiffResult {
                result: Arc::new(result),
                cache_hit: CacheHitType::Miss,
                sections_recomputed: ChangedSections::all_changed(),
                computation_time: start.elapsed(),
            });
        }

        let cache_key = DiffCacheKey::from_sboms(old, new);

        // Check for exact cache hit — shared, not deep-cloned back out.
        if let Some(mut cached) = self.cache.get(&cache_key) {
            // Day-count fields embed the day they were computed; a hit
            // across midnight would serve yesterday's counts. The clone
            // only happens when a count actually changed (rare).
            if cached.day_counts_stale() {
                Arc::make_mut(&mut cached).refresh_derived_day_counts();
            }
            return Ok(IncrementalDiffResult {
                result: cached,
                cache_hit: CacheHitType::Full,
                sections_recomputed: ChangedSections::default(),
                computation_time: start.elapsed(),
            });
        }

        // Compute section hashes
        let old_hashes = SectionHashes::from_sbom(old);
        let new_hashes = SectionHashes::from_sbom(new);

        // Check for incremental opportunity against the last diffed pair
        let (changed, prev_key) = {
            let last = self.last_diff.read().expect("last_diff lock poisoned");
            match &*last {
                Some(meta) => {
                    let old_changed = old_hashes != meta.old_hashes;
                    let new_changed = new_hashes != meta.new_hashes;

                    if !old_changed && !new_changed {
                        // Nothing changed, but we don't have the result cached
                        // This shouldn't normally happen, but fall through to full compute
                        (None, None)
                    } else {
                        (
                            Some(
                                meta.old_hashes
                                    .changed_sections(&old_hashes)
                                    .or(&meta.new_hashes.changed_sections(&new_hashes)),
                            ),
                            Some(meta.key.clone()),
                        )
                    }
                }
                None => (None, None),
            }
        };

        // Section-selective or full computation
        let (result, cache_hit, sections_recomputed) = if let Some(ref changed) = changed
            && let Some(ref prev_key) = prev_key
            && !changed.all()
            && changed.any()
        {
            // Change detection is relative to the last diffed pair, so only
            // that exact pair's cached result is a valid splice base
            if let Some(prev_result) = self.find_previous_result(prev_key) {
                match self.engine.diff_sections(old, new, changed, &prev_result) {
                    Ok(result) => (result, CacheHitType::Partial, changed.clone()),
                    Err(_) => {
                        // Fall back to full computation on diff_sections errors
                        let result = self.engine.diff(old, new)?;
                        (result, CacheHitType::Miss, ChangedSections::all_changed())
                    }
                }
            } else {
                // Last pair's entry was evicted or expired — full computation
                let result = self.engine.diff(old, new)?;
                (result, CacheHitType::Miss, ChangedSections::all_changed())
            }
        } else {
            // Either no change detection possible, or all sections changed — full computation
            let result = self.engine.diff(old, new)?;
            let sections = changed.unwrap_or_else(ChangedSections::all_changed);
            (result, CacheHitType::Miss, sections)
        };

        // Track incremental hits in cache stats
        if cache_hit == CacheHitType::Partial {
            self.cache
                .stats
                .incremental_hits
                .fetch_add(1, Ordering::Relaxed);
        }

        // Partial splices reuse cached vulnerability sections, which carry
        // day counts from when the splice base was computed.
        let mut result = result;
        if cache_hit == CacheHitType::Partial {
            result.refresh_derived_day_counts();
        }

        // Cache the result: Arc hand-off, no deep clone of the DiffResult.
        let result = Arc::new(result);
        self.cache.put(
            cache_key.clone(),
            Arc::clone(&result),
            old_hashes.clone(),
            new_hashes.clone(),
        );

        // Update last diff metadata
        *self.last_diff.write().expect("last_diff lock poisoned") = Some(LastDiffMeta {
            key: cache_key,
            old_hashes,
            new_hashes,
        });

        Ok(IncrementalDiffResult {
            result,
            cache_hit,
            sections_recomputed,
            computation_time: start.elapsed(),
        })
    }

    /// Find the last diffed pair's cached result to use as a base for
    /// incremental recomputation.
    ///
    /// Section change detection is computed against the last diffed pair, so
    /// only that exact pair's cached entry is a valid splice base.
    fn find_previous_result(&self, key: &DiffCacheKey) -> Option<Arc<DiffResult>> {
        let cache = self.cache.cache.read().ok()?;
        cache
            .get(key)
            .filter(|e| e.is_valid(self.cache.config.ttl))
            .map(|e| Arc::clone(&e.result))
    }

    /// Get the underlying engine.
    pub const fn engine(&self) -> &DiffEngine {
        &self.engine
    }

    /// Get cache statistics.
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

impl ChangedSections {
    /// Combine two `ChangedSections` with OR logic.
    const fn or(&self, other: &Self) -> Self {
        Self {
            components: self.components || other.components,
            dependencies: self.dependencies || other.dependencies,
            licenses: self.licenses || other.licenses,
            vulnerabilities: self.vulnerabilities || other.vulnerabilities,
        }
    }
}

/// Type of cache hit achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheHitType {
    /// Full result was in cache
    Full,
    /// Partial cache hit, some sections reused
    Partial,
    /// No cache hit, full computation required
    Miss,
}

/// Result of an incremental diff operation.
#[derive(Debug)]
pub struct IncrementalDiffResult {
    /// The diff result, shared with the cache entry (no deep clone on
    /// either the miss or the full-hit path)
    pub result: Arc<DiffResult>,
    /// Type of cache hit
    pub cache_hit: CacheHitType,
    /// Which sections were recomputed (false = reused from cache)
    pub sections_recomputed: ChangedSections,
    /// Time taken for this operation
    pub computation_time: Duration,
}

impl IncrementalDiffResult {
    /// Get the diff result.
    pub fn into_result(self) -> DiffResult {
        // The cache usually holds the other reference; clone only then.
        Arc::try_unwrap(self.result).unwrap_or_else(|shared| (*shared).clone())
    }

    /// Check if this was a cache hit.
    #[must_use]
    pub fn was_cached(&self) -> bool {
        self.cache_hit == CacheHitType::Full
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DocumentMetadata;

    fn make_sbom(name: &str, components: &[&str]) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for comp_name in components {
            let comp = crate::model::Component::new(
                comp_name.to_string(),
                format!("{}-{}", name, comp_name),
            );
            sbom.add_component(comp);
        }
        // Ensure unique content hash
        sbom.content_hash = {
            use std::collections::hash_map::DefaultHasher;
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            for c in components {
                c.hash(&mut hasher);
            }
            hasher.finish()
        };
        sbom
    }

    #[test]
    fn test_section_hashes() {
        let sbom1 = make_sbom("test1", &["a", "b", "c"]);
        let sbom2 = make_sbom("test2", &["a", "b", "c"]);
        let sbom3 = make_sbom("test3", &["a", "b", "d"]);

        let hash1 = SectionHashes::from_sbom(&sbom1);
        let hash2 = SectionHashes::from_sbom(&sbom2);
        let hash3 = SectionHashes::from_sbom(&sbom3);

        // Different SBOMs with same components should have different component hashes
        // (because canonical IDs differ)
        assert_ne!(hash1.components, hash2.components);

        // Different components should definitely differ
        assert_ne!(hash1.components, hash3.components);
    }

    #[test]
    fn test_changed_sections() {
        let hash1 = SectionHashes {
            components: 100,
            dependencies: 200,
            licenses: 300,
            vulnerabilities: 400,
        };

        let hash2 = SectionHashes {
            components: 100,
            dependencies: 200,
            licenses: 999, // Changed
            vulnerabilities: 400,
        };

        let changed = hash1.changed_sections(&hash2);
        assert!(!changed.components);
        assert!(!changed.dependencies);
        assert!(changed.licenses);
        assert!(!changed.vulnerabilities);
        assert_eq!(changed.count(), 1);
    }

    #[test]
    fn test_diff_cache_basic() {
        let cache = DiffCache::new();
        let key = DiffCacheKey {
            old_hash: 123,
            new_hash: 456,
        };

        // Initially empty
        assert!(cache.get(&key).is_none());
        assert!(cache.is_empty());

        // Add a result
        let result = DiffResult::new();
        let hashes = SectionHashes {
            components: 0,
            dependencies: 0,
            licenses: 0,
            vulnerabilities: 0,
        };
        cache.put(key.clone(), Arc::new(result), hashes.clone(), hashes.clone());

        // Should be retrievable
        assert!(cache.get(&key).is_some());
        assert_eq!(cache.len(), 1);

        // Stats should show 1 hit, 1 miss
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_diff_cache_eviction() {
        let config = DiffCacheConfig {
            max_entries: 3,
            ttl: Duration::from_secs(3600),
        };
        let cache = DiffCache::with_config(config);

        let hashes = SectionHashes {
            components: 0,
            dependencies: 0,
            licenses: 0,
            vulnerabilities: 0,
        };

        // Add 5 entries, should only keep 3
        for i in 0..5 {
            let key = DiffCacheKey {
                old_hash: i,
                new_hash: i + 100,
            };
            cache.put(key, Arc::new(DiffResult::new()), hashes.clone(), hashes.clone());
        }

        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_cache_hit_type() {
        assert_eq!(CacheHitType::Full, CacheHitType::Full);
        assert_ne!(CacheHitType::Full, CacheHitType::Miss);
    }

    #[test]
    fn test_incremental_diff_engine() {
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);

        let old = make_sbom("old", &["a", "b", "c"]);
        let new = make_sbom("new", &["a", "b", "d"]);

        // First diff should be a miss
        let result1 = incremental.diff(&old, &new).expect("diff should succeed");
        assert_eq!(result1.cache_hit, CacheHitType::Miss);

        // Same diff should be a hit
        let result2 = incremental.diff(&old, &new).expect("diff should succeed");
        assert_eq!(result2.cache_hit, CacheHitType::Full);

        // Stats should reflect this
        let stats = incremental.cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_changed_sections_all_changed() {
        let all = ChangedSections::all_changed();
        assert!(all.components);
        assert!(all.dependencies);
        assert!(all.licenses);
        assert!(all.vulnerabilities);
        assert!(all.all());
        assert!(all.any());
        assert_eq!(all.count(), 4);
    }

    #[test]
    fn test_changed_sections_or_combine() {
        let a = ChangedSections {
            components: true,
            dependencies: false,
            licenses: false,
            vulnerabilities: false,
        };
        let b = ChangedSections {
            components: false,
            dependencies: false,
            licenses: true,
            vulnerabilities: false,
        };
        let combined = a.or(&b);
        assert!(combined.components);
        assert!(!combined.dependencies);
        assert!(combined.licenses);
        assert!(!combined.vulnerabilities);
        assert_eq!(combined.count(), 2);
    }

    #[test]
    fn test_diff_sections_selective_recomputation() {
        // Test that diff_sections on DiffEngine produces a valid result
        // when only a subset of sections are marked as changed
        let engine = DiffEngine::new();
        let old = make_sbom("old", &["a", "b", "c"]);
        let new = make_sbom("new", &["a", "b", "d"]);

        // Full diff first to get a baseline
        let full_result = engine.diff(&old, &new).expect("diff should succeed");

        // Now do a section-selective diff recomputing only components
        let sections = ChangedSections {
            components: true,
            dependencies: false,
            licenses: false,
            vulnerabilities: false,
        };
        let selective_result = engine
            .diff_sections(&old, &new, &sections, &full_result)
            .expect("diff_sections should succeed");

        // Components should be freshly computed — same as full diff
        assert_eq!(
            selective_result.components.added.len(),
            full_result.components.added.len()
        );
        assert_eq!(
            selective_result.components.removed.len(),
            full_result.components.removed.len()
        );
        assert_eq!(
            selective_result.components.modified.len(),
            full_result.components.modified.len()
        );

        // Dependencies were not recomputed — should be preserved from cached
        assert_eq!(
            selective_result.dependencies.added.len(),
            full_result.dependencies.added.len()
        );
        assert_eq!(
            selective_result.dependencies.removed.len(),
            full_result.dependencies.removed.len()
        );
    }

    #[test]
    fn test_diff_sections_all_changed_matches_full_diff() {
        // When all sections are marked as changed, diff_sections should produce
        // the same result as a full diff
        let engine = DiffEngine::new();
        let old = make_sbom("old", &["a", "b", "c"]);
        let new = make_sbom("new", &["a", "b", "d"]);

        let full_result = engine.diff(&old, &new).expect("diff should succeed");
        let sections = ChangedSections::all_changed();
        let selective_result = engine
            .diff_sections(&old, &new, &sections, &DiffResult::new())
            .expect("diff_sections should succeed");

        assert_eq!(
            selective_result.components.added.len(),
            full_result.components.added.len()
        );
        assert_eq!(
            selective_result.components.removed.len(),
            full_result.components.removed.len()
        );
        assert_eq!(
            selective_result.vulnerabilities.introduced.len(),
            full_result.vulnerabilities.introduced.len()
        );
    }

    #[test]
    fn test_incremental_partial_change_detection() {
        // Simulate the incremental path: diff two SBOMs, then diff again
        // with a slightly different new SBOM that shares the same old SBOM.
        // This tests that the engine detects partial changes and attempts
        // section-selective diff.
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);

        let old = make_sbom("old", &["a", "b", "c"]);
        let new1 = make_sbom("new1", &["a", "b", "d"]);

        // First diff populates the last-diff metadata
        let result1 = incremental.diff(&old, &new1).expect("diff should succeed");
        assert_eq!(result1.cache_hit, CacheHitType::Miss);

        // Second diff with different SBOMs (different content hashes = no exact cache hit)
        // but the last-diff metadata is now set, so change detection runs
        let new2 = make_sbom("new2", &["a", "b", "e"]);
        let result2 = incremental.diff(&old, &new2).expect("diff should succeed");

        // This should either be a Partial hit (if section-selective kicked in)
        // or a Miss (if all sections changed). Either way, it should produce a valid result.
        assert!(
            result2.cache_hit == CacheHitType::Partial || result2.cache_hit == CacheHitType::Miss
        );
        // The result should have been computed successfully regardless
        assert!(result2.sections_recomputed.any());
    }

    #[test]
    fn test_find_previous_result_empty_cache() {
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);
        let key = DiffCacheKey {
            old_hash: 1,
            new_hash: 2,
        };
        // With an empty cache, find_previous_result should return None
        assert!(incremental.find_previous_result(&key).is_none());
    }

    #[test]
    fn test_find_previous_result_after_diff() {
        let engine = DiffEngine::new();
        let incremental = IncrementalDiffEngine::new(engine);

        let old = make_sbom("old", &["a", "b"]);
        let new = make_sbom("new", &["a", "c"]);

        // Populate the cache
        let _ = incremental.diff(&old, &new).expect("diff should succeed");

        // The diffed pair's key should be retrievable; an unrelated key should not
        let key = DiffCacheKey::from_sboms(&old, &new);
        assert!(incremental.find_previous_result(&key).is_some());
        let other_key = DiffCacheKey {
            old_hash: key.old_hash.wrapping_add(1),
            new_hash: key.new_hash,
        };
        assert!(incremental.find_previous_result(&other_key).is_none());
    }

    fn assert_sections_match(actual: &DiffResult, expected: &DiffResult) {
        assert_eq!(
            actual.components.added.len(),
            expected.components.added.len()
        );
        assert_eq!(
            actual.components.removed.len(),
            expected.components.removed.len()
        );
        assert_eq!(
            actual.components.modified.len(),
            expected.components.modified.len()
        );
        assert_eq!(
            actual.licenses.new_licenses.len(),
            expected.licenses.new_licenses.len()
        );
        assert_eq!(
            actual.licenses.removed_licenses.len(),
            expected.licenses.removed_licenses.len()
        );
        assert_eq!(
            actual.vulnerabilities.introduced.len(),
            expected.vulnerabilities.introduced.len()
        );
        assert_eq!(
            actual.vulnerabilities.resolved.len(),
            expected.vulnerabilities.resolved.len()
        );
        assert_eq!(
            actual.dependencies.added.len(),
            expected.dependencies.added.len()
        );
        assert_eq!(
            actual.dependencies.removed.len(),
            expected.dependencies.removed.len()
        );
    }

    #[test]
    fn test_no_cross_pair_section_splice() {
        // Note: DiffEngine::diff has no constructible Err path today, so the
        // Result-propagation change is covered at the type level only.
        let incremental = IncrementalDiffEngine::new(DiffEngine::new());

        let a_old = make_sbom("a-old", &["a", "b", "c"]);
        let a_new = make_sbom("a-new", &["a", "b", "d"]);
        let b_old = make_sbom("b-old", &["x", "y"]);
        let b_new = make_sbom("b-new", &["x", "z", "w"]);

        // Pair A first, then pair B through the same engine
        let _ = incremental
            .diff(&a_old, &a_new)
            .expect("diff should succeed");
        let b_result = incremental
            .diff(&b_old, &b_new)
            .expect("diff should succeed");

        // Every section of B's result must match a from-scratch full diff —
        // no sections spliced in from pair A's cached result
        let fresh = DiffEngine::new()
            .diff(&b_old, &b_new)
            .expect("diff should succeed");
        assert_sections_match(&b_result.result, &fresh);
    }

    #[test]
    fn test_partial_splice_uses_last_pair_base() {
        let incremental = IncrementalDiffEngine::new(DiffEngine::new());

        let s0 = make_sbom("s0", &["a", "b", "c"]);
        let s1 = make_sbom("s1", &["a", "b", "d"]);
        let s2 = make_sbom("s2", &["a", "b", "e"]);

        // s0->s1 first so that s0->s2 only differs in the components section
        let _ = incremental.diff(&s0, &s1).expect("diff should succeed");
        let result = incremental.diff(&s0, &s2).expect("diff should succeed");
        assert_eq!(result.cache_hit, CacheHitType::Partial);

        // The spliced result must match a from-scratch full diff of s0->s2
        let fresh = DiffEngine::new()
            .diff(&s0, &s2)
            .expect("diff should succeed");
        assert_sections_match(&result.result, &fresh);
    }

    // ------------------------------------------------------------------
    // Stale-splice regressions: every scenario below previously produced a
    // Partial hit whose section hash missed the change, splicing a stale
    // section from the previous pair's result. Each test primes the engine
    // with (base, v1), diffs (base, v2), and requires the result to be
    // byte-equivalent (via serde) to a from-scratch full diff.
    // ------------------------------------------------------------------

    use crate::model::{
        Component, DependencyEdge, DependencyScope, DependencyType, LicenseExpression,
        Organization, Severity, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource,
    };

    fn rich_comp(name: &str, version: &str) -> Component {
        let mut c = Component::new(name.to_string(), format!("pkg:npm/{name}@{version}"));
        c.version = Some(version.to_string());
        c
    }

    fn with_vuln(mut c: Component, id: &str, severity: Severity) -> Component {
        let mut v = VulnerabilityRef::new(id.to_string(), VulnerabilitySource::Osv);
        v.severity = Some(severity);
        c.vulnerabilities.push(v);
        c
    }

    fn with_license(mut c: Component, expr: &str) -> Component {
        c.licenses.add_declared(LicenseExpression::new(expr.to_string()));
        c
    }

    fn rich_sbom(comps: Vec<Component>, edges: Vec<DependencyEdge>) -> NormalizedSbom {
        let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
        for mut c in comps {
            c.calculate_content_hash();
            sbom.add_component(c);
        }
        for e in edges {
            sbom.add_edge(e);
        }
        sbom.calculate_content_hash();
        sbom
    }

    fn edge(from: &Component, to: &Component, scope: Option<DependencyScope>) -> DependencyEdge {
        let mut e = DependencyEdge::new(
            from.canonical_id.clone(),
            to.canonical_id.clone(),
            DependencyType::DependsOn,
        );
        e.scope = scope;
        e
    }

    /// Prime with (base, v1), diff (base, v2), and require equivalence with
    /// a from-scratch full diff of (base, v2).
    fn assert_incremental_matches_full<F>(engine: F, base: &NormalizedSbom, v1: &NormalizedSbom, v2: &NormalizedSbom)
    where
        F: Fn() -> DiffEngine,
    {
        let incremental = IncrementalDiffEngine::new(engine());
        let _ = incremental.diff(base, v1).expect("prime diff");
        let got = incremental.diff(base, v2).expect("target diff");
        assert_eq!(
            got.cache_hit,
            CacheHitType::Partial,
            "test fixture must exercise the partial-splice path \
             (recomputed: {:?})",
            got.sections_recomputed
        );

        let fresh = engine().diff(base, v2).expect("full diff");
        assert_eq!(
            serde_json::to_value(got.result.as_ref()).expect("serialize incremental"),
            serde_json::to_value(&fresh).expect("serialize full"),
            "incremental result diverged from a from-scratch full diff"
        );
    }

    #[test]
    fn vulnerability_moving_between_components_is_not_spliced_stale() {
        let base = rich_sbom(
            vec![
                with_vuln(rich_comp("liba", "1.0.0"), "CVE-2024-0001", Severity::High),
                rich_comp("libb", "1.0.0"),
                rich_comp("app", "1.0.0"),
            ],
            vec![],
        );
        let v1 = rich_sbom(
            vec![
                with_vuln(rich_comp("liba", "1.0.0"), "CVE-2024-0001", Severity::High),
                rich_comp("libb", "1.0.0"),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        // Same vuln id, different owning component: the old id-only section
        // hash was identical to v1's, splicing v1's stale attribution.
        let v2 = rich_sbom(
            vec![
                rich_comp("liba", "1.0.0"),
                with_vuln(rich_comp("libb", "1.0.0"), "CVE-2024-0001", Severity::High),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    #[test]
    fn vulnerability_severity_change_is_not_spliced_stale() {
        let base = rich_sbom(
            vec![
                with_vuln(rich_comp("liba", "1.0.0"), "CVE-2024-0002", Severity::Low),
                rich_comp("app", "1.0.0"),
            ],
            vec![],
        );
        let v1 = rich_sbom(
            vec![
                with_vuln(rich_comp("liba", "1.0.0"), "CVE-2024-0002", Severity::Low),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        let v2 = rich_sbom(
            vec![
                with_vuln(rich_comp("liba", "1.0.0"), "CVE-2024-0002", Severity::Critical),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    #[test]
    fn vex_status_change_is_not_spliced_stale() {
        let vex_comp = |state: Option<VexState>| {
            let mut c = rich_comp("liba", "1.0.0");
            let mut v =
                VulnerabilityRef::new("CVE-2024-0003".to_string(), VulnerabilitySource::Osv);
            v.severity = Some(Severity::High);
            v.vex_status = state.map(VexStatus::new);
            c.vulnerabilities.push(v);
            c
        };
        let base = rich_sbom(vec![vex_comp(None), rich_comp("app", "1.0.0")], vec![]);
        let v1 = rich_sbom(vec![vex_comp(None), rich_comp("app", "2.0.0")], vec![]);
        let v2 = rich_sbom(
            vec![
                vex_comp(Some(VexState::NotAffected)),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    #[test]
    fn license_moving_between_components_is_not_spliced_stale() {
        let base = rich_sbom(
            vec![
                with_license(rich_comp("liba", "1.0.0"), "MIT"),
                rich_comp("libb", "1.0.0"),
                rich_comp("app", "1.0.0"),
            ],
            vec![],
        );
        let v1 = rich_sbom(
            vec![
                with_license(rich_comp("liba", "1.0.0"), "MIT"),
                rich_comp("libb", "1.0.0"),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        // Same flattened expression sequence, different owner.
        let v2 = rich_sbom(
            vec![
                rich_comp("liba", "1.0.0"),
                with_license(rich_comp("libb", "1.0.0"), "MIT"),
                rich_comp("app", "2.0.0"),
            ],
            vec![],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    #[test]
    fn edge_scope_change_is_not_spliced_stale() {
        let a = rich_comp("a", "1.0.0");
        let b = rich_comp("b", "1.0.0");
        let base = rich_sbom(
            vec![a.clone(), b.clone()],
            vec![edge(&a, &b, Some(DependencyScope::Required))],
        );
        let a2 = rich_comp("a", "2.0.0");
        let v1 = rich_sbom(
            vec![a2.clone(), b.clone()],
            vec![edge(&a2, &b, Some(DependencyScope::Required))],
        );
        // Only the edge scope flips between v1 and v2: the old section hash
        // (from/to/relationship only) saw no change and spliced v1's empty
        // dependency diff.
        let v2 = rich_sbom(
            vec![a2.clone(), b.clone()],
            vec![edge(&a2, &b, Some(DependencyScope::Optional))],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    #[test]
    fn graph_changes_and_match_metrics_refresh_on_partial_hit() {
        let engine = || {
            DiffEngine::new().with_graph_diff(crate::diff::GraphDiffConfig::default())
        };
        let a = rich_comp("a", "1.0.0");
        let b = rich_comp("b", "1.0.0");
        let c = rich_comp("c", "1.0.0");
        let d = rich_comp("d", "1.0.0");
        let base = rich_sbom(vec![a.clone(), b.clone()], vec![edge(&a, &b, None)]);
        let v1 = rich_sbom(
            vec![a.clone(), b.clone(), c.clone()],
            vec![edge(&a, &b, None), edge(&a, &c, None)],
        );
        // v2 differs from v1 in components and edges: the graph diff and the
        // match metrics must be recomputed, not carried from (base, v1).
        let v2 = rich_sbom(
            vec![a.clone(), b.clone(), c.clone(), d.clone()],
            vec![edge(&a, &b, None), edge(&a, &c, None), edge(&b, &d, None)],
        );
        assert_incremental_matches_full(engine, &base, &v1, &v2);
    }

    /// Audit regression: every section computer consumes the component
    /// MATCHES, which derive from component content. A component-only change
    /// (rename with unchanged canonical id, so the edges — and the
    /// dependencies/licenses section hashes — are untouched) can flip a
    /// fuzzy match and with it the dependency and license diffs; those
    /// sections must rerun rather than splice stale.
    #[test]
    fn component_only_change_refreshes_match_dependent_sections() {
        let app = rich_comp("app", "1.0.0");
        // Fuzzy-matched counterpart of base's "libfoo": different purl (so
        // no exact-id match), identical name.
        let make_lib = |name: &str| {
            let mut c = Component::new(name.to_string(), "pkg:npm/libfoo-fork@1.0.0".to_string());
            c.version = Some("1.0.0".to_string());
            c.licenses
                .add_declared(LicenseExpression::new("MIT".to_string()));
            c
        };
        let base_lib = with_license(rich_comp("libfoo", "1.0.0"), "MIT");

        let base = rich_sbom(
            vec![app.clone(), base_lib.clone()],
            vec![edge(&app, &base_lib, None)],
        );
        let v1_lib = make_lib("libfoo");
        let v1 = rich_sbom(
            vec![app.clone(), v1_lib.clone()],
            vec![edge(&app, &v1_lib, None)],
        );
        // v2: same canonical id (same purl-derived ref), renamed — the match
        // against base's "libfoo" breaks, so the edge and license diffs
        // change while the dependencies/licenses section hashes stay clean.
        let v2_lib = make_lib("totally-unrelated");
        let v2 = rich_sbom(
            vec![app.clone(), v2_lib.clone()],
            vec![edge(&app, &v2_lib, None)],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    /// Audit regression: VulnerabilityDetail carries component_depth,
    /// derived from edges — an EDGE-ONLY change (component set and
    /// vulnerability content untouched) must still rerun the vulnerability
    /// computer, or spliced details carry stale depths.
    #[test]
    fn edge_only_change_refreshes_vulnerability_depths() {
        let app = rich_comp("app", "1.0.0");
        let mid = rich_comp("mid", "1.0.0");
        let vulnerable = with_vuln(rich_comp("leaf", "1.0.0"), "CVE-2024-0009", Severity::High);
        let app2 = rich_comp("app", "2.0.0");

        // base/v1: leaf is a direct dependency (depth 1); mid is isolated.
        let base = rich_sbom(
            vec![app.clone(), mid.clone(), vulnerable.clone()],
            vec![edge(&app, &vulnerable, None)],
        );
        let v1 = rich_sbom(
            vec![app2.clone(), mid.clone(), vulnerable.clone()],
            vec![edge(&app2, &vulnerable, None)],
        );
        // v2: identical components, but leaf now sits behind mid (depth 2).
        let v2 = rich_sbom(
            vec![app2.clone(), mid.clone(), vulnerable.clone()],
            vec![edge(&app2, &mid, None), edge(&mid, &vulnerable, None)],
        );
        assert_incremental_matches_full(DiffEngine::new, &base, &v1, &v2);
    }

    #[test]
    fn zero_content_hash_sboms_bypass_the_cache() {
        // Hand-built SBOMs without calculate_content_hash() all carry hash 0
        // and previously collided on the (0,0) cache key: the second pair got
        // the first pair's result as a Full hit.
        let hand_built = |names: &[&str]| {
            let mut sbom = NormalizedSbom::new(DocumentMetadata::default());
            for name in names {
                sbom.add_component(Component::new((*name).to_string(), format!("ref-{name}")));
            }
            sbom
        };
        let incremental = IncrementalDiffEngine::new(DiffEngine::new());

        let first = incremental
            .diff(&hand_built(&["a", "b"]), &hand_built(&["a", "b", "c"]))
            .expect("first diff");
        assert_eq!(first.cache_hit, CacheHitType::Miss);

        let second = incremental
            .diff(&hand_built(&["x"]), &hand_built(&["x", "y", "z", "w"]))
            .expect("second diff");
        assert_eq!(
            second.cache_hit,
            CacheHitType::Miss,
            "zero-hash pairs must never be served from cache"
        );
        assert_eq!(second.result.summary.components_added, 3);
    }

    #[test]
    fn section_hashes_cover_all_section_computer_inputs() {
        // Direct sensitivity checks: each mutation must flip its section hash.
        let a = rich_comp("liba", "1.0.0");
        let b = rich_comp("libb", "1.0.0");

        // Edge scope
        let s1 = rich_sbom(
            vec![a.clone(), b.clone()],
            vec![edge(&a, &b, Some(DependencyScope::Required))],
        );
        let s2 = rich_sbom(
            vec![a.clone(), b.clone()],
            vec![edge(&a, &b, Some(DependencyScope::Optional))],
        );
        assert_ne!(
            SectionHashes::from_sbom(&s1).dependencies,
            SectionHashes::from_sbom(&s2).dependencies,
            "edge scope must be part of the dependencies hash"
        );

        // Vulnerability attribution
        let v1 = rich_sbom(
            vec![
                with_vuln(a.clone(), "CVE-1", Severity::High),
                b.clone(),
            ],
            vec![],
        );
        let v2 = rich_sbom(
            vec![
                a.clone(),
                with_vuln(b.clone(), "CVE-1", Severity::High),
            ],
            vec![],
        );
        assert_ne!(
            SectionHashes::from_sbom(&v1).vulnerabilities,
            SectionHashes::from_sbom(&v2).vulnerabilities,
            "the owning component must be part of the vulnerabilities hash"
        );

        // Severity
        let sev1 = rich_sbom(vec![with_vuln(a.clone(), "CVE-1", Severity::Low)], vec![]);
        let sev2 = rich_sbom(
            vec![with_vuln(a.clone(), "CVE-1", Severity::Critical)],
            vec![],
        );
        assert_ne!(
            SectionHashes::from_sbom(&sev1).vulnerabilities,
            SectionHashes::from_sbom(&sev2).vulnerabilities,
            "severity must be part of the vulnerabilities hash"
        );

        // License attribution
        let l1 = rich_sbom(
            vec![with_license(a.clone(), "MIT"), b.clone()],
            vec![],
        );
        let l2 = rich_sbom(
            vec![a.clone(), with_license(b.clone(), "MIT")],
            vec![],
        );
        assert_ne!(
            SectionHashes::from_sbom(&l1).licenses,
            SectionHashes::from_sbom(&l2).licenses,
            "the owning component must be part of the licenses hash"
        );
    }

    /// Cached results embed the day their day-count fields were computed;
    /// a cache hit across midnight must refresh them from the stored dates.
    #[test]
    fn day_count_refresh_corrects_stale_counts() {
        let mut detail = crate::diff::VulnerabilityDetail::from_ref(
            &VulnerabilityRef::new("CVE-2024-1111".to_string(), VulnerabilitySource::Osv),
            &rich_comp("liba", "1.0.0"),
        );
        detail.published_date = Some("2020-01-01".to_string());
        detail.days_since_published = Some(1); // stale: computed "long ago"
        detail.kev_due_date = Some("2030-01-01".to_string());
        detail.days_until_due = Some(9999); // stale

        let today = chrono::Utc::now().date_naive();
        assert!(detail.refresh_day_counts(today), "stale counts must change");
        let expected_since =
            (today - chrono::NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()).num_days();
        let expected_due =
            (chrono::NaiveDate::from_ymd_opt(2030, 1, 1).unwrap() - today).num_days();
        assert_eq!(detail.days_since_published, Some(expected_since));
        assert_eq!(detail.days_until_due, Some(expected_due));

        // Idempotent: a second refresh on the same day changes nothing.
        assert!(!detail.refresh_day_counts(today));

        // Producer/refresher parity: a FRESHLY computed KEV-bearing detail
        // must not read as stale (from_ref previously stored a
        // DateTime-truncated due-day count, one lower than the refresher's
        // date-granular value for midnight-UTC due dates — so every KEV
        // cache hit deep-cloned and hit/miss disagreed).
        let mut kev_vuln =
            VulnerabilityRef::new("CVE-2024-2222".to_string(), VulnerabilitySource::Osv);
        kev_vuln.is_kev = true;
        kev_vuln.kev_info = Some(crate::model::KevInfo::new(
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::days(30),
            "patch".to_string(),
        ));
        let mut fresh = crate::diff::VulnerabilityDetail::from_ref(
            &kev_vuln,
            &rich_comp("libb", "1.0.0"),
        );
        assert!(
            !fresh.refresh_day_counts(today),
            "fresh KEV day counts must already be date-granular consistent"
        );
    }

    #[test]
    fn component_hash_distinguishes_field_boundaries() {
        // Dropped license "MIT" + gained supplier "MIT" used to collide.
        let mut with_mit_license = rich_comp("x", "1.0.0");
        with_mit_license
            .licenses
            .add_declared(LicenseExpression::new("MIT".to_string()));
        with_mit_license.calculate_content_hash();

        let mut with_mit_supplier = rich_comp("x", "1.0.0");
        with_mit_supplier.supplier = Some(Organization::new("MIT".to_string()));
        with_mit_supplier.calculate_content_hash();

        assert_ne!(
            with_mit_license.content_hash, with_mit_supplier.content_hash,
            "field boundaries must be unambiguous in the content hash"
        );

        // Severity and VEX changes must be hash-visible.
        let low = {
            let mut c = with_vuln(rich_comp("y", "1.0.0"), "CVE-9", Severity::Low);
            c.calculate_content_hash();
            c
        };
        let critical = {
            let mut c = with_vuln(rich_comp("y", "1.0.0"), "CVE-9", Severity::Critical);
            c.calculate_content_hash();
            c
        };
        assert_ne!(low.content_hash, critical.content_hash);

        let vexed = {
            let mut c = with_vuln(rich_comp("y", "1.0.0"), "CVE-9", Severity::Low);
            c.vulnerabilities[0].vex_status = Some(VexStatus::new(VexState::NotAffected));
            c.calculate_content_hash();
            c
        };
        assert_ne!(low.content_hash, vexed.content_hash);

        // CVSS-only changes must be hash-visible: same id, same severity,
        // different base score.
        let cvss = |score: f32| {
            let mut c = with_vuln(rich_comp("z", "1.0.0"), "CVE-9", Severity::High);
            c.vulnerabilities[0].cvss.push(crate::model::CvssScore {
                version: crate::model::CvssVersion::V31,
                base_score: score,
                vector: None,
                exploitability_score: None,
                impact_score: None,
            });
            c.calculate_content_hash();
            c
        };
        assert_ne!(
            cvss(7.5).content_hash,
            cvss(8.0).content_hash,
            "CVSS base score must be part of the content hash"
        );

        // ML list framing: a training dataset and a performance metric with
        // the same payload used to collide byte-for-byte.
        use crate::model::{DatasetRef, MetricEntry, MlModelInfo};
        let with_training = {
            let mut c = rich_comp("m", "1.0.0");
            c.ml_model = Some(MlModelInfo {
                training_datasets: vec![DatasetRef {
                    reference: Some("a".to_string()),
                    name: None,
                    purl: None,
                }],
                ..MlModelInfo::default()
            });
            c.calculate_content_hash();
            c
        };
        let with_metric = {
            let mut c = rich_comp("m", "1.0.0");
            c.ml_model = Some(MlModelInfo {
                performance_metrics: vec![MetricEntry {
                    metric_type: Some("a".to_string()),
                    value: None,
                    slice: None,
                }],
                ..MlModelInfo::default()
            });
            c.calculate_content_hash();
            c
        };
        assert_ne!(
            with_training.content_hash, with_metric.content_hash,
            "ml list boundaries must be unambiguous in the content hash"
        );
    }
}
