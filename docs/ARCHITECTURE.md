# Architecture

## Overview
sbom-tools follows a linear pipeline that normalizes inputs, performs semantic
diffing and scoring, and renders the result through reports or the TUI.

```
SBOM/CBOM/AI-BOM files
  -> parsers (CycloneDX 1.4-1.7, SPDX 2.2/2.3, SPDX 3.0 JSON-LD; streaming for large files)
  -> NormalizedSbom (canonical model, incl. CryptoProperties)
  -> BomProfile detection (SBOM / CBOM / AI-BOM auto-detect)
  -> matching (PURL, alias, ecosystem, adaptive fuzzy, LSH index)
  -> diff engine (semantic + graph)
  -> DiffResult / QualityReport (profile-aware: Standard, CBOM, or AI-readiness scoring)
  -> reports (json/ndjson/sarif/oscal-json/html/markdown/csv/summary/table/side-by-side) or TUI
```

## Core Modules

- **cli** (`src/cli/`): Clap command handlers for diff, view, validate, quality, query, diff-multi, timeline, matrix, watch, enrich, tailor, merge, convert, license-check, verify, vex, cache, cra-docs, cra-standards-watch, config, completions, config-schema, and man.
- **config** (`src/config/`): Typed configuration with YAML/JSON support, presets, validation, and schema generation.
- **parsers** (`src/parsers/`): CycloneDX (1.4–1.7, JSON/XML) and SPDX (2.2/2.3 plus SPDX 3.0 JSON-LD via a separate `spdx3.rs` parser) format detection and parsing into NormalizedSbom. Includes a streaming parser for memory-efficient parsing of large files with progress callbacks; inputs are capped at 512 MB.
- **model** (`src/model/`): Canonical data model — NormalizedSbom, Component, CanonicalId, DocumentMetadata, Vulnerability, DependencyEdge, License, CryptoProperties, BomProfile. Includes CycloneDX 1.6/1.7 crypto types (CryptoAssetType, AlgorithmProperties, CertificateProperties, RelatedCryptoMaterialProperties, ProtocolProperties).
- **matching** (`src/matching/`): Multi-tier fuzzy matching for component alignment.
  - Exact PURL match, alias lookup, ecosystem-specific normalization, string similarity (Jaro-Winkler, Levenshtein).
  - Adaptive thresholds that adjust based on score distribution.
  - LSH (locality-sensitive hashing) index for fast candidate lookup.
  - Custom rule engine for user-defined matching rules.
- **diff** (`src/diff/`): Semantic diff engine with graph-aware dependency diffing, incremental diff tracking, and cost-model scoring.
- **enrichment** (`src/enrichment/`): OSV and KEV vulnerability database integration, EPSS exploit-probability scores, EOL detection via endoflife.date API, package-registry staleness detection, Hugging Face model-registry metadata, and VEX ingestion (feature-gated behind `enrichment`). Includes file-based caching with TTL and staleness tracking, plus an offline mode served purely from cache.
- **quality** (`src/quality/`): 8-category quality scoring engine with profile-aware weights (Standard, Security, CRA, BSI, CBOM, AI-readiness, etc.). CBOM profile scores algorithm strength, PQC readiness, OID coverage, crypto completeness, key/cert lifecycle, and cross-reference resolution with hard caps for broken cryptography. Compliance checks against 13 selectable standards: NTIA, FDA, CRA Phase 1/2, CRA Art. 24 (OSS steward), BSI TR-03183-2 v2.1.0, NIST SSDF, EO 14028, CNSA 2.0, NIST PQC (IR 8547), EUCC, EU AI Act, and BSI/G7 SBOM-for-AI.
- **pipeline** (`src/pipeline/`): Orchestrates the parse → enrich → diff → report workflow. Handles stage sequencing and output routing.
- **reports** (`src/reports/`): Report generators for JSON, NDJSON, SARIF, OSCAL 1.1.2 assessment-results (validate), HTML, Markdown, CSV, summary, table, and side-by-side formats. Includes a streaming reporter for large outputs.
- **tui** (`src/tui/`): Interactive ratatui-based UI for exploring diffs and single SBOMs/CBOMs. Supports diff mode, view mode (with SBOM/CBOM profile-driven tabs), fleet comparison, and timeline views. CBOM mode provides dedicated Algorithms, Certificates, Keys, Protocols, and PQC Compliance tabs with sorting and crypto inventory panels.
- **verification** (`src/verification/`): File hash verification (SHA-256/512) and component hash auditing.
- **license** (`src/license/`): License policy engine (allow/deny/review lists) with dependency propagation analysis.
- **serialization** (`src/serialization/`): Raw JSON enrichment, SBOM tailoring (filter), merging with deduplication, and format emit/conversion (backing the `convert` command).
- **watch** (`src/watch/`): Continuous SBOM monitoring with file watcher, vulnerability alerts, and debounced change detection.

## Data Flow

### Single Diff (`diff` command)

The `diff` command uses the full pipeline:

1. CLI parses arguments and merges config (`src/cli/`, `src/config/`).
2. `pipeline::parse_sbom_with_context()` reads and parses both SBOMs into `ParsedSbom` (preserves raw content for TUI Source tab).
3. Optional enrichment mutates SBOMs in-place with OSV/KEV data (`pipeline::enrich_sbom()`, feature-gated). Currently called from CLI, not pipeline.
4. `pipeline::compute_diff()` builds `DiffEngine` with matching config, rules, and graph options, then diffs.
5. `pipeline::output_report()` selects reporter format, pre-computes CRA compliance, and writes to file or stdout. For TUI output, raw content is preserved; for non-TUI, it is dropped to save memory.

### Multi-SBOM Commands (`diff-multi`, `timeline`, `matrix`)

Multi-SBOM commands reuse the pipeline for parsing and enrichment, then use `MultiDiffEngine` directly:

```
cli/multi.rs
  -> pipeline::parse_sbom_with_context() per path (+ optional enrichment)
  -> FuzzyMatchConfig + optional matching rules (load_multi_rules)
  -> MultiDiffEngine::new()
  -> .diff_multi() / .timeline() / .matrix()
  -> JSON or TUI output only
```

Key differences from single-diff:
- Typed `MultiDiffConfig` (baseline/targets, enrichment, filtering, graph-diff, output sections)
- No report format variety — JSON or TUI only (no SARIF/CSV/HTML/Markdown)
- No streaming support

### Query Command (`query`)

The `query` command searches for components across multiple SBOMs:

```
cli/query.rs
  -> parse_multiple_sboms() (reused from multi.rs)
  -> Optional: enrich_sbom() / enrich_eol() (feature-gated)
  -> For each SBOM: NormalizedSbomIndex::build()
  -> QueryFilter::matches() on each component via ComponentSortKey
  -> Deduplicate by (name_lower, version), merge found_in sources
  -> Output: table (default), JSON, or CSV
```

Key design:
- Reuses `parse_multiple_sboms()` and `get_sbom_name()` from `cli/multi.rs`
- Supports optional enrichment (OSV vulns + EOL) before searching
- Version filter tries semver range parsing first (for `<2.17.0`), falls back to exact match
- All filters are AND-combined; pattern filter uses `ComponentSortKey::contains()` for broad matching
- Deduplication groups by `(name_lower, version)` and merges `found_in` sources and vulnerability IDs
- Exit code 1 if no matches (useful for CI gate checks)

### Enrichment Flow

Enrichment is feature-gated behind the `enrichment` Cargo feature. When enabled,
the CLI layer (`src/cli/diff.rs`) constructs `OsvEnricherConfig` from `DiffConfig.enrichment`
and calls `pipeline::enrich_sbom()` to mutate each SBOM in-place before diffing.

```
DiffConfig.enrichment → OsvEnricherConfig
  → pipeline::enrich_sbom(&mut sbom, &config)
    → OsvEnricher::new() → enricher.enrich(&mut components)
    → Re-insert enriched components into sbom.components
```

The pipeline module exports `enrich_sbom()` but does not orchestrate it — the CLI is
responsible for calling it at the right time.

## TUI Architecture

The TUI has two independent app types:

- **DiffApp** (`src/tui/app.rs`, `src/tui/views/`): Handles diff mode with `App` struct holding all state. Supports diff, multi-diff, timeline, and matrix modes across 12 tabs. Uses `ViewState` trait with per-tab state structs for all tabs.

- **ViewApp** (`src/tui/view/app.rs`, `src/tui/view/views/`): Handles single-SBOM/CBOM/AI-BOM view mode. Profile-driven tab system via `ViewTab::tabs_for_profile(BomProfile)` — SBOM mode shows 8 tabs, CBOM mode shows 8 crypto-specific tabs, AI-BOM mode shows 6 tabs (Overview, Models, Datasets, AI Readiness, Compliance, Source). Quality scoring uses `ScoringProfile::Cbom` when CBOM is detected. Runtime toggle via `P` key re-scores with the selected profile.

Both app types share rendering utilities in `src/tui/shared/` (quality charts, component info, theme) and use `RenderContext` for read-only frame preparation.

## Invariants and Conventions

- NormalizedSbom is the single source of truth for parsed data.
- Components are keyed by CanonicalId for stability across formats.
- DiffResult summary values are derived from change lists.
- TUI layers should align selection/sort with the same source lists.
- Builders use `with_*` naming and `mut self -> Self` pattern.
- Error handling: thiserror for library code, anyhow for CLI.
- No `&String`, `&Vec<T>`, `Box<dyn Error>`, or production panics.

## Extension Points

- **Matching rules**: Configurable matching behavior via YAML configs and custom rule engine.
- **Enrichment**: OSV/KEV integration for vulnerability data and EOL detection via endoflife.date API (feature-gated).
- **Reports**: Add new generators by implementing ReportGenerator.
- **Compliance**: Add new standards by extending the compliance engine (`src/quality/compliance/`) and its `StandardSelector`/`rule_meta()` registry (currently: NTIA, FDA, CRA Phase 1/2, CRA Art. 24, BSI TR-03183-2, NIST SSDF, EO 14028, CNSA 2.0, NIST PQC, EUCC, EU AI Act, BSI/G7 SBOM-for-AI).
- **CBOM Scoring**: Add new crypto quality categories by extending `CryptographyMetrics` and adding scoring methods. New `ScoringProfile` variants can define custom weight distributions.
- **BOM Profiles**: Add new profile types beyond SBOM/CBOM/AI-BOM by extending `BomProfile` enum and `tabs_for_profile()`.

## Known Technical Debt

- Multi-SBOM fleet commands (diff-multi, timeline, matrix) support enrichment but remain limited to JSON/TUI output.
- Enrichment is orchestrated by CLI, not the pipeline module.
- TUI has two parallel app types (DiffApp for diff modes, ViewApp for view mode) — intentionally separate but share rendering utilities.
- SPDX 3.0 parser does not extract crypto properties (CycloneDX-only for CBOM).
- ~2,200 tests (~1,580 unit + ~630 integration) across 51 integration test suites.
