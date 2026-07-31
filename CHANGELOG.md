# Changelog

All notable user-visible changes to sbom-tools are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
sbom-tools is pre-1.0 (`0.x`), so breaking changes are permitted in a minor or
patch release — but they are never implied by the version number alone. Every
one of them is listed under **BREAKING** at the top of its release.

Releases up to and including v0.1.22 are also described, in more narrative
detail, in `RELEASE_NOTES_v0.1.21.md`, `RELEASE_NOTES_v0.1.22.md` and the
GitHub release notes.

## [Unreleased]

### BREAKING

Machine-readable output and the Rust API changed. CI jobs that parse
`diff-multi`/`timeline` JSON, pin `-o` values on the multi-SBOM commands, or
link the library should be reviewed before upgrading.

- **Deviation is a 0–1 fraction — `diff-multi` only.** `diff-multi -o json` now
  emits `summary.deviation_scores` and `summary.max_deviation` in `0.0…1.0`; they
  were previously double-scaled and rendered as e.g. `10000.0%`. `timeline -o json`
  has no `summary` object and no deviation field of any kind, so it is unaffected
  by this change. The three scales are now pinned by tests and documented:
  single-`diff` `semantic_score` is `0–100`, `matrix` `similarity_scores` is `0–1`
  (`= semantic_score / 100`), and deviation is `0–1` (`= 1 − similarity`).
- **Multi-SBOM component identity is the version-stripped logical purl.**
  `variable_components`, `inconsistent_components` and the timeline
  evolution/divergence entries key on `pkg:npm/express` rather than
  `pkg:npm/express@4.18.2`, so a version bump is one component with a version
  spread instead of an Added + Removed pair.
- **`diff -o json`: `ComponentChange` gains `component_type`.** Additive, but
  strict consumers must accept it. Crypto assets resolve to their CycloneDX asset
  type (`algorithm`, `certificate`, `protocol`), except `related-crypto-material`,
  which narrows to its declared material type — any of the 17 kinds (`public-key`,
  `private-key`, `symmetric-key`, `key-pair`, `secret-key`, `signature`, `digest`,
  `initialization-vector`, `nonce`, `seed`, `salt`, `shared-secret`, `tag`,
  `password`, `credential`, `token`, `unknown`) or a custom string the document
  declares. ML components resolve to `machine-learning-model` and `data`.
- **`diff -o json`: `metadata_changes` gains `doc_version` entries.** The
  CycloneDX top-level revision counter is now captured, diffed and re-emitted, so
  a pure revision bump is no longer reported as "no changes". Combined with purl
  ref resolution (below), change totals move: the `demo-old`/`demo-new` fixture
  pair goes from 15 to 18 total changes.
- **`diff-multi`, `timeline` and `matrix` accept only `-o auto|tui|json`.**
  `--help` lists exactly those, and an unsupported value is now a clap usage
  error (exit `2`) at parse time instead of a runtime failure (exit `3`) after
  every SBOM had already been parsed.
- **Rust API: `CryptographyMetrics::quantum_readiness_score` and
  `::pqc_readiness_score` return `Option<f32>`.** They return `None` when a
  document declares zero cryptographic algorithms, instead of a vacuous `100.0`.
  The CBOM scorer proportionally redistributes the PQC weight when the score is
  absent.
- **Exit-code contract is reachable and fails closed.** Operational errors — I/O,
  parse failures, an unsupported `-o` for the command, an invalid `--as-of` or
  `--cra-product-class`, a broken explicit `--cra-sidecar`, an invalid config
  file — exit `3`; command-line parse errors exit `2`; gate verdicts keep
  `1`/`2`/`4`/`5`/`6`/`7`. A nonzero exit is only a gate verdict when the expected
  report was produced.
- **`validate --standard ntia` and `--standard fda` are engine-backed.** Their
  divergent fast paths are gone; both are stricter, and SBOMs that passed before
  can now fail.
- **Compliance rule identity comes from the registry.** Several SARIF/JSON
  `rule_id`s were renamed, EUCC checks got their own standard kind and rule ids,
  and fallback rule identity is family-correct at the source.
- **CRA phases re-anchored to Reg. (EU) 2024/2847.** Phase 1 is the Art. 14
  reporting phase applying from 11 Sep 2026 (was labelled "11 December 2027") and
  Phase 2 is full application from 11 Dec 2027 (was "11 December 2029"). Article
  and Annex citations were corrected throughout.
- **`validate --standard bsi` is rebased on BSI TR-03183-2 v2.1.0** — format
  gate, SHA-512 hashes, ten required fields, corrected tiers.
- **The TUI keymap changed** (details under *Changed*). Recorded demos, scripts
  and third-party docs that reference the old keys are stale.

### Added

- **Three compliance standards, bringing `validate --standard` to 16.**
  - `cisa-2026` (aliases `cisa`, `cisa2026`, `minimum-elements-2026`) — CISA/NSA/FBI
    "2026 Minimum Elements for an SBOM" v2.1 (July 2026), successor to the NTIA
    2021 elements, 17 rules. Deliberately stricter than the NTIA profile: a
    tool-only creator list does not satisfy SBOM Author, and a silently absent
    license fails where an explicit no-assertion passes.
  - `pci-dss` (aliases `pci`, `pci-dss-6-3-2`, `pci-dss-4`) — PCI DSS v4.0.1
    Requirement 6.3.2 software-inventory profile, 10 rules. A passing verdict is
    evidence the inventory exists and is usable, **not** a PCI compliance
    certification.
  - `fsct` (aliases `fsct-3`, `component-transparency`) — CISA "Framing Software
    Component Transparency" 3rd ed. (2024), 27 rules across three maturity tiers
    mapped Minimum Expected → Error, Recommended Practice → Warning,
    Aspirational → Info.
- **CDXA attestation ingestion (phase 1).** CycloneDX 1.6 `declarations`
  (assessors, attestations, claims, evidence, affirmation, signatories) are parsed
  into a normalized model, gated on `specVersion >= 1.6`, with refs resolved
  through the same id map as the rest of the document. This is **structural
  verification only** — signature *presence* is recorded, never cryptographically
  verified. Phase 2 (external in-toto/DSSE bundles) is not implemented.
- **Attestation evidence satisfies existing compliance rules.** A declaration
  covering an SSDF practice (PS.1/PO.3/PW.6), a CRA conformity route, an EUCC
  certificate reference or EO 14028 provenance now satisfies that rule at
  structural/signature-present level. Every pre-existing satisfaction path remains
  valid as a self-declared fallback, and documents without declarations are
  unaffected.
- **`quality -o sbomqs-json`** — emits the `interlynk-io/sbomqs` v2.0.11
  `score --json` schema (`run_id`, `creation_info`, `files[].scores[]`,
  `avg_score`) so sbom-tools and sbomqs can be compared side by side, plus a
  0–10 category table in the plain-text `quality` summary. Categories that cannot
  be computed are emitted as `ignored` with a reason rather than silently dropped.
  sbomqs' own scoring quirks are reproduced faithfully and documented in
  `docs/STANDARDS_VERSIONS.md`.
- **`validate -o oscal-json`** — OSCAL 1.1.2 assessment-results export,
  applicability-faithful (N/A findings, multi-standard run summaries). `diff` and
  `view` reject the format with a pointer to `validate`; every other command
  rejects it as an unsupported output format for that command.
- **`--as-of <DATETIME>`** on `validate` and `quality` pins the evaluation clock
  for deadline-sensitive checks (CRA Art. 14 readiness, SBOM age, EUCC certificate
  expiry) so CI runs are reproducible.
- **`--fail-on-ml-regression`** on `diff` (exit code `7`) gates on regressions in
  supported ML performance metrics, and **`--fail-on-noncompliant`** on `quality`
  gates on the compliance verdict independently of `--min-score`.
- **`timeline` JSON gains `incremental_pairs` and `cumulative_pairs`** —
  index-aligned `from_index`/`to_index`/`from_name`/`to_name` records, so
  consumers no longer have to infer which pair an array position refers to.
  Additive.
- **`doc_version` on `DocumentMetadata`** — the CycloneDX revision counter is
  captured (additive JSON) and round-trips through `convert`, which previously
  hardcoded `"version": 1`.
- **purl-fallback ref resolution.** `dependencies[].ref`, `dependsOn` and
  `vulnerabilities[].affects[].ref` expressed as purls now resolve to components
  (explicit bom-refs still win on collision). Such edges and CVEs were previously
  dropped silently.
- **SPDX 3.0.1 canonical JSON-LD parsing** plus document-level metadata
  completeness, shared `CreationInfo`, and `software_` aliases.
- **Python (ctypes) and Node.js (Koffi) FFI bindings** alongside the existing Go
  and Swift wrappers.
- **Compliance violations carry structured identity** — a `component_id` join key
  and affected/total counts.
- **TUI:** component deep dive (Enter on diff Components), a threshold-tuning
  overlay on `t` (previously unreachable by any key), a `Q` quick-filter picker,
  AI Inventory and AI Readiness overview panels for the AI-BOM profile, a
  monochrome theme, VEX gap counts and by-state breakdown, KEV/Fixable/EPSS triage
  summaries, license-compatibility conflicts, ML performance regressions with
  direction-aware coloring, match-confidence intervals, and mouse support in the
  Matrix/Timeline/Multi-Diff modes.
- **`cra-docs --force`** to overwrite an existing dossier (a re-run otherwise
  refuses to clobber hand-completed documents).
- **Test infrastructure:** a registry-driven per-rule matrix gives every rule in
  the FDA/SSDF/EO 14028/Standard/Comprehensive profiles a firing and a silent
  fixture, with exhaustiveness enforced.

### Changed

- **TUI keymap.**
  - Digits always jump tabs in diff mode; no tab may shadow them. The Components
    security quick filters moved behind the `Q` picker modal (digits toggle
    filters while it is open), and the Side-by-Side filters moved to
    `A`/`r`/`m`/`x`.
  - `e` is export on every tab in Diff and View mode (the Dependencies
    expand-all moved to `x`/`X`, so the "e export" footer hint is never a lie);
    the cycles toggle moved to `C`; the threshold overlay opens on `t`.
  - View app: the KEV filter moved from `k` to `K` (`k` stays navigation),
    vulnerability groups jump on `}`/`{`, `P` cycles the BOM profile, and `/` on
    the Tree is relabelled as the filter it always was.
  - Matrix `D` explains itself instead of opening a hollow component modal — its
    rows are SBOMs, not components.
  - Tab dispatch is gated to Diff mode: the multi modes have no visible tabs, so
    no key leaks into an invisible tab handler. The dead View-mode scaffolding and
    the shortcuts it advertised are gone.
- **Honest empty states.** "Great news! No known vulnerabilities" is gone —
  absence of data is not proof of absence. Quantum readiness shows `n/a` rather
  than 100% when a document declares no crypto assets, and the Graph tab
  distinguishes "no graph data" from "identical".
- **`--no-color` now applies to the TUI** (it previously honoured only the
  `NO_COLOR` environment variable) and forces the monochrome theme, which stays
  sticky under the `T` toggle.
- **An empty `NO_COLOR=` counts as unset everywhere**, per the convention — the
  variable strips color only when set to a non-empty value. Text and side-by-side
  report output now agrees with the TUI theme and the logs, which already did.
- **`-o side-by-side` honours `--no-color` and `NO_COLOR`** — it previously
  ignored both.
- **`QualityDelta` category names are profile-aware**: CBOM pairs are scored under
  the CBOM profile and report crypto category names.
- **Quality scoring is monotonic and deterministic** (vulnerability baseline,
  freshness, coverage clamp), license/identifier metrics are counted per component
  rather than per entry, required compliance elements gate the score, and the
  crypto score is honest about inventories it cannot verify.
- **The Quality, Compliance and AI-Readiness TUI tabs no longer collapse to empty
  borders at 80×24.**
- **The compliance verdict is tri-state** — compliant / non-compliant /
  not-applicable, the last surfaced as `"compliant": null` — with one honest
  compliance score shared across the TUI, reports and exports; N/A findings are
  surfaced rather than counted as passes.
- **`enrich` is lossless, `merge` stops dropping data, and `tailor` prunes by
  identity** rather than by name.
- **Config files reject unknown keys** and sidecar trust is consistent across
  commands.

### Fixed

- **Parsers.** CycloneDX hard-fails, assemblies, services and per-version VEX
  status gating; SPDX 2.x data loss (`documentDescribes`, files, `LicenseRef`,
  CPE, purpose, emails); SPDX relationship parsing, `@graph` serialization and
  tag-value text blocks; UTF-8 BOM stripping, streaming metadata, and format
  detection misrouting; deterministic content hashing.
- **Diff and matching.** Stale-splice and hash-blindness holes in incremental
  diffing; multi-engine version classification, clustering, naming and timeline
  semantics; equivalence rules bridging real IDs during matching instead of
  corrupting the result; `sparse_assignment` optimality restored; wrong-neighbor
  and cross-ecosystem false merges eliminated behind one tier pipeline; the
  ransomware-KEV flag is preserved into diff mode. Remaining quadratic hot paths
  removed.
- **Enrichment.** VEX status mapping corrected so external VEX can no longer
  silently suppress real vulnerabilities; OSV result attribution validated and
  hydration fan-out bounded; the network trust surface hardened (URL validation,
  hash provenance, cache integrity).
- **Compliance.** Vacuous CRA passes closed (steward gates, evidence scoping, class
  monotonicity, EUCC sidecar); crypto-compliance false passes (vacuous CNSA2/PQC,
  classical crypto, undocumented CBOM); AI profile applicability gates; CNSA2/PQC
  classification made input-robust; per-standard element gaps; registry/SARIF
  severity consistency.
- **CLI.** A UTF-8 panic in `query`, format gates that did not gate, and filters
  that claimed more than they did; security gates fail closed and machine output
  stays parseable. Non-TUI reports honour the CRA sidecar and product class like
  the TUI does.
- **`diff` and `view` reject `-o sbomqs-json` up front**, with a pointer to
  `quality -o sbomqs-json`; they previously fell through to the JSON reporter and
  silently emitted ordinary diff/view JSON under a format the caller never asked
  for.
- **Reports.** Resolved `LicenseRef` names are surfaced, CycloneDX authors and
  SPDX creators/files/licensing infos are emitted, and CycloneDX VEX
  unaffected-version handling is correct.
- **TUI.** Terminal restored on all exits; UTF-8 render panics removed; selection
  kept on-screen at any terminal size; `Esc` never quits; wrapped-line scrolling;
  mouse hit-testing derived from the real rendered layout; search unified on one
  matcher across diff and multi modes; compliance exports aligned with the
  canonical result contract.

### Security

- `quick-xml` 0.41 (RUSTSEC-2026-0194, RUSTSEC-2026-0195), `quinn-proto` 0.11.15
  (RUSTSEC-2026-0185) and `crossbeam-epoch` 0.9.20 (RUSTSEC-2026-0204).
- Untrusted-input DoS vectors bounded in the parsers; every untrusted response
  read and the EPSS gzip decompression are size-bounded.

## [0.1.22] - 2026-06-15

The AI BOM release. Full notes: `RELEASE_NOTES_v0.1.22.md`.

### Added

- AI/ML bill of materials as a first-class domain: `quality --profile
  ai-readiness` (AI-001…AI-010), CycloneDX ML-BOM and SPDX 3.0 AI/Dataset
  parsing, semantic model and dataset diffing, `verify model-weights`, Hugging
  Face enrichment, `SBOM-AIBOM-*` SARIF rules, and a TUI AI-BOM profile.
- EU AI Act (Annex IV) and BSI/G7 "SBOM for AI — Minimum Elements" compliance
  levels; a compliance rule registry giving every violation a stable `rule_id`.
- `convert` command (CycloneDX 1.7 ↔ SPDX 2.3) with a fidelity report.
- CISA KEV and EPSS enrichment (`--kev`, `--epss`, `--fail-on-kev`), a global
  `--offline` mode and a `cache` subcommand for air-gapped transfer.
- Stdin input (`-`), a globally honoured `--config`, typed exit codes and
  `-o ndjson`, and document-metadata diffing.

### Changed

- Scoring engine 2.0 → 2.1 (cycle detection counts strongly-connected
  components), `semantic_score` counts per-component license transitions, and
  `license-check` gating is stricter.
- Logs moved to stderr so machine-readable output on stdout stays parseable; the
  EPSS default endpoint moved to the official FIRST host.
- Library API: `IncrementalDiffEngine::diff` and
  `MultiDiffEngine::{diff_multi,timeline,matrix}` return `Result`.

### Fixed

- Hostile-SBOM stack overflow (iterative Tarjan SCC), empty OSV severity data,
  CycloneDX XML parsing, license-policy correctness, empty per-component license
  changes, false watch-mode "resolved" alerts, incremental-diff cache splicing,
  and diff determinism.

[Unreleased]: https://github.com/sbom-tool/sbom-tools/compare/v0.1.22...HEAD
[0.1.22]: https://github.com/sbom-tool/sbom-tools/releases/tag/v0.1.22
