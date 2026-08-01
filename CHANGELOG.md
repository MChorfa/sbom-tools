# Changelog

Release notes for every version, in the same form as the
[GitHub Releases page](https://github.com/sbom-tool/sbom-tools/releases):
**Highlights**, **What's New**, **Bug Fixes**, and **Upgrade notes**. Each
published version's notes are also kept verbatim in `RELEASE_NOTES_v*.md`.

sbom-tools is pre-1.0 (`0.x`), so breaking changes are permitted in a minor
release — but they are never implied by the version number alone. Every one of
them is listed under **Upgrade notes** for its release.

---

## v0.2.0 — unreleased

### Highlights

The **correctness release.** Where v0.1.22 added an AI-BOM domain, this release
goes back over what was already there and checks whether it told the truth.
Systematic audits of the diff engine, the parser layer, enrichment, quality
scoring, the compliance engine, the CLI surface and the TUI turned up defects
that shared a shape: the tool reporting something other than what it had
computed. A demo SBOM shipped in this repository reported "no vulnerabilities"
while its own Source view displayed a CVSS 9.8 entry. Fleet deviations rendered
as `10000.0%`. A document containing no cryptography scored a perfect 100 for
quantum readiness. A keyboard overlay advertised keys that did nothing.

All of those are fixed, and most are now pinned by tests that fail if the
behaviour regresses.

Alongside the audit work: three new compliance standards bring
`validate --standard` to **16** — **CISA's 2026 Minimum Elements**, **PCI DSS
v4.0.1 Requirement 6.3.2**, and **CISA Framing Software Component Transparency
3rd ed.** — plus **CDXA attestation ingestion**, so a signed machine-readable
declaration can satisfy an SSDF practice or a CRA conformity route that
previously accepted only self-declaration. A new **`quality -o sbomqs-json`**
emits the [sbomqs](https://github.com/interlynk-io/sbomqs) 0–10 score model for
side-by-side comparison.

> **Please read [Upgrade notes](#upgrade-notes) below** — this release changes
> machine-readable output, the Rust API, several compliance verdicts, and the
> TUI keymap.

### What's New

#### Compliance

- **CISA 2026 Minimum Elements** — `validate --standard cisa-2026` (aliases `cisa`, `cisa2026`, `minimum-elements-2026`), 17 rules against the final v2.1 document published July 2026, successor to the NTIA 2021 elements. Deliberately stricter than the NTIA profile where the document is: a tool-only creator list does not satisfy SBOM Author, and a silently absent license fails where an explicit no-assertion passes. (#333)
- **PCI DSS 6.3.2** — `validate --standard pci-dss` (aliases `pci`, `pci-dss-6-3-2`, `pci-dss-4`), 10 rules treating the SBOM as the required inventory of bespoke, custom and third-party components. A passing verdict is evidence the inventory exists and is usable, **not** a PCI compliance certification, and thresholds chosen by this tool rather than the standard are labelled as such in the message. (#333)
- **CISA FSCT 3rd ed.** — `validate --standard fsct` (aliases `fsct-3`, `component-transparency`), 27 rules across the document's three maturity tiers, mapped Minimum Expected → Error, Recommended Practice → Warning, Aspirational → Info. Checks are format-gated where the evidence cannot exist rather than failing a document for its format. (#333)
- **CDXA attestation ingestion (phase 1).** CycloneDX 1.6 `declarations` (assessors, attestations, claims, evidence, affirmation, signatories) parse into a normalized model, gated on `specVersion >= 1.6`, with refs resolved through the same id map as the rest of the document. **Structural verification only** — signature *presence* is recorded, never cryptographically verified. Phase 2 (external in-toto/DSSE bundles) is not implemented. (#333)
- **Attestation evidence satisfies existing rules.** A declaration covering an SSDF practice (PS.1/PO.3/PW.6), a CRA conformity route, an EUCC certificate reference or EO 14028 provenance satisfies that rule at structural/signature-present level. Every pre-existing satisfaction path remains valid as a self-declared fallback, so documents without declarations are unaffected. (#334)
- **`--as-of <DATETIME>`** on `validate` and `quality` pins the evaluation clock for deadline-sensitive checks (CRA Art. 14 readiness, SBOM age, EUCC expiry), so CI runs are reproducible instead of drifting with the wall clock. (#320)
- **Registry-driven rule identity** across JSON, SARIF, the quality CLI and OSCAL; structured violation identity (a `component_id` join key with affected/total counts); tri-state applicability so "not applicable" is distinct from "compliant". (#320)
- **Per-rule test matrix** — every rule in the FDA, SSDF, EO 14028, Standard and Comprehensive profiles has a firing and a silent fixture, with exhaustiveness enforced in both directions so a new check site forces a matrix entry. (#333)

#### Interoperability and output

- **`quality -o sbomqs-json`** emits the sbomqs v2.0.11 `score --json` schema (`run_id`, `creation_info`, `files[].scores[]`, `avg_score`), and the plain-text `quality` summary gains a 0–10 category table. Formulas were read from that release's sources rather than its documentation, including the behaviours a reimplementation would otherwise "correct"; categories that cannot be computed are emitted as `ignored` with a stated reason instead of approximated. Quirks are documented in `docs/STANDARDS_VERSIONS.md`. (#333)
- **`validate -o oscal-json`** — OSCAL 1.1.2 assessment-results export, applicability-faithful (N/A findings, multi-standard run summaries). (#280, #320)
- **`timeline` JSON gains `incremental_pairs` and `cumulative_pairs`** — index-aligned `from_index`/`to_index`/`from_name`/`to_name` records, so consumers no longer infer which pair an array position refers to. Additive. (#334)
- **`--fail-on-ml-regression`** on `diff` (exit code `7`) gates on regressions in supported ML performance metrics, and **`--fail-on-noncompliant`** on `quality` gates on the compliance verdict independently of `--min-score`. (#279, #320)
- **`cra-docs --force`** overwrites an existing dossier; a re-run otherwise refuses to clobber hand-completed documents. (#322)

#### Parsers

- **SPDX 3.0.1 canonical JSON-LD** parsing, plus document-level metadata completeness, shared `CreationInfo`, and `software_` aliases. (#311)
- **SPDX 2.x data-loss gaps closed** — `documentDescribes`, file entries, `LicenseRef` resolution, CPE, purpose and emails. (#315)
- **CycloneDX correctness** — spec-valid documents that hard-failed now parse, nested assemblies are inventory, and serialization round-trips. (#314)
- **purl-fallback ref resolution.** `dependencies[].ref`, `dependsOn` and `vulnerabilities[].affects[].ref` expressed as purls resolve to components (explicit bom-refs still win on collision). Such edges and CVEs were previously dropped silently. (#333)
- **Document revision tracking** — the CycloneDX top-level `version` counter is captured, diffed, and round-trips through `convert`, which previously hardcoded `"version": 1`. (#333, #334)

#### TUI

- Four phases land here: data surfacing and a theme backbone (#309), per-tab depth with detail panels and ML/VEX/match transparency (#310), a multi-mode overhaul with shared builders (#312), and unified search behind a single shortcuts surface (#313).
- **A UX audit of every mode** against a 269-frame corpus produced 203 findings; the 30 that survived adversarial verification are fixed, along with the tail. Empty states no longer celebrate, every advertised key exists, `y` copies the row you actually selected, and the Quality, Compliance and AI-Readiness tabs no longer collapse to empty borders at 80×24 — the app's own advertised minimum size. (#333, #334)
- **New surfaces:** component deep dive (Enter on diff Components), a threshold-tuning overlay on `t` (previously unreachable by any key), a `Q` quick-filter picker, AI Inventory and AI Readiness overview panels for the AI-BOM profile, a monochrome theme, VEX gap counts and by-state breakdown, KEV/Fixable/EPSS triage summaries, license-compatibility conflicts, ML performance regressions with direction-aware coloring, match-confidence intervals, and mouse support in the Matrix/Timeline/Multi-Diff modes. (#309, #310, #312, #333)

#### Bindings and documentation

- **Python (ctypes) and Node.js (Koffi) FFI bindings** alongside the existing Go and Swift wrappers. (#274, #275)
- **`docs/TUI_SHORTCUTS.md`** documents every binding across all three TUIs, each traced to its handler with the guard that makes a key mean different things on different tabs. (#334)
- **This changelog**, and a README/`docs/` refresh whose every claim was verified against the built binary and re-checked by independent adversarial review. (#323, #334)

### Bug Fixes

- **Vulnerabilities and dependency edges were silently dropped** whenever a CycloneDX document referenced components by purl — including this repository's own demo fixtures, where the Vulnerabilities tab reported a clean bill while the Source tab displayed a CVSS 9.8 CVE. (#333)
- **Fleet deviation was double-scaled**, rendering as `10000.0%` and saturating every gauge and severity band. It is now a 0–1 fraction, and the three similarity scales are pinned by tests. (#333)
- **A version bump counted as both an addition and a removal** in multi-SBOM analysis, so "Inconsistent" totals exceeded the number of distinct components and Timeline listed every upgrade twice. (#333)
- **Documents with no cryptography scored 100 for quantum readiness.** The score is now absent rather than vacuously perfect, and the CBOM scorer redistributes the weight. (#333)
- **Diff and matching.** Stale-splice and hash-blindness holes in incremental diffing; multi-engine version classification, clustering, naming and timeline semantics; equivalence rules bridging real IDs during matching instead of corrupting the result; `sparse_assignment` optimality restored; wrong-neighbor and cross-ecosystem false merges eliminated behind one tier pipeline; remaining quadratic hot paths removed. (#299)
- **Parsers.** 29 untrusted-input findings, CycloneDX hard-fails, assemblies, services and per-version VEX status gating, SPDX relationship parsing, `@graph` serialization, tag-value text blocks, UTF-8 BOM stripping, streaming metadata, format-detection misrouting, and deterministic content hashing. (#300, #314, #315)
- **Enrichment.** VEX status mapping corrected so external VEX can no longer silently suppress real vulnerabilities; OSV result attribution validated and hydration fan-out bounded; the network trust surface hardened (URL validation, hash provenance, cache integrity). (#303)
- **Compliance.** Vacuous CRA passes closed (steward gates, evidence scoping, class monotonicity, EUCC sidecar); crypto-compliance false passes (vacuous CNSA2/PQC, classical crypto, undocumented CBOM); AI profile applicability gates; CNSA2/PQC classification made input-robust; per-standard element gaps; registry/SARIF severity consistency. (#304, #320)
- **Quality scoring** is monotonic and deterministic (vulnerability baseline, freshness, coverage clamp); license and identifier metrics count per component rather than per entry; required compliance elements gate the score; the crypto score is honest about inventories it cannot verify. (#304)
- **CLI.** A UTF-8 panic in `query`, format gates that did not gate, and filters that claimed more than they did; security gates fail closed and machine output stays parseable; non-TUI reports honour the CRA sidecar and product class like the TUI does; `enrich` is lossless, `merge` stops dropping data, and `tailor` prunes by identity rather than by name; config files reject unknown keys. (#322)
- **`diff` and `view` accepted `-o sbomqs-json`** and silently emitted ordinary JSON under a format the caller never asked for. Both now reject it with a pointer to `quality`. (#334)
- **`--no-color` did not reach the TUI**, which consulted only the `NO_COLOR` environment variable, and the side-by-side reporter ignored both. An empty `NO_COLOR=` now counts as unset everywhere, per the convention. (#333, #334)
- **The shortcuts overlay contradicted itself** — its global rows were gated by mode but not by tab, so one frame could assert both `l Color legend` and `h/l Collapse/expand` on a tab where `l` switches standards. The Graph Changes tab also advertised a `g` binding it never had. (#334)
- **TUI robustness.** Terminal restored on all exits; UTF-8 render panics removed; selection kept on-screen at any terminal size; `Esc` never quits; wrapped-line scrolling; mouse hit-testing derived from the real rendered layout; compliance exports aligned with the canonical result contract. (#309, #310, #312, #313, #324)
- **Reports.** Resolved `LicenseRef` names are surfaced, CycloneDX authors and SPDX creators/files/licensing infos are emitted, and CycloneDX VEX unaffected-version handling is correct. (#321)
- **Security.** `quick-xml` 0.41 (RUSTSEC-2026-0194, RUSTSEC-2026-0195), `quinn-proto` 0.11.15 (RUSTSEC-2026-0185) and `crossbeam-epoch` 0.9.20 (RUSTSEC-2026-0204); untrusted-input DoS vectors bounded in the parsers, and every untrusted response read plus the EPSS gzip decompression are size-bounded. (#300, #303)

### Upgrade notes

These behaviors changed in this release:

- **Deviation is a 0–1 fraction — `diff-multi` only.** `diff-multi -o json` emits `summary.deviation_scores` and `summary.max_deviation` in `0.0…1.0`; they were previously double-scaled. `timeline -o json` has no `summary` object and no deviation field of any kind, so it is unaffected. The three scales are now pinned by tests: single-`diff` `semantic_score` is `0–100`, `matrix` `similarity_scores` is `0–1` (`= semantic_score / 100`), and deviation is `0–1` (`= 1 − similarity`). (#333, #334)
- **Multi-SBOM component identity is the version-stripped logical purl.** `variable_components`, `inconsistent_components` and the timeline evolution/divergence entries key on `pkg:npm/express` rather than `pkg:npm/express@4.18.2`, so a version bump is one component with a version spread instead of an Added + Removed pair. (#333)
- **`diff -o json`: `ComponentChange` gains `component_type`.** Additive, but strict consumers must accept it. Crypto assets resolve to their CycloneDX asset type (`algorithm`, `certificate`, `protocol`), except `related-crypto-material`, which narrows to its declared material type — any of the 17 kinds (`public-key`, `private-key`, `symmetric-key`, `key-pair`, `secret-key`, `signature`, `digest`, `initialization-vector`, `nonce`, `seed`, `salt`, `shared-secret`, `tag`, `password`, `credential`, `token`, `unknown`) or a custom declared string. ML components resolve to `machine-learning-model` and `data`. (#333)
- **`diff -o json`: `metadata_changes` gains `doc_version` entries**, so a pure revision bump is no longer reported as "no changes". Combined with purl ref resolution, change totals move: the `demo-old`/`demo-new` fixture pair goes from 15 to 18. (#333, #334)
- **`diff-multi`, `timeline` and `matrix` accept only `-o auto|tui|json`.** `--help` lists exactly those, and an unsupported value is a clap usage error (exit `2`) at parse time instead of a runtime failure (exit `3`) after every SBOM had been parsed. (#334)
- **Library API:** `CryptographyMetrics::{quantum_readiness_score, pqc_readiness_score}` return `Option<f32>` — `None` when a document declares zero algorithms, instead of a vacuous `100.0`; the CBOM scorer redistributes the PQC weight. `run_tui` and `run_view_tui` take a `no_color` parameter. (#333, #334)
- **Exit-code contract is reachable and fails closed.** Operational errors — I/O, parse failures, an unsupported `-o` for the command, an invalid `--as-of` or `--cra-product-class`, a broken explicit `--cra-sidecar`, an invalid config file — exit `3`; command-line parse errors exit `2`; gate verdicts keep `1`/`2`/`4`/`5`/`6`/`7`. A nonzero exit is only a gate verdict when the expected report was produced. (#322)
- **`validate --standard ntia` and `--standard fda` are engine-backed.** Their divergent fast paths are gone; both are stricter, and SBOMs that passed before can now fail. (#320)
- **Compliance rule identity comes from the registry.** Several SARIF/JSON `rule_id`s were renamed, EUCC checks got their own standard kind and rule ids, and fallback rule identity is family-correct at the source. (#320)
- **CRA phases re-anchored to Reg. (EU) 2024/2847.** Phase 1 is the Art. 14 reporting phase applying from 11 Sep 2026 (was labelled "11 December 2027") and Phase 2 is full application from 11 Dec 2027 (was "11 December 2029"). Article and Annex citations were corrected throughout. (#320)
- **`validate --standard bsi` is rebased on BSI TR-03183-2 v2.1.0** — format gate, SHA-512 hashes, ten required fields, corrected tiers. (#320)
- **The compliance verdict is tri-state** — compliant / non-compliant / not-applicable, the last surfaced as `"compliant": null` — with one honest compliance score shared across the TUI, reports and exports; N/A findings are surfaced rather than counted as passes. (#320)
- **The TUI keymap changed.** Digits always jump tabs in diff mode; Components' quick filters moved to a `Q` picker, Side-by-Side filters to `A`/`r`/`m`/`x`, the KEV filter from `k` to `K`, vulnerability group jump to `}`/`{`, Dependencies fold to `x`/`X`, the cycles toggle to `C`, and the threshold overlay to `t`. `e` is export on every tab. `docs/TUI_SHORTCUTS.md` is the full reference; `?` in the app is context-aware. Recorded demos, scripts and third-party docs referencing the old keys are stale. (#333, #334)

### Known gaps

- Attestation-satisfied compliance checks are not surfaced positively in `validate` output; the effect is visible only by comparing against a declarations-stripped document.
- CDXA ingestion reads CycloneDX **JSON** only — the XML path does not parse `declarations`, and `convert` does not round-trip them.
- Attestation phase 2 (external in-toto / DSSE bundles) is not implemented.

---

## v0.1.22 — 2026-06-15

The **AI BOM release.** Full notes: [`RELEASE_NOTES_v0.1.22.md`](RELEASE_NOTES_v0.1.22.md)
· [GitHub release](https://github.com/sbom-tool/sbom-tools/releases/tag/v0.1.22)

### Highlights

AI systems became a first-class domain across the whole pipeline: CycloneDX
ML-BOM and SPDX 3.0 AI/Dataset parsing, AI-readiness scoring (AI-001…AI-010),
machine-checked **EU AI Act (Annex IV)** and **G7/BSI "SBOM for AI — Minimum
Elements"** standards, semantic model and dataset diffing, model-weight
integrity verification, Hugging Face enrichment, and a dedicated AI-BOM TUI
profile. Alongside it: a `convert` command (CycloneDX ↔ SPDX), KEV/EPSS
enrichment with an offline/air-gapped mode, and broad CLI/TUI alignment.

### Upgrade notes

- Scoring engine 2.0 → 2.1 (cycle detection counts strongly-connected components), `semantic_score` counts per-component license transitions, and `license-check` gating is stricter. (#215, #211, #212)
- Logs moved to stderr so machine-readable output on stdout stays parseable; the EPSS default endpoint moved to the official FIRST host. (#256, #248)
- Library API: `IncrementalDiffEngine::diff` and `MultiDiffEngine::{diff_multi,timeline,matrix}` return `Result`. (#217)

---

Earlier releases: [`RELEASE_NOTES_v0.1.21.md`](RELEASE_NOTES_v0.1.21.md) and the
[GitHub Releases page](https://github.com/sbom-tool/sbom-tools/releases).

[Unreleased]: https://github.com/sbom-tool/sbom-tools/compare/v0.1.22...HEAD
[0.1.22]: https://github.com/sbom-tool/sbom-tools/releases/tag/v0.1.22
