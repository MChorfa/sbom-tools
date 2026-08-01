# sbom-tools v0.2.0

## Highlights

The **correctness release.** Where v0.1.22 added an AI-BOM domain, this release goes back over what was already there and checks whether it told the truth. Systematic audits of the diff engine, the parser layer, enrichment, quality scoring, the compliance engine, the CLI surface and the TUI turned up defects that shared a shape: the tool reporting something other than what it had computed. A demo SBOM shipped in this repository reported "no vulnerabilities" while its own Source view displayed a CVSS 9.8 entry. Fleet deviations rendered as `10000.0%`. A document containing no cryptography scored a perfect 100 for quantum readiness. A keyboard overlay advertised keys that did nothing.

All of those are fixed, and most are now pinned by tests that fail if the behaviour regresses.

Alongside the audit work: three new compliance standards bring `validate --standard` to **16** — **CISA's 2026 Minimum Elements** (published July 2026, successor to the NTIA 2021 elements), **PCI DSS v4.0.1 Requirement 6.3.2**, and **CISA Framing Software Component Transparency 3rd ed.** — plus **CDXA attestation ingestion**, so a signed machine-readable declaration can satisfy an SSDF practice or a CRA conformity route that previously accepted only self-declaration. A new **`quality -o sbomqs-json`** emits the [sbomqs](https://github.com/interlynk-io/sbomqs) 0–10 score model for side-by-side comparison. The project also gains its first **`CHANGELOG.md`** and a **TUI keyboard reference**.

> **Please read [Upgrade notes](#upgrade-notes) below** — this release changes machine-readable output, the Rust API, several compliance verdicts, and the TUI keymap.

## What's New

### Compliance

- **CISA 2026 Minimum Elements** — `validate --standard cisa-2026` (aliases `cisa`, `minimum-elements-2026`), 17 rules against the final v2.1 document published 2026-07-29. Deliberately stricter than the NTIA profile where the document is: a tool-only creator list does not satisfy SBOM Author, and a silently absent license fails where an explicit no-assertion passes. (#333)
- **PCI DSS 6.3.2** — `validate --standard pci-dss`, 10 rules treating the SBOM as the required inventory of bespoke, custom and third-party components. A passing verdict is evidence the inventory exists and is usable, **not** a PCI compliance certification, and thresholds chosen by this tool rather than the standard are labelled as such in the message. (#333)
- **CISA FSCT 3rd ed.** — `validate --standard fsct`, 27 rules across the document's three maturity tiers, mapped Minimum Expected → Error, Recommended Practice → Warning, Aspirational → Info. Checks are format-gated where the evidence cannot exist rather than failing a document for its format. (#333)
- **CDXA attestation evidence.** CycloneDX 1.6 `declarations` are parsed into a normalized model, and a declaration covering an SSDF practice, a CRA conformity route, an EUCC certificate reference or EO 14028 provenance now satisfies that rule at structural evidence level. Every pre-existing satisfaction path remains valid as a self-declared fallback, so documents without declarations are unaffected. Verification is **structural only** — signature presence is recorded, never cryptographically verified. (#333, #334)
- **Pinned evaluation clock.** `--as-of` fixes the date deadline-sensitive checks evaluate against, so CI runs are reproducible instead of drifting with the wall clock. (#320)
- **Registry-driven rule identity** across JSON, SARIF, the quality CLI and OSCAL, plus tri-state applicability so "not applicable" is distinct from "compliant". (#320)
- **Per-rule test matrix.** Every rule in the FDA, SSDF, EO 14028, Standard and Comprehensive profiles now has a firing and a silent fixture, with exhaustiveness enforced in both directions so a new check site forces a matrix entry. (#333)

### Interoperability

- **`quality -o sbomqs-json`** emits the sbomqs v2.0.11 `score --json` schema, and the plain-text quality summary gains a 0–10 category table. Formulas were read from that release's sources rather than its documentation, including the behaviours a reimplementation would otherwise "correct"; categories that cannot be computed are emitted as `ignored` with a stated reason instead of approximated. (#333)

### Parsers

- **SPDX 3.0.1 JSON-LD** documents parse, including canonical `@graph` forms. (#311)
- **SPDX 2.x data-loss gaps closed** — `documentDescribes`, file entries, and `LicenseRef` resolution. (#315)
- **CycloneDX correctness** — spec-valid documents that hard-failed now parse, nested assemblies are inventory, and serialization round-trips. (#314)
- **purl-shaped references resolve.** `dependencies[].ref` and `vulnerabilities[].affects[].ref` given as purls now match components, with bom-refs still winning on collision. Documents written this way previously lost dependency edges and vulnerabilities silently. (#333)
- **Document revision tracking.** The CycloneDX top-level `version` counter is captured, diffed, and round-tripped through `convert`, which had hardcoded `"version": 1`. (#333, #334)

### TUI

- Four phases of work land here: data surfacing and a theme backbone (#309), per-tab depth with detail panels and ML/VEX/match transparency (#310), a multi-mode overhaul with shared builders (#312), and unified search behind a single shortcuts surface (#313).
- **A UX audit of every mode** against a 269-frame corpus produced 203 findings; the 30 that survived adversarial verification are fixed, along with the tail. Empty states no longer celebrate, every advertised key exists, `y` copies the row you actually selected, and the Quality, Compliance and AI-Readiness tabs no longer collapse to empty borders at 80×24 — the app's own advertised minimum size. (#333, #334)
- **`docs/TUI_SHORTCUTS.md`** documents every binding across all three TUIs, each traced to its handler with the guard that makes a key mean different things on different tabs. (#334)

### Documentation

- **`CHANGELOG.md`**, which the project had never had. Every claim in it and in the refreshed `README`/`docs` was verified against the built binary and then re-checked by independent adversarial review. (#334)

## Bug Fixes

- **Vulnerabilities and dependency edges were silently dropped** whenever a CycloneDX document referenced components by purl — including this repository's own demo fixtures, where the Vulnerabilities tab reported a clean bill while the Source tab displayed a CVSS 9.8 CVE. (#333)
- **Fleet deviation was double-scaled**, rendering as `10000.0%` and saturating every gauge and severity band. It is now a 0–1 fraction, and the three similarity scales are pinned by tests. (#333)
- **A version bump counted as both an addition and a removal** in multi-SBOM analysis, so "Inconsistent" totals exceeded the number of distinct components and Timeline listed every upgrade twice. (#333)
- **Documents with no cryptography scored 100 for quantum readiness.** The score is now absent rather than vacuously perfect, and the CBOM scorer redistributes the weight. (#333)
- **The diff engine, parser, enrichment, quality and CLI audits** closed the solver/matching/incremental-cache defects (#299), 29 untrusted-input parser findings (#300), VEX correctness and network trust surface (#303), compliance false-passes and score math (#304), and the CLI exit-code contract and fail-closed gates (#322).
- **Compliance engine overhaul** — correct verdicts, verified citations, one output contract, and the removal of vacuous CRA passes. (#320)
- **`diff` and `view` accepted `-o sbomqs-json`** and silently emitted ordinary JSON under a format the caller never asked for. Both now reject it with a pointer to `quality`. (#334)
- **`--no-color` did not reach the TUI**, which consulted only the `NO_COLOR` environment variable, and the side-by-side reporter ignored both. An empty `NO_COLOR=` now counts as unset everywhere, per the convention. (#333, #334)
- **The shortcuts overlay contradicted itself** — its global rows were gated by mode but not by tab, so one frame could assert both `l Color legend` and `h/l Collapse/expand` on a tab where `l` switches standards. (#334)
- **Post-merge end-to-end testing** closed four further bugs in emitted VEX, LicenseRef surfacing, SPDX creator/file emission, and SARIF family fallback. (#321)

## Upgrade notes

These behaviors changed in this release. `CHANGELOG.md` carries the full list with details.

- **Deviation is a 0–1 fraction (`diff-multi` only).** `summary.deviation_scores` and `summary.max_deviation` are now `0.0…1.0`; they were double-scaled before. `timeline -o json` has no `summary` object and is unaffected.
- **Multi-SBOM component identity is the version-stripped logical purl** (`pkg:npm/express`, not `pkg:npm/express@4.18.2`), so a version bump is one component with a version spread.
- **`diff -o json` gains `component_type` on component changes and `doc_version` metadata entries.** Additive, but strict consumers must accept them. Change totals move: the demo fixture pair goes from 15 to 18.
- **`diff-multi`, `timeline` and `matrix` accept only `-o auto|tui|json`.** An unsupported value is a usage error (exit `2`) at parse time rather than a runtime failure (exit `3`).
- **Library API:** `CryptographyMetrics::{quantum_readiness_score, pqc_readiness_score}` return `Option<f32>`; `run_tui`/`run_view_tui` take a `no_color` parameter.
- **`validate --standard ntia` and `--standard fda` are engine-backed** and stricter — SBOMs that passed before can now fail.
- **CRA phases re-anchored to Reg. (EU) 2024/2847** — Phase 1 is Art. 14 reporting from 11 Sep 2026, Phase 2 is full application from 11 Dec 2027. Article and Annex citations were corrected throughout.
- **`validate --standard bsi` is rebased on BSI TR-03183-2 v2.1.0**, and several SARIF/JSON `rule_id`s were renamed to registry-driven identity.
- **Exit codes fail closed.** Operational errors exit `3`, command-line parse errors exit `2`, and a nonzero exit is a gate verdict only when the expected report was produced.
- **The TUI keymap changed.** Digits always jump tabs; Components' quick filters moved to a `Q` picker, Side-by-Side filters to `A`/`r`/`m`/`x`, the KEV filter to `K`, vulnerability group jump to `}`/`{`, Dependencies fold to `x`/`X`, the cycles toggle to `C`, and the threshold overlay — previously unreachable — to `t`. `docs/TUI_SHORTCUTS.md` is the full reference; `?` in the app is context-aware.

## Known gaps

- Attestation-satisfied compliance checks are not surfaced positively in `validate` output; the effect is visible only by comparing against a declarations-stripped document.
- CDXA ingestion reads CycloneDX **JSON** only — the XML path does not yet parse `declarations`, and `convert` does not round-trip them.
- Attestation phase 2 (external in-toto / DSSE bundles) is not implemented.

---

Install: `cargo install sbom-tools`
Homebrew: `brew install sbom-tool/tap/sbom-tools`
Crate: https://crates.io/crates/sbom-tools
Full changelog: https://github.com/sbom-tool/sbom-tools/compare/v0.1.22...v0.2.0
