# Standards versions and watch list

The compliance engine pins its checks and citations to specific editions of
the underlying standards. This file records which edition each profile
targets, verified against the primary source on the date shown, plus the
items expected to move. Update this file whenever a checker is rebased onto
a new edition.

Last full verification: **2026-07-12** (primary sources fetched directly).

## Pinned editions

| Profile / reference | Edition implemented | Canonical source | Notes |
|---|---|---|---|
| EU CRA (`cra`, `oss-steward`) | Regulation (EU) 2024/2847 (OJ L, 2024-11-20) | <https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng> | Art. 14 applies from 2026-09-11; full application 2027-12-11 (Art. 71(2)). No 2029 milestone exists. |
| BSI TR-03183-2 (`bsi`) | v2.1.0 (2025-08-20) | <https://bsi.bund.de/dok/TR-03183-en> | CycloneDX ≥ 1.6 / SPDX ≥ 3.0.1; SHA-512 hash of the deployable component; the §7 six-month grace for v2.0.0 ended 2026-02-20. |
| NTIA minimum elements (`ntia`) | July 2021 report | <https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom> | Canonical host is ntia.gov (ntia.doc.gov survives via redirect). Remains the operative baseline while the CISA 2025 update is a draft. |
| FDA premarket cybersecurity (`fda`) | Final, 2026-02-03 — "Quality **Management** System Considerations…" | <https://www.fda.gov/media/119933/download> | Supersedes the June 2025 and Sept 2023 finals. SBOM elements (NTIA baseline + level of support + end-of-support date) unchanged. |
| NIST SSDF (`ssdf`) | SP 800-218 v1.1 | <https://doi.org/10.6028/NIST.SP.800-218> | |
| EO 14028 (`eo14028`) | May 2021 + NTIA elements | <https://www.federalregister.gov/d/2021-10460> | |
| CNSA 2.0 (`cnsa2`) | Sept 2022 fact sheet (rev.) | NSA CSA CNSA 2.0 | 2030/2033 milestones not yet severity-scaled (see plan P2). |
| NIST PQC (`pqc`) | **IR 8547 ipd (draft, Nov 2024)** + FIPS 203/204/205 (final, 2024-08-13) + SP 800-208 + SP 800-131A **Rev. 2** | <https://csrc.nist.gov/projects/post-quantum-cryptography> | Cite IR 8547 as draft; SP 800-131A Rev. 3 is draft-only. |
| EUCC (`eucc`) | Implementing Regulation (EU) 2024/482 | <https://eur-lex.europa.eu/eli/reg_impl/2024/482/oj/eng> | Reference-only profile. |
| EU AI Act (`ai-act`) | Regulation (EU) 2024/1689 Annex IV | <https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng> | Readiness profile. |
| BSI/G7 SBOM for AI (`bsi-ai`) | Final joint G7 guidance, 2026-05-12 | <https://www.cisa.gov/resources-tools/resources/software-bill-materials-ai-minimum-elements> | Supersedes the Feb 2026 BSI draft the profile was first built against; element clusters unchanged at the level we check. |
| CSAF | v2.0 (OASIS Standard, 2022; ISO/IEC 20153:2025) | <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html> | |

## Watch list (expected to move)

| Item | Status (2026-07-12) | Action when it lands |
|---|---|---|
| CEN/CENELEC prEN 40000-1-3 (CRA vulnerability handling / SBOM) | Enquiry closed 2026-02-09; comment resolution before Formal Vote; publication expected H2 2026, may slip to 2027 | The `PRE-*-RQ-*` ids hardcoded in registry refs must be re-verified against the published EN; revisit `Pren40000_1_3` help-URI (currently None — draft is paywalled). |
| NIST IR 8547 | Initial Public Draft only (comment period closed 2025-01-10) | Change "IR 8547 ipd" citations to final; re-check 2030/2035 timeline wording. |
| CISA 2025 SBOM Minimum Elements | Draft (RFC closed 2025-10-03), no final posted | New `ComplianceLevel` profile (plan P4); NTIA 2021 stays the baseline until then. |
| OASIS CSAF 2.1 | Committee Specification Draft 02 (2026-02-25) | Update `Csaf2` references when it reaches OASIS Standard. |
| NIST SP 800-131A Rev. 3 | Draft only (ipd 2024-10-21) | Update PQC registry refs from Rev. 2. |
| BSI TR-03183-2 | v2.1.0 current; no v2.2.0 exists (the `_v2_2_0.pdf` URL on bsi.bund.de serves the archived v1.1 — do not trust the filename) | Rebase `bsi` checker; §7 gives a six-month transition from publication of the next edition. |
