# CRA Compliance — Standards Reverse Map

This document maps every compliance check sbom-tools surfaces under
`--standard cra` (and the related Article 24 / BSI / Annex III/IV
profiles) to the underlying regulation, harmonised standard, and
ENISA / industry guidance. Use it to:

- **Auditors / notified bodies**: locate the regulatory text behind each
  finding by Article number or Annex reference.
- **Engineers**: see which sidecar field (`CraSidecarMetadata`) or SBOM
  field clears each violation.
- **GRC / dashboards**: cross-reference SARIF `properties.standardIds`
  and `properties.standardHelpUris` to produce control-mapping reports.

> Generated and maintained alongside the sbom-tools source tree.
> If a check or article moves, send a PR — the reverse map is the
> single source of truth for both human readers and the
> `Violation::derive_standard_refs()` lookup table.

## CRA timeline anchors

| Date          | Event                                                         |
|---------------|---------------------------------------------------------------|
| 2024-12-10    | CRA enters into force (Regulation (EU) 2024/2847)             |
| 2026-09-11    | Article 14 reporting obligations apply                        |
| 2027-12-11    | Phase 1 deadline (`ComplianceLevel::CraPhase1`)               |
| 2029-12-11    | Phase 2 deadline (`ComplianceLevel::CraPhase2`)               |

## Compliance levels

| `ComplianceLevel`           | sbom-tools `--standard` alias                                                                       | Scope                                                                                                            |
|-----------------------------|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `CraPhase1`                 | `cra` (defaults to Phase 2; pin Phase 1 via the `Cra` profile)                                      | CRA Phase 1 reporting obligations (deadline 2027-12-11)                                                          |
| `CraPhase2`                 | `cra`                                                                                               | Full CRA compliance (deadline 2029-12-11)                                                                        |
| `CraOssSteward`             | `oss-steward`, `cra-oss-steward`, `cra-oss`, `cra-art24`, `art24`                                   | Article 24 lighter profile for open-source software stewards                                                     |
| `BsiTr03183_2`              | `bsi`, `tr-03183`, `tr03183`, `bsi-tr-03183-2`                                                      | BSI TR-03183-2 (German national CRA-aligned baseline)                                                            |
| `Cnsa2`                     | `cnsa2`, `cnsa-2`, `cnsa_2`, `cnsa2.0`                                                              | NSA CNSA 2.0 (post-quantum mandate for US national-security systems)                                             |
| `NistPqc`                   | `pqc`, `nist-pqc`, `nist_pqc`                                                                       | NIST IR 8547 + FIPS 203/204/205 (PQC migration)                                                                  |

The `--cra-product-class` flag (or sidecar `productClass`) drives the
[CRA-P3.2 calibration table](#cra-p32-product-class-severity-calibration)
that scales severity for vendor-hash, EOL, cycles, DoC, EUCC, PSIRT,
and module-attestation checks.

## Reverse map

Each row maps a sbom-tools `Violation::requirement` string to its
regulatory anchor, the harmonised-standard requirement ID
(prEN 40000-1-3 where known), the BSI section, and the canonical URL
that ends up in SARIF `properties.standardHelpUris`.

### CRA Article 13 (essential requirements & SBOM-related obligations)

| Requirement string                                              | CRA Article    | prEN 40000-1-3      | BSI TR-03183-2 § | sidecar field that clears it                              |
|-----------------------------------------------------------------|----------------|---------------------|------------------|-----------------------------------------------------------|
| `CRA Art. 13(2): Documented risk assessment`                    | Art. 13(2)     | —                   | §4.1             | `riskAssessmentUrl` + `riskAssessmentMethodology`         |
| `CRA Art. 13(3): SBOM freshness`                                | Art. 13(3)     | PRE-7-RQ-04         | §5.1             | regenerate SBOM on each release                           |
| `CRA Art. 13(4): SBOM machine-readable format`                  | Art. 13(4)     | PRE-7-RQ-04         | §5.2             | parse-time check (CycloneDX 1.4+ / SPDX 2.3+)             |
| `CRA Art. 13(5): Licensed component tracking`                   | Art. 13(5)     | PRE-7-RQ-05         | §5.4 (reco.)     | populate component `license` fields                       |
| `CRA Art. 13(6): Vulnerability disclosure contact`              | Art. 13(6)     | RLS-2-RQ-01         | §5.5 (reco.)     | `securityContact` / `vulnerabilityDisclosureUrl`          |
| `CRA Art. 13(7): Coordinated vulnerability disclosure policy`   | Art. 13(7)     | RLS-2-RQ-02         | —                | `coordinatedDisclosurePolicyUrl`                          |
| `CRA Art. 13(8): Support period / lifecycle management`         | Art. 13(8)     | PRE-7-RQ-06         | §5.5             | `supportEndDate` + EOL enrichment                         |
| `CRA Art. 13(9): Known vulnerabilities statement`               | Art. 13(9)     | RLS-2-RQ-04         | §5.5             | OSV / KEV / VEX enrichment                                |
| `CRA Art. 13(11): Component lifecycle monitoring`               | Art. 13(11)    | PRE-7-RQ-06         | §5.5             | EOL enrichment + transitive supplier coverage             |
| `CRA Art. 13(12): Product name and version identification`      | Art. 13(12)    | PRE-7-RQ-06         | §5.3             | SBOM `metadata.component.name` + `version` + sidecar      |
| `CRA Art. 13(15): Manufacturer identification`                  | Art. 13(15)    | —                   | §5.3             | `manufacturerName` + `manufacturerEmail`                  |

### CRA Article 14 (reporting obligations, applicable from 2026-09-11)

| Requirement string                                          | CRA Article    | prEN 40000-1-3      | sidecar field                         |
|-------------------------------------------------------------|----------------|---------------------|---------------------------------------|
| `CRA Art. 14: PSIRT contact for external vulnerability reports` | Art. 14    | RLS-2-RQ-03         | `psirtUrl`                            |
| `CRA Art. 14(1): 24-hour early-warning channel`             | Art. 14(1)     | RLS-2-RQ-03         | `earlyWarningContact`                 |
| `CRA Art. 14(2): 72-hour incident-report channel`           | Art. 14(2)     | RLS-2-RQ-03         | `incidentReportContact`               |
| `CRA Art. 14(7): ENISA single reporting platform`           | Art. 14(7)     | RLS-2-RQ-03-RE      | `enisaReportingPlatformId`            |

Pre-deadline (`Utc::now() < 2026-09-11`) findings are emitted as `Info`;
post-deadline they become `Warning` (or `Error` at
`ImportantClass2`/`Critical` per the
[product-class calibration](#cra-p32-product-class-severity-calibration)).

### CRA Annexes

| Requirement string                                          | CRA Annex                | prEN 40000-1-3      | What clears it                                          |
|-------------------------------------------------------------|--------------------------|---------------------|---------------------------------------------------------|
| `CRA Annex I Part II / prEN 40000-1-3 [PRE-7-RQ-07-RE]: Vendor hash carry-through` | Annex I Part II | PRE-7-RQ-07-RE | strong (SHA-256+) hash on vendor-supplied components |
| `CRA Annex I Part II 1: Component identifier`               | Annex I Part II 1        | PRE-7-RQ-07         | PURL / CPE / SWID / SWHID on each component             |
| `CRA Annex I Part III: Supply chain transparency`           | Annex I Part III         | PRE-7-RQ-01,03      | supplier on direct + transitive deps                    |
| `CRA Annex III: Document signature/integrity`               | Annex III                | —                   | serial number / digital signature / attestation hash    |
| `CRA Annex IV: EUCC reference (Common Criteria certificate)`| Annex IV                 | —                   | `Certification` external ref with `eucc`/`common-criteria` URL |
| `CRA Annex V: Technical documentation`                      | Annex V                  | —                   | run `sbom-tools cra-docs <sbom> --output dossier/`     |
| `CRA Annex VII: EU Declaration of Conformity reference`     | Annex VII                | —                   | `Attestation`/`Certification` external ref OR `ceMarkingReference` |
| `CRA Annex VIII: <Module> attestation reference`            | Annex VIII (Module B+C/H/EUCC) | —             | Module-specific `Attestation`/`Certification` external ref |
| `CRA prEN 40000-1-3 [PRE-8-RQ-02]: Hardware component inventory` | Annex I Part II   | PRE-8-RQ-02         | producer + identifier + firmware version on hardware    |

### Article 24 — open-source software steward floor

| Requirement string                                          | CRA reference  | Cleared by                                            |
|-------------------------------------------------------------|----------------|-------------------------------------------------------|
| `CRA Art. 24: Vulnerability-handling process (steward floor)` | Art. 24      | `SecurityContact` / `Advisories` / `VulnerabilityAssertion` external ref OR `psirtUrl` / `vulnerabilityDisclosureUrl` |
| `CRA Art. 13(7): Coordinated vulnerability disclosure policy` (relaxed to Warning under steward) | Art. 13(7) | `Advisories` external ref OR `coordinatedDisclosurePolicyUrl` |

Article 24 *suppresses* manufacturer-only checks (Art. 13(15) email,
Annex VII DoC, Annex VIII attestation, Article 14 channels, hardware
[PRE-8-RQ-02], vendor-hash carry-through).

## CRA-P3.2 product-class severity calibration

When `--cra-product-class` (or sidecar `productClass`) is set, the
severity of certain checks scales per Annex III/IV class. Selecting a
class also implies a default conformity-assessment route (Annex VIII),
overridable via sidecar `conformityAssessmentRoute`.

| Check                          | Default | Important-1 | Important-2 | Critical |
|--------------------------------|---------|-------------|-------------|----------|
| Vendor-hash coverage threshold | 50%     | 80%         | 80%         | 100%     |
| Vendor-hash severity           | Warning | Warning     | Error       | Error    |
| EOL components                 | Warning | Warning     | Error       | Error    |
| Cycles                         | Warning | Warning     | Error       | Error    |
| Annex VII DoC reference        | Info    | Warning     | Error       | Error    |
| EUCC reference                 | n/a     | n/a         | Info        | Error    |
| PSIRT documented               | Warning | Warning     | Error       | Error    |
| Module attestation reference   | n/a     | Warning (B+C) | Error (B+C/H) | Error (EUCC) |

Default conformity routes per class:

| Class             | Default route       |
|-------------------|---------------------|
| Default           | Module A (self-assessment) |
| ImportantClass1   | Module A (self-assessment, B+C optional) |
| ImportantClass2   | Module B+C          |
| Critical          | EUCC                |

## BSI TR-03183-2 — quick mapping

`ComplianceLevel::BsiTr03183_2` runs the §5 mandatory rules plus §6
recommendations. SARIF rule prefix: `SBOM-BSI-TR-03183-2-*`. Canonical URL:
[bsi.bund.de TR-03183](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html).

| BSI section | Required signal                                                | Cleared by                                                  |
|-------------|----------------------------------------------------------------|-------------------------------------------------------------|
| §5.1        | Mandatory ISO 8601 timestamp on document metadata              | parse-time validation                                        |
| §5.2        | Mandatory creator + tool identification                        | SBOM `metadata.tools` / SPDX `creator`                      |
| §5.3        | Mandatory PURL or other unique identifier per component        | one of `purl` / `cpe` / `swid` / `swhid` per component       |
| §5.4        | Mandatory SHA-256+ hash per component                          | strong hash on every component                              |
| §5.5        | Mandatory dependency relationships                             | populated `dependencies` graph                              |
| §6 (reco.)  | License, supplier, lifecycle phase                             | `license` / `supplier` / lifecycle properties               |

## CSAF v2.0 (ISO/IEC 20153:2025)

CSAF advisories ingest into `VexEnricher` alongside OpenVEX and
CycloneDX VEX. Format auto-detection: `document.csaf_version` starts
with `2.`. CSAF emit support: see
[`vex export --format csaf`](#csaf-emit) (P4.2).

| CSAF field                                | Internal mapping                              |
|-------------------------------------------|-----------------------------------------------|
| `vulnerabilities[].cve`                   | `Vulnerability.id`                            |
| `vulnerabilities[].ids[].text` (fallback) | `Vulnerability.id` (e.g., GHSA)               |
| `product_status.known_affected`           | `VexState::Affected`                          |
| `product_status.known_not_affected`       | `VexState::NotAffected`                       |
| `product_status.fixed`, `first_fixed`, `last_affected` | `VexState::Fixed`                |
| `product_status.under_investigation`      | `VexState::UnderInvestigation`                |
| `product_status.recommended`              | `VexState::Affected` (with note)              |
| `product_tree.full_product_names[].product_identification_helper.purl` | `(vuln_id, purl)` lookup key |

## CLI cheat sheet

```bash
# Multi-standard validate with CRA + BSI + NTIA in one pass
sbom-tools validate sbom.json --standard cra,bsi,ntia

# CRA Phase 2 with product-class calibration via sidecar
sbom-tools validate sbom.json --standard cra --cra-sidecar sbom.cra.yaml

# CRA validation with explicit product class
sbom-tools validate sbom.json --standard cra --cra-product-class important-class-2

# Article 24 steward profile
sbom-tools validate sbom.json --standard oss-steward

# SARIF output for CI (with helpUri populated)
sbom-tools validate sbom.json --standard cra -o sarif -O compliance.sarif

# Generate CRA technical-documentation dossier (Annex V)
sbom-tools cra-docs sbom.json --output dossier/ --cra-sidecar sbom.cra.yaml

# Apply CSAF advisories to enrich SBOM with VEX data
sbom-tools vex apply sbom.json --vex advisory.csaf.json
```

## Sidecar example

```yaml
manufacturerName: "Example Corp"
manufacturerEmail: "legal@example.com"
productName: "Example Product"
productVersion: "1.0.0"
ceMarkingReference: "EU-DoC-2026-001"
supportEndDate: "2030-12-31T00:00:00Z"

productClass: "important-class-1"
conformityAssessmentRoute: "module-a"

riskAssessmentUrl: "https://example.com/risk-assessment.pdf"
riskAssessmentMethodology: "ISO/IEC 27005:2022"

securityContact: "security@example.com"
psirtUrl: "https://example.com/psirt"
coordinatedDisclosurePolicyUrl: "https://example.com/security/cvd-policy"
earlyWarningContact: "ew@example.com"
incidentReportContact: "incidents@example.com"
enisaReportingPlatformId: "EU-MFR-12345"

isOssSteward: false
```

Auto-discovered next to the SBOM at any of:
`<stem>.cra.{json,yaml,yml}`, `<stem>-cra.{json,yaml}`, with multi-extension
stems also tried (`app.cdx.json` → `app.cra.json` works).

## Standards bibliography

| Standard / regulation              | URL                                                                                                                                                |
|------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| CRA — Regulation (EU) 2024/2847    | https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng                                                                                                 |
| prEN 40000-1-3 (in development)    | (CEN-CENELEC JTC 13 — paywalled draft; URLs unstable)                                                                                              |
| BSI TR-03183-2                     | https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03183/TR-03183_node.html |
| ENISA SBOM Implementation Guidance | https://www.enisa.europa.eu/publications/sbom-implementation-guidance                                                                              |
| NIST SP 800-218 SSDF               | https://doi.org/10.6028/NIST.SP.800-218                                                                                                            |
| EO 14028                           | https://www.federalregister.gov/d/2021-10460                                                                                                       |
| FDA premarket cybersecurity        | https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions |
| NTIA SBOM minimum elements         | https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf                                                                  |
| CSAF v2.0 (ISO/IEC 20153:2025)     | https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html                                                                                          |
| OpenVEX                            | https://github.com/openvex/spec                                                                                                                    |
| CISA KEV                           | https://www.cisa.gov/known-exploited-vulnerabilities-catalog                                                                                       |
| OSV.dev                            | https://osv.dev                                                                                                                                    |
| EUCC (Reg. (EU) 2024/482)          | https://eur-lex.europa.eu/eli/reg/2024/482/oj/eng                                                                                                  |

## Where this map lives in the code

- `Violation::derive_standard_refs()` in `src/quality/compliance.rs` —
  string → `(StandardKind, id)` mapping. Drives SARIF
  `properties.standardIds`.
- `StandardKind::canonical_help_uri()` in `src/quality/compliance.rs` —
  `(StandardKind, id)` → URL. Drives SARIF `helpUri` and
  `properties.standardHelpUris`.
- `rule_help_uri()` in `src/reports/sarif.rs` — rule-ID prefix → URL
  for `runs[].tool.driver.rules[].helpUri`.
- `ComplianceChecker::class_severity()` in `src/quality/compliance.rs` —
  P3.2 calibration table.
- `cli::run_cra_docs` in `src/cli/cra_docs.rs` — Annex V dossier
  generator.
