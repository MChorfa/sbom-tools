# Submitting sbom-tools to the CycloneDX Tool Center

Guidance for listing `sbom-tools` in the [CycloneDX Tool Center](https://github.com/CycloneDX/tool-center).
The Tool Center is a community-curated catalog of SBOM/xBOM tooling, published under
CC BY-SA 4.0.

## How submissions work

Since September 2025 the Tool Center uses a **split-file model**: each tool is one JSON
file in the `tools/` directory. A helper (`helpers/tools-assemble.py`) assembles every
file into the aggregate `tools.json`. **Never edit `tools.json` directly** — add or edit
the per-tool file only.

Each file is validated against `schemas/tool.schema.json`
(`$id: https://cyclonedx.org/schema/tool-center-v2.tool.schema.json`, spec version `2.0`).

Two submission paths:

1. **MetaConfigurator (recommended for most contributors).** Open
   <https://www.metaconfigurator.org> — the Tool Center schema and settings are
   pre-loaded — fill in the form, then submit the resulting PR.
2. **Manual file editing.** Add a JSON file under `tools/` and open a PR yourself.
   This is the path documented below.

## Step-by-step (manual path)

1. Fork <https://github.com/CycloneDX/tool-center> and clone your fork.
2. Create `tools/semantic_sbom_diff.json` (lowercase, underscores — matches existing files
   like `apko.json`, `amazon_inspector_sbom_generator.json`). The filename must match
   the tool's `name` (parentheses stripped) — reviewers will request a rename if it
   doesn't (see [tool-center#111](https://github.com/CycloneDX/tool-center/pull/111)).
3. Paste the entry from the next section.
4. Validate it against `schemas/tool.schema.json` before pushing, e.g.:
   ```bash
   pip install check-jsonschema
   check-jsonschema --schemafile schemas/tool.schema.json tools/semantic_sbom_diff.json
   ```
5. Optionally run `python helpers/tools-assemble.py` to confirm it merges cleanly.
6. Commit, push, and open a PR. In the PR description confirm: the tool is
   SBOM/xBOM-related, the metadata is accurate and current, and licensing/attribution
   is respected.
7. CODEOWNERS-designated maintainers review. For questions, use the CycloneDX Slack.

## Ready-to-use entry for sbom-tools

Save as `tools/semantic_sbom_diff.json`:

```json
{
  "$schema": "https://cyclonedx.org/schema/tool-center-v2.tool.schema.json",
  "specVersion": "2.0",
  "tool": {
    "name": "Semantic SBOM Diff (sbom-tools)",
    "publisher": "sbom-tool",
    "description": "Semantic diff and analysis for CycloneDX and SPDX SBOMs, CBOMs and AI-BOMs. Compares BOMs, enriches with vulnerability, KEV and EOL data, scores quality, validates against compliance standards, and watches SBOMs for change.",
    "repository_url": "https://github.com/sbom-tool/sbom-tools",
    "website_url": "https://sbom.tools",
    "capabilities": [
      "SBOM",
      "CBOM",
      "AI/ML-BOM",
      "VDR/VEX"
    ],
    "availability": [
      "OPEN_SOURCE",
      "OSI_APPROVED"
    ],
    "functions": [
      "ANALYSIS",
      "TRANSFORM"
    ],
    "analysis": [
      "LICENSE_REPORTING",
      "OUTDATED_COMPONENTS",
      "POLICY_EVALUATION",
      "SECURITY_VULNERABILITIES"
    ],
    "transform": [
      "BOM_SERIALIZATION_FORMAT"
    ],
    "packaging": [
      "COMMAND_LINE_UTILITY"
    ],
    "library": [
      "RUST"
    ],
    "platform": [
      "LINUX",
      "MAC",
      "WINDOWS"
    ],
    "lifecycle": [
      "POST-BUILD",
      "OPERATIONS"
    ],
    "supportedStandards": [
      "CYCLONEDX",
      "SPDX",
      "PACKAGE_URL"
    ],
    "cycloneDxVersion": [
      "CYCLONEDX_V1.7",
      "CYCLONEDX_V1.6",
      "CYCLONEDX_V1.5",
      "CYCLONEDX_V1.4"
    ]
  }
}
```

## Why each field is set this way

| Field | Value | Rationale |
|-------|-------|-----------|
| `name` / `publisher` | `Semantic SBOM Diff (sbom-tools)` / `sbom-tool` | Leads with the functional differentiator (the original generic `sbom-tools` was flagged as too broad in [tool-center#111](https://github.com/CycloneDX/tool-center/pull/111)); crate name retained in parentheses for discoverability. Publisher is the GitHub org. |
| `description` | 2 sentences, 223 chars | Schema caps `description` at 250 chars (min 10); keep it plain text. |
| `capabilities` | `SBOM`, `CBOM`, `AI/ML-BOM`, `VDR/VEX` | BOM profile is auto-detected as SBOM, CBOM, or AI-BOM, each with its own scoring profile (`quality --profile cbom` / `ai-readiness`), compliance standards (CNSA 2.0, NIST PQC / EU AI Act, BSI SBOM-for-AI), and TUI tabs. `VDR/VEX` covers the `vex` subcommand (OpenVEX, CycloneDX VEX, CSAF in; CSAF out). |
| `availability` | `OPEN_SOURCE`, `OSI_APPROVED` | MIT-licensed (MIT is OSI-approved). |
| `functions` | `ANALYSIS`, `TRANSFORM` | Analyzes CycloneDX/SPDX BOMs; `convert`/`merge`/`tailor`/`enrich` transform them. It never authors a BOM from source, so `AUTHOR` is not claimed. |
| `analysis` | license / outdated / policy / vuln | `license-check`, EOL detection, license+quality policy engine, OSV/KEV enrichment. |
| `transform` | `BOM_SERIALIZATION_FORMAT` | `convert` converts between formats (SPDX 2.3 JSON ↔ CycloneDX 1.7 JSON); `merge`/`tailor` read and write JSON BOMs, preserving the input format (they do not accept XML, and `merge` requires both inputs in the same format). |
| `packaging` | `COMMAND_LINE_UTILITY` | Shipped as a CLI (also crates.io / Homebrew / prebuilt binaries). |
| `library` | `RUST` | Implementation language. |
| `platform` | Linux/Mac/Windows | Release ships binaries for all three (x86_64 + aarch64 Linux, x86_64 + aarch64 macOS, x86_64 Windows). |
| `lifecycle` | `POST-BUILD`, `OPERATIONS` | Operates on built SBOMs; watch mode monitors operational inventory. |
| `supportedStandards` | CycloneDX, SPDX, Package-URL | Parses CycloneDX 1.4–1.7 (JSON/XML) and SPDX 2.2/2.3 (JSON, tag-value, RDF/XML) + SPDX 3.0 (JSON-LD); component identity and matching are PURL-based. |
| `cycloneDxVersion` | 1.4–1.7 | Parser support range (`convert --to cyclonedx` emits 1.7 JSON). |

### Notes before submitting

- **Verify `repository_url`/`website_url`.** `repository_url` is the GitHub repo
  above; `website_url` is <https://sbom.tools>. Update either if the canonical
  locations change.
- **`supportedLanguages` is intentionally omitted.** That field means the *ecosystems
  the tool analyzes*, not the tool's own language. sbom-tools is format- and
  ecosystem-agnostic, so leaving it empty is more accurate than enumerating languages.
- **`CDXA` and `HBOM` are intentionally not claimed** even though both enum values
  exist. sbom-tools parses CycloneDX 1.6 `declarations` and uses them as compliance
  evidence, but it records signature *presence* only — signatures are never verified
  — and it does not emit declarations, so claiming the CDXA capability would oversell
  it. Hardware components are read and checked (CRA `[PRE-8-RQ-02]`), but there is no
  HBOM profile. Revisit both when attestation verification and an HBOM profile land.
- **`CPE`/`SWID` are not claimed under `supportedStandards`.** Those identifiers are
  parsed and count towards unique-identifier checks, but matching, query, and diff
  identity are PURL-based, so listing them would imply more than the tool does.
- **Re-verify the entry against the shipped binary before submitting.** The claims
  above were checked against `sbom-tools 0.1.22` (`--version`, per-command `--help`,
  and real fixture runs) on 2026-07-31.
- **Re-check enum values against the live schema** before opening the PR — the Tool
  Center schema evolves. Only the values present in `schemas/tool.schema.json` are valid;
  `additionalProperties` is `false`, so unknown fields fail validation.
- Required fields are only `name`, `publisher`, `description` — everything else is
  optional but improves discoverability via the Tool Center's faceted filters.
