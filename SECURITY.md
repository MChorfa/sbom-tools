# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in sbom-tools, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Private Vulnerability Reporting (preferred):** Use the [Security Advisories](https://github.com/sbom-tool/sbom-tools/security/advisories/new) page to privately report a vulnerability.
2. **Email:** Send details to the maintainers via the email listed in `Cargo.toml`.

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- The affected version(s)
- Any suggested fix, if available

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days with an initial assessment
- **Fix timeline** depends on severity:
  - **Critical/High:** Patch release within 7 days
  - **Medium:** Patch in the next scheduled release
  - **Low:** Fix queued for a future release
- You will be credited in the release notes and GitHub Security Advisory (unless you prefer anonymity)
- We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)

### Scope

The following are in scope:

- Vulnerabilities in sbom-tools source code
- Dependency vulnerabilities that affect sbom-tools users
- Unsafe parsing of untrusted SBOM inputs (e.g., path traversal, resource exhaustion)

The following are out of scope:

- Vulnerabilities in dependencies that do not affect sbom-tools
- Issues that require physical access to a machine running sbom-tools
- Social engineering attacks

## Security Practices

This project follows supply chain security best practices:

- All dependencies are audited with [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) (advisories, licenses, bans, sources)
- GitHub Actions are pinned to full commit SHAs
- [OpenSSF Scorecard](https://scorecard.dev/) runs weekly to monitor security posture
- Releases are published to crates.io via [Trusted Publishing](https://blog.rust-lang.org/2023/11/09/crates-io-trusted-publishing.html) (OIDC, no long-lived tokens)
- Dependabot monitors for dependency and GitHub Actions updates
- Release tags are protected against force-push and deletion
- Release binaries are signed with [Sigstore](https://www.sigstore.dev/) and attested with [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
- SLSA Level 3 provenance is generated for crate packages
- A daily tag integrity check verifies all release tags point to commits on `main`

## Verifying Release Artifacts

Every release binary is signed and attested. You should verify artifacts before use.

### Verify GitHub Artifact Attestations (recommended)

Requires the [GitHub CLI](https://cli.github.com/) (`gh`):

```bash
# Download a release binary, then verify its build provenance
gh attestation verify sbom-tools-linux-x86_64.tar.gz --repo sbom-tool/sbom-tools
```

This confirms the binary was built by this repository's CI pipeline (tied to GitHub Actions OIDC identity). If the attestation is missing or invalid, **do not use the binary**.

### Verify Sigstore Cosign Signatures

Requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```bash
# Download the binary and its .bundle file, then verify
cosign verify-blob \
  --bundle sbom-tools-linux-x86_64.tar.gz.bundle \
  --certificate-identity-regexp "https://github.com/sbom-tool/sbom-tools/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sbom-tools-linux-x86_64.tar.gz
```

### Verify SHA256 Checksums

```bash
# Download checksums.sha256 from the release, then verify
sha256sum --check checksums.sha256
```

Note: Checksums alone do not prove provenance. An attacker who replaces a binary can also replace the checksum file. Always use attestation or Sigstore verification as the primary check.
