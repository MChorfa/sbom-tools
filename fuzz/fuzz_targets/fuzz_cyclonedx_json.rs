#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::parsers::{CycloneDxParser, SbomParser};

const MAX_WRAPPED_INPUT_LEN: usize = 10_000;

/// Fuzz the CycloneDX JSON parser directly.
///
/// Prefixes input with a minimal CycloneDX JSON wrapper to increase
/// the likelihood of reaching deep parsing logic rather than failing
/// at format detection.
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = CycloneDxParser::new();

        // Try raw input first
        let _ = parser.parse_str(s);

        // Also try wrapping in CycloneDX JSON envelope
        if s.len() < MAX_WRAPPED_INPUT_LEN {
            let wrapped = format!(
                r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{s}]}}"#,
            );
            let _ = parser.parse_str(&wrapped);

            // Wrap as a vulnerability so apply_vulnerability — the most
            // security-sensitive conversion path (ratings/severity, VEX
            // analysis, affects fan-out) — is reachable. A fixed component
            // gives affects[].ref a resolvable target.
            let vuln_wrapped = format!(
                r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{{"type":"library","bom-ref":"c","name":"c","version":"1.0"}}],"vulnerabilities":[{s}]}}"#,
            );
            let _ = parser.parse_str(&vuln_wrapped);

            // And as fields INSIDE a vulnerability object, so fuzz bytes
            // land directly in ratings/analysis/affects structures.
            let vuln_fields_wrapped = format!(
                r#"{{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{{"type":"library","bom-ref":"c","name":"c","version":"1.0"}}],"vulnerabilities":[{{"id":"CVE-0-0",{s}"affects":[{{"ref":"c"}}]}}]}}"#,
            );
            let _ = parser.parse_str(&vuln_fields_wrapped);
        }
    }
});
