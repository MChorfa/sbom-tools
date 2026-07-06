#![no_main]
use libfuzzer_sys::fuzz_target;
use sbom_tools::parsers::{SbomParser, Spdx3Parser};

const MAX_WRAPPED_INPUT_LEN: usize = 10_000;

/// Fuzz the SPDX 3.0 JSON-LD parser directly.
///
/// The SPDX 3.0 parser is the loosest-deserializing parser (polymorphic
/// element graph, untagged enums) and was previously unreachable by the
/// envelope fuzzers: `fuzz_parse_sbom` only reaches it through detect(),
/// which requires specific context markers raw fuzz input rarely produces.
///
/// Wraps input three ways to reach deep conversion logic:
/// - raw (exercises detection/dispatch and top-level deserialization)
/// - as an element inside an inline-`element` SpdxDocument envelope
/// - as a node inside a JSON-LD `@graph` envelope (the canonical
///   serialization, which exercises the graph-chaining path)
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parser = Spdx3Parser::new();

        // Try raw input first
        let _ = parser.parse_str(s);

        if s.len() < MAX_WRAPPED_INPUT_LEN {
            let element_wrapped = format!(
                r#"{{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","type":"SpdxDocument","spdxId":"urn:doc","element":[{s}]}}"#,
            );
            let _ = parser.parse_str(&element_wrapped);

            let graph_wrapped = format!(
                r#"{{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[{{"type":"SpdxDocument","spdxId":"urn:doc"}},{s}]}}"#,
            );
            let _ = parser.parse_str(&graph_wrapped);
        }
    }
});
