//! Centralized format detection for SBOM parsers.
//!
//! This module provides consistent format detection logic used by both
//! the standard parser and streaming parser, ensuring aligned confidence
//! thresholds and detection behavior.

use super::traits::{FormatConfidence, FormatDetection, ParseError, SbomParser};
use super::{CycloneDxParser, Spdx3Parser, SpdxParser, strip_bom};
use crate::model::NormalizedSbom;
use std::io::{BufRead, Read};

/// Read a reader into a string, rejecting streams over
/// [`MAX_SBOM_FILE_SIZE`](super::MAX_SBOM_FILE_SIZE).
///
/// Reads incrementally and bails the moment the accumulated length would
/// exceed the cap, so a hostile multi-GB stream is rejected without buffering
/// its tail, and a small input never over-allocates. Errors on the overrun
/// rather than silently truncating.
fn read_to_string_capped<R: Read>(reader: &mut R) -> Result<String, ParseError> {
    let limit = super::MAX_SBOM_FILE_SIZE as usize;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| ParseError::IoError(e.to_string()))?;
        if n == 0 {
            break;
        }
        if buf.len() + n > limit {
            return Err(ParseError::IoError(format!(
                "SBOM stream exceeds the {} MB limit",
                super::MAX_SBOM_FILE_SIZE / (1024 * 1024),
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8(buf)
        .map_err(|e| ParseError::IoError(format!("SBOM stream is not valid UTF-8: {e}")))
}

/// Minimum confidence threshold for accepting a format detection.
/// This is LOW confidence (0.25) - the parser believes it might be able to handle the content.
pub const MIN_CONFIDENCE_THRESHOLD: f32 = 0.25;

/// Parser type identified during detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserKind {
    CycloneDx,
    Spdx,
    Spdx3,
}

impl ParserKind {
    /// Get the human-readable name for this parser.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::CycloneDx => "CycloneDX",
            Self::Spdx | Self::Spdx3 => "SPDX",
        }
    }
}

/// Result of format detection.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// The parser that should handle this content, if detected.
    pub parser: Option<ParserKind>,
    /// Confidence level of the detection.
    pub confidence: FormatConfidence,
    /// Detected format variant (e.g., "JSON", "XML", "tag-value").
    pub variant: Option<String>,
    /// Detected version if available.
    pub version: Option<String>,
    /// Any warnings about the detection.
    pub warnings: Vec<String>,
}

impl DetectionResult {
    /// Create a result indicating no format was detected.
    #[must_use]
    pub fn unknown(reason: &str) -> Self {
        Self {
            parser: None,
            confidence: FormatConfidence::NONE,
            variant: None,
            version: None,
            warnings: vec![reason.to_string()],
        }
    }

    /// Create a result for `CycloneDX` detection.
    #[must_use]
    pub fn cyclonedx(detection: FormatDetection) -> Self {
        Self {
            parser: Some(ParserKind::CycloneDx),
            confidence: detection.confidence,
            variant: detection.variant,
            version: detection.version,
            warnings: detection.warnings,
        }
    }

    /// Create a result for SPDX 2.x detection.
    #[must_use]
    pub fn spdx(detection: FormatDetection) -> Self {
        Self {
            parser: Some(ParserKind::Spdx),
            confidence: detection.confidence,
            variant: detection.variant,
            version: detection.version,
            warnings: detection.warnings,
        }
    }

    /// Create a result for SPDX 3.0 detection.
    #[must_use]
    pub fn spdx3(detection: FormatDetection) -> Self {
        Self {
            parser: Some(ParserKind::Spdx3),
            confidence: detection.confidence,
            variant: detection.variant,
            version: detection.version,
            warnings: detection.warnings,
        }
    }

    /// Check if the detection is confident enough to parse.
    #[must_use]
    pub fn can_parse(&self) -> bool {
        self.parser.is_some() && self.confidence.value() >= MIN_CONFIDENCE_THRESHOLD
    }
}

/// Centralized format detector for SBOM content.
///
/// Provides consistent detection logic for both standard and streaming parsers.
pub struct FormatDetector {
    cyclonedx: CycloneDxParser,
    spdx: SpdxParser,
    spdx3: Spdx3Parser,
    min_confidence: f32,
}

impl Default for FormatDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatDetector {
    /// Create a new format detector with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cyclonedx: CycloneDxParser::new(),
            spdx: SpdxParser::new(),
            spdx3: Spdx3Parser::new(),
            min_confidence: MIN_CONFIDENCE_THRESHOLD,
        }
    }

    /// Create a format detector with a custom confidence threshold.
    #[must_use]
    pub const fn with_threshold(min_confidence: f32) -> Self {
        Self {
            cyclonedx: CycloneDxParser::new(),
            spdx: SpdxParser::new(),
            spdx3: Spdx3Parser::new(),
            min_confidence: min_confidence.clamp(0.0, 1.0),
        }
    }

    /// Detect format from full content string.
    ///
    /// This performs full detection using each parser's `detect()` method
    /// and picks the single strict winner (see [`Self::select_best_of_three`]).
    #[must_use]
    pub fn detect_from_content(&self, content: &str) -> DetectionResult {
        let content = strip_bom(content);
        let cdx_detection = self.cyclonedx.detect(content);
        let spdx_detection = self.spdx.detect(content);
        let spdx3_detection = self.spdx3.detect(content);

        self.select_best_of_three(cdx_detection, spdx_detection, spdx3_detection)
    }

    /// Detect format from peeked bytes (for streaming).
    ///
    /// This performs detection using a prefix of the content, suitable for
    /// streaming parsers that can only peek at the beginning of a file.
    #[must_use]
    pub fn detect_from_peek(&self, peek: &[u8]) -> DetectionResult {
        // Find first non-whitespace, non-BOM byte. A UTF-8 BOM (EF BB BF) is
        // not ASCII whitespace, so without skipping it explicitly it would
        // become "first_char" and fail every match arm below.
        let peek = if peek.starts_with(&[0xEF, 0xBB, 0xBF]) {
            &peek[3..]
        } else {
            peek
        };
        let first_char = peek.iter().find(|&&b| !b.is_ascii_whitespace());

        match first_char {
            Some(b'{' | b'<') => {
                // Convert peek to string for detection
                let preview = String::from_utf8_lossy(peek);
                let cdx_detection = self.cyclonedx.detect(&preview);
                let spdx_detection = self.spdx.detect(&preview);
                let spdx3_detection = self.spdx3.detect(&preview);

                self.select_best_of_three(cdx_detection, spdx_detection, spdx3_detection)
            }
            Some(c) if c.is_ascii_alphabetic() => {
                // Might be tag-value format (starts with letters like "SPDXVersion:")
                let preview = String::from_utf8_lossy(peek);
                let cdx_detection = self.cyclonedx.detect(&preview);
                let spdx_detection = self.spdx.detect(&preview);
                // SPDX 3.0 is JSON-LD only; detect() itself no-matches
                // content that doesn't start with '{', so this is just for
                // a single unified selection call, not a real candidate.
                let spdx3_detection = self.spdx3.detect(&preview);

                self.select_best_of_three(cdx_detection, spdx_detection, spdx3_detection)
            }
            Some(_) => DetectionResult::unknown("Unrecognized content format"),
            None => DetectionResult::unknown("Empty content"),
        }
    }

    /// Select the best parser among all three candidate detections.
    ///
    /// Uses consistent threshold checking and returns an error-like result
    /// instead of defaulting to a specific parser when ambiguous. Unlike a
    /// short-circuit (e.g. "return SPDX 3.0 immediately if its confidence is
    /// HIGH"), all three detections are computed and compared BEFORE any
    /// selection, so a document that also satisfies another format's markers
    /// as strongly cannot silently misroute or empty-parse: a genuine tie at
    /// the top confidence is reported as ambiguous rather than resolved by
    /// an arbitrary priority order.
    fn select_best_of_three(
        &self,
        cdx_detection: FormatDetection,
        spdx_detection: FormatDetection,
        spdx3_detection: FormatDetection,
    ) -> DetectionResult {
        let cdx_conf = cdx_detection.confidence.value();
        let spdx_conf = spdx_detection.confidence.value();
        let spdx3_conf = spdx3_detection.confidence.value();

        tracing::debug!(
            "Format detection: CycloneDX={:.2}, SPDX={:.2}, SPDX3={:.2}, threshold={:.2}",
            cdx_conf,
            spdx_conf,
            spdx3_conf,
            self.min_confidence
        );

        let max_conf = cdx_conf.max(spdx_conf).max(spdx3_conf);

        if max_conf < self.min_confidence {
            // No default bias - return unknown if nobody meets threshold
            let mut result =
                DetectionResult::unknown("Could not detect SBOM format with sufficient confidence");
            for (name, conf) in [
                ("CycloneDX", cdx_conf),
                ("SPDX", spdx_conf),
                ("SPDX 3.0", spdx3_conf),
            ] {
                if conf > 0.0 {
                    result.warnings.push(format!(
                        "{name} detection: {:.0}% confidence (threshold: {:.0}%)",
                        conf * 100.0,
                        self.min_confidence * 100.0
                    ));
                }
            }
            return result;
        }

        // A tie at the top confidence between two or more formats is
        // reported as ambiguous rather than resolved by priority order —
        // this is what closes the misrouting/empty-parse class of bugs.
        const EPSILON: f32 = 1e-6;
        let winners: Vec<&str> = [
            ("CycloneDX", cdx_conf),
            ("SPDX", spdx_conf),
            ("SPDX 3.0", spdx3_conf),
        ]
        .into_iter()
        .filter(|&(_, conf)| (conf - max_conf).abs() < EPSILON)
        .map(|(name, _)| name)
        .collect();

        if winners.len() > 1 {
            return DetectionResult::unknown(&format!(
                "Ambiguous format: {} are equally confident ({:.0}%) — refusing to guess",
                winners.join(" and "),
                max_conf * 100.0
            ));
        }

        if (cdx_conf - max_conf).abs() < EPSILON {
            DetectionResult::cyclonedx(cdx_detection)
        } else if (spdx_conf - max_conf).abs() < EPSILON {
            DetectionResult::spdx(spdx_detection)
        } else {
            DetectionResult::spdx3(spdx3_detection)
        }
    }

    /// Parse content using the detected format.
    ///
    /// This combines detection and parsing in a single operation.
    pub fn parse_str(&self, content: &str) -> Result<NormalizedSbom, ParseError> {
        let detection = self.detect_from_content(content);

        // Log any warnings
        for warning in &detection.warnings {
            tracing::warn!("{}", warning);
        }

        match detection.parser {
            Some(ParserKind::CycloneDx) if detection.can_parse() => {
                self.cyclonedx.parse_str(content)
            }
            Some(ParserKind::Spdx) if detection.can_parse() => self.spdx.parse_str(content),
            Some(ParserKind::Spdx3) if detection.can_parse() => self.spdx3.parse_str(content),
            _ => Err(ParseError::UnknownFormat(
                "Could not detect SBOM format. Expected CycloneDX or SPDX.".to_string(),
            )),
        }
    }

    /// Parse from a reader using streaming JSON parsing.
    ///
    /// Peeks at the content to detect format, then uses the appropriate
    /// reader-based parser for memory-efficient parsing. All reads are
    /// bounded by [`MAX_SBOM_FILE_SIZE`](super::MAX_SBOM_FILE_SIZE): unlike
    /// the path-based `parse_sbom`, this entry point (used by the streaming
    /// parser) has no up-front `metadata().len()` check, so an unbounded
    /// `read_to_string` here was an OOM vector for a hostile stream.
    pub fn parse_reader<R: BufRead>(&self, mut reader: R) -> Result<NormalizedSbom, ParseError> {
        // Peek at the buffer to detect format
        let peek = reader
            .fill_buf()
            .map_err(|e| ParseError::IoError(e.to_string()))?;

        if peek.is_empty() {
            return Err(ParseError::IoError("Empty content".to_string()));
        }

        // detect_from_peek already skips a leading BOM for its own analysis;
        // separately note its length so it can be consumed from the actual
        // stream below — parse_json_reader reads straight from `reader` with
        // no string-level strip_bom() pass, so the BOM must be physically
        // skipped here or it reaches serde_json and fails to parse.
        let bom_len = usize::from(peek.starts_with(&[0xEF, 0xBB, 0xBF])) * 3;
        let detection = self.detect_from_peek(peek);

        // Log any warnings
        for warning in &detection.warnings {
            tracing::warn!("{}", warning);
        }

        reader.consume(bom_len);

        // Cap every downstream read at the file-size limit (+1 to detect
        // overrun). fill_buf only peeked, so the buffered bytes are preserved.
        let mut reader = reader.take(super::MAX_SBOM_FILE_SIZE + 1);

        match detection.parser {
            Some(ParserKind::CycloneDx) if detection.can_parse() => {
                // Check if it's XML (needs string-based parsing)
                let is_xml = detection.variant.as_deref() == Some("XML");
                if is_xml {
                    let content = read_to_string_capped(&mut reader)?;
                    self.cyclonedx.parse_str(&content)
                } else {
                    self.cyclonedx.parse_json_reader(reader)
                }
            }
            Some(ParserKind::Spdx) if detection.can_parse() => {
                // Check variant - tag-value and RDF need string-based parsing
                let needs_string =
                    matches!(detection.variant.as_deref(), Some("tag-value" | "RDF"));
                if needs_string {
                    let content = read_to_string_capped(&mut reader)?;
                    self.spdx.parse_str(&content)
                } else {
                    self.spdx.parse_json_reader(reader)
                }
            }
            Some(ParserKind::Spdx3) if detection.can_parse() => {
                // SPDX 3.0 is JSON-LD only - read full content and parse
                let content = read_to_string_capped(&mut reader)?;
                self.spdx3.parse_str(&content)
            }
            _ => Err(ParseError::UnknownFormat(
                "Could not detect SBOM format. Expected CycloneDX or SPDX.".to_string(),
            )),
        }
    }

    /// Get a reference to the `CycloneDX` parser.
    #[must_use]
    pub const fn cyclonedx_parser(&self) -> &CycloneDxParser {
        &self.cyclonedx
    }

    /// Get a reference to the SPDX parser.
    #[must_use]
    pub const fn spdx_parser(&self) -> &SpdxParser {
        &self.spdx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cyclonedx_json() {
        let detector = FormatDetector::new();
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5"}"#;
        let result = detector.detect_from_content(content);

        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
        assert_eq!(result.variant, Some("JSON".to_string()));
    }

    #[test]
    fn test_detect_spdx_json() {
        let detector = FormatDetector::new();
        let content = r#"{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let result = detector.detect_from_content(content);

        assert_eq!(result.parser, Some(ParserKind::Spdx));
        assert!(result.can_parse());
        assert_eq!(result.variant, Some("JSON".to_string()));
    }

    #[test]
    fn test_detect_from_peek_cyclonedx() {
        let detector = FormatDetector::new();
        let peek = br#"{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}"#;
        let result = detector.detect_from_peek(peek);

        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
    }

    #[test]
    fn test_detect_unknown_format() {
        let detector = FormatDetector::new();
        let content = r#"{"some": "random", "json": "content"}"#;
        let result = detector.detect_from_content(content);

        assert!(result.parser.is_none());
        assert!(!result.can_parse());
    }

    #[test]
    fn test_no_default_bias() {
        let detector = FormatDetector::new();
        // Ambiguous JSON that doesn't match either format
        let content = r#"{"data": "test"}"#;
        let result = detector.detect_from_content(content);

        // Should NOT default to CycloneDX or any other format
        assert!(result.parser.is_none());
        assert!(!result.can_parse());
    }

    #[test]
    fn test_threshold_enforcement() {
        let detector = FormatDetector::with_threshold(0.5);
        // Content with low confidence might not pass higher threshold
        let content = r#"{"specVersion": "1.5", "components": []}"#;
        let result = detector.detect_from_content(content);

        // If confidence is below 0.5, should not parse
        if result.confidence.value() < 0.5 {
            assert!(!result.can_parse());
        }
    }

    /// A UTF-8 BOM must not defeat detection: str::trim() does not strip
    /// U+FEFF, so a BOM-prefixed valid document previously failed on the
    /// content.trim().starts_with('{') check in every parser's detect().
    #[test]
    fn bom_prefixed_content_still_detects() {
        let detector = FormatDetector::new();
        let content = "\u{FEFF}{\"bomFormat\": \"CycloneDX\", \"specVersion\": \"1.5\"}";
        let result = detector.detect_from_content(content);
        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
    }

    /// Same BOM guard on the peek/streaming path.
    #[test]
    fn bom_prefixed_peek_still_detects() {
        let detector = FormatDetector::new();
        let mut peek = vec![0xEF, 0xBB, 0xBF];
        peek.extend_from_slice(br#"{"bomFormat": "CycloneDX", "specVersion": "1.5"}"#);
        let result = detector.detect_from_peek(&peek);
        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
    }

    /// A component/property VALUE that happens to equal a marker word
    /// ("SPDXID") must not trip SPDX detection on an unrelated CycloneDX
    /// document — the marker must appear as an actual JSON key.
    #[test]
    fn marker_word_as_value_does_not_misroute() {
        let detector = FormatDetector::new();
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "library", "name": "spdxVersion", "version": "1.0"},
                            {"type": "library", "name": "SPDXID", "version": "1.0"}]}"#;
        let result = detector.detect_from_content(content);
        assert_eq!(
            result.parser,
            Some(ParserKind::CycloneDx),
            "a component merely NAMED 'spdxVersion'/'SPDXID' must not misroute to SPDX"
        );
    }

    /// A CycloneDX document that also contains "@context"/"spdx3" as plain
    /// text (e.g. in a description) must not be misrouted to the SPDX 3.0
    /// parser and silently produce an empty SBOM.
    #[test]
    fn cyclonedx_with_spdx3_looking_text_is_not_misrouted() {
        let detector = FormatDetector::new();
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "library", "name": "lib", "version": "1.0",
                "description": "migrated from spdx3 format; see @context notes"}]}"#;
        let result = detector.detect_from_content(content);
        assert_eq!(result.parser, Some(ParserKind::CycloneDx));
        assert!(result.can_parse());
    }

    /// A genuine tie at the top confidence between two formats must be
    /// reported as ambiguous, not silently resolved by an arbitrary
    /// priority order (the previous SPDX3-short-circuit / SPDX-tie-break
    /// bias).
    #[test]
    fn genuine_tie_is_reported_ambiguous_not_silently_resolved() {
        let detector = FormatDetector::new();
        // CERTAIN CycloneDX markers (bomFormat + CycloneDX) AND CERTAIN SPDX
        // markers (spdxVersion + SPDXID keys) in the same document.
        let content = r#"{"bomFormat": "CycloneDX", "specVersion": "1.5",
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}"#;
        let result = detector.detect_from_content(content);
        assert!(
            result.parser.is_none(),
            "a genuine tie must not silently pick a parser, got {:?}",
            result.parser
        );
        assert!(!result.can_parse());
    }
}
