//! Shared CBOM detail line-builders and status indicators.
//!
//! One source of truth for the five crypto detail renderers (unified Crypto
//! tab + the four dedicated asset tabs) so their output cannot drift, plus
//! the single definition of the quantum/status glyphs the lists and legends
//! share. Pure builders in the `render_ml_dataset_lines` style: no `App`
//! dependency, all colors via [`colors()`].

use crate::model::{
    AlgorithmProperties, CertificateProperties, Component, CryptoMaterialState, CryptoMode,
    CryptoPrimitive, NormalizedSbom, ProtocolProperties, RelatedCryptoMaterialProperties,
};
use crate::tui::theme::colors;
use ratatui::prelude::*;

/// One broken-practice predicate for every CBOM surface: a weak/broken
/// algorithm family or name (MD5, SHA-1, DES, RC4, …) or ECB mode, which
/// SP 800-131A disallows (the compliance engine fails it via SBOM-PQC-008).
///
/// Sharing this with [`quantum_indicator`] is what keeps the Algorithms and
/// Crypto lists from blessing an asset (e.g. `AES-128-ECB`) that the PQC
/// Compliance tab fails for the same reason.
#[must_use]
pub fn is_broken_practice(component_name: &str, algo: &AlgorithmProperties) -> bool {
    algo.is_weak_by_name(component_name) || algo.mode == Some(CryptoMode::Ecb)
}

/// The one quantum-posture indicator for crypto asset lists:
/// `!` weak/broken practice, `Q` quantum-safe, `V` quantum-vulnerable
/// (level 0), `?` unknown (no level / no algorithm properties).
pub fn quantum_indicator(comp: &Component) -> Span<'static> {
    let scheme = colors();
    comp.crypto_properties
        .as_ref()
        .and_then(|cp| cp.algorithm_properties.as_ref())
        .map_or_else(
            || Span::styled("?", Style::default().fg(scheme.text_muted)),
            |a| {
                if is_broken_practice(&comp.name, a) {
                    Span::styled(
                        "!",
                        Style::default()
                            .fg(scheme.critical)
                            .add_modifier(Modifier::BOLD),
                    )
                } else if a.is_quantum_safe() {
                    Span::styled("Q", Style::default().fg(scheme.success))
                } else if a.nist_quantum_security_level == Some(0) {
                    Span::styled("V", Style::default().fg(scheme.warning))
                } else {
                    Span::styled("?", Style::default().fg(scheme.text_muted))
                }
            },
        )
}

/// Human-readable label for a [`CryptoPrimitive`]. The `Display` impl emits
/// the CycloneDX 1.6 wire token (kept for serialization); cryptic tokens
/// like `ae` are expanded here for the detail panes.
#[must_use]
pub fn primitive_label(primitive: &CryptoPrimitive) -> String {
    match primitive {
        CryptoPrimitive::Ae => "authenticated encryption (ae)".to_string(),
        CryptoPrimitive::BlockCipher => "block cipher".to_string(),
        CryptoPrimitive::StreamCipher => "stream cipher".to_string(),
        CryptoPrimitive::Hash => "hash".to_string(),
        CryptoPrimitive::Mac => "message authentication code (mac)".to_string(),
        CryptoPrimitive::Signature => "signature".to_string(),
        CryptoPrimitive::Pke => "public-key encryption (pke)".to_string(),
        CryptoPrimitive::Kem => "key encapsulation mechanism (kem)".to_string(),
        CryptoPrimitive::Kdf => "key derivation function (kdf)".to_string(),
        CryptoPrimitive::KeyAgree => "key agreement".to_string(),
        CryptoPrimitive::Xof => "extendable-output function (xof)".to_string(),
        CryptoPrimitive::Drbg => "random bit generator (drbg)".to_string(),
        CryptoPrimitive::Combiner => "hybrid combiner".to_string(),
        CryptoPrimitive::Other(s) => s.clone(),
        CryptoPrimitive::Unknown => "unknown".to_string(),
    }
}

/// Status glyph + color for a certificate (expiry posture).
pub fn cert_status_glyph(cert: &CertificateProperties) -> (&'static str, Color) {
    let scheme = colors();
    if cert.is_expired() {
        ("X", scheme.error)
    } else if cert.is_expiring_soon(90) {
        ("!", scheme.warning)
    } else {
        ("\u{2713}", scheme.success)
    }
}

/// Status glyph + color for key material state.
pub fn key_state_glyph(state: &CryptoMaterialState) -> (&'static str, Color) {
    let scheme = colors();
    match state {
        CryptoMaterialState::Active => ("\u{25cf}", scheme.success),
        CryptoMaterialState::Compromised => ("!", scheme.critical),
        CryptoMaterialState::Deactivated => ("\u{25cb}", scheme.text_muted),
        CryptoMaterialState::Destroyed => ("X", scheme.text_muted),
        _ => ("?", scheme.warning),
    }
}

/// Pick the widest legend variant that fits `max_width` columns — ratatui's
/// `title_bottom` otherwise hard-truncates mid-word, silently dropping the
/// trailing legend entries at narrow widths.
fn legend_for_width(max_width: u16, variants: &[&'static str]) -> Line<'static> {
    use unicode_width::UnicodeWidthStr;
    let text = variants
        .iter()
        .find(|v| UnicodeWidthStr::width(**v) as u16 <= max_width)
        .or(variants.last())
        .copied()
        .unwrap_or("");
    Line::styled(text, Style::default().fg(colors().text_muted))
}

/// Legend for the quantum indicator, rendered as a list `title_bottom`.
/// `max_width` is the panel's inner width (borders excluded).
pub fn quantum_legend(max_width: u16) -> Line<'static> {
    legend_for_width(
        max_width,
        &[
            " ! weak/broken  Q quantum-safe  V vulnerable  ? unknown ",
            " ! weak  Q quantum-safe  V vulnerable  ? unknown ",
            " ! weak  Q safe  V vuln  ? unk ",
            " ! Q V ? ",
        ],
    )
}

/// Legend for the certificate status glyphs.
pub fn cert_legend(max_width: u16) -> Line<'static> {
    legend_for_width(
        max_width,
        &[
            " \u{2713} valid  ! expiring  X expired ",
            " \u{2713} ok  ! expiring  X expired ",
            " \u{2713} ! X ",
        ],
    )
}

/// Legend for the key-state glyphs.
pub fn key_legend(max_width: u16) -> Line<'static> {
    legend_for_width(
        max_width,
        &[
            " \u{25cf} active  ! compromised  \u{25cb} deactivated  X destroyed ",
            " \u{25cf} active  ! compromised  \u{25cb} deact  X destr ",
            " \u{25cf} act  ! comp  \u{25cb} deact  X destr ",
            " \u{25cf} ! \u{25cb} X ",
        ],
    )
}

/// Bom-ref → component lookup for the crypto detail panes, so
/// `cryptoRefArray` / `algorithmRef` / `signatureAlgorithmRef` render the
/// referenced component's name instead of a raw ref like
/// `crypto/algorithm/ml-dsa-87` (falling back to the raw ref when it
/// doesn't resolve).
pub struct CryptoRefLookup<'a> {
    by_ref: std::collections::HashMap<&'a str, &'a Component>,
}

impl<'a> CryptoRefLookup<'a> {
    /// Index every component carrying a format-level id (CycloneDX bom-ref).
    #[must_use]
    pub fn new(sbom: &'a NormalizedSbom) -> Self {
        let mut by_ref: std::collections::HashMap<&'a str, &'a Component> =
            std::collections::HashMap::new();
        for comp in sbom.components.values() {
            let format_id = comp.identifiers.format_id.as_str();
            if !format_id.is_empty() {
                by_ref.entry(format_id).or_insert(comp);
            }
        }
        Self { by_ref }
    }

    /// Display name for a crypto ref: the resolved component's name, or the
    /// raw ref when unresolved.
    #[must_use]
    pub fn display(&self, bom_ref: &str) -> String {
        self.by_ref
            .get(bom_ref)
            .map_or_else(|| bom_ref.to_string(), |c| c.name.clone())
    }

    /// Comma-joined display names for a ref list.
    fn display_list(&self, refs: &[String]) -> String {
        refs.iter()
            .map(|r| self.display(r))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Inline verdict for a resolved *algorithm* ref: `[weak]` for broken
    /// practice, `[quantum-vulnerable]` for declared level 0 — so a
    /// SHA-1/RSA-1024-signed certificate carries a visible verdict instead
    /// of hiding it behind an opaque ref. `None` when the ref doesn't
    /// resolve to an algorithm or carries no adverse verdict.
    fn verdict_marker(&self, bom_ref: &str) -> Option<Span<'static>> {
        let comp = self.by_ref.get(bom_ref)?;
        let algo = comp
            .crypto_properties
            .as_ref()?
            .algorithm_properties
            .as_ref()?;
        let scheme = colors();
        if is_broken_practice(&comp.name, algo) {
            Some(Span::styled(
                " [weak]",
                Style::default()
                    .fg(scheme.critical)
                    .add_modifier(Modifier::BOLD),
            ))
        } else if algo.nist_quantum_security_level == Some(0) {
            Some(Span::styled(
                " [quantum-vulnerable]",
                Style::default().fg(scheme.warning),
            ))
        } else {
            None
        }
    }

    /// `"Label: name"` line for a resolved ref, with the inline verdict
    /// marker appended when the referenced algorithm warrants one.
    fn ref_line(&self, label: &str, bom_ref: &str) -> Line<'static> {
        let mut spans = vec![Span::raw(format!("{label}{}", self.display(bom_ref)))];
        if let Some(marker) = self.verdict_marker(bom_ref) {
            spans.push(marker);
        }
        Line::from(spans)
    }
}

/// Detail lines for an algorithm asset (field superset of the dedicated
/// Algorithms tab; the unified Crypto tab renders the same body).
pub fn algorithm_detail_lines(
    component_name: &str,
    algo: &AlgorithmProperties,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(format!(
        "Primitive: {}",
        primitive_label(&algo.primitive)
    )));
    if let Some(f) = &algo.algorithm_family {
        lines.push(Line::from(format!("Family:    {f}")));
    }
    if let Some(p) = &algo.parameter_set_identifier {
        lines.push(Line::from(format!("Params:    {p}")));
    }
    if let Some(m) = &algo.mode {
        if *m == CryptoMode::Ecb {
            lines.push(Line::from(vec![
                Span::raw(format!("Mode:      {m}")),
                Span::styled(
                    "  BROKEN PRACTICE (SP 800-131A)",
                    Style::default()
                        .fg(scheme.critical)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        } else {
            lines.push(Line::from(format!("Mode:      {m}")));
        }
    }
    if let Some(c) = &algo.elliptic_curve {
        lines.push(Line::from(format!("Curve:     {c}")));
    }
    if let Some(bits) = algo.classical_security_level {
        lines.push(Line::from(format!("Security:  {bits} bits")));
    }
    if let Some(ql) = algo.nist_quantum_security_level {
        let color = if ql == 0 {
            scheme.error
        } else if ql >= 3 {
            scheme.success
        } else {
            scheme.warning
        };
        // NIST category 1-2 is quantum-resistant but reads "marginal", not a
        // bare green SAFE: CNSA 2.0 targets the top of the scale, and the PQC
        // Compliance tab may fail the same asset — the qualifier is what
        // makes that split explainable instead of contradictory.
        let (verdict, verdict_color) = if ql == 0 {
            (" VULNERABLE", scheme.error)
        } else if ql >= 3 {
            (" SAFE", scheme.success)
        } else {
            (" SAFE (marginal)", scheme.warning)
        };
        lines.push(Line::from(vec![
            Span::raw("Quantum:   "),
            Span::styled(
                format!("Level {ql}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(verdict, Style::default().fg(verdict_color)),
        ]));
    }
    if algo.is_weak_by_name(component_name) {
        lines.push(Line::styled(
            "WARNING: Weak/broken algorithm",
            Style::default()
                .fg(scheme.critical)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if algo.is_hybrid_pqc() {
        lines.push(Line::styled(
            "Hybrid PQC combiner",
            Style::default().fg(scheme.primary),
        ));
    }
    if !algo.crypto_functions.is_empty() {
        let funcs: Vec<_> = algo
            .crypto_functions
            .iter()
            .map(ToString::to_string)
            .collect();
        lines.push(Line::from(format!("Functions: {}", funcs.join(", "))));
    }
    if !algo.certification_level.is_empty() {
        let certs: Vec<_> = algo
            .certification_level
            .iter()
            .map(ToString::to_string)
            .collect();
        lines.push(Line::from(format!("Certified: {}", certs.join(", "))));
    }
    if let Some(p) = &algo.padding {
        lines.push(Line::from(format!("Padding:   {p}")));
    }
    if let Some(env) = &algo.execution_environment {
        lines.push(Line::from(format!("Exec Env:  {env}")));
    }
    if let Some(platform) = &algo.implementation_platform {
        lines.push(Line::from(format!("Platform:  {platform}")));
    }

    lines
}

/// Detail lines for a certificate asset (superset source: the dedicated
/// Certificates tab, including Remaining / Sig Algo / Public Key).
pub fn certificate_detail_lines(
    cert: &CertificateProperties,
    refs: &CryptoRefLookup<'_>,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines: Vec<Line> = Vec::new();

    if let Some(s) = &cert.subject_name {
        lines.push(Line::from(format!("Subject:    {s}")));
    }
    if let Some(i) = &cert.issuer_name {
        lines.push(Line::from(format!("Issuer:     {i}")));
    }
    lines.push(Line::raw(""));
    if let Some(nb) = &cert.not_valid_before {
        lines.push(Line::from(format!("Valid From: {}", nb.format("%Y-%m-%d"))));
    }
    if let Some(na) = &cert.not_valid_after {
        let color = if cert.is_expired() {
            scheme.error
        } else if cert.is_expiring_soon(90) {
            scheme.warning
        } else {
            scheme.success
        };
        let status_label = if cert.is_expired() {
            " EXPIRED"
        } else if cert.is_expiring_soon(90) {
            " EXPIRING SOON"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            Span::raw("Valid To:   "),
            Span::styled(
                na.format("%Y-%m-%d").to_string(),
                Style::default().fg(color),
            ),
            Span::styled(status_label, Style::default().fg(color)),
        ]));
        if let Some(days) = cert.validity_days() {
            lines.push(Line::from(format!("Remaining:  {days} days")));
        }
    }
    lines.push(Line::raw(""));
    if let Some(fmt) = &cert.certificate_format {
        lines.push(Line::from(format!("Format:     {fmt}")));
    }
    if let Some(sig_ref) = &cert.signature_algorithm_ref {
        lines.push(refs.ref_line("Sig Algo:   ", sig_ref));
    }
    if let Some(key_ref) = &cert.subject_public_key_ref {
        lines.push(refs.ref_line("Public Key: ", key_ref));
    }

    lines
}

/// Detail lines for key material (superset source: the dedicated Keys tab,
/// including algorithm ref, the Secured By subsection, and lifecycle dates).
pub fn key_material_detail_lines(
    mat: &RelatedCryptoMaterialProperties,
    refs: &CryptoRefLookup<'_>,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(format!("Type:   {}", mat.material_type)));
    if let Some(state) = &mat.state {
        let (_, color) = key_state_glyph(state);
        lines.push(Line::from(vec![
            Span::raw("State:  "),
            Span::styled(state.to_string(), Style::default().fg(color)),
        ]));
    }
    if let Some(size) = mat.size {
        lines.push(Line::from(format!("Size:   {size} bits")));
    }
    if let Some(fmt) = &mat.format {
        lines.push(Line::from(format!("Format: {fmt}")));
    }
    if let Some(algo_ref) = &mat.algorithm_ref {
        lines.push(refs.ref_line("Algo:   ", algo_ref));
    }
    if let Some(sb) = &mat.secured_by {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "-- Secured By --",
            Style::default().fg(scheme.primary),
        ));
        lines.push(Line::from(format!("Mechanism: {}", sb.mechanism)));
        if let Some(a) = &sb.algorithm_ref {
            lines.push(refs.ref_line("Algorithm: ", a));
        }
    }
    lines.push(Line::raw(""));
    if let Some(d) = &mat.creation_date {
        lines.push(Line::from(format!("Created:   {}", d.format("%Y-%m-%d"))));
    }
    if let Some(d) = &mat.activation_date {
        lines.push(Line::from(format!("Activated: {}", d.format("%Y-%m-%d"))));
    }
    if let Some(d) = &mat.expiration_date {
        lines.push(Line::from(format!("Expires:   {}", d.format("%Y-%m-%d"))));
    }

    lines
}

/// Detail lines for a protocol asset (superset source: the dedicated
/// Protocols tab, including cipher suites, IKEv2 transforms, and refs).
pub fn protocol_detail_lines(
    proto: &ProtocolProperties,
    refs: &CryptoRefLookup<'_>,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(format!("Protocol: {}", proto.protocol_type)));
    if let Some(v) = &proto.version {
        lines.push(Line::from(format!("Version:  {v}")));
    }

    if !proto.cipher_suites.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            format!("-- Cipher Suites ({}) --", proto.cipher_suites.len()),
            Style::default().fg(scheme.primary),
        ));
        for suite in &proto.cipher_suites {
            if let Some(name) = &suite.name {
                lines.push(Line::from(format!("  {name}")));
            }
            if !suite.algorithms.is_empty() {
                lines.push(Line::styled(
                    format!("    Algorithms: {}", refs.display_list(&suite.algorithms)),
                    Style::default().fg(scheme.text_muted),
                ));
            }
        }
    }

    if let Some(ikev2) = &proto.ikev2_transform_types {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "-- IKEv2 Transform Types --",
            Style::default().fg(scheme.primary),
        ));
        if !ikev2.encr.is_empty() {
            lines.push(Line::from(format!(
                "Encryption: {}",
                refs.display_list(&ikev2.encr)
            )));
        }
        if !ikev2.prf.is_empty() {
            lines.push(Line::from(format!(
                "PRF:        {}",
                refs.display_list(&ikev2.prf)
            )));
        }
        if !ikev2.integ.is_empty() {
            lines.push(Line::from(format!(
                "Integrity:  {}",
                refs.display_list(&ikev2.integ)
            )));
        }
        if !ikev2.ke.is_empty() {
            lines.push(Line::from(format!(
                "Key Exch:   {}",
                refs.display_list(&ikev2.ke)
            )));
        }
    }

    if !proto.crypto_ref_array.is_empty() {
        lines.push(Line::raw(""));
        // cryptoRefArray may reference ANY crypto asset type (certificates,
        // keys, …), not just algorithms — the heading must not overclaim.
        lines.push(Line::styled(
            "-- Referenced Crypto Assets --",
            Style::default().fg(scheme.primary),
        ));
        for r in &proto.crypto_ref_array {
            lines.push(refs.ref_line("  ", r));
        }
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CryptoAssetType, CryptoPrimitive, CryptoProperties};

    /// Regression for the divergent 'V': one definition for every tab —
    /// unknown level is '?', level 0 is 'V'.
    #[test]
    fn quantum_indicator_unknown_level_is_question_mark() {
        crate::tui::test_support::pin_theme();
        let mut comp = Component::new("AES-256".to_string(), "aes-ref".to_string());
        comp.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm)
                .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::BlockCipher)),
        );
        assert_eq!(quantum_indicator(&comp).content, "?");

        comp.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Pke).with_nist_quantum_security_level(0),
            ),
        );
        assert_eq!(quantum_indicator(&comp).content, "V");

        comp.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Kem).with_nist_quantum_security_level(3),
            ),
        );
        assert_eq!(quantum_indicator(&comp).content, "Q");

        // No crypto properties at all: also '?'.
        comp.crypto_properties = None;
        assert_eq!(quantum_indicator(&comp).content, "?");
    }

    /// Lines-to-text helper for the pure builders.
    fn text_of(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A tiny SBOM with resolvable crypto refs: a PQC signature algorithm
    /// and a weak (SHA-1) algorithm, both addressable by bom-ref.
    fn ref_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        for (name, bom_ref, primitive, level) in [
            (
                "ML-DSA-87",
                "crypto/algorithm/ml-dsa-87",
                CryptoPrimitive::Signature,
                Some(5),
            ),
            (
                "SHA-1",
                "crypto/algorithm/sha-1",
                CryptoPrimitive::Hash,
                Some(0),
            ),
        ] {
            let mut comp = Component::new(name.to_string(), bom_ref.to_string());
            comp.component_type = crate::model::ComponentType::Cryptographic;
            let mut algo = AlgorithmProperties::new(primitive);
            algo.nist_quantum_security_level = level;
            comp.crypto_properties = Some(
                CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(algo),
            );
            let id = comp.canonical_id.clone();
            sbom.components.insert(id, comp);
        }
        sbom
    }

    #[test]
    fn certificate_detail_lines_cover_refs_and_remaining() {
        crate::tui::test_support::pin_theme();
        let empty = NormalizedSbom::default();
        let refs = CryptoRefLookup::new(&empty);
        let cert = CertificateProperties::new()
            .with_not_valid_after(chrono::Utc::now() + chrono::Duration::days(365));
        let mut cert = cert;
        cert.signature_algorithm_ref = Some("sig-algo-ref".to_string());
        cert.subject_public_key_ref = Some("pubkey-ref".to_string());
        let text = text_of(&certificate_detail_lines(&cert, &refs));
        assert!(text.contains("Remaining:"), "{text}");
        // Unresolvable refs must fall back to the raw ref, never vanish.
        assert!(text.contains("Sig Algo:   sig-algo-ref"), "{text}");
        assert!(text.contains("Public Key: pubkey-ref"), "{text}");
    }

    /// Resolved refs render the component's display name, and a weak signing
    /// algorithm carries a visible verdict instead of hiding behind the ref.
    #[test]
    fn certificate_detail_lines_resolve_refs_and_flag_weak_signers() {
        crate::tui::test_support::pin_theme();
        let sbom = ref_sbom();
        let refs = CryptoRefLookup::new(&sbom);

        let mut cert = CertificateProperties::new();
        cert.signature_algorithm_ref = Some("crypto/algorithm/ml-dsa-87".to_string());
        let text = text_of(&certificate_detail_lines(&cert, &refs));
        assert!(
            text.contains("Sig Algo:   ML-DSA-87"),
            "resolved refs must show the component name, not the raw bom-ref: {text}"
        );
        assert!(!text.contains("crypto/algorithm/ml-dsa-87"), "{text}");

        let mut cert = CertificateProperties::new();
        cert.signature_algorithm_ref = Some("crypto/algorithm/sha-1".to_string());
        let text = text_of(&certificate_detail_lines(&cert, &refs));
        assert!(
            text.contains("Sig Algo:   SHA-1 [weak]"),
            "a SHA-1-signed certificate must carry a visible weak verdict: {text}"
        );
    }

    #[test]
    fn key_material_detail_lines_cover_lifecycle_and_secured_by() {
        crate::tui::test_support::pin_theme();
        let empty = NormalizedSbom::default();
        let refs = CryptoRefLookup::new(&empty);
        let mut mat =
            RelatedCryptoMaterialProperties::new(crate::model::CryptoMaterialType::PrivateKey);
        mat.algorithm_ref = Some("algo-ref".to_string());
        mat.creation_date = Some(chrono::Utc::now());
        mat.secured_by = Some(crate::model::SecuredBy {
            mechanism: "HSM".to_string(),
            algorithm_ref: None,
        });
        let text = text_of(&key_material_detail_lines(&mat, &refs));
        assert!(text.contains("Algo:   algo-ref"), "{text}");
        assert!(text.contains("-- Secured By --"), "{text}");
        assert!(text.contains("Mechanism: HSM"), "{text}");
        assert!(text.contains("Created:"), "{text}");
    }

    #[test]
    fn algorithm_detail_lines_cover_padding() {
        crate::tui::test_support::pin_theme();
        let mut algo = AlgorithmProperties::new(CryptoPrimitive::BlockCipher);
        algo.padding = Some(crate::model::CryptoPadding::Pkcs5);
        let text = text_of(&algorithm_detail_lines("AES", &algo));
        assert!(text.contains("Padding:"), "{text}");
    }

    /// The raw CycloneDX wire token `ae` is jargon — the detail pane must
    /// expand primitives to words (Display keeps the token for serialization).
    #[test]
    fn algorithm_detail_lines_expand_primitive_tokens() {
        crate::tui::test_support::pin_theme();
        let algo = AlgorithmProperties::new(CryptoPrimitive::Ae);
        let text = text_of(&algorithm_detail_lines("AES-256-GCM", &algo));
        assert!(
            text.contains("Primitive: authenticated encryption (ae)"),
            "'ae' must be expanded for humans: {text}"
        );
        // The Display impl is untouched (spec wire token).
        assert_eq!(CryptoPrimitive::Ae.to_string(), "ae");
    }

    /// One source of truth for the quantum verdict: ECB mode is broken
    /// practice (SP 800-131A; the engine fails it via SBOM-PQC-008), so the
    /// indicator must show '!' — the old 'Q quantum-safe' for AES-128-ECB
    /// contradicted the FAIL/FAIL verdict on the PQC Compliance tab.
    #[test]
    fn quantum_indicator_ecb_mode_is_broken_practice() {
        crate::tui::test_support::pin_theme();
        let mut comp = Component::new("AES-128-ECB".to_string(), "aes-128-ecb-ref".to_string());
        let mut algo = AlgorithmProperties::new(CryptoPrimitive::BlockCipher)
            .with_nist_quantum_security_level(1);
        algo.mode = Some(CryptoMode::Ecb);
        comp.crypto_properties =
            Some(CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(algo));
        assert_eq!(
            quantum_indicator(&comp).content,
            "!",
            "ECB mode must outrank the declared quantum level"
        );

        // Detail pane: the ECB line is flagged and level 1 reads marginal,
        // not a bare green SAFE.
        let a = comp
            .crypto_properties
            .as_ref()
            .and_then(|cp| cp.algorithm_properties.as_ref())
            .expect("algorithm properties were just set");
        let text = text_of(&algorithm_detail_lines("AES-128-ECB", a));
        assert!(text.contains("BROKEN PRACTICE"), "{text}");
        assert!(text.contains("Level 1 SAFE (marginal)"), "{text}");
    }

    /// Protocol details: cryptoRefArray holds arbitrary asset refs, so the
    /// heading must not say "Algorithms"; refs resolve to component names.
    #[test]
    fn protocol_detail_lines_resolve_refs_under_honest_heading() {
        crate::tui::test_support::pin_theme();
        let sbom = ref_sbom();
        let refs = CryptoRefLookup::new(&sbom);
        let mut proto = ProtocolProperties::new(crate::model::ProtocolType::Ikev2);
        proto.crypto_ref_array = vec!["crypto/certificate/pqc-cert".to_string()];
        proto.ikev2_transform_types = Some(crate::model::Ikev2TransformTypes {
            encr: vec!["crypto/algorithm/ml-dsa-87".to_string()],
            prf: vec![],
            integ: vec![],
            ke: vec![],
        });
        let text = text_of(&protocol_detail_lines(&proto, &refs));
        assert!(text.contains("-- Referenced Crypto Assets --"), "{text}");
        assert!(
            !text.contains("-- Referenced Algorithms --"),
            "certificates listed under an 'Algorithms' heading: {text}"
        );
        assert!(
            text.contains("Encryption: ML-DSA-87"),
            "IKEv2 transform refs must resolve to names: {text}"
        );
        // Unresolvable ref falls back to the raw ref.
        assert!(text.contains("crypto/certificate/pqc-cert"), "{text}");
    }

    /// Narrow panels get a compact legend instead of ratatui's silent
    /// mid-word truncation that dropped trailing entries entirely.
    #[test]
    fn legends_fit_the_available_width() {
        use unicode_width::UnicodeWidthStr;
        crate::tui::test_support::pin_theme();
        for width in [9u16, 31, 34, 52, 80] {
            for legend in [quantum_legend(width), cert_legend(width), key_legend(width)] {
                let text = legend.to_string();
                assert!(
                    UnicodeWidthStr::width(text.as_str()) as u16 <= width,
                    "legend {text:?} overflows width {width}"
                );
            }
        }
        // The wide variant is unchanged from the historical full legend.
        assert_eq!(
            quantum_legend(80).to_string(),
            " ! weak/broken  Q quantum-safe  V vulnerable  ? unknown "
        );
        // The 80x24 asset panels (34 inner cols) keep all four entries.
        let compact = quantum_legend(34).to_string();
        for needle in ["!", "Q", "V", "?"] {
            assert!(compact.contains(needle), "{compact}");
        }
    }

    /// Stronger leg for the unified quantum indicator: the '!' weak arm has
    /// no coverage anywhere (no unit case, no snapshot row). MD5-class names
    /// must render '!', and weakness must outrank the quantum-safe check.
    #[test]
    fn quantum_indicator_weak_by_name_is_exclamation() {
        crate::tui::test_support::pin_theme();
        let mut comp = Component::new("MD5".to_string(), "md5-ref".to_string());
        comp.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm)
                .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::Hash)),
        );
        assert_eq!(
            quantum_indicator(&comp).content,
            "!",
            "weak-by-name algorithms (is_weak_by_name matches the MD5 prefix) \
                 must show the weak indicator, not fall through to '?'"
        );

        // Weakness outranks quantum safety: even with a PQC security level
        // the weak arm is checked first, so MD5 still reads '!' not 'Q'.
        comp.crypto_properties = Some(
            CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
                AlgorithmProperties::new(CryptoPrimitive::Hash).with_nist_quantum_security_level(3),
            ),
        );
        assert_eq!(
            quantum_indicator(&comp).content,
            "!",
            "the weak arm must take precedence over the quantum-safe 'Q' arm"
        );
    }
}
