//! Shared CBOM detail line-builders and status indicators.
//!
//! One source of truth for the five crypto detail renderers (unified Crypto
//! tab + the four dedicated asset tabs) so their output cannot drift, plus
//! the single definition of the quantum/status glyphs the lists and legends
//! share. Pure builders in the `render_ml_dataset_lines` style: no `App`
//! dependency, all colors via [`colors()`].

use crate::model::{
    AlgorithmProperties, CertificateProperties, Component, CryptoMaterialState, ProtocolProperties,
    RelatedCryptoMaterialProperties,
};
use crate::tui::theme::colors;
use ratatui::prelude::*;

/// The one quantum-posture indicator for crypto asset lists:
/// `!` weak/broken, `Q` quantum-safe, `V` quantum-vulnerable (level 0),
/// `?` unknown (no level / no algorithm properties).
pub fn quantum_indicator(comp: &Component) -> Span<'static> {
    let scheme = colors();
    comp.crypto_properties
        .as_ref()
        .and_then(|cp| cp.algorithm_properties.as_ref())
        .map_or_else(
            || Span::styled("?", Style::default().fg(scheme.text_muted)),
            |a| {
                if a.is_weak_by_name(&comp.name) {
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

/// Legend for the quantum indicator, rendered as a list `title_bottom`.
pub fn quantum_legend() -> Line<'static> {
    Line::styled(
        " ! weak  Q quantum-safe  V vulnerable  ? unknown ",
        Style::default().fg(colors().text_muted),
    )
}

/// Legend for the certificate status glyphs.
pub fn cert_legend() -> Line<'static> {
    Line::styled(
        " \u{2713} valid  ! expiring  X expired ",
        Style::default().fg(colors().text_muted),
    )
}

/// Legend for the key-state glyphs.
pub fn key_legend() -> Line<'static> {
    Line::styled(
        " \u{25cf} active  ! compromised  \u{25cb} deactivated  X destroyed ",
        Style::default().fg(colors().text_muted),
    )
}

/// Detail lines for an algorithm asset (field superset of the dedicated
/// Algorithms tab; the unified Crypto tab renders the same body).
pub fn algorithm_detail_lines(
    component_name: &str,
    algo: &AlgorithmProperties,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(format!("Primitive: {}", algo.primitive)));
    if let Some(f) = &algo.algorithm_family {
        lines.push(Line::from(format!("Family:    {f}")));
    }
    if let Some(p) = &algo.parameter_set_identifier {
        lines.push(Line::from(format!("Params:    {p}")));
    }
    if let Some(m) = &algo.mode {
        lines.push(Line::from(format!("Mode:      {m}")));
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
        lines.push(Line::from(vec![
            Span::raw("Quantum:   "),
            Span::styled(
                format!("Level {ql}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            if ql == 0 {
                Span::styled(" VULNERABLE", Style::default().fg(scheme.error))
            } else {
                Span::styled(" SAFE", Style::default().fg(scheme.success))
            },
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
pub fn certificate_detail_lines(cert: &CertificateProperties) -> Vec<Line<'static>> {
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
        lines.push(Line::from(format!("Sig Algo:   {sig_ref}")));
    }
    if let Some(key_ref) = &cert.subject_public_key_ref {
        lines.push(Line::from(format!("Public Key: {key_ref}")));
    }

    lines
}

/// Detail lines for key material (superset source: the dedicated Keys tab,
/// including algorithm ref, the Secured By subsection, and lifecycle dates).
pub fn key_material_detail_lines(mat: &RelatedCryptoMaterialProperties) -> Vec<Line<'static>> {
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
        lines.push(Line::from(format!("Algo:   {algo_ref}")));
    }
    if let Some(sb) = &mat.secured_by {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "-- Secured By --",
            Style::default().fg(scheme.primary),
        ));
        lines.push(Line::from(format!("Mechanism: {}", sb.mechanism)));
        if let Some(a) = &sb.algorithm_ref {
            lines.push(Line::from(format!("Algorithm: {a}")));
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
pub fn protocol_detail_lines(proto: &ProtocolProperties) -> Vec<Line<'static>> {
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
                    format!("    Algorithms: {}", suite.algorithms.join(", ")),
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
            lines.push(Line::from(format!("Encryption: {}", ikev2.encr.join(", "))));
        }
        if !ikev2.prf.is_empty() {
            lines.push(Line::from(format!("PRF:        {}", ikev2.prf.join(", "))));
        }
        if !ikev2.integ.is_empty() {
            lines.push(Line::from(format!(
                "Integrity:  {}",
                ikev2.integ.join(", ")
            )));
        }
        if !ikev2.ke.is_empty() {
            lines.push(Line::from(format!("Key Exch:   {}", ikev2.ke.join(", "))));
        }
    }

    if !proto.crypto_ref_array.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "-- Referenced Algorithms --",
            Style::default().fg(scheme.primary),
        ));
        for r in &proto.crypto_ref_array {
            lines.push(Line::from(format!("  {r}")));
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

    #[test]
    fn certificate_detail_lines_cover_refs_and_remaining() {
        crate::tui::test_support::pin_theme();
        let cert = CertificateProperties::new()
            .with_not_valid_after(chrono::Utc::now() + chrono::Duration::days(365));
        let mut cert = cert;
        cert.signature_algorithm_ref = Some("sig-algo-ref".to_string());
        cert.subject_public_key_ref = Some("pubkey-ref".to_string());
        let text: String = certificate_detail_lines(&cert)
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Remaining:"), "{text}");
        assert!(text.contains("Sig Algo:   sig-algo-ref"), "{text}");
        assert!(text.contains("Public Key: pubkey-ref"), "{text}");
    }

    #[test]
    fn key_material_detail_lines_cover_lifecycle_and_secured_by() {
        crate::tui::test_support::pin_theme();
        let mut mat =
            RelatedCryptoMaterialProperties::new(crate::model::CryptoMaterialType::PrivateKey);
        mat.algorithm_ref = Some("algo-ref".to_string());
        mat.creation_date = Some(chrono::Utc::now());
        mat.secured_by = Some(crate::model::SecuredBy {
            mechanism: "HSM".to_string(),
            algorithm_ref: None,
        });
        let text: String = key_material_detail_lines(&mat)
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
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
        let text: String = algorithm_detail_lines("AES", &algo)
            .iter()
            .map(|l| l.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Padding:"), "{text}");
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
