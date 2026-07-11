//! Cryptographic asset inventory view for the TUI.
//!
//! Displays algorithms, certificates, key material, and protocols
//! with quantum readiness indicators.

use crate::model::{ComponentType, CryptoAssetType};
use crate::quality::CryptographyMetrics;
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the crypto inventory tab.
pub fn render_crypto(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let crypto_components: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::Cryptographic)
        .collect();

    if crypto_components.is_empty() {
        let msg = Paragraph::new("No cryptographic assets found in this SBOM.\n\nCBOM data (CycloneDX 1.6+) is required for this tab.")
            .block(Block::default().borders(Borders::ALL).title(" Crypto "))
            .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }

    let metrics = CryptographyMetrics::from_sbom(&app.sbom);

    // Layout: header (2 text lines + borders) + main content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    // ── Header: quantum readiness summary ──
    render_header(frame, chunks[0], &metrics);

    // ── Main: left list + right detail ──
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    render_list(frame, panels[0], app, &crypto_components);
    render_detail(frame, panels[1], app, &crypto_components);
}

fn render_header(frame: &mut Frame, area: Rect, metrics: &CryptographyMetrics) {
    let scheme = crate::tui::theme::colors();
    let readiness = metrics.quantum_readiness_score();
    let readiness_color = if readiness >= 80.0 {
        scheme.success
    } else if readiness >= 40.0 {
        scheme.warning
    } else {
        scheme.error
    };

    // Line 1: danger metrics, most severe first, zero counts omitted — leading
    // with the worst signal guarantees it survives narrow-width truncation.
    let mut danger: Vec<Span> = Vec::new();
    let critical_bold = Style::default()
        .fg(scheme.critical)
        .add_modifier(Modifier::BOLD);
    let push_danger = |spans: &mut Vec<Span<'static>>, label: &str, n: usize, style: Style| {
        if n > 0 {
            if !spans.is_empty() {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(format!("{label}:{n}"), style));
        }
    };
    push_danger(
        &mut danger,
        "Compromised",
        metrics.compromised_keys,
        critical_bold,
    );
    push_danger(
        &mut danger,
        "Weak",
        metrics.weak_algorithm_count,
        critical_bold,
    );
    push_danger(
        &mut danger,
        "QVuln",
        metrics.quantum_vulnerable_count,
        Style::default().fg(scheme.error),
    );
    push_danger(
        &mut danger,
        "Expired",
        metrics.expired_certificates,
        Style::default().fg(scheme.error),
    );
    push_danger(
        &mut danger,
        "WeakKeys",
        metrics.inadequate_key_sizes,
        Style::default().fg(scheme.error),
    );
    push_danger(
        &mut danger,
        "Expiring",
        metrics.expiring_soon_certificates,
        Style::default().fg(scheme.warning),
    );
    push_danger(
        &mut danger,
        "HybridPQC",
        metrics.hybrid_pqc_count,
        Style::default().fg(scheme.primary),
    );
    let danger_line = if danger.is_empty() {
        Line::from(Span::styled(
            " No crypto risk flags",
            Style::default().fg(scheme.success),
        ))
    } else {
        danger.insert(0, Span::raw(" "));
        Line::from(danger)
    };

    // Line 2: the neutral inventory counts + quantum readiness.
    let counts_line = Line::from(vec![
        Span::raw(format!(
            " Algo:{} Cert:{} Key:{} Proto:{} ",
            metrics.algorithms_count,
            metrics.certificates_count,
            metrics.keys_count,
            metrics.protocols_count,
        )),
        Span::raw("| Quantum: "),
        Span::styled(
            format!("{readiness:.0}%"),
            Style::default()
                .fg(readiness_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            " ({}/{}) ",
            metrics.quantum_safe_count, metrics.algorithms_count
        )),
    ]);

    let header = Paragraph::new(vec![danger_line, counts_line]).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Crypto Summary "),
    );
    frame.render_widget(header, area);
}

fn render_list(
    frame: &mut Frame,
    area: Rect,
    app: &ViewApp,
    crypto_components: &[&crate::model::Component],
) {
    let scheme = crate::tui::theme::colors();
    let items: Vec<ListItem> = crypto_components
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let cp = comp.crypto_properties.as_ref();
            let type_label = cp
                .map(|p| match p.asset_type {
                    CryptoAssetType::Algorithm => "ALG",
                    CryptoAssetType::Certificate => "CRT",
                    CryptoAssetType::RelatedCryptoMaterial => "KEY",
                    CryptoAssetType::Protocol => "PRT",
                    _ => "???",
                })
                .unwrap_or("???");

            let quantum_indicator = cp
                .and_then(|p| p.algorithm_properties.as_ref())
                .map(|a| {
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
                        Span::raw(" ")
                    }
                })
                .unwrap_or_else(|| Span::raw(" "));

            let style = if i == app.crypto_list_selected {
                crate::tui::theme::Styles::selected()
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{type_label}] "),
                    Style::default().fg(scheme.primary),
                ),
                quantum_indicator,
                Span::raw(" "),
                Span::raw(&comp.name),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Assets ({}) ", crypto_components.len())),
    );
    // Stateful render so the selected asset scrolls into view on large CBOMs
    // (a plain render_widget always shows the top of the list).
    let mut list_state = ratatui::widgets::ListState::default();
    if !crypto_components.is_empty() {
        list_state.select(Some(
            app.crypto_list_selected.min(crypto_components.len() - 1),
        ));
    }
    frame.render_stateful_widget(list, area, &mut list_state);
}

fn render_detail(
    frame: &mut Frame,
    area: Rect,
    app: &ViewApp,
    crypto_components: &[&crate::model::Component],
) {
    let scheme = crate::tui::theme::colors();
    let selected = app
        .crypto_list_selected
        .min(crypto_components.len().saturating_sub(1));
    let Some(comp) = crypto_components.get(selected) else {
        let empty = Paragraph::new("No selection")
            .block(Block::default().borders(Borders::ALL).title(" Detail "));
        frame.render_widget(empty, area);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(&comp.name),
    ]));

    if let Some(cp) = &comp.crypto_properties {
        lines.push(Line::from(vec![
            Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(cp.asset_type.to_string()),
        ]));
        if let Some(oid) = &cp.oid {
            lines.push(Line::from(vec![
                Span::styled("OID:  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(oid.as_str()),
            ]));
        }

        lines.push(Line::raw(""));

        if let Some(algo) = &cp.algorithm_properties {
            lines.push(Line::styled(
                "-- Algorithm Properties --",
                Style::default().fg(scheme.primary),
            ));
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
            if algo.is_weak_by_name(&comp.name) {
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
                    .map(|f| f.to_string())
                    .collect();
                lines.push(Line::from(format!("Functions: {}", funcs.join(", "))));
            }
            if !algo.certification_level.is_empty() {
                let certs: Vec<_> = algo
                    .certification_level
                    .iter()
                    .map(|c| c.to_string())
                    .collect();
                lines.push(Line::from(format!("Certified: {}", certs.join(", "))));
            }
            if let Some(env) = &algo.execution_environment {
                lines.push(Line::from(format!("Exec Env:  {env}")));
            }
            if let Some(plat) = &algo.implementation_platform {
                lines.push(Line::from(format!("Platform:  {plat}")));
            }
        }

        if let Some(cert) = &cp.certificate_properties {
            lines.push(Line::styled(
                "-- Certificate Properties --",
                Style::default().fg(scheme.primary),
            ));
            if let Some(s) = &cert.subject_name {
                lines.push(Line::from(format!("Subject: {s}")));
            }
            if let Some(i) = &cert.issuer_name {
                lines.push(Line::from(format!("Issuer:  {i}")));
            }
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
                lines.push(Line::from(vec![
                    Span::raw("Valid To:   "),
                    Span::styled(
                        na.format("%Y-%m-%d").to_string(),
                        Style::default().fg(color),
                    ),
                    if cert.is_expired() {
                        Span::styled(" EXPIRED", Style::default().fg(scheme.error))
                    } else if cert.is_expiring_soon(90) {
                        Span::styled(" EXPIRING SOON", Style::default().fg(scheme.warning))
                    } else {
                        Span::raw("")
                    },
                ]));
            }
            if let Some(fmt) = &cert.certificate_format {
                lines.push(Line::from(format!("Format:  {fmt}")));
            }
        }

        if let Some(mat) = &cp.related_crypto_material_properties {
            lines.push(Line::styled(
                "-- Key Material Properties --",
                Style::default().fg(scheme.primary),
            ));
            lines.push(Line::from(format!("Type:  {}", mat.material_type)));
            if let Some(state) = &mat.state {
                let color = match state {
                    crate::model::CryptoMaterialState::Active => scheme.success,
                    crate::model::CryptoMaterialState::Compromised => scheme.critical,
                    crate::model::CryptoMaterialState::Deactivated => scheme.text_muted,
                    _ => scheme.warning,
                };
                lines.push(Line::from(vec![
                    Span::raw("State: "),
                    Span::styled(state.to_string(), Style::default().fg(color)),
                ]));
            }
            if let Some(size) = mat.size {
                lines.push(Line::from(format!("Size:  {size} bits")));
            }
            if let Some(fmt) = &mat.format {
                lines.push(Line::from(format!("Format: {fmt}")));
            }
            if let Some(sb) = &mat.secured_by {
                lines.push(Line::from(format!("Secured by: {}", sb.mechanism)));
            }
        }

        if let Some(proto) = &cp.protocol_properties {
            lines.push(Line::styled(
                "-- Protocol Properties --",
                Style::default().fg(scheme.primary),
            ));
            lines.push(Line::from(format!("Protocol: {}", proto.protocol_type)));
            if let Some(v) = &proto.version {
                lines.push(Line::from(format!("Version:  {v}")));
            }
            if !proto.cipher_suites.is_empty() {
                lines.push(Line::from(format!(
                    "Cipher Suites: {}",
                    proto.cipher_suites.len()
                )));
                for suite in &proto.cipher_suites {
                    if let Some(name) = &suite.name {
                        lines.push(Line::from(format!("  - {name}")));
                    }
                }
            }
        }
    }

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, area);
}
