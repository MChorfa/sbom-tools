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
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No cryptographic assets found",
            Some("Requires CycloneDX 1.6+ CBOM data (cryptoProperties)"),
            None,
        );
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

    // Line 2: the neutral inventory counts + quantum readiness. A zero
    // denominator must read n/a — 100% "(0/0)" is a vacuously perfect
    // verdict over zero evidence.
    let mut counts_spans = vec![Span::raw(format!(
        " Algo:{} Cert:{} Key:{} Proto:{} ",
        metrics.algorithms_count,
        metrics.certificates_count,
        metrics.keys_count,
        metrics.protocols_count,
    ))];
    match metrics.quantum_readiness_score() {
        None => {
            counts_spans.push(Span::raw("| Quantum: "));
            counts_spans.push(Span::styled(
                "n/a (no algorithms) ",
                Style::default().fg(scheme.text_muted),
            ));
        }
        Some(readiness) => {
            let readiness_color = if readiness >= 80.0 {
                scheme.success
            } else if readiness >= 40.0 {
                scheme.warning
            } else {
                scheme.error
            };
            counts_spans.push(Span::raw("| Quantum: "));
            counts_spans.push(Span::styled(
                format!("{readiness:.0}%"),
                Style::default()
                    .fg(readiness_color)
                    .add_modifier(Modifier::BOLD),
            ));
            counts_spans.push(Span::raw(format!(
                " ({}/{}) ",
                metrics.quantum_safe_count, metrics.algorithms_count
            )));
        }
    }
    let counts_line = Line::from(counts_spans);

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

            let quantum_indicator = crate::tui::shared::crypto::quantum_indicator(comp);

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
            .title(format!(" Assets ({}) ", crypto_components.len()))
            .title_bottom(crate::tui::shared::crypto::quantum_legend(
                area.width.saturating_sub(2),
            )),
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
        let refs = crate::tui::shared::crypto::CryptoRefLookup::new(&app.sbom);
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
            lines.extend(crate::tui::shared::crypto::algorithm_detail_lines(
                &comp.name, algo,
            ));
        }

        if let Some(cert) = &cp.certificate_properties {
            lines.push(Line::styled(
                "-- Certificate Properties --",
                Style::default().fg(scheme.primary),
            ));
            lines.extend(crate::tui::shared::crypto::certificate_detail_lines(
                cert, &refs,
            ));
        }

        if let Some(mat) = &cp.related_crypto_material_properties {
            lines.push(Line::styled(
                "-- Key Material Properties --",
                Style::default().fg(scheme.primary),
            ));
            lines.extend(crate::tui::shared::crypto::key_material_detail_lines(
                mat, &refs,
            ));
        }

        if let Some(proto) = &cp.protocol_properties {
            lines.push(Line::styled(
                "-- Protocol Properties --",
                Style::default().fg(scheme.primary),
            ));
            lines.extend(crate::tui::shared::crypto::protocol_detail_lines(
                proto, &refs,
            ));
        }
    }

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, area);
}
