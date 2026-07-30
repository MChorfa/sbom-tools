//! Certificate validity view for the CBOM TUI mode.
//!
//! Shows certificates sorted by expiry with validity status coloring.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the certificates tab (CBOM mode).
pub fn render_certificates(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = crate::tui::theme::colors();
    let certs: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Certificate)
        })
        .collect();

    let mut certs = certs;
    certs.sort_by(|a, b| {
        let days_remaining = |c: &&crate::model::Component| -> i64 {
            c.crypto_properties
                .as_ref()
                .and_then(|cp| cp.certificate_properties.as_ref())
                .and_then(|cert| cert.validity_days())
                .unwrap_or(i64::MAX)
        };
        days_remaining(a).cmp(&days_remaining(b)) // most urgent first
    });

    if certs.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No certificates found",
            Some("Requires CycloneDX 1.6+ CBOM data (cryptoProperties)"),
            None,
        );
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: certificate list ──
    let inner_width = panels[0].width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = certs
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let cert = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.certificate_properties.as_ref());

            let (status_icon, status_color) = cert
                .map(crate::tui::shared::crypto::cert_status_glyph)
                .unwrap_or(("?", scheme.text_muted));

            let expiry = cert
                .and_then(|c| c.not_valid_after.as_ref())
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "-".to_string());

            let style = if i == app.certificates_selected {
                crate::tui::theme::Styles::selected()
            } else {
                Style::default()
            };

            // Ellipsize the name so the expiry date survives narrow widths
            // (ratatui otherwise clips the row and the date degrades to "2").
            let expiry_txt = format!("  {expiry}");
            let name = crate::tui::widgets::truncate_str(
                &comp.name,
                inner_width
                    .saturating_sub(2 + unicode_width::UnicodeWidthStr::width(expiry_txt.as_str())),
            );

            ListItem::new(Line::from(vec![
                Span::styled(format!("{status_icon} "), Style::default().fg(status_color)),
                Span::raw(name),
                Span::styled(expiry_txt, Style::default().fg(scheme.text_muted)),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Certificates ({}) ", certs.len()))
            .title_bottom(crate::tui::shared::crypto::cert_legend(
                panels[0].width.saturating_sub(2),
            )),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !certs.is_empty() {
        list_state.select(Some(app.certificates_selected.min(certs.len() - 1)));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(certs.len().saturating_sub(1));
    let Some(comp) = certs.get(selected) else {
        frame.render_widget(
            Paragraph::new("No selection")
                .block(Block::default().borders(Borders::ALL).title(" Detail ")),
            panels[1],
        );
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(&comp.name),
    ]));

    if let Some(cp) = &comp.crypto_properties
        && let Some(cert) = &cp.certificate_properties
    {
        let refs = crate::tui::shared::crypto::CryptoRefLookup::new(&app.sbom);
        lines.push(Line::raw(""));
        lines.extend(crate::tui::shared::crypto::certificate_detail_lines(
            cert, &refs,
        ));
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Certificate Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
