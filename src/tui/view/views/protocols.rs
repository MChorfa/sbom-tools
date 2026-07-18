//! Protocol and cipher suite view for the CBOM TUI mode.
//!
//! Shows protocols with their cipher suites and version information.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the protocols tab (CBOM mode).
pub fn render_protocols(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = crate::tui::theme::colors();
    let protos: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Protocol)
        })
        .collect();

    if protos.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No protocols found",
            Some("Requires CycloneDX 1.6+ CBOM data (cryptoProperties)"),
            None,
        );
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: protocol list ──
    let items: Vec<ListItem> = protos
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let proto = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.protocol_properties.as_ref());

            let version = proto.and_then(|p| p.version.as_deref()).unwrap_or("-");

            let suite_count = proto.map_or(0, |p| p.cipher_suites.len());

            let style = if i == app.protocols_selected {
                crate::tui::theme::Styles::selected()
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::raw(&comp.name),
                Span::styled(
                    format!("  v{version}  [{suite_count} suites]"),
                    Style::default().fg(scheme.text_muted),
                ),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Protocols ({}) ", protos.len())),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !protos.is_empty() {
        list_state.select(Some(app.protocols_selected.min(protos.len() - 1)));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(protos.len().saturating_sub(1));
    let Some(comp) = protos.get(selected) else {
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
        && let Some(proto) = &cp.protocol_properties
    {
        lines.push(Line::raw(""));
        lines.extend(crate::tui::shared::crypto::protocol_detail_lines(proto));
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Protocol Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
