//! Key material view for the CBOM TUI mode.
//!
//! Shows cryptographic key material grouped by state with size and type info.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the keys tab (CBOM mode).
pub fn render_keys(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = crate::tui::theme::colors();
    let keys: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::RelatedCryptoMaterial)
        })
        .collect();

    if keys.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No key material found",
            Some("Requires CycloneDX 1.6+ CBOM data (cryptoProperties)"),
            None,
        );
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: key list ──
    let inner_width = panels[0].width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = keys
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let mat = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.related_crypto_material_properties.as_ref());

            let (state_icon, state_color) = mat
                .and_then(|m| m.state.as_ref())
                .map(crate::tui::shared::crypto::key_state_glyph)
                .unwrap_or(("?", scheme.text_muted));

            let type_label = mat.map(|m| m.material_type.to_string()).unwrap_or_default();

            let style = if i == app.keys_selected {
                crate::tui::theme::Styles::selected()
            } else {
                Style::default()
            };

            // Ellipsize the name so the trailing (type) survives narrow
            // widths instead of ratatui clipping the row mid-word.
            let type_txt = format!("  ({type_label})");
            let name = crate::tui::widgets::truncate_str(
                &comp.name,
                inner_width
                    .saturating_sub(2 + unicode_width::UnicodeWidthStr::width(type_txt.as_str())),
            );

            ListItem::new(Line::from(vec![
                Span::styled(format!("{state_icon} "), Style::default().fg(state_color)),
                Span::raw(name),
                Span::styled(type_txt, Style::default().fg(scheme.text_muted)),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Key Material ({}) ", keys.len()))
            .title_bottom(crate::tui::shared::crypto::key_legend(
                panels[0].width.saturating_sub(2),
            )),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !keys.is_empty() {
        list_state.select(Some(app.keys_selected.min(keys.len() - 1)));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(keys.len().saturating_sub(1));
    let Some(comp) = keys.get(selected) else {
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
        && let Some(mat) = &cp.related_crypto_material_properties
    {
        let refs = crate::tui::shared::crypto::CryptoRefLookup::new(&app.sbom);
        lines.push(Line::raw(""));
        lines.extend(crate::tui::shared::crypto::key_material_detail_lines(
            mat, &refs,
        ));
    }

    let detail = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Key Detail "))
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
