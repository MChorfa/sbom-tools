//! Algorithm inventory view for the CBOM TUI mode.
//!
//! Shows algorithms grouped by family with quantum safety indicators,
//! security levels, and FIPS/CNSA compliance status.

use crate::model::{ComponentType, CryptoAssetType};
use crate::tui::view::app::{AlgorithmSortBy, ViewApp};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the algorithms tab (CBOM mode).
pub fn render_algorithms(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let scheme = crate::tui::theme::colors();
    let algorithms: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Algorithm)
        })
        .collect();

    let mut algorithms = algorithms;
    algorithms.sort_by(|a, b| match app.algorithm_sort_by {
        AlgorithmSortBy::Name => a.name.cmp(&b.name),
        AlgorithmSortBy::Family => {
            let af = a
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.algorithm_family.as_deref())
                .unwrap_or("");
            let bf = b
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.algorithm_family.as_deref())
                .unwrap_or("");
            af.cmp(bf)
        }
        AlgorithmSortBy::QuantumLevel => {
            let al = a
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.nist_quantum_security_level)
                .unwrap_or(0);
            let bl = b
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref())
                .and_then(|algo| algo.nist_quantum_security_level)
                .unwrap_or(0);
            bl.cmp(&al) // descending: highest quantum level first
        }
        AlgorithmSortBy::Strength => {
            let strength = |c: &&crate::model::Component| -> u8 {
                let Some(cp) = &c.crypto_properties else {
                    return 1;
                };
                let Some(algo) = &cp.algorithm_properties else {
                    return 1;
                };
                if algo.is_weak_by_name(&c.name) {
                    return 0;
                }
                if algo.nist_quantum_security_level == Some(0) {
                    return 1;
                }
                2
            };
            strength(a).cmp(&strength(b))
        }
    });

    if algorithms.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No algorithms found",
            Some("Requires CycloneDX 1.6+ CBOM data (cryptoProperties)"),
            None,
        );
        return;
    }

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // ── Left: algorithm list ──
    let items: Vec<ListItem> = algorithms
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let algo = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref());

            let qi = crate::tui::shared::crypto::quantum_indicator(comp);

            let family = algo
                .and_then(|a| a.algorithm_family.as_deref())
                .unwrap_or("-");

            let style = if i == app.algorithms_selected {
                crate::tui::theme::Styles::selected()
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                qi,
                Span::raw(" "),
                Span::raw(&comp.name),
                Span::styled(
                    format!("  [{family}]"),
                    Style::default().fg(scheme.text_muted),
                ),
            ]))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " Algorithms ({}) [{}] ",
                algorithms.len(),
                app.algorithm_sort_by.label()
            ))
            .title_bottom(crate::tui::shared::crypto::quantum_legend()),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !algorithms.is_empty() {
        list_state.select(Some(app.algorithms_selected.min(algorithms.len() - 1)));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let selected = app
        .active_crypto_selected()
        .min(algorithms.len().saturating_sub(1));
    let Some(comp) = algorithms.get(selected) else {
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

    if let Some(cp) = &comp.crypto_properties {
        if let Some(oid) = &cp.oid {
            lines.push(Line::from(vec![
                Span::styled("OID:  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(oid.as_str()),
            ]));
        }
        lines.push(Line::raw(""));

        if let Some(algo) = &cp.algorithm_properties {
            lines.extend(crate::tui::shared::crypto::algorithm_detail_lines(
                &comp.name, algo,
            ));
        }
    }

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Algorithm Detail "),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, panels[1]);
}
