//! Machine-learning model inventory view for the AI-BOM TUI mode.
//!
//! Lists `MachineLearningModel` components with a detail panel that reuses the
//! shared ML / dataset metadata renderer (`render_ml_dataset_lines`).

use crate::model::ComponentType;
use crate::tui::shared::components::render_ml_dataset_lines;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

/// Render the Models tab (AI-BOM mode).
pub fn render_models(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let scheme = colors();
    let mut models: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type == ComponentType::MachineLearningModel)
        .collect();
    models.sort_by(|a, b| a.name.cmp(&b.name));

    // Components whose model card parsed but whose CycloneDX `type` is not
    // machine-learning-model: list them too (badged with the declared type)
    // instead of silently denying the parsed modelCard data to the user.
    let mut mistyped: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| c.component_type != ComponentType::MachineLearningModel && c.ml_model.is_some())
        .collect();
    mistyped.sort_by(|a, b| a.name.cmp(&b.name));

    if models.is_empty() && mistyped.is_empty() {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "∅",
            "No machine-learning models found",
            Some("Requires CycloneDX machine-learning-model components"),
            None,
        );
        return;
    }

    let typed_count = models.len();
    models.extend(mistyped);

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // ── Left: model list ──
    let selected = app.models_selected.min(models.len().saturating_sub(1));
    let items: Vec<ListItem> = models
        .iter()
        .enumerate()
        .map(|(i, comp)| {
            let style = if i == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let ver = comp.version.as_deref().unwrap_or("");
            let mut spans = vec![
                Span::styled(comp.name.clone(), Style::default().fg(scheme.text)),
                Span::styled(format!("  {ver}"), Style::default().fg(scheme.text_muted)),
            ];
            if i >= typed_count {
                spans.push(Span::styled(
                    format!("  [typed: {}]", comp.component_type),
                    Style::default().fg(scheme.warning),
                ));
            }
            ListItem::new(Line::from(spans)).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Models ({}) ", models.len())),
    );
    let mut list_state = ratatui::widgets::ListState::default();
    if !models.is_empty() {
        list_state.select(Some(selected));
    }
    frame.render_stateful_widget(list, panels[0], &mut list_state);

    // ── Right: detail panel ──
    let Some(comp) = models.get(selected) else {
        return;
    };
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Name: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(comp.name.clone(), Style::default().fg(scheme.accent)),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                comp.version.clone().unwrap_or_else(|| "-".to_string()),
                Style::default().fg(scheme.text),
            ),
        ]),
    ];
    // Mistyped carrier: say what the document declares and how to fix it.
    if selected >= typed_count {
        lines.push(Line::from(vec![
            Span::styled("Type: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(
                    "{} — has a model card but is not typed machine-learning-model; fix the 'type' field",
                    comp.component_type
                ),
                Style::default().fg(scheme.warning),
            ),
        ]));
    }
    if let Some(purl) = &comp.identifiers.purl {
        lines.push(Line::from(vec![
            Span::styled("PURL: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(purl.clone(), Style::default().fg(scheme.text_muted)),
        ]));
    }
    // Resolve training-dataset bom-refs to the referenced component's name
    // ("product-reviews-1M (ref: data-reviews)") so the Models and Datasets
    // tabs agree on identity; raw refs remain only when unresolvable.
    let ml = comp.ml_model.as_ref().map(|ml| {
        let mut ml = ml.clone();
        for ds in &mut ml.training_datasets {
            if ds.name.is_none()
                && let Some(r) = ds.reference.clone()
                && let Some(target) = app
                    .sbom
                    .components
                    .values()
                    .find(|c| c.identifiers.format_id == r)
            {
                ds.name = Some(format!("{} (ref: {})", target.name, r));
            }
        }
        ml
    });
    let dataset = comp
        .dataset
        .as_ref()
        .map(super::without_generic_dataset_type);
    // Reuse the shared ML / Dataset metadata renderer, retitled for this tab.
    let mut ml_lines = render_ml_dataset_lines(ml.as_ref(), dataset.as_ref(), panels[1].width);
    super::relabel_ml_section_header(&mut ml_lines, "Model Card");
    lines.extend(ml_lines);

    // K/J detail scrolling (model cards routinely overflow 80x24).
    let inner_width = panels[1].width.saturating_sub(2);
    let visible_rows = panels[1].height.saturating_sub(2) as usize;
    let total_rows = crate::tui::shared::text::wrapped_line_count(&lines, inner_width);
    let max_scroll = total_rows.saturating_sub(visible_rows) as u16;
    let scroll = app.models_detail_scroll.min(max_scroll);

    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(" Model Detail ");
    if max_scroll > 0 {
        block = block.title_bottom(Line::styled(
            " [K/J] scroll ",
            Style::default().fg(scheme.text_muted),
        ));
    }
    let detail = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: true })
        .scroll((scroll, 0));
    frame.render_widget(detail, panels[1]);
    app.models_detail_scroll = scroll;
}
