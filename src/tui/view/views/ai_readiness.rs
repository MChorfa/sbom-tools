//! AI-readiness dashboard view for the AI-BOM TUI mode.
//!
//! Renders the AI-readiness quality report as a self-contained dashboard:
//! a score header (visually aligned with the SBOM/CBOM Quality header: grade
//! letter + grade word + gauge bar + rounded NN/100 + engine version), the
//! per-check pass/fail table, and the recommendations list.
//!
//! The layout is height-aware: the score header is allocated first so the
//! tab's headline datum stays visible even at the 80x24 minimum terminal
//! size, then the checks table, and the recommendations panel only gets rows
//! that remain. Panels are dropped whole rather than squeezed into
//! border-only slivers.
//!
//! The recommendations panel deliberately renders no selection cursor and no
//! `'v'` hint: the AI-Readiness tab has no view toggle and no per-item
//! selection state (a single shared offset scrolls both panes), so
//! advertising either would be dishonest.

use crate::quality::{QualityReport, SCORING_ENGINE_VERSION};
use crate::tui::shared::quality as shared;
use crate::tui::theme::colors;
use crate::tui::view::app::ViewApp;
use ratatui::{
    Frame,
    layout::Rect,
    prelude::*,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

/// Render the AI-Readiness tab (AI-BOM mode).
pub fn render_ai_readiness(frame: &mut Frame, area: Rect, app: &ViewApp) {
    render_ai_summary(frame, area, &app.quality_report, app.ai_readiness_scroll);
}

/// Short "why this matters" rationale for each AI-readiness check.
///
/// Keyed on the check ID embedded in the recommendation message (e.g.
/// "[AI-005] Fairness assessments included"). Returns `None` for unknown
/// checks — the rationale line is dropped rather than showing a generic
/// category sentence that does not apply to the check.
fn ai_check_rationale(message: &str) -> Option<&'static str> {
    const RATIONALES: [(&str, &str); 11] = [
        (
            "AI-001",
            "Model cards are the primary documentation consumers audit",
        ),
        (
            "AI-002",
            "Architecture family informs risk and compatibility review",
        ),
        (
            "AI-003",
            "Dataset references establish data provenance for review",
        ),
        (
            "AI-004",
            "Metrics substantiate the model's fitness-for-purpose",
        ),
        (
            "AI-005",
            "Documents bias risks required by model-card standards",
        ),
        (
            "AI-006",
            "Energy disclosure supports sustainability reporting",
        ),
        (
            "AI-007",
            "Declared use-cases expose out-of-scope deployment",
        ),
        ("AI-008", "Known limitations warn against unsafe contexts"),
        ("AI-009", "Expected by AI governance and ethics frameworks"),
        (
            "AI-010",
            "Weight hashes let consumers verify against tampering",
        ),
        (
            "AI-011",
            "Links the model to OSV/KEV/EPSS/VEX security tooling",
        ),
    ];
    RATIONALES
        .iter()
        .find(|(id, _)| message.contains(id))
        .map(|(_, rationale)| *rationale)
}

/// Height-aware AI-readiness dashboard shared by the AI-Readiness tab and the
/// AI-BOM Quality tab's small-terminal fallback.
///
/// `scroll` is the single shared offset (footer advertises one up/down pair
/// for the whole tab); it is clamped per pane so the shorter list never
/// scrolls into blank space.
pub(crate) fn render_ai_summary(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    scroll: usize,
) {
    let scheme = colors();
    let Some(metrics) = report.ai_readiness_metrics.as_ref() else {
        let widget = Paragraph::new(Line::styled(
            " AI readiness metrics are unavailable for this document.",
            Style::default().fg(scheme.warning),
        ))
        .block(
            Block::default()
                .title(" AI Readiness ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.warning)),
        );
        frame.render_widget(widget, area);
        return;
    };

    // Degenerate heights: the headline score is the last thing to go.
    if area.height < 3 {
        frame.render_widget(Paragraph::new(score_line(report, metrics)), area);
        return;
    }

    // Allocate the 4-row score header first, then the checks table, and give
    // the recommendations panel only rows that remain. A panel that cannot
    // show at least one item is dropped entirely (never border-only).
    let rec_total = report.recommendations.len();
    let rec_full: u16 = if rec_total == 0 {
        3 // border + single "all passed" line
    } else {
        (rec_total.min(6) as u16) * 3 + 2 // 3 lines per item + borders
    };
    let rec_min: u16 = if rec_total == 0 { 3 } else { 5 };
    const CHECKS_MIN: u16 = 6;
    let rest = area.height.saturating_sub(4);
    let show_checks = rest >= 4;
    let rec_h = {
        let avail = rest.saturating_sub(CHECKS_MIN);
        let h = rec_full.min(avail);
        if h < rec_min { 0 } else { h }
    };

    let mut constraints = vec![Constraint::Length(4)];
    if show_checks {
        constraints.push(Constraint::Min(4));
    }
    if rec_h > 0 {
        constraints.push(Constraint::Length(rec_h));
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    render_score_header(frame, chunks[0], report, metrics);
    if show_checks {
        render_checks_table(frame, chunks[1], metrics, scroll);
    }
    if rec_h > 0 {
        render_recommendations(frame, chunks[chunks.len() - 1], report, scroll);
    }
}

/// Single-line score summary used when the area is too small for any panel.
fn score_line(
    report: &QualityReport,
    metrics: &crate::quality::AiReadinessMetrics,
) -> Line<'static> {
    let scheme = colors();
    if metrics.is_not_applicable() {
        return Line::styled(
            " AI Readiness: N/A (not applicable)",
            Style::default().fg(scheme.warning).bold(),
        );
    }
    let score = report.overall_score.round() as u16;
    Line::from(vec![
        Span::styled(" AI Readiness: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("{score}/100 ({})", report.grade.letter()),
            Style::default()
                .fg(shared::grade_color(report.grade))
                .bold(),
        ),
    ])
}

/// 4-row score header, format-aligned with the SBOM/CBOM Quality header:
/// grade letter + grade word + 20-char gauge + rounded score + engine version.
fn render_score_header(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    metrics: &crate::quality::AiReadinessMetrics,
) {
    let scheme = colors();
    let na = metrics.is_not_applicable();

    let (line1, border_color) = if na {
        (
            Line::from(vec![
                Span::styled(" N/A ", Style::default().fg(scheme.warning).bold()),
                Span::styled("Not applicable", Style::default().fg(scheme.text)),
                Span::styled("  Profile: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    shared::profile_display_label(report.profile),
                    Style::default().fg(scheme.primary),
                ),
                Span::styled(
                    format!("  Engine v{SCORING_ENGINE_VERSION}"),
                    Style::default().fg(scheme.muted),
                ),
            ]),
            scheme.warning,
        )
    } else {
        // Rounded, never truncated: 88.9 displays as 89 everywhere.
        let score = report.overall_score.round() as u16;
        let (grade_col, grade_word) = shared::grade_color_and_label(report.grade);
        let bar_max = 20usize;
        let filled = ((f32::from(score.min(100)) / 100.0) * bar_max as f32).round() as usize;
        let bar: String = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(bar_max - filled);
        (
            Line::from(vec![
                Span::styled(
                    format!(" {} ", report.grade.letter()),
                    Style::default().fg(grade_col).bold(),
                ),
                Span::styled(format!("{grade_word} "), Style::default().fg(scheme.text)),
                Span::styled(bar, Style::default().fg(grade_col)),
                Span::styled(
                    format!(" {score}/100"),
                    Style::default().fg(scheme.text).bold(),
                ),
                Span::styled("  Profile: ", Style::default().fg(scheme.muted)),
                Span::styled(
                    shared::profile_display_label(report.profile),
                    Style::default().fg(scheme.primary),
                ),
                Span::styled(
                    format!("  Engine v{SCORING_ENGINE_VERSION}"),
                    Style::default().fg(scheme.muted),
                ),
            ]),
            grade_col,
        )
    };

    let line2 = if na {
        Line::styled(
            format!(
                " {}",
                metrics
                    .na_reason
                    .clone()
                    .unwrap_or_else(|| "No ML model components found".to_string())
            ),
            Style::default().fg(scheme.warning),
        )
    } else {
        Line::from(vec![
            Span::styled(" ML Components: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                metrics.ml_component_count.to_string(),
                Style::default().fg(scheme.primary).bold(),
            ),
            Span::styled(
                "  \u{2502}  Fully documented: ",
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(
                metrics.components_fully_documented.to_string(),
                Style::default().fg(scheme.success).bold(),
            ),
        ])
    };

    let widget = Paragraph::new(vec![line1, line2]).block(
        Block::default()
            .title(" AI Readiness Score ")
            .title_style(Style::default().bold().fg(scheme.text))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(widget, area);
}

/// Per-check pass/fail table. The title states the PASS semantics precisely:
/// a check reads PASS only when every ML component satisfies it.
fn render_checks_table(
    frame: &mut Frame,
    area: Rect,
    metrics: &crate::quality::AiReadinessMetrics,
    scroll: usize,
) {
    let scheme = colors();

    if metrics.checks.is_empty() {
        let widget = Paragraph::new(Line::styled(
            " No AI readiness checks were evaluated (no ML components found).",
            Style::default().fg(scheme.text_muted),
        ))
        .block(
            Block::default()
                .title(" AI Readiness Checks ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        );
        frame.render_widget(widget, area);
        return;
    }

    let rows: Vec<Row> = metrics
        .checks
        .iter()
        .map(|check| {
            let status = if check.passed { "PASS" } else { "FAIL" };
            let status_style = if check.passed {
                Style::default().fg(scheme.success)
            } else {
                Style::default().fg(scheme.error)
            };
            Row::new(vec![
                check.id.clone(),
                check.name.clone(),
                format!("{:.0}%", check.weight * 100.0),
                status.to_string(),
            ])
            .style(status_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(28),
            Constraint::Length(8),
            Constraint::Length(8),
        ],
    )
    .block(
        Block::default()
            .title(" AI Readiness Checks (PASS = every ML component passes) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.accent)),
    )
    .header(
        Row::new(vec!["Check", "Description", "Weight", "Status"])
            .style(Style::default().fg(scheme.accent).bold())
            .bottom_margin(1),
    );

    let n_checks = metrics.checks.len();
    let offset = scroll.min(n_checks.saturating_sub(1));
    let mut table_state = ratatui::widgets::TableState::default().with_offset(offset);
    frame.render_stateful_widget(table, area, &mut table_state);

    // Visible rows: inner height minus borders, header and its bottom margin.
    let visible = area.height.saturating_sub(2 + 2) as usize;
    if n_checks > visible {
        crate::tui::widgets::render_scrollbar(
            frame,
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            n_checks,
            offset,
        );
    }
}

/// Recommendations panel: no selection cursor (there is no selection state on
/// this tab) and no `'v'` hint (there is no view toggle on this tab). Each
/// item shows the affected count, the potential gain, and a rationale derived
/// from the actual failed check.
fn render_recommendations(frame: &mut Frame, area: Rect, report: &QualityReport, scroll: usize) {
    let scheme = colors();
    let rec_total = report.recommendations.len();
    let inner_width = area.width.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::new();

    if rec_total == 0 {
        lines.push(Line::from(vec![
            Span::styled(" \u{2713} ", Style::default().fg(scheme.success)),
            Span::styled(
                "All AI readiness checks passed for every ML component.",
                Style::default().fg(scheme.text),
            ),
        ]));
    } else {
        // Item-based scroll, clamped to this pane's own list length.
        let offset = scroll.min(rec_total.saturating_sub(1));
        for rec in report.recommendations.iter().skip(offset) {
            // Ellipsize instead of letting the paragraph hard-clip the message.
            let prefix_width = 6 + rec.category.name().len() + 3;
            let msg_width = inner_width.saturating_sub(prefix_width);
            let message = crate::tui::widgets::truncate_str(&rec.message, msg_width);
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [P{}] ", rec.priority),
                    shared::priority_style(rec.priority),
                ),
                Span::styled(
                    format!("[{}] ", rec.category.name()),
                    Style::default().fg(scheme.info),
                ),
                Span::styled(message, Style::default().fg(scheme.text)),
            ]));
            let affected = if rec.affected_count == 0 {
                "document-level".to_string()
            } else {
                format!("{} affected", rec.affected_count)
            };
            let pts_color = if rec.impact >= 5.0 {
                scheme.success
            } else if rec.impact >= 2.0 {
                scheme.warning
            } else {
                scheme.muted
            };
            lines.push(Line::from(vec![
                Span::raw("       "),
                Span::styled(affected, Style::default().fg(scheme.muted)),
                Span::styled("  |  ", Style::default().fg(scheme.border)),
                Span::styled(
                    format!("+{:.1}pts", rec.impact),
                    Style::default().fg(pts_color),
                ),
            ]));
            if let Some(rationale) = ai_check_rationale(&rec.message) {
                let why = crate::tui::widgets::truncate_str(
                    &format!("       Why: {rationale}"),
                    inner_width,
                );
                lines.push(Line::styled(why, Style::default().fg(scheme.text_muted)));
            }
        }
    }

    let content_rows = area.height.saturating_sub(2);
    let overflow = rec_total * 3 > content_rows as usize;
    let title = if overflow {
        format!(" Recommendations ({rec_total}) [\u{2191}\u{2193} scroll] ")
    } else {
        format!(" Recommendations ({rec_total}) ")
    };

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(title)
            .title_style(Style::default().fg(scheme.error).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.error)),
    );
    frame.render_widget(widget, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_support::{AIBOM_BSI, aibom_single, pin_theme, render_to_text};
    use crate::tui::view::ViewApp;

    fn aibom_app() -> ViewApp {
        pin_theme();
        let (sbom, profile) = aibom_single();
        ViewApp::new(sbom, AIBOM_BSI, profile)
    }

    /// At the 80x24 minimum size the tab's headline datum — the AI-readiness
    /// score — must be visible (the content area is 17 rows tall there).
    #[test]
    fn score_header_visible_at_min_size_content_area() {
        let app = aibom_app();
        let expected = format!("{}/100", app.quality_report.overall_score.round() as u16);
        let text = render_to_text(80, 17, |frame| {
            render_ai_readiness(frame, Rect::new(0, 0, 80, 17), &app);
        });
        assert!(
            text.contains("AI Readiness Score"),
            "score header panel must render at min size:\n{text}"
        );
        assert!(
            text.contains(&expected),
            "headline score {expected} must be visible at min size:\n{text}"
        );
        assert!(
            text.contains("ML Components:"),
            "ML component count must stay visible at min size:\n{text}"
        );
    }

    /// Score presentation parity with the Quality tab: grade word + gauge bar
    /// glyphs + engine version, not a bare "66/100".
    #[test]
    fn score_header_matches_quality_presentation() {
        let app = aibom_app();
        let text = render_to_text(120, 33, |frame| {
            render_ai_readiness(frame, Rect::new(0, 0, 120, 33), &app);
        });
        let (_, grade_word) =
            crate::tui::shared::quality::grade_color_and_label(app.quality_report.grade);
        assert!(
            text.contains(grade_word),
            "grade word `{grade_word}` must render like the Quality header:\n{text}"
        );
        assert!(
            text.contains('\u{2588}') || text.contains('\u{2591}'),
            "gauge bar glyphs must render like the Quality header:\n{text}"
        );
        assert!(
            text.contains(&format!("Engine v{SCORING_ENGINE_VERSION}")),
            "engine version must render like the Quality header:\n{text}"
        );
    }

    /// The recommendations panel must not advertise the dead 'v' key, must
    /// not render a frozen '>' cursor, and must not show the boilerplate
    /// vulnerability-scanning rationale on AI checks.
    #[test]
    fn recommendations_panel_is_honest() {
        let app = aibom_app();
        let text = render_to_text(120, 33, |frame| {
            render_ai_readiness(frame, Rect::new(0, 0, 120, 33), &app);
        });
        assert!(
            !text.contains("'v' to switch view"),
            "'v' does nothing on the AI-Readiness tab; the hint must be gone:\n{text}"
        );
        assert!(
            !text.contains("> [P"),
            "no selection state exists, so no cursor marker may render:\n{text}"
        );
        assert!(
            !text.contains("Complete data enables accurate vulnerability scanning"),
            "boilerplate category rationale must not be shown for AI checks:\n{text}"
        );
        assert!(
            text.contains("Recommendations (4)"),
            "recommendations panel must still render with its count:\n{text}"
        );
        // Per-check rationale derived from the actual failed check.
        assert!(
            text.contains("Why:"),
            "failed checks must carry a check-specific rationale:\n{text}"
        );
    }

    /// The overview sentence must describe the PASS semantics, not imply the
    /// table lists only passing checks (it lists FAIL rows too).
    #[test]
    fn checks_table_states_pass_semantics() {
        let app = aibom_app();
        let text = render_to_text(120, 33, |frame| {
            render_ai_readiness(frame, Rect::new(0, 0, 120, 33), &app);
        });
        assert!(
            !text.contains("Checks passing for every ML component are shown below"),
            "old misleading sentence must be gone:\n{text}"
        );
        assert!(
            text.contains("PASS = every ML component passes"),
            "the PASS semantics must be stated:\n{text}"
        );
        assert!(
            text.contains("FAIL"),
            "failing checks stay listed in the table:\n{text}"
        );
    }
}
