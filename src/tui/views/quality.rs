//! Quality score view for the TUI with enhanced explainability.
//!
//! Diff-specific rendering lives here; shared rendering functions are
//! delegated to `crate::tui::shared::quality`.

use crate::diff::QualityDelta;
use crate::quality::QualityReport;
use crate::tui::app::AppMode;
use crate::tui::render_context::RenderContext;
use crate::tui::shared::quality as shared;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Gauge, Paragraph},
};

pub fn render_quality(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    match ctx.mode {
        AppMode::Diff | AppMode::View => render_diff_quality(frame, area, ctx),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_diff_quality(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let old_report = ctx.old_quality;
    let new_report = ctx.new_quality;

    if old_report.is_none() && new_report.is_none() {
        render_no_quality_data(frame, area);
        return;
    }

    let quality_delta = ctx.diff_result.and_then(|r| r.quality_delta.as_ref());

    // Compute dynamic height for the grade/regression banner:
    // 1 line for grade transition, 1 line for regressions (if any), + 2 for borders
    let has_regressions = quality_delta.is_some_and(|qd| !qd.regressions.is_empty());
    let banner_height = if quality_delta.is_some() {
        if has_regressions { 4 } else { 3 }
    } else {
        0
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),             // score gauges
            Constraint::Length(banner_height), // grade transition + regression banner
            Constraint::Length(14),            // metrics comparison with delta
            Constraint::Min(8),                // recommendations
        ])
        .split(area);

    render_score_comparison(frame, chunks[0], old_report, new_report);
    if quality_delta.is_some() {
        render_grade_banner(frame, chunks[1], quality_delta);
    }
    render_metrics_comparison(frame, chunks[2], old_report, new_report, quality_delta);
    render_combined_recommendations(frame, chunks[3], old_report, new_report, ctx);
}

fn render_no_quality_data(frame: &mut Frame, area: Rect) {
    widgets::render_empty_state_enhanced(
        frame,
        area,
        "--",
        "Quality analysis unavailable",
        Some("Quality scoring requires a valid SBOM to analyze"),
        Some("Ensure the SBOM was successfully parsed"),
    );
}

// ---------------------------------------------------------------------------
// Diff-specific rendering
// ---------------------------------------------------------------------------

fn render_score_comparison(
    frame: &mut Frame,
    area: Rect,
    old_report: Option<&QualityReport>,
    new_report: Option<&QualityReport>,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(report) = old_report {
        shared::render_score_gauge(frame, chunks[0], report, "Old SBOM Quality");
    } else {
        render_empty_gauge(frame, chunks[0], "Old SBOM Quality");
    }

    if let Some(report) = new_report {
        shared::render_score_gauge(frame, chunks[1], report, "New SBOM Quality");
    } else {
        render_empty_gauge(frame, chunks[1], "New SBOM Quality");
    }
}

fn render_empty_gauge(frame: &mut Frame, area: Rect, title: &str) {
    let scheme = colors();
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!(" {title} "))
                .title_style(Style::default().fg(scheme.muted))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.muted)),
        )
        .gauge_style(Style::default().fg(scheme.muted))
        .percent(0)
        .label("N/A");
    frame.render_widget(gauge, area);
}

// ---------------------------------------------------------------------------
// Grade transition badge + regression alert banner (4.2, 4.3)
// ---------------------------------------------------------------------------

fn render_grade_banner(frame: &mut Frame, area: Rect, quality_delta: Option<&QualityDelta>) {
    let Some(qd) = quality_delta else { return };
    let scheme = colors();

    let mut lines: Vec<Line> = Vec::new();

    // Grade transition line
    let old_letter = qd
        .old_grade
        .as_ref()
        .map_or("?", crate::quality::QualityGrade::letter);
    let new_letter = qd
        .new_grade
        .as_ref()
        .map_or("?", crate::quality::QualityGrade::letter);

    let delta = qd.overall_score_delta;
    let (arrow, grade_color) = if delta > 0.0 {
        ("\u{25b2}", scheme.added)
    } else if delta < 0.0 {
        ("\u{25bc}", scheme.removed)
    } else {
        ("\u{2014}", scheme.muted)
    };

    lines.push(Line::from(vec![
        Span::styled(" Grade: ", Style::default().fg(scheme.text)),
        Span::styled(old_letter, Style::default().fg(scheme.text).bold()),
        Span::styled(" \u{2192} ", Style::default().fg(scheme.text_muted)),
        Span::styled(new_letter, Style::default().fg(grade_color).bold()),
        Span::styled(
            format!("  {arrow} {delta:+.1} pts"),
            Style::default().fg(grade_color),
        ),
    ]));

    // Regression alert line
    if !qd.regressions.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(
                " \u{26a0} Regressions: ",
                Style::default().fg(scheme.warning).bold(),
            ),
            Span::styled(
                qd.regressions.join(", "),
                Style::default().fg(scheme.removed),
            ),
        ]));
    }

    let border_color = if !qd.regressions.is_empty() {
        scheme.warning
    } else if delta > 0.0 {
        scheme.added
    } else if delta < 0.0 {
        scheme.removed
    } else {
        scheme.muted
    };

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Quality Delta ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Metrics comparison with delta column (4.1)
// ---------------------------------------------------------------------------

fn render_metrics_comparison(
    frame: &mut Frame,
    area: Rect,
    old_report: Option<&QualityReport>,
    new_report: Option<&QualityReport>,
    quality_delta: Option<&QualityDelta>,
) {
    // When both reports are available and we have delta data, render a unified
    // table with Old / New / Delta columns.
    if let (Some(old), Some(new), Some(qd)) = (old_report, new_report, quality_delta) {
        render_unified_metrics_table(frame, area, old, new, qd);
        return;
    }

    // Fall back to side-by-side panels when only one report is present.
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(report) = old_report {
        render_metrics_panel_with_explanation(frame, chunks[0], report, "Old");
    } else {
        render_empty_metrics(frame, chunks[0], "Old");
    }

    if let Some(report) = new_report {
        render_metrics_panel_with_explanation(frame, chunks[1], report, "New");
    } else {
        render_empty_metrics(frame, chunks[1], "New");
    }
}

/// Render a single unified table showing all categories with Old, New, and
/// Delta columns. The delta column uses colored arrows for quick scanning.
fn render_unified_metrics_table(
    frame: &mut Frame,
    area: Rect,
    old: &QualityReport,
    new: &QualityReport,
    qd: &QualityDelta,
) {
    let scheme = colors();
    let weights = shared::get_profile_weights(new.profile);

    // Build rows from the 8 categories, using CategoryDelta for the delta
    // value when available (it covers optional categories too).
    let categories: Vec<(&str, f32, f32, f32)> = vec![
        (
            "Completeness",
            old.completeness_score,
            new.completeness_score,
            weights.0,
        ),
        (
            "Identifiers",
            old.identifier_score,
            new.identifier_score,
            weights.1,
        ),
        ("Licenses", old.license_score, new.license_score, weights.2),
        (
            "VulnDocs",
            old.vulnerability_score.unwrap_or(0.0),
            new.vulnerability_score.unwrap_or(0.0),
            if new.vulnerability_score.is_some() {
                weights.3
            } else {
                0.0
            },
        ),
        (
            "Dependencies",
            old.dependency_score,
            new.dependency_score,
            weights.4,
        ),
        (
            "Integrity",
            old.integrity_score,
            new.integrity_score,
            weights.5,
        ),
        (
            "Provenance",
            old.provenance_score,
            new.provenance_score,
            weights.6,
        ),
        (
            "Lifecycle",
            old.lifecycle_score.unwrap_or(0.0),
            new.lifecycle_score.unwrap_or(0.0),
            if new.lifecycle_score.is_some() {
                weights.7
            } else {
                0.0
            },
        ),
    ];

    let rows: Vec<ratatui::widgets::Row> = categories
        .iter()
        .map(|(name, old_s, new_s, w)| {
            // Look up delta from CategoryDelta if available, else compute.
            let delta = qd
                .category_deltas
                .iter()
                .find(|cd| cd.category == *name)
                .map_or(new_s - old_s, |cd| cd.delta);

            let (arrow, delta_color) = if delta > 0.5 {
                ("\u{25b2}", scheme.added) // up-pointing triangle
            } else if delta < -0.5 {
                ("\u{25bc}", scheme.removed) // down-pointing triangle
            } else {
                ("\u{2014}", scheme.muted) // em-dash
            };

            let is_na = (*name == "VulnDocs"
                && old.vulnerability_score.is_none()
                && new.vulnerability_score.is_none())
                || (*name == "Lifecycle"
                    && old.lifecycle_score.is_none()
                    && new.lifecycle_score.is_none());

            let old_str = if is_na {
                "N/A".to_string()
            } else {
                format!("{old_s:.0}%")
            };
            let new_str = if is_na {
                "N/A".to_string()
            } else {
                format!("{new_s:.0}%")
            };
            let delta_cell = if is_na {
                Span::styled("\u{2014}", Style::default().fg(scheme.muted))
            } else {
                Span::styled(
                    format!("{arrow} {delta:+.1}"),
                    Style::default().fg(delta_color),
                )
            };

            ratatui::widgets::Row::new(vec![
                ratatui::widgets::Cell::from(name.to_string()),
                ratatui::widgets::Cell::from(old_str),
                ratatui::widgets::Cell::from(new_str),
                ratatui::widgets::Cell::from(delta_cell),
                ratatui::widgets::Cell::from(format!("\u{00d7}{:.0}%", w * 100.0)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(14),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(6),
    ];

    let table = ratatui::widgets::Table::new(rows, widths)
        .block(
            Block::default()
                .title(" Score Factors (Old vs New) ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.info)),
        )
        .header(
            ratatui::widgets::Row::new(vec!["Category", "Old", "New", "Delta", "Weight"])
                .style(Style::default().fg(scheme.primary).bold())
                .bottom_margin(1),
        );
    frame.render_widget(table, area);
}

fn render_metrics_panel_with_explanation(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    label: &str,
) {
    let scheme = colors();
    let weights = shared::get_profile_weights(report.profile);

    let rows = vec![
        ratatui::widgets::Row::new(vec![
            "Completeness".to_string(),
            format!("{:.0}%", report.completeness_score),
            format!("×{:.0}%", weights.0 * 100.0),
            shared::explain_completeness_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Identifiers".to_string(),
            format!("{:.0}%", report.identifier_score),
            format!("×{:.0}%", weights.1 * 100.0),
            shared::explain_identifier_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Licenses".to_string(),
            format!("{:.0}%", report.license_score),
            format!("×{:.0}%", weights.2 * 100.0),
            shared::explain_license_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Vulnerabilities".to_string(),
            match report.vulnerability_score {
                Some(score) => format!("{score:.0}%"),
                None => "N/A".to_string(),
            },
            format!(
                "×{:.0}%",
                if report.vulnerability_score.is_some() {
                    weights.3 * 100.0
                } else {
                    0.0
                }
            ),
            shared::explain_vulnerability_score(report),
        ]),
        ratatui::widgets::Row::new(vec![
            "Dependencies".to_string(),
            format!("{:.0}%", report.dependency_score),
            format!("×{:.0}%", weights.4 * 100.0),
            shared::explain_dependency_score(report),
        ]),
    ];

    let widths = [
        Constraint::Length(14),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Min(15),
    ];

    let table = ratatui::widgets::Table::new(rows, widths)
        .block(
            Block::default()
                .title(format!(" {label} - Score Factors "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.info)),
        )
        .header(
            ratatui::widgets::Row::new(vec!["Category", "Score", "Weight", "Reason"])
                .style(Style::default().fg(scheme.primary).bold())
                .bottom_margin(1),
        );
    frame.render_widget(table, area);
}

fn render_empty_metrics(frame: &mut Frame, area: Rect, label: &str) {
    crate::tui::widgets::render_empty_state_enhanced(
        frame,
        area,
        "--",
        &format!("No {} metrics available", label.to_lowercase()),
        Some("Quality analysis could not be performed for this SBOM"),
        Some("SBOM may lack the required metadata for scoring"),
    );
}

fn render_combined_recommendations(
    frame: &mut Frame,
    area: Rect,
    old_report: Option<&QualityReport>,
    new_report: Option<&QualityReport>,
    ctx: &RenderContext,
) {
    let scheme = colors();
    let mut lines: Vec<Line> = vec![];

    if let (Some(old), Some(new)) = (old_report, new_report) {
        let score_diff = new.overall_score as i32 - old.overall_score as i32;
        let (icon, color, text) = if score_diff > 5 {
            (
                "↑",
                scheme.added,
                format!("Quality improved by {score_diff} points"),
            )
        } else if score_diff < -5 {
            (
                "↓",
                scheme.removed,
                format!("Quality decreased by {} points", score_diff.abs()),
            )
        } else {
            ("→", scheme.warning, "Quality score unchanged".to_string())
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {icon} "), Style::default().fg(color).bold()),
            Span::styled(text, Style::default().fg(color)),
        ]));

        // Add specific change reasons
        lines.push(Line::from(""));
        add_change_reasons(&mut lines, old, new);
    }

    if let Some(report) = new_report {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            " Top Actions to Improve Score:",
            Style::default().fg(scheme.primary).bold(),
        ));

        for (i, rec) in report.recommendations.iter().take(4).enumerate() {
            let is_selected = i == ctx.quality.selected_recommendation;
            let prefix = if is_selected { "▶ " } else { "  " };
            let style = if is_selected {
                Style::default().fg(scheme.text).bold()
            } else {
                Style::default().fg(scheme.text)
            };

            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(scheme.primary)),
                Span::styled(
                    format!("[P{}] ", rec.priority),
                    shared::priority_style(rec.priority),
                ),
                Span::styled(&rec.message, style),
                Span::styled(
                    format!(" (+{:.0}pts)", rec.impact),
                    Style::default().fg(scheme.success),
                ),
            ]));
        }
    }

    let total_lines = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Quality Analysis ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.error)),
        )
        .scroll((ctx.quality.scroll_offset as u16, 0));
    frame.render_widget(paragraph, area);

    // Render scrollbar
    if total_lines > area.height.saturating_sub(2) as usize {
        widgets::render_scrollbar(
            frame,
            area.inner(ratatui::prelude::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            total_lines,
            ctx.quality.scroll_offset,
        );
    }
}

fn add_change_reasons(lines: &mut Vec<Line>, old: &QualityReport, new: &QualityReport) {
    let scheme = colors();
    let changes = vec![
        (
            "Completeness",
            old.completeness_score,
            new.completeness_score,
        ),
        ("Identifiers", old.identifier_score, new.identifier_score),
        ("Licenses", old.license_score, new.license_score),
        ("Dependencies", old.dependency_score, new.dependency_score),
    ];

    for (name, old_score, new_score) in changes {
        let diff = new_score - old_score;
        if diff.abs() > 5.0 {
            let (icon, color) = if diff > 0.0 {
                ("↑", scheme.added)
            } else {
                ("↓", scheme.removed)
            };
            lines.push(Line::from(vec![
                Span::styled(format!("   {icon} "), Style::default().fg(color)),
                Span::styled(format!("{name}: "), Style::default().fg(scheme.text)),
                Span::styled(
                    format!("{old_score:.0}% → {new_score:.0}%"),
                    Style::default().fg(color),
                ),
            ]));
        }
    }
}
