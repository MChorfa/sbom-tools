//! Quality tab for `ViewApp` - delegates to shared rendering functions.
//!
//! The Summary view is height-aware: the shared summary layout needs a fixed
//! number of rows (header + insights + chart floor + recommendations) and
//! silently squeezes its `Length` panels into border-only slivers when the
//! terminal is shorter — which used to make the headline score invisible at
//! the advertised 80x24 minimum size. Below that threshold this module
//! renders a compact fallback instead: the score header first (rounded, never
//! truncated), then the recommendations; the decorative insights/chart/
//! checklist panels are dropped whole rather than squeezed into borders.

use crate::quality::{QualityReport, SCORING_ENGINE_VERSION, ScoringProfile};
use crate::tui::shared::quality as shared;
use crate::tui::theme::colors;
use crate::tui::view::app::QualityViewMode;
use crate::tui::view::app::ViewApp;
use ratatui::{
    Frame,
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

pub fn render_quality(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let report = &app.quality_report;

    match app.quality_state.view_mode {
        QualityViewMode::Summary => render_summary(frame, area, app),
        QualityViewMode::Breakdown => shared::render_score_breakdown(frame, area, report),
        QualityViewMode::Metrics => shared::render_quality_metrics(frame, area, report),
        QualityViewMode::Recommendations => shared::render_quality_recommendations(
            frame,
            area,
            report,
            app.quality_state.selected_recommendation,
            app.quality_state.scroll_offset,
        ),
    }
}

/// Route the Summary view: shared renderer when the area can fit its fixed
/// layout without collapsing panels, compact fallback otherwise.
fn render_summary(frame: &mut Frame, area: Rect, app: &ViewApp) {
    let report = &app.quality_report;

    if report.profile == ScoringProfile::AiReadiness {
        // The shared AI-readiness summary needs 4+5+10+8 = 27 rows before its
        // two leading Length panels (score, overview) collapse to borders.
        if area.height >= 27 {
            shared::render_quality_summary(
                frame,
                area,
                report,
                app.quality_state.selected_recommendation,
                app.quality_state.scroll_offset,
            );
        } else {
            super::ai_readiness::render_ai_summary(
                frame,
                area,
                report,
                app.quality_state.scroll_offset,
            );
        }
        return;
    }

    // Shared layout: Length(4) header + Length(4) insights + chart (floor 10)
    // + Min(rec_height). Below that total, Min() starves the Length panels
    // into border-only slivers, so switch to the compact fallback.
    let rec_count = report.recommendations.len().min(6) as u16;
    let rec_height = if rec_count == 0 { 5 } else { rec_count * 2 + 3 };
    if area.height >= 4 + 4 + 10 + rec_height {
        shared::render_quality_summary(
            frame,
            area,
            report,
            app.quality_state.selected_recommendation,
            app.quality_state.scroll_offset,
        );
    } else {
        render_compact_summary(
            frame,
            area,
            report,
            app.quality_state.selected_recommendation,
        );
    }
}

/// Compact Summary for short terminals: score header first, recommendations
/// with whatever remains. Insights/chart/checklist are dropped whole — the
/// full panels are still available at larger sizes and via the Breakdown and
/// Metrics views ('v').
fn render_compact_summary(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    selected_rec: usize,
) {
    if area.height < 3 {
        // Degenerate height: the headline score is the last thing to go.
        frame.render_widget(Paragraph::new(compact_score_line(report)), area);
        return;
    }
    if area.height < 8 {
        // Room for one panel only: the score header.
        render_compact_score_header(frame, area, report);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(area);
    render_compact_score_header(frame, chunks[0], report);
    render_compact_recommendations(frame, chunks[1], report, selected_rec);
}

/// One-line score summary for degenerate heights.
fn compact_score_line(report: &QualityReport) -> Line<'static> {
    let scheme = colors();
    let score = report.overall_score.round() as u16;
    let (grade_col, grade_word) = shared::grade_color_and_label(report.grade);
    Line::from(vec![
        Span::styled(
            format!(" {} {grade_word} ", report.grade.letter()),
            Style::default().fg(grade_col).bold(),
        ),
        Span::styled(
            format!("{score}/100"),
            Style::default().fg(scheme.text).bold(),
        ),
    ])
}

/// 4-row score header: grade + gauge + rounded score + profile + engine, and
/// a Best/Focus line. All percentages are rounded (never truncated) so the
/// header agrees with every other rounded display of the same metric.
fn render_compact_score_header(frame: &mut Frame, area: Rect, report: &QualityReport) {
    let scheme = colors();
    let score = report.overall_score.round() as u16;
    let (gauge_color, grade_label) = shared::grade_color_and_label(report.grade);

    let bar_max = 20usize;
    let filled = ((f32::from(score.min(100)) / 100.0) * bar_max as f32).round() as usize;
    let bar: String = "\u{2588}".repeat(filled) + &"\u{2591}".repeat(bar_max - filled);

    // Strongest/weakest categories (same category set as the shared header).
    let is_cbom = report.profile == ScoringProfile::Cbom;
    let scores: Vec<(&str, f32)> = if is_cbom {
        let cm = &report.cryptography_metrics;
        let mut s = vec![
            ("Crypto Compl", cm.crypto_completeness_score()),
            ("OIDs", cm.crypto_identifier_score()),
            ("Algo Strength", cm.algorithm_strength_score()),
            ("Crypto Refs", cm.crypto_dependency_score()),
            ("Crypto Life", cm.crypto_lifecycle_score()),
        ];
        // `None` (no algorithms) is excluded from Best/Focus, matching the
        // Vuln Docs / Lifecycle treatment below.
        if let Some(pqc) = cm.pqc_readiness_score() {
            s.push(("PQC Readiness", pqc));
        }
        s.push(("Provenance", report.provenance_score));
        s.push(("Licenses", report.license_score));
        s
    } else {
        let mut s = vec![
            ("Completeness", report.completeness_score),
            ("Identifiers", report.identifier_score),
            ("Licenses", report.license_score),
            ("Dependencies", report.dependency_score),
            ("Integrity", report.integrity_score),
            ("Provenance", report.provenance_score),
        ];
        if let Some(vs) = report.vulnerability_score {
            s.push(("Vuln Docs", vs));
        }
        if let Some(lc) = report.lifecycle_score {
            s.push(("Lifecycle", lc));
        }
        s
    };
    let strongest = scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(&scores[0]);
    let weakest = scores
        .iter()
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(&scores[0]);

    let line1 = Line::from(vec![
        Span::styled(
            format!(" {} ", report.grade.letter()),
            Style::default().fg(gauge_color).bold(),
        ),
        Span::styled(format!("{grade_label} "), Style::default().fg(scheme.text)),
        Span::styled(bar, Style::default().fg(gauge_color)),
        Span::styled(
            format!(" {score}/100"),
            Style::default().fg(scheme.text).bold(),
        ),
        Span::styled("  Profile: ", Style::default().fg(scheme.muted)),
        Span::styled(
            crate::tui::shared::quality::profile_display_label(report.profile),
            Style::default().fg(scheme.primary),
        ),
        Span::styled(
            format!("  Engine v{SCORING_ENGINE_VERSION}"),
            Style::default().fg(scheme.muted),
        ),
    ]);

    let mut line2_spans = vec![
        Span::styled(" Best: ", Style::default().fg(scheme.success)),
        Span::styled(
            format!("{} ({}%)", strongest.0, strongest.1.round() as u16),
            Style::default().fg(scheme.text),
        ),
    ];
    if weakest.1 < 70.0 {
        line2_spans.push(Span::styled(
            "  Focus: ",
            Style::default().fg(scheme.warning),
        ));
        line2_spans.push(Span::styled(
            format!("{} ({}%)", weakest.0, weakest.1.round() as u16),
            Style::default().fg(scheme.text),
        ));
    }

    let header_title = if is_cbom {
        " CBOM Quality Score "
    } else {
        " SBOM Quality Score "
    };
    let widget = Paragraph::new(vec![line1, Line::from(line2_spans)]).block(
        Block::default()
            .title(header_title)
            .title_style(Style::default().bold().fg(scheme.text))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(gauge_color)),
    );
    frame.render_widget(widget, area);
}

/// Compact recommendations list: 2 lines per item, windowed around the
/// selection so `↑↓` always keeps the selected item visible. Document-level
/// items (affected_count == 0) say so instead of claiming "0 affected".
fn render_compact_recommendations(
    frame: &mut Frame,
    area: Rect,
    report: &QualityReport,
    selected_rec: usize,
) {
    let scheme = colors();
    let total = report.recommendations.len();
    let mut lines: Vec<Line> = Vec::new();

    let title = if total == 0 {
        " Top Recommendations (0) ".to_string()
    } else {
        format!(" Top Recommendations ({total}) [\u{2191}\u{2193} select, Enter\u{2192}detail] ")
    };

    if total == 0 {
        lines.push(Line::from(vec![
            Span::styled("  \u{2713} ", Style::default().fg(scheme.success)),
            Span::styled(
                "No issues found - SBOM meets all quality checks",
                Style::default().fg(scheme.text),
            ),
        ]));
    } else {
        let visible = ((area.height.saturating_sub(2)) / 2).max(1) as usize;
        let selected = selected_rec.min(total - 1);
        let start = if selected < visible {
            0
        } else {
            selected + 1 - visible
        };

        for (i, rec) in report
            .recommendations
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
        {
            let is_selected = i == selected;
            let prefix = if is_selected { "> " } else { "  " };
            let sel_bg = if is_selected {
                scheme.selection
            } else {
                Color::Reset
            };
            let msg_style = if is_selected {
                Style::default().fg(scheme.text).bold().bg(sel_bg)
            } else {
                Style::default().fg(scheme.text)
            };
            // Ellipsize instead of letting the paragraph hard-clip the message.
            let prefix_width = 2 + 5 + rec.category.name().len() + 3;
            let msg_width = (area.width.saturating_sub(2) as usize).saturating_sub(prefix_width);
            let message = crate::tui::widgets::truncate_str(&rec.message, msg_width);
            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(scheme.primary).bg(sel_bg)),
                Span::styled(
                    format!("[P{}] ", rec.priority),
                    shared::priority_style(rec.priority).bg(sel_bg),
                ),
                Span::styled(
                    format!("[{}] ", rec.category.name()),
                    Style::default().fg(scheme.info).bg(sel_bg),
                ),
                Span::styled(message, msg_style),
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
        }
    }

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.warning)),
    );
    frame.render_widget(widget, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_support::{
        CBOM, DEMO_NEW, cbom_single, demo_single, pin_theme, render_to_text,
    };
    use crate::tui::view::ViewApp;

    fn demo_app() -> ViewApp {
        pin_theme();
        let (sbom, profile) = demo_single();
        ViewApp::new(sbom, DEMO_NEW, profile)
    }

    fn cbom_app() -> ViewApp {
        pin_theme();
        let (sbom, profile) = cbom_single();
        ViewApp::new(sbom, CBOM, profile)
    }

    /// At 80x24 the Quality tab's content area is 17 rows tall; the headline
    /// score must be visible there instead of a border-only sliver.
    #[test]
    fn sbom_quality_score_visible_at_min_size_content_area() {
        let mut app = demo_app();
        let expected = format!("{}/100", app.quality_report.overall_score.round() as u16);
        let text = render_to_text(80, 17, |frame| {
            render_quality(frame, Rect::new(0, 0, 80, 17), &mut app);
        });
        assert!(
            text.contains("SBOM Quality Score"),
            "score header panel must render at min size:\n{text}"
        );
        assert!(
            text.contains(&expected),
            "headline score {expected} must be visible at min size:\n{text}"
        );
        assert!(
            text.contains("Top Recommendations"),
            "recommendations must still be reachable at min size:\n{text}"
        );
    }

    /// Same guarantee for the CBOM profile (same code path, different labels).
    #[test]
    fn cbom_quality_score_visible_at_min_size_content_area() {
        let mut app = cbom_app();
        let expected = format!("{}/100", app.quality_report.overall_score.round() as u16);
        let text = render_to_text(80, 17, |frame| {
            render_quality(frame, Rect::new(0, 0, 80, 17), &mut app);
        });
        assert!(
            text.contains("CBOM Quality Score"),
            "CBOM score header panel must render at min size:\n{text}"
        );
        assert!(
            text.contains(&expected),
            "headline CBOM score {expected} must be visible at min size:\n{text}"
        );
    }

    /// Document-level recommendations must not claim "0 affected" while
    /// promising points — the demo fixture carries one such item.
    #[test]
    fn document_level_recommendation_does_not_say_zero_affected() {
        let mut app = demo_app();
        assert!(
            app.quality_report
                .recommendations
                .iter()
                .any(|r| r.affected_count == 0),
            "fixture must carry a document-level recommendation"
        );
        let text = render_to_text(80, 17, |frame| {
            render_quality(frame, Rect::new(0, 0, 80, 17), &mut app);
        });
        assert!(
            !text.contains(" 0 affected"),
            "document-level items must not read as broken math:\n{text}"
        );
        assert!(
            text.contains("document-level"),
            "document-level items must be labeled as such:\n{text}"
        );
    }

    /// The compact header must round percentages, never truncate: the demo
    /// fixture's Identifiers category is 88.9%, which must display as 89%.
    #[test]
    fn compact_header_rounds_percentages() {
        let mut app = demo_app();
        let report = &app.quality_report;
        let mut scores = vec![
            report.completeness_score,
            report.identifier_score,
            report.license_score,
            report.dependency_score,
            report.integrity_score,
            report.provenance_score,
        ];
        scores.extend(report.vulnerability_score);
        scores.extend(report.lifecycle_score);
        let strongest = scores.into_iter().fold(f32::MIN, f32::max);
        let expected = format!("({}%)", strongest.round() as u16);
        let truncated = format!("({}%)", strongest as u16);
        let text = render_to_text(80, 17, |frame| {
            render_quality(frame, Rect::new(0, 0, 80, 17), &mut app);
        });
        assert!(
            text.contains(&expected),
            "Best category must show the rounded value {expected}:\n{text}"
        );
        if truncated != expected {
            assert!(
                !text.contains(&truncated),
                "truncated percentage {truncated} must not appear:\n{text}"
            );
        }
    }
}
