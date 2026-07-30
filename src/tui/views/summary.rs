//! Summary view with visual gauges and charts.

use crate::tui::app::AppMode;
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Paragraph},
};

pub fn render_summary(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    match ctx.mode {
        AppMode::Diff => render_diff_summary(frame, area, ctx),
        // Multi-comparison modes have their own views
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => {}
    }
}

fn render_diff_summary(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let Some(result) = ctx.diff_result else {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "--",
            "No diff data loaded",
            Some("Summary requires a completed diff analysis"),
            None,
        );
        return;
    };
    let old_count = ctx
        .old_sbom
        .map_or(0, crate::model::NormalizedSbom::component_count);
    let new_count = ctx
        .new_sbom
        .map_or(0, crate::model::NormalizedSbom::component_count);

    // Check if vulnerability chart has data (used for dynamic height)
    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let has_vulns = severity_counts.values().any(|&v| v > 0);
    // No-vuln charts need real height: SBOM Comparison has 6 content lines +
    // borders (it previously got 3 rows and rendered header-only).
    let chart_height = if has_vulns { 10 } else { 8 };

    // Count findings for dynamic height
    let findings_count = count_findings(result);

    // Determine height for insights + policy merged row
    let has_quality_delta = result.quality_delta.is_some();
    let has_match_metrics = result.match_metrics.is_some();
    let has_vex_data = diff_total_vulns(result) > 0;
    let insights_policy_h: u16 = if has_quality_delta || has_match_metrics || has_vex_data {
        5
    } else {
        3
    };

    let plan = summary_layout_plan(area.height, findings_count, insights_policy_h, chart_height);

    if plan.compact {
        // Dense risk strip + tall scrollable All Changes: at small heights the
        // stacked fixed rows collapsed every box to ~1 line (empty bordered
        // shells, 3 visible changes).
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Min(6)])
            .split(area);
        render_compact_summary_header(frame, rows[0], ctx);
        render_all_changes(frame, rows[1], ctx);
        return;
    }

    // Plan-driven rows: hidden rows drop their constraints entirely instead
    // of rendering empty shells.
    let mut constraints = vec![
        Constraint::Length(plan.summary_h), // Risk + Findings (merged)
        Constraint::Length(6),              // Stats cards (4 columns)
    ];
    if plan.show_insights {
        constraints.push(Constraint::Length(insights_policy_h));
    }
    if plan.show_charts {
        constraints.push(Constraint::Length(chart_height));
    }
    constraints.push(Constraint::Min(6)); // All changes (scrollable)

    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // Row 0: Merged risk assessment + key findings
    render_summary_header(frame, main_chunks[0], ctx);

    // Row 1: Stats cards (6 lines, 4 columns)
    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(main_chunks[1]);

    render_components_card(frame, stats_chunks[0], result, old_count, new_count);
    render_dependencies_card(frame, stats_chunks[1], result);
    render_vulnerabilities_card(frame, stats_chunks[2], ctx);
    render_license_card(frame, stats_chunks[3], ctx);

    let mut row = 2;
    if plan.show_insights {
        render_insights_policy_row(frame, main_chunks[row], ctx);
        row += 1;
    }

    if plan.show_charts {
        let chart_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[row]);

        render_ecosystem_breakdown_chart(frame, chart_chunks[0], ctx);
        if has_vulns {
            render_severity_chart(frame, chart_chunks[1], result);
        } else {
            render_sbom_comparison(frame, chart_chunks[1], ctx);
        }
        row += 1;
    }

    // Last row: All changes (scrollable, sorted by importance)
    render_all_changes(frame, main_chunks[row], ctx);
}

/// Layout decision for the diff Summary at a given content height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SummaryLayoutPlan {
    summary_h: u16,
    show_insights: bool,
    show_charts: bool,
    compact: bool,
}

/// Deterministic degradation cascade for the Summary rows: shrink the header,
/// then drop the charts, then the insights, and finally fall back to the
/// compact strip when even header+stats+changes cannot fit.
fn summary_layout_plan(
    content_h: u16,
    findings_count: usize,
    insights_h: u16,
    chart_h: u16,
) -> SummaryLayoutPlan {
    let mut summary_h = (findings_count + 5).clamp(7, 13) as u16;
    let mut show_insights = true;
    let mut show_charts = true;

    let demand = |summary_h: u16, insights: bool, charts: bool| -> u16 {
        summary_h + 6 + if insights { insights_h } else { 0 } + if charts { chart_h } else { 0 } + 6
    };

    // (a) shrink the header
    while demand(summary_h, show_insights, show_charts) > content_h && summary_h > 7 {
        summary_h -= 1;
    }
    // (b) drop the charts row
    if demand(summary_h, show_insights, show_charts) > content_h {
        show_charts = false;
    }
    // (c) drop the insights row
    if demand(summary_h, show_insights, show_charts) > content_h {
        show_insights = false;
    }
    // (d) compact fallback
    let compact = demand(7, false, false) > content_h;

    SummaryLayoutPlan {
        summary_h,
        show_insights,
        show_charts,
        compact,
    }
}

/// Render the Quality Delta / Matching / VEX insights row (items 1.1, 1.2, 1.3).
fn render_insights_row(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let has_quality = result.quality_delta.is_some();
    let has_matching = result.match_metrics.is_some();
    let has_vex = diff_total_vulns(result) > 0;

    // Split row into columns for each present insight card
    let col_count = usize::from(has_quality) + usize::from(has_matching) + usize::from(has_vex);
    if col_count == 0 {
        return;
    }
    let pct = 100u16 / col_count as u16;
    let constraints: Vec<Constraint> = (0..col_count)
        .map(|_| Constraint::Percentage(pct))
        .collect();
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);

    let mut col = 0;

    // --- 1.1: Quality Delta card ---
    if let Some(qd) = &result.quality_delta {
        render_quality_delta_card(frame, chunks[col], qd);
        col += 1;
    }

    // --- 1.2: Match Metrics card ---
    if let Some(mm) = &result.match_metrics {
        render_match_metrics_card(frame, chunks[col], mm, result);
        col += 1;
    }

    // --- 1.3: VEX Coverage card ---
    if has_vex {
        render_vex_coverage_card(frame, chunks[col], result);
    }
}

/// Render quality delta card (item 1.1).
fn render_quality_delta_card(frame: &mut Frame, area: Rect, qd: &crate::diff::QualityDelta) {
    let scheme = colors();
    let delta = qd.overall_score_delta;
    let is_improvement = delta > 0.0;
    let delta_color = if is_improvement {
        scheme.success
    } else if delta < 0.0 {
        scheme.error
    } else {
        scheme.text_muted
    };
    let arrow = if is_improvement {
        "\u{25b2}"
    } else if delta < 0.0 {
        "\u{25bc}"
    } else {
        "="
    };

    // Line 1: grade transition + delta
    let old_grade = qd
        .old_grade
        .as_ref()
        .map_or("?", crate::quality::QualityGrade::letter);
    let new_grade = qd
        .new_grade
        .as_ref()
        .map_or("?", crate::quality::QualityGrade::letter);

    let mut lines = vec![Line::from(vec![
        Span::styled("Quality: ", Style::default().fg(scheme.text_muted)),
        Span::styled(old_grade, Style::default().fg(scheme.text).bold()),
        Span::styled(" \u{2192} ", Style::default().fg(scheme.text_muted)),
        Span::styled(new_grade, Style::default().fg(scheme.text).bold()),
        Span::styled(
            format!(" ({arrow} {delta:+.1})"),
            Style::default().fg(delta_color).bold(),
        ),
    ])];

    // Line 2: regressions
    if !qd.regressions.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Regressions: ", Style::default().fg(scheme.error)),
            Span::styled(qd.regressions.join(", "), Style::default().fg(scheme.error)),
        ]));
    }

    // Line 3: improvements
    if !qd.improvements.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Improvements: ", Style::default().fg(scheme.success)),
            Span::styled(
                qd.improvements.join(", "),
                Style::default().fg(scheme.success),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Quality Impact ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(delta_color)),
    );
    frame.render_widget(paragraph, area);
}

/// Render match metrics card (item 1.2).
fn render_match_metrics_card(
    frame: &mut Frame,
    area: Rect,
    mm: &crate::diff::MatchMetrics,
    result: &crate::diff::DiffResult,
) {
    let scheme = colors();
    let total_matched = mm.exact_matches + mm.fuzzy_matches + mm.rule_matches;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Matched: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", mm.exact_matches),
                Style::default().fg(scheme.success).bold(),
            ),
            // Score buckets (>=0.995 vs below), NOT match methods — a
            // Fuzzy-method pairing with score 1.00 counts as high-conf.
            Span::styled(" high-conf, ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", mm.fuzzy_matches),
                Style::default().fg(scheme.warning).bold(),
            ),
            Span::styled(" low-conf", Style::default().fg(scheme.text_muted)),
            if mm.rule_matches > 0 {
                Span::styled(
                    format!(", {} rule", mm.rule_matches),
                    Style::default().fg(scheme.secondary),
                )
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled("Unmatched: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{} old", mm.unmatched_old),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(", ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{} new", mm.unmatched_new),
                Style::default().fg(scheme.added),
            ),
        ]),
    ];

    if total_matched > 0 {
        lines.push(Line::from(vec![
            Span::styled("Avg score: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.2}", mm.avg_match_score),
                Style::default().fg(if mm.avg_match_score >= 0.9 {
                    scheme.success
                } else if mm.avg_match_score >= 0.7 {
                    scheme.warning
                } else {
                    scheme.error
                }),
            ),
            Span::styled("  Min: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.2}", mm.min_match_score),
                Style::default().fg(if mm.min_match_score >= 0.8 {
                    scheme.success
                } else if mm.min_match_score >= 0.6 {
                    scheme.warning
                } else {
                    scheme.error
                }),
            ),
        ]));
        // Name the shakiest pairing (the likeliest source of a bogus
        // "modified" row) — but only when something is actually inexact:
        // <0.995 keeps exact-only diffs from naming an arbitrary component.
        if mm.min_match_score < 0.995
            && let Some((_, name)) = result
                .components
                .modified
                .iter()
                .filter_map(|c| c.match_info.as_ref().map(|m| (m.score, c.name.as_str())))
                .min_by(|a, b| a.0.total_cmp(&b.0))
            && let Some(last) = lines.last_mut()
        {
            last.push_span(Span::styled(
                format!(
                    " ({})",
                    crate::tui::widgets::truncate_str(
                        name,
                        (area.width as usize).saturating_sub(31)
                    )
                ),
                Style::default().fg(scheme.text_muted),
            ));
        }
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Matching ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );
    frame.render_widget(paragraph, area);
}

/// Total vulnerability rows in the diff (introduced + resolved + persistent):
/// the VEX card's visibility gate — a diff whose new vulns have ZERO VEX
/// coverage (the pure gap case) must still show the card.
fn diff_total_vulns(result: &crate::diff::DiffResult) -> usize {
    result.vulnerabilities.introduced.len()
        + result.vulnerabilities.resolved.len()
        + result.vulnerabilities.persistent.len()
}

/// Render VEX coverage card (item 1.3).
fn render_vex_coverage_card(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let vex = result.vulnerabilities.vex_summary();

    let coverage_color = if vex.coverage_pct >= 80.0 {
        scheme.success
    } else if vex.coverage_pct >= 50.0 {
        scheme.warning
    } else {
        scheme.error
    };

    let mut lines = vec![Line::from(vec![
        Span::styled("VEX: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{:.0}%", vex.coverage_pct),
            Style::default().fg(coverage_color).bold(),
        ),
        Span::styled(
            format!(" ({}/{} covered)", vex.with_vex, vex.total_vulns),
            Style::default().fg(scheme.text_muted),
        ),
    ])];

    // The security worklist: newly introduced vulns with no triage at all
    // (computed by vex_summary, previously never rendered).
    if vex.introduced_without_vex > 0 || vex.persistent_without_vex > 0 {
        lines.push(Line::from(vec![
            Span::styled("Gaps: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{} new", vex.introduced_without_vex),
                Style::default().fg(scheme.error).bold(),
            ),
            Span::styled(" \u{b7} ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{} ongoing", vex.persistent_without_vex),
                Style::default().fg(scheme.warning),
            ),
            Span::styled(" (no VEX)", Style::default().fg(scheme.text_muted)),
        ]));
    }

    if vex.actionable > 0
        || !result.vulnerabilities.vex_changes.is_empty()
        || !vex.by_state.is_empty()
    {
        let mut spans = vec![
            Span::styled("Actionable: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{}", vex.actionable),
                Style::default().fg(scheme.warning).bold(),
            ),
            Span::styled(
                format!(
                    " \u{b7} \u{394}{}",
                    result.vulnerabilities.vex_changes.len()
                ),
                Style::default().fg(scheme.accent),
            ),
        ];
        // Compact by_state tail, most-actionable-first so the important
        // counts survive clipping in the ~26-col card (codes/colors match
        // render_vex_badge_spans).
        use crate::model::VexState;
        for (state, code, color) in [
            (VexState::Affected, "AF", scheme.critical),
            (VexState::UnderInvestigation, "UI", scheme.medium),
            (VexState::NotAffected, "NA", scheme.low),
            (VexState::Fixed, "FX", scheme.low),
        ] {
            if let Some(n) = vex.by_state.get(&state)
                && *n > 0
            {
                spans.push(Span::styled(
                    format!(" {code}:{n}"),
                    Style::default().fg(color),
                ));
            }
        }
        lines.push(Line::from(spans));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" VEX Coverage ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(coverage_color)),
    );
    frame.render_widget(paragraph, area);
}

/// Compute risk level label and color from a diff result.
fn compute_risk_level(
    result: &crate::diff::DiffResult,
    scheme: &crate::tui::theme::ColorScheme,
) -> (&'static str, Color, Color) {
    let major_bumps = count_major_bumps(&result.components.modified);
    let critical_vulns = *result
        .vulnerabilities
        .introduced_by_severity()
        .get("Critical")
        .unwrap_or(&0);
    let high_vulns = *result
        .vulnerabilities
        .introduced_by_severity()
        .get("High")
        .unwrap_or(&0);
    let new_vulns = result.summary.vulnerabilities_introduced;
    let total_changes = result.summary.components_added
        + result.summary.components_removed
        + result.summary.components_modified;

    // Badge foreground follows the theme convention (severity_badge_fg):
    // light text on the dark critical/error backgrounds, dark text on the
    // bright warning/success ones.
    if critical_vulns > 0 {
        ("Critical Risk", scheme.critical, scheme.badge_fg_light)
    } else if high_vulns > 0 || major_bumps >= 3 {
        ("High Risk", scheme.error, scheme.badge_fg_light)
    } else if major_bumps > 0 || new_vulns > 0 || result.summary.components_removed > 3 {
        ("Medium Risk", scheme.warning, scheme.badge_fg_dark)
    } else if total_changes > 0 {
        ("Low Risk", scheme.success, scheme.badge_fg_dark)
    } else {
        ("No Changes", scheme.muted, scheme.badge_fg_dark)
    }
}

/// Count major version bumps in modified components.
fn count_major_bumps(modified: &[crate::diff::ComponentChange]) -> usize {
    modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .count()
}

/// Count the number of key findings that will be generated (used for dynamic height).
fn count_findings(result: &crate::diff::DiffResult) -> usize {
    let mut count = 0;

    // Critical vulnerabilities (up to 2)
    let critical_vulns = result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .count();
    count += critical_vulns.min(2);

    // Major version bumps (up to 3)
    let major_bumps: usize = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .take(3)
        .count();
    count += major_bumps;

    // License conflicts
    if !result.licenses.conflicts.is_empty() {
        count += 1;
    }

    // Quality regressions
    if let Some(delta) = &result.quality_delta
        && !delta.regressions.is_empty()
    {
        count += 1;
    }

    // ML regressions (up to 3 lines + one overflow line)
    count += result.ml_regressions.len().min(3) + usize::from(result.ml_regressions.len() > 3);

    // Added components
    if !result.components.added.is_empty() {
        count += 1;
    }

    // Removed components
    if !result.components.removed.is_empty() {
        count += 1;
    }

    // Vulnerability status (always 1 line)
    count += 1;

    count
}

/// Merged summary header: risk assessment + key findings in one bordered card.
/// Reduces visual clutter by combining two sections into one with a separator.
/// The one-line risk strip: badge + semantic score + change/major-bump counts.
/// Shared by the full header and the compact 80x24 header.
fn summary_risk_line(
    result: &crate::diff::DiffResult,
    scheme: &crate::tui::theme::ColorScheme,
    compact: bool,
) -> Line<'static> {
    let (risk_label, risk_color, risk_badge_fg) = compute_risk_level(result, scheme);
    let score = result.semantic_score;
    let total_changes = result.summary.total_changes;
    let major_bumps = count_major_bumps(&result.components.modified);

    // Scope the headline: total_changes mixes component, dependency-edge and
    // metadata changes, and the unlabeled sum contradicted every other count
    // on the same screen.
    let s = &result.summary;
    let comp_changes = s.components_added + s.components_removed + s.components_modified;
    let dep_changes = s.dependencies_added + s.dependencies_removed;
    let meta_changes = result.metadata_changes.len();
    let (comp_l, dep_l, meta_l) = if compact {
        ("c", "d", "m")
    } else {
        (" comp", " dep", " meta")
    };
    let mut scope_parts = vec![format!("{comp_changes}{comp_l}")];
    if dep_changes > 0 {
        scope_parts.push(format!("{dep_changes}{dep_l}"));
    }
    if meta_changes > 0 {
        scope_parts.push(format!("{meta_changes}{meta_l}"));
    }

    let mut line1 = vec![
        Span::styled(
            format!(" {risk_label} "),
            Style::default().fg(risk_badge_fg).bg(risk_color).bold(),
        ),
        // The number is a 0-100 similarity percentage, not a risk score —
        // label it so "Low Risk / 66" cannot read as contradictory.
        Span::raw("  Similarity: "),
        Span::styled(
            format!("{score:.0}%"),
            Style::default().fg(risk_color).bold(),
        ),
        Span::raw("  \u{2502}  "),
        Span::styled(
            format!("{total_changes} changes"),
            Style::default().fg(scheme.text),
        ),
        Span::styled(
            format!(" ({})", scope_parts.join(", ")),
            Style::default().fg(scheme.text_muted),
        ),
    ];
    if major_bumps > 0 {
        let label = if compact {
            format!(", {major_bumps} major")
        } else {
            format!(", {major_bumps} major bumps")
        };
        line1.push(Span::styled(
            label,
            Style::default().fg(scheme.warning).bold(),
        ));
    }
    Line::from(line1)
}

/// Compact Summary header for small terminals: the risk strip plus a single
/// dense stat line covering components/deps/vulns/licenses.
fn render_compact_summary_header(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };
    let (_, risk_color, _) = compute_risk_level(result, &scheme);
    let s = &result.summary;

    let stat_line = Line::from(vec![
        Span::styled("Comp ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("+{}", s.components_added),
            Style::default().fg(scheme.added),
        ),
        Span::styled(
            format!(" -{}", s.components_removed),
            Style::default().fg(scheme.removed),
        ),
        Span::styled(
            format!(" ~{}", s.components_modified),
            Style::default().fg(scheme.modified),
        ),
        Span::styled(" \u{2502} Deps ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("+{}", s.dependencies_added),
            Style::default().fg(scheme.added),
        ),
        Span::styled(
            format!(" -{}", s.dependencies_removed),
            Style::default().fg(scheme.removed),
        ),
        Span::styled(" \u{2502} Vuln ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("\u{25b2}{}", s.vulnerabilities_introduced),
            Style::default().fg(scheme.critical),
        ),
        Span::styled(
            format!(" \u{25bc}{}", s.vulnerabilities_resolved),
            Style::default().fg(scheme.added),
        ),
        Span::styled(" \u{2502} Lic ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("+{}", s.licenses_added),
            Style::default().fg(scheme.added),
        ),
        Span::styled(
            format!(" -{}", s.licenses_removed),
            Style::default().fg(scheme.removed),
        ),
    ]);

    let para = Paragraph::new(vec![summary_risk_line(result, &scheme, true), stat_line]).block(
        Block::default()
            .title(" Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(risk_color)),
    );
    frame.render_widget(para, area);
}

fn render_summary_header(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let (_, risk_color, _) = compute_risk_level(result, &scheme);

    let mut lines: Vec<Line> = Vec::new();

    // Line 1: Risk badge + Score + Changes
    lines.push(summary_risk_line(result, &scheme, false));

    // Line 2: SBOM metadata + Quality + Matching
    let mut line2: Vec<Span> = Vec::new();
    if let Some(old) = ctx.old_sbom {
        // Show a format/spec-version transition when the two sides differ —
        // the badge previously described only the old document.
        let old_fmt = format!("{} {}", old.document.format, old.document.format_version);
        let badge = match ctx.new_sbom {
            Some(new) => {
                let new_fmt = format!("{} {}", new.document.format, new.document.format_version);
                if new_fmt == old_fmt {
                    old_fmt
                } else {
                    format!("{old_fmt} \u{2192} {new_fmt}")
                }
            }
            None => old_fmt,
        };
        line2.push(Span::styled(badge, Style::default().fg(scheme.accent)));
        line2.push(Span::raw("  "));
    }
    if let Some(delta) = result.quality_delta.as_ref() {
        let old_g = delta
            .old_grade
            .as_ref()
            .map_or("?", crate::quality::QualityGrade::letter);
        let new_g = delta
            .new_grade
            .as_ref()
            .map_or("?", crate::quality::QualityGrade::letter);
        line2.push(Span::styled(
            format!("Quality: {old_g}\u{2192}{new_g}"),
            Style::default().fg(scheme.muted),
        ));
        line2.push(Span::raw("  "));
    }
    if let Some(metrics) = result.match_metrics.as_ref() {
        // Confidence buckets, not methods: the engine counts by score
        // (>=0.995), so a Fuzzy-method 1.00 pairing lands in the first
        // bucket. Calling that bucket "exact" contradicted the per-component
        // "via Fuzzy" detail on the Components tab.
        line2.push(Span::styled(
            format!(
                "Match: {} high-conf, {} low-conf",
                metrics.exact_matches, metrics.fuzzy_matches
            ),
            Style::default().fg(scheme.muted),
        ));
    }
    if !line2.is_empty() {
        lines.push(Line::from(line2));
    }

    // Separator line
    lines.push(Line::from(Span::styled(
        "\u{2500}".repeat(area.width.saturating_sub(2) as usize),
        Style::default().fg(scheme.border),
    )));

    // Key findings
    // Critical vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .take(2)
    {
        lines.push(Line::from(vec![
            Span::styled(
                " \u{26a0} CRITICAL ",
                Style::default()
                    .fg(scheme.severity_badge_fg("critical"))
                    .bg(scheme.critical)
                    .bold(),
            ),
            Span::styled(
                format!(" {} in {}", vuln.id, vuln.component_name),
                Style::default().fg(scheme.critical),
            ),
        ]));
    }
    // Major version bumps
    for comp in result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .take(3)
    {
        let old_v = comp.old_version.as_deref().unwrap_or("?");
        let new_v = comp.new_version.as_deref().unwrap_or("?");
        lines.push(Line::from(vec![
            Span::styled(
                " \u{25b2} MAJOR ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.warning)
                    .bold(),
            ),
            Span::raw(format!(" {} ", comp.name)),
            Span::styled(old_v.to_string(), Style::default().fg(scheme.muted)),
            Span::styled(" \u{2192} ", Style::default().fg(scheme.modified)),
            Span::styled(
                new_v.to_string(),
                Style::default().fg(scheme.modified).bold(),
            ),
        ]));
    }
    // License conflicts
    if !result.licenses.conflicts.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" \u{26a0} ", Style::default().fg(scheme.critical)),
            Span::styled(
                format!("{} license conflicts", result.licenses.conflicts.len()),
                Style::default().fg(scheme.critical),
            ),
        ]));
    }
    // Quality regressions
    if let Some(delta) = &result.quality_delta
        && !delta.regressions.is_empty()
    {
        lines.push(Line::from(vec![
            Span::styled(" \u{25bc} ", Style::default().fg(scheme.warning)),
            Span::styled(
                format!("Quality regressions: {}", delta.regressions.join(", ")),
                Style::default().fg(scheme.warning),
            ),
        ]));
    }
    // ML performance regressions (CLI --fail-on-ml-regression gate data,
    // previously invisible interactively)
    for reg in result.ml_regressions.iter().take(3) {
        lines.push(Line::from(vec![
            Span::styled(
                " \u{25bc} ML REGRESSION ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.error)
                    .bold(),
            ),
            Span::styled(
                format!(
                    " {} {}: {:.2} \u{2192} {:.2}",
                    reg.component, reg.metric, reg.previous_value, reg.new_value
                ),
                Style::default().fg(scheme.error),
            ),
        ]));
    }
    if result.ml_regressions.len() > 3 {
        lines.push(Line::styled(
            format!(
                "   \u{2026} +{} more ML regressions",
                result.ml_regressions.len() - 3
            ),
            Style::default().fg(scheme.muted),
        ));
    }
    // Added/removed summaries
    let added_count = result.components.added.len();
    if added_count > 0 {
        let names: Vec<&str> = result
            .components
            .added
            .iter()
            .take(4)
            .map(|c| c.name.as_str())
            .collect();
        let suffix = if added_count > 4 {
            format!(", +{} more", added_count - 4)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(" + ", Style::default().fg(scheme.added).bold()),
            Span::styled(
                format!("{added_count} added"),
                Style::default().fg(scheme.added),
            ),
            Span::styled(
                format!(" ({}{})", names.join(", "), suffix),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }
    let removed_count = result.components.removed.len();
    if removed_count > 0 {
        let names: Vec<&str> = result
            .components
            .removed
            .iter()
            .take(4)
            .map(|c| c.name.as_str())
            .collect();
        let suffix = if removed_count > 4 {
            format!(", +{} more", removed_count - 4)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(" - ", Style::default().fg(scheme.removed).bold()),
            Span::styled(
                format!("{removed_count} removed"),
                Style::default().fg(scheme.removed),
            ),
            Span::styled(
                format!(" ({}{})", names.join(", "), suffix),
                Style::default().fg(scheme.muted),
            ),
        ]));
    }
    // Vulnerability status
    let new_vulns = result.vulnerabilities.introduced.len();
    if new_vulns > 0 {
        lines.push(Line::from(vec![
            Span::styled(" \u{26a0} ", Style::default().fg(scheme.critical)),
            Span::styled(
                format!("{new_vulns} new vulnerabilities"),
                Style::default().fg(scheme.critical),
            ),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled(" \u{2713} ", Style::default().fg(scheme.added)),
            Span::styled("No new vulnerabilities", Style::default().fg(scheme.added)),
        ]));
    }

    let block = Block::default()
        .title(" Summary ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(risk_color));
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn render_components_card(
    frame: &mut Frame,
    area: Rect,
    result: &crate::diff::DiffResult,
    old_count: usize,
    new_count: usize,
) {
    let scheme = colors();
    let added = result.summary.components_added;
    let removed = result.summary.components_removed;
    let modified = result.summary.components_modified;

    let text = vec![
        Line::from(vec![
            Span::styled(
                " + ADDED    ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {added}")),
        ]),
        Line::from(vec![
            Span::styled(
                " - REMOVED  ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {removed}")),
        ]),
        Line::from(vec![
            Span::styled(
                " ~ MODIFIED ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.modified)
                    .bold(),
            ),
            Span::raw(format!("  {modified}")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Old: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{old_count}  ")),
            Span::styled("New: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{new_count}  ")),
            Span::styled("Changed: ", Style::default().fg(scheme.muted)),
            Span::raw(format!("{}", added + removed + modified)),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Components ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.secondary)),
    );

    frame.render_widget(paragraph, area);
}

fn render_dependencies_card(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let added = result.summary.dependencies_added;
    let removed = result.summary.dependencies_removed;

    let text = vec![
        Line::from(vec![
            Span::styled(
                " + ADDED   ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {added}")),
        ]),
        Line::from(vec![
            Span::styled(
                " - REMOVED ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {removed}")),
        ]),
        Line::from(""),
        {
            let net = added as i32 - removed as i32;
            if net == 0 {
                Line::from(Span::styled(
                    "No net change",
                    Style::default().fg(scheme.muted),
                ))
            } else {
                Line::from(vec![
                    Span::styled("Net change: ", Style::default().fg(scheme.muted)),
                    Span::styled(
                        format!("{net:+}"),
                        if net > 0 {
                            Style::default().fg(scheme.added)
                        } else {
                            Style::default().fg(scheme.removed)
                        },
                    ),
                ])
            }
        },
    ];

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .title(" Dependencies ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.critical)),
    );

    frame.render_widget(paragraph, area);
}

fn render_license_card(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let new_count = result.licenses.new_licenses.len();
    let removed_count = result.licenses.removed_licenses.len();
    let changed_count = result.licenses.component_changes.len();
    let conflicts = result.licenses.conflicts.len();

    let border_color = if conflicts > 0 {
        scheme.critical
    } else if new_count + removed_count > 0 {
        scheme.warning
    } else {
        scheme.border
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" New:      ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{new_count}"),
                Style::default().fg(if new_count > 0 {
                    scheme.added
                } else {
                    scheme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Removed:  ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{removed_count}"),
                Style::default().fg(if removed_count > 0 {
                    scheme.removed
                } else {
                    scheme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Changed:  ", Style::default().fg(scheme.muted)),
            Span::styled(
                format!("{changed_count}"),
                Style::default().fg(if changed_count > 0 {
                    scheme.modified
                } else {
                    scheme.text
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Conflicts:", Style::default().fg(scheme.muted)),
            Span::styled(
                format!(" {conflicts}"),
                Style::default().fg(if conflicts > 0 {
                    scheme.critical
                } else {
                    scheme.text
                }),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" Licenses ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Merged insights + policy row.
fn render_insights_policy_row(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let has_quality = result.quality_delta.is_some();
    let has_matching = result.match_metrics.is_some();
    let has_vex = diff_total_vulns(result) > 0;
    let has_insights = has_quality || has_matching || has_vex;

    if has_insights {
        // Split: insights on left, policy on right
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        render_insights_row(frame, cols[0], result);
        render_policy_compact(frame, cols[1], ctx);
    } else {
        // Policy takes full width
        render_policy_compact(frame, area, ctx);
    }
}

/// Compact policy compliance widget.
fn render_policy_compact(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let compliance = ctx.compliance_state;

    let mut spans = vec![
        Span::styled("Policy: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {} ", compliance.policy_preset.label()),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.primary)
                .bold(),
        ),
        Span::raw("  "),
    ];

    if let Some(ref result) = compliance.result {
        // Applicability first: `passes` stays `true` for a standard that did
        // not evaluate this SBOM, and rendering it as a green PASS (or any
        // score) would report a verdict that was never computed.
        if let Some(reason) = result.not_applicable.as_deref() {
            spans.push(Span::styled(
                " N/A ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.muted)
                    .bold(),
            ));
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                crate::tui::widgets::truncate_str(reason, 60),
                Style::default().fg(scheme.text_muted).italic(),
            ));
            render_policy_block(frame, area, compliance, spans);
            return;
        }

        let (status, status_style) = if result.passes {
            (
                " PASS ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.success)
                    .bold(),
            )
        } else {
            (
                " FAIL ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.error)
                    .bold(),
            )
        };

        spans.push(Span::styled(status, status_style));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("Score: {}", result.score),
            Style::default().fg(if result.score >= 80 {
                scheme.success
            } else if result.score >= 50 {
                scheme.warning
            } else {
                scheme.error
            }),
        ));
        spans.push(Span::raw("  "));

        let critical = result.count_by_severity(crate::tui::security::PolicySeverity::Critical);
        let high = result.count_by_severity(crate::tui::security::PolicySeverity::High);
        let medium = result.count_by_severity(crate::tui::security::PolicySeverity::Medium);
        let low = result.count_by_severity(crate::tui::security::PolicySeverity::Low);

        if critical > 0 {
            spans.push(Span::styled(
                format!("\u{25cf}{critical} "),
                Style::default().fg(scheme.critical).bold(),
            ));
        }
        if high > 0 {
            spans.push(Span::styled(
                format!("\u{25cf}{high} "),
                Style::default().fg(scheme.high),
            ));
        }
        if medium > 0 {
            spans.push(Span::styled(
                format!("\u{25cf}{medium} "),
                Style::default().fg(scheme.medium),
            ));
        }
        if low > 0 {
            spans.push(Span::styled(
                format!("\u{25cb}{low} "),
                Style::default().fg(scheme.low),
            ));
        }

        if let Some(violation) = result.violations.first() {
            spans.push(Span::styled(
                "\u{2502} ",
                Style::default().fg(scheme.border),
            ));
            spans.push(Span::styled(
                crate::tui::widgets::truncate_str(&violation.description, 50),
                Style::default().fg(scheme.text_muted).italic(),
            ));
        }
    } else {
        spans.push(Span::styled(
            "Not checked  ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled("[P]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " check  ",
            Style::default().fg(scheme.text_muted),
        ));
        spans.push(Span::styled("[p]", Style::default().fg(scheme.accent)));
        spans.push(Span::styled(
            " cycle",
            Style::default().fg(scheme.text_muted),
        ));
    }

    render_policy_block(frame, area, compliance, spans);
}

/// Render the assembled policy spans in the bordered " Security Policy "
/// block. The border stays neutral for N/A results (no verdict was
/// computed, so neither the green pass nor the red fail border applies).
fn render_policy_block<'a>(
    frame: &mut Frame,
    area: Rect,
    compliance: &crate::tui::app_states::PolicyComplianceState,
    spans: Vec<Span<'a>>,
) {
    let scheme = colors();
    let not_applicable = compliance
        .result
        .as_ref()
        .is_some_and(|r| r.not_applicable.is_some());

    let border_style = if not_applicable || !compliance.checked {
        Style::default().fg(scheme.border)
    } else if compliance.passes() {
        Style::default().fg(scheme.success)
    } else {
        Style::default().fg(scheme.error)
    };

    let paragraph = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .title(" Security Policy ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(paragraph, area);
}

fn render_vulnerabilities_card(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result.as_ref() else {
        return;
    };

    let introduced = result.summary.vulnerabilities_introduced;
    let resolved = result.summary.vulnerabilities_resolved;
    let persistent = result.summary.vulnerabilities_persistent;

    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let critical = *severity_counts.get("Critical").unwrap_or(&0);
    let high = *severity_counts.get("High").unwrap_or(&0);

    #[cfg(feature = "enrichment")]
    let is_enriched = ctx.enrichment_stats_old.is_some() || ctx.enrichment_stats_new.is_some();
    #[cfg(not(feature = "enrichment"))]
    let is_enriched = false;

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                " \u{25b2} NEW     ",
                Style::default()
                    .fg(scheme.badge_fg_light)
                    .bg(scheme.removed)
                    .bold(),
            ),
            Span::raw(format!("  {introduced}")),
        ]),
        Line::from(vec![
            Span::styled(
                " \u{25bc} FIXED   ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.added)
                    .bold(),
            ),
            Span::raw(format!("  {resolved}")),
        ]),
        Line::from(vec![
            Span::styled(
                " \u{25cf} PERSIST ",
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(scheme.modified)
                    .bold(),
            ),
            Span::raw(format!("  {persistent}")),
        ]),
    ];

    if !is_enriched && introduced == 0 && resolved == 0 && persistent == 0 {
        lines.push(Line::from(Span::styled(
            " Not enriched",
            Style::default().fg(scheme.muted).italic(),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Critical: ", Style::default().fg(scheme.critical).bold()),
            Span::raw(format!("{critical}  ")),
            Span::styled("High: ", Style::default().fg(scheme.high)),
            Span::raw(format!("{high}")),
        ]));
    }

    let border_color = if critical > 0 {
        scheme.critical
    } else if introduced > 0 {
        scheme.warning
    } else {
        scheme.success
    };

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .title(" Vulnerabilities ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    frame.render_widget(paragraph, area);
}

fn render_ecosystem_breakdown_chart(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result else {
        return;
    };

    // CBOM/AI-BOM diffs group by component TYPE (algorithm/certificate/
    // ml-model/…) resolved from the loaded SBOMs: crypto assets and models
    // have no package ecosystem, so the ecosystem grouping lumped nearly
    // everything under "unknown" (#80).
    let typed = super::components::is_typed_bom_diff(ctx.old_quality, ctx.new_quality);
    let key_of = |comp: &crate::diff::ComponentChange| -> String {
        if typed {
            super::components::component_display_type(ctx.old_sbom, ctx.new_sbom, &comp.id)
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            comp.ecosystem
                .clone()
                .unwrap_or_else(|| "unknown".to_string())
        }
    };

    // Per-group (added, removed, modified) triples: the previous flat sum
    // hid the change direction, and its rotating palette could paint a
    // group in the semantically-critical red.
    let mut eco_counts: std::collections::HashMap<String, (u64, u64, u64)> =
        std::collections::HashMap::new();
    for comp in &result.components.added {
        eco_counts.entry(key_of(comp)).or_default().0 += 1;
    }
    for comp in &result.components.removed {
        eco_counts.entry(key_of(comp)).or_default().1 += 1;
    }
    for comp in &result.components.modified {
        eco_counts.entry(key_of(comp)).or_default().2 += 1;
    }

    let mut ecosystems: Vec<_> = eco_counts.into_iter().collect();
    ecosystems.sort_by(|a, b| {
        let ta = a.1.0 + a.1.1 + a.1.2;
        let tb = b.1.0 + b.1.1 + b.1.2;
        tb.cmp(&ta).then_with(|| a.0.cmp(&b.0))
    });

    let block = Block::default()
        .title(if typed {
            " Changes by Asset Type "
        } else {
            " Changes by Ecosystem "
        })
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border));

    if ecosystems.len() <= 1 {
        // Single ecosystem: a labelled tally row beats a labelless bar.
        let lines: Vec<Line> = ecosystems
            .iter()
            .map(|(eco, (a, r, m))| {
                Line::from(vec![
                    Span::styled(
                        format!("{:<12} ", crate::tui::widgets::truncate_str(eco, 12)),
                        Style::default().fg(scheme.text),
                    ),
                    Span::styled(format!("+{a}"), Style::default().fg(scheme.added)),
                    Span::raw("  "),
                    Span::styled(format!("-{r}"), Style::default().fg(scheme.removed)),
                    Span::raw("  "),
                    Span::styled(format!("~{m}"), Style::default().fg(scheme.modified)),
                ])
            })
            .collect();
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    // Multi-ecosystem: grouped bars — one group per ecosystem (top 3 by
    // total), three semantic bars (+/-/~) per group. Grouped, not stacked:
    // ratatui's BarChart has no stacked mode.
    let groups: Vec<BarGroup> = ecosystems
        .iter()
        .take(3)
        .map(|(eco, (a, r, m))| {
            // ratatui only prints a bar's value when it fits inside
            // bar_width(3); compact 4+-digit counts to "Nk" so huge diffs
            // don't silently lose their numbers.
            let compact = |v: u64| {
                let mut bar = Bar::default().value(v);
                if v > 999 {
                    bar = bar.text_value(format!("{}k", v / 1000));
                }
                bar
            };
            let bars = vec![
                compact(*a)
                    .label(Line::from("+"))
                    .style(Style::default().fg(scheme.added)),
                compact(*r)
                    .label(Line::from("-"))
                    .style(Style::default().fg(scheme.removed)),
                compact(*m)
                    .label(Line::from("~"))
                    .style(Style::default().fg(scheme.modified)),
            ];
            // 9 = the group's own width (3 bars × 3): "algorithm" fits
            // exactly; longer labels elide.
            BarGroup::default()
                .label(Line::from(crate::tui::widgets::truncate_str(eco, 9)))
                .bars(&bars)
        })
        .collect();

    let mut bar_chart = BarChart::default()
        .block(block)
        .bar_width(3)
        .bar_gap(0)
        .group_gap(2)
        .value_style(Style::default().fg(scheme.text).bold())
        .label_style(Style::default().fg(scheme.text));
    for g in groups {
        bar_chart = bar_chart.data(g);
    }

    frame.render_widget(bar_chart, area);
}

fn render_severity_chart(frame: &mut Frame, area: Rect, result: &crate::diff::DiffResult) {
    let scheme = colors();
    let severity_counts = result.vulnerabilities.introduced_by_severity();
    let critical = *severity_counts.get("Critical").unwrap_or(&0) as u64;
    let high = *severity_counts.get("High").unwrap_or(&0) as u64;
    let medium = *severity_counts.get("Medium").unwrap_or(&0) as u64;
    let low = *severity_counts.get("Low").unwrap_or(&0) as u64;

    let bar_chart = BarChart::default()
        .block(
            Block::default()
                .title(" New Vulnerabilities by Severity ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .bar_width(6)
        .bar_gap(1)
        .bar_style(Style::default().fg(scheme.error))
        .value_style(Style::default().fg(scheme.text).bold())
        .label_style(Style::default().fg(scheme.text))
        .data(
            BarGroup::default().bars(&[
                Bar::default()
                    .value(critical)
                    .label(Line::from("Crit"))
                    .style(Style::default().fg(scheme.critical)),
                Bar::default()
                    .value(high)
                    .label(Line::from("High"))
                    .style(Style::default().fg(scheme.high)),
                Bar::default()
                    .value(medium)
                    .label(Line::from("Med"))
                    .style(Style::default().fg(scheme.medium)),
                Bar::default()
                    .value(low)
                    .label(Line::from("Low"))
                    .style(Style::default().fg(scheme.low)),
            ]),
        );

    frame.render_widget(bar_chart, area);
}

/// Priority for sorting changes by importance.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum ChangePriority {
    CriticalVuln,
    MajorBump,
    Downgrade,
    HighVuln,
    Removed,
    Added,
    MinorBump,
    PatchBump,
    Other,
}

/// Map a [`MetadataChangeKind`] to a short badge label and the scheme color
/// used for both the badge background and the field name.
fn metadata_badge(
    kind: crate::diff::MetadataChangeKind,
    scheme: &crate::tui::theme::ColorScheme,
) -> (&'static str, Color) {
    match kind {
        crate::diff::MetadataChangeKind::Added => (" + META ", scheme.added),
        crate::diff::MetadataChangeKind::Removed => (" - META ", scheme.removed),
        crate::diff::MetadataChangeKind::Modified => (" ~ META ", scheme.modified),
    }
}

/// Build the document-metadata change lines for the All Changes panel.
///
/// These mirror the `field: old -> new` rows the CLI summary report renders
/// (`reports/summary.rs`) but were previously invisible in the diff TUI even
/// though `summary.total_changes` already counts them — so the "N changes"
/// header was inflated by rows the user could not see. Rendered as a labeled
/// block at the top of the panel (rather than appended to the priority-sorted
/// list, where they would be clipped) so metadata changes stay visible. Each
/// row is colored by add/removed/modified kind.
fn metadata_change_lines<'a>(
    result: &'a crate::diff::DiffResult,
    scheme: &crate::tui::theme::ColorScheme,
) -> Vec<Line<'a>> {
    if result.metadata_changes.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![Line::from(vec![
        Span::styled("\u{2500}\u{2500} ", Style::default().fg(scheme.border)),
        Span::styled(
            "Metadata Changes",
            Style::default().fg(scheme.accent).bold(),
        ),
        Span::styled(" \u{2500}\u{2500}", Style::default().fg(scheme.border)),
    ])];

    for change in &result.metadata_changes {
        let (badge, color) = metadata_badge(change.kind, scheme);
        let old = change.old_value.as_deref().unwrap_or("\u{2205}");
        let new = change.new_value.as_deref().unwrap_or("\u{2205}");
        lines.push(Line::from(vec![
            Span::styled(
                badge,
                Style::default()
                    .fg(scheme.change_badge_fg())
                    .bg(color)
                    .bold(),
            ),
            Span::raw(" "),
            Span::styled(change.field.clone(), Style::default().fg(color)),
            Span::styled(": ", Style::default().fg(scheme.muted)),
            Span::styled(old.to_string(), Style::default().fg(scheme.removed)),
            Span::styled(" \u{2192} ", Style::default().fg(scheme.muted)),
            Span::styled(new.to_string(), Style::default().fg(scheme.added)),
        ]));
    }

    lines
}

/// A single change entry with priority and rendered line.
struct ChangeEntry<'a> {
    priority: ChangePriority,
    line: Line<'a>,
}

/// All changes section with importance sorting and scrollable list.
fn render_sbom_comparison(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let (Some(old), Some(new)) = (ctx.old_sbom, ctx.new_sbom) else {
        return;
    };

    let rows: Vec<(&str, usize, usize)> = vec![
        ("Components", old.component_count(), new.component_count()),
        ("Dependencies", old.edges.len(), new.edges.len()),
        (
            "With licenses",
            old.components
                .values()
                .filter(|c| !c.licenses.declared.is_empty())
                .count(),
            new.components
                .values()
                .filter(|c| !c.licenses.declared.is_empty())
                .count(),
        ),
        (
            "With vulns",
            old.components
                .values()
                .filter(|c| !c.vulnerabilities.is_empty())
                .count(),
            new.components
                .values()
                .filter(|c| !c.vulnerabilities.is_empty())
                .count(),
        ),
    ];

    let mut lines: Vec<Line> = Vec::new();

    // Header row
    lines.push(Line::from(vec![
        Span::styled(format!("{:<14}", ""), Style::default()),
        Span::styled(
            format!("{:>8}", "Old"),
            Style::default().fg(scheme.muted).bold(),
        ),
        Span::styled(
            format!("{:>8}", "New"),
            Style::default().fg(scheme.muted).bold(),
        ),
        Span::styled(
            format!("{:>8}", "Delta"),
            Style::default().fg(scheme.muted).bold(),
        ),
    ]));

    // Data rows
    for (label, old_v, new_v) in &rows {
        let diff = *new_v as isize - *old_v as isize;
        let delta_span = match diff.cmp(&0) {
            std::cmp::Ordering::Greater => {
                Span::styled(format!("+{diff}"), Style::default().fg(scheme.added))
            }
            std::cmp::Ordering::Less => {
                Span::styled(format!("{diff}"), Style::default().fg(scheme.removed))
            }
            std::cmp::Ordering::Equal => {
                Span::styled("0".to_string(), Style::default().fg(scheme.muted))
            }
        };

        lines.push(Line::from(vec![
            Span::styled(format!(" {label:<13}"), Style::default().fg(scheme.text)),
            Span::styled(format!("{old_v:>8}"), Style::default().fg(scheme.muted)),
            Span::styled(format!("{new_v:>8}"), Style::default().fg(scheme.text)),
            Span::raw("    "),
            delta_span,
        ]));
    }

    // Timestamps
    let old_date = old.document.created.format("%Y-%m-%d").to_string();
    let new_date = new.document.created.format("%Y-%m-%d").to_string();
    lines.push(Line::from(vec![
        Span::styled(" Created      ", Style::default().fg(scheme.text)),
        Span::styled(format!("{old_date:>8}"), Style::default().fg(scheme.muted)),
        Span::styled(format!("   {new_date}"), Style::default().fg(scheme.text)),
    ]));

    let block = Block::default()
        .title(" SBOM Comparison ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_all_changes(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let scheme = colors();
    let Some(result) = ctx.diff_result else {
        return;
    };

    let mut entries: Vec<ChangeEntry> = Vec::new();

    // Critical vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
    {
        entries.push(ChangeEntry {
            priority: ChangePriority::CriticalVuln,
            line: Line::from(vec![
                Span::styled(
                    " \u{26a0} CRITICAL ",
                    Style::default()
                        .fg(scheme.badge_fg_light)
                        .bg(scheme.critical)
                        .bold(),
                ),
                Span::raw(" "),
                Span::styled(vuln.id.clone(), Style::default().fg(scheme.critical).bold()),
                Span::styled(" in ", Style::default().fg(scheme.muted)),
                Span::raw(vuln.component_name.clone()),
                Span::styled(
                    vuln.description
                        .as_ref()
                        .map(|d| format!(" - {}", crate::tui::widgets::truncate_str(d, 40)))
                        .unwrap_or_default(),
                    Style::default().fg(scheme.muted),
                ),
            ]),
        });
    }

    // High vulnerabilities
    for vuln in result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "High")
    {
        entries.push(ChangeEntry {
            priority: ChangePriority::HighVuln,
            line: Line::from(vec![
                Span::styled(
                    " \u{26a0} HIGH ",
                    Style::default()
                        .fg(scheme.badge_fg_light)
                        .bg(scheme.high)
                        .bold(),
                ),
                Span::raw(" "),
                Span::styled(vuln.id.clone(), Style::default().fg(scheme.high).bold()),
                Span::styled(" in ", Style::default().fg(scheme.muted)),
                Span::raw(vuln.component_name.clone()),
            ]),
        });
    }

    // Modified components (sorted by version change level)
    for comp in &result.components.modified {
        let level = version_change_level(comp.old_version.as_deref(), comp.new_version.as_deref());

        let (priority, name_color, level_label) = match level {
            VersionLevel::Major => (
                ChangePriority::MajorBump,
                scheme.error,
                Some(Span::styled(
                    " MAJOR",
                    Style::default().fg(scheme.error).bold(),
                )),
            ),
            VersionLevel::Downgrade => (
                ChangePriority::Downgrade,
                scheme.error,
                Some(Span::styled(
                    " \u{26a0} downgrade",
                    Style::default().fg(scheme.error).bold(),
                )),
            ),
            VersionLevel::Minor => (
                ChangePriority::MinorBump,
                scheme.warning,
                Some(Span::styled(" minor", Style::default().fg(scheme.warning))),
            ),
            VersionLevel::Patch => (
                ChangePriority::PatchBump,
                scheme.success,
                Some(Span::styled(" patch", Style::default().fg(scheme.success))),
            ),
            VersionLevel::Unknown => (ChangePriority::Other, scheme.modified, None),
        };

        let mut spans = vec![
            Span::styled(" ~ ", Style::default().fg(name_color).bold()),
            Span::styled(comp.name.clone(), Style::default().fg(name_color)),
            Span::raw(" "),
        ];
        // When the version pair says nothing ("1.0.0 → 1.0.0", "? → ?"),
        // show WHAT changed instead: the changed-field names from the diff.
        let version_is_informative = comp.old_version != comp.new_version
            && (comp.old_version.is_some() || comp.new_version.is_some());
        if version_is_informative {
            spans.push(Span::styled(
                comp.old_version
                    .as_deref()
                    .unwrap_or("\u{2014}")
                    .to_string(),
                Style::default().fg(scheme.removed),
            ));
            spans.push(Span::styled(
                " \u{2192} ",
                Style::default().fg(scheme.muted),
            ));
            spans.push(Span::styled(
                comp.new_version
                    .as_deref()
                    .unwrap_or("\u{2014}")
                    .to_string(),
                Style::default().fg(scheme.added),
            ));
        } else {
            let mut fields: Vec<&str> = comp
                .field_changes
                .iter()
                .filter(|c| c.field != "version")
                .map(|c| c.field.as_str())
                .collect();
            let extra = fields.len().saturating_sub(3);
            fields.truncate(3);
            let label = if fields.is_empty() {
                if comp.old_version.is_none() && comp.new_version.is_none() {
                    "(no version)".to_string()
                } else {
                    format!(
                        "{} (unchanged version)",
                        comp.new_version.as_deref().unwrap_or("\u{2014}")
                    )
                }
            } else if extra > 0 {
                format!("changed: {} +{extra} more", fields.join(", "))
            } else {
                format!("changed: {}", fields.join(", "))
            };
            spans.push(Span::styled(label, Style::default().fg(scheme.text_muted)));
        }
        if let Some(label) = level_label {
            spans.push(label);
        }

        entries.push(ChangeEntry {
            priority,
            line: Line::from(spans),
        });
    }

    // Removed components
    for comp in &result.components.removed {
        entries.push(ChangeEntry {
            priority: ChangePriority::Removed,
            line: Line::from(vec![
                Span::styled(" - ", Style::default().fg(scheme.removed).bold()),
                Span::styled(comp.name.clone(), Style::default().fg(scheme.removed)),
                Span::styled(
                    format!(" {}", comp.old_version.as_deref().unwrap_or("")),
                    Style::default().fg(scheme.muted),
                ),
            ]),
        });
    }

    // Added components (with vuln warning)
    for comp in &result.components.added {
        let has_vuln = result
            .vulnerabilities
            .introduced
            .iter()
            .any(|v| v.component_id == comp.id);
        let icon = if has_vuln { "\u{26a0}" } else { "+" };
        let style = if has_vuln {
            Style::default().fg(scheme.error)
        } else {
            Style::default().fg(scheme.added)
        };

        let mut spans = vec![
            Span::styled(format!(" {icon} "), style.bold()),
            Span::styled(comp.name.clone(), style),
            Span::styled(
                format!(" {}", comp.new_version.as_deref().unwrap_or("")),
                Style::default().fg(scheme.muted),
            ),
        ];
        if has_vuln {
            spans.push(Span::styled(
                " (has vulnerabilities)",
                Style::default().fg(scheme.error),
            ));
        }

        entries.push(ChangeEntry {
            priority: ChangePriority::Added,
            line: Line::from(spans),
        });
    }

    // Sort by priority
    entries.sort_by_key(|e| e.priority);

    // Count of real change rows (component/vuln entries + metadata changes),
    // excluding the metadata section header, for the panel title.
    let total = entries.len() + result.metadata_changes.len();

    // Document-metadata changes (author/tool/timestamp/spec-version/lifecycle/
    // signature/version) are counted in summary.total_changes but were
    // otherwise unrepresented in the diff TUI. Render them as a labeled block at
    // the top so they reconcile the "N changes" header and stay visible above
    // the priority-sorted component/vuln entries.
    let mut lines: Vec<Line> = metadata_change_lines(result, &scheme);

    if entries.is_empty() {
        if lines.is_empty() {
            lines.push(Line::styled(
                "No significant changes to highlight",
                Style::default().fg(scheme.muted),
            ));
        }
    } else {
        lines.extend(entries.into_iter().map(|e| e.line));
    }
    let major = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Major
            )
        })
        .count();
    let minor = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Minor
            )
        })
        .count();
    let patch = result
        .components
        .modified
        .iter()
        .filter(|c| {
            matches!(
                version_change_level(c.old_version.as_deref(), c.new_version.as_deref()),
                VersionLevel::Patch
            )
        })
        .count();
    let added = result.components.added.len();
    let removed = result.components.removed.len();
    let meta = result.metadata_changes.len();
    let meta_suffix = if meta > 0 {
        format!("meta:{meta} ")
    } else {
        String::new()
    };
    // Scroll window: the list was previously pinned at .scroll((0,0)) with no
    // key handling, silently hiding everything below the fold — users read
    // the visible handful as the complete change set.
    let visible = area.height.saturating_sub(2) as usize;
    let max_scroll = lines.len().saturating_sub(visible);
    let offset = ctx.summary.scroll_offset.min(max_scroll);

    // Line positions ("Ln", like the Source tab), not change counts: the
    // rendered list includes section-header rows, so a bare [a-b/N] read as
    // a second, disagreeing change total next to the "(N)" in this title.
    let window_suffix = if lines.len() > visible {
        format!(
            "[Ln {}-{}/{} j/k] ",
            offset + 1,
            (offset + visible).min(lines.len()),
            lines.len()
        )
    } else {
        String::new()
    };
    let title = format!(
        " All Changes ({total}) \u{2014} MAJOR:{major} minor:{minor} patch:{patch} +{added} -{removed} {meta_suffix}{window_suffix}"
    );

    let overflows = lines.len() > visible;
    let total_lines = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.border)),
        )
        .scroll((u16::try_from(offset).unwrap_or(u16::MAX), 0));

    frame.render_widget(paragraph, area);

    if overflows {
        crate::tui::widgets::render_scrollbar(
            frame,
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            total_lines,
            offset,
        );
    }
}

/// Number of lines `render_all_changes` builds for this diff — drives the
/// Summary scroll bound set in `App::prepare_render`. Mirrors the render
/// exactly: metadata section (header + rows) when non-empty, plus the
/// priority-sorted entries (introduced Critical/High vulns, modified,
/// removed, added), or the single empty-state line.
pub(crate) fn all_changes_line_count(result: &crate::diff::DiffResult) -> usize {
    let crit = result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "Critical")
        .count();
    let high = result
        .vulnerabilities
        .introduced
        .iter()
        .filter(|v| v.severity == "High")
        .count();
    let entries = crit
        + high
        + result.components.modified.len()
        + result.components.removed.len()
        + result.components.added.len();
    let meta = result.metadata_changes.len();
    let meta_lines = if meta > 0 { meta + 1 } else { 0 };
    if entries == 0 && meta_lines == 0 {
        1
    } else {
        entries + meta_lines
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionLevel {
    Patch,
    Minor,
    Major,
    Downgrade,
    Unknown,
}

/// Classify a version change via the diff engine's lenient classifier, which
/// handles v-prefixes (Go), short versions (`1.2`), 4-segment versions, and
/// pre-release promotion — strict `semver::Version::parse` classified all of
/// those as Unknown, silently undercounting major bumps and the Risk level.
fn version_change_level(old: Option<&str>, new: Option<&str>) -> VersionLevel {
    use crate::diff::VersionChangeType;

    let (Some(o), Some(n)) = (old, new) else {
        return VersionLevel::Unknown;
    };
    match crate::diff::classify_version_strings(o, n) {
        VersionChangeType::MajorUpgrade => VersionLevel::Major,
        VersionChangeType::MinorUpgrade => VersionLevel::Minor,
        VersionChangeType::PatchUpgrade => VersionLevel::Patch,
        VersionChangeType::Downgrade => VersionLevel::Downgrade,
        _ => VersionLevel::Unknown,
    }
}

#[cfg(test)]
mod version_level_tests {
    use super::*;

    /// Regression: non-strict-semver ecosystems (Go v-prefix, 2-component,
    /// 4-segment, pre-release promotion) previously all classified as Unknown,
    /// undercounting major bumps and the Summary Risk level.
    #[test]
    fn version_level_classifies_non_semver_ecosystems() {
        // Go-style v-prefix.
        assert_eq!(
            version_change_level(Some("v1.2.3"), Some("v2.0.0")),
            VersionLevel::Major
        );
        // Two-component version.
        assert_eq!(
            version_change_level(Some("1.2"), Some("1.3")),
            VersionLevel::Minor
        );
        // Four-segment version must not fall to Unknown.
        assert_ne!(
            version_change_level(Some("1.2.3.4"), Some("1.2.3.5")),
            VersionLevel::Unknown
        );
        // Downgrade detection.
        assert_eq!(
            version_change_level(Some("2.0.0"), Some("1.9.0")),
            VersionLevel::Downgrade
        );
        // Pre-release promotion within the same triple is a patch-level step.
        assert_eq!(
            version_change_level(Some("1.0.0-alpha"), Some("1.0.0")),
            VersionLevel::Patch
        );
        // Honestly unknown: non-numeric schemes and missing versions.
        assert_eq!(
            version_change_level(Some("abc"), Some("def")),
            VersionLevel::Unknown
        );
        assert_eq!(
            version_change_level(None, Some("1.0.0")),
            VersionLevel::Unknown
        );
    }

    /// Go pseudo-versions must classify deterministically without panicking.
    #[test]
    fn version_level_go_pseudo_version() {
        let level = version_change_level(
            Some("v0.0.0-20200101000000-abcdef123456"),
            Some("v0.0.0-20210101000000-fedcba654321"),
        );
        assert_eq!(
            level,
            VersionLevel::Patch,
            "pseudo-version timestamp bump orders as a pre-release (patch) step"
        );
    }
}

#[cfg(test)]
mod risk_badge_tests {
    use super::*;

    /// Badge foreground must follow the theme convention: light text on the
    /// dark critical/error badge backgrounds, dark text on bright ones
    /// (previously hardcoded black everywhere).
    #[test]
    fn compute_risk_level_badge_fg() {
        let scheme = crate::tui::theme::ColorScheme::dark();

        // Critical risk: one Critical introduced vulnerability.
        let mut critical = crate::diff::DiffResult::default();
        let vref = crate::model::VulnerabilityRef::new(
            "CVE-2024-0001".to_string(),
            crate::model::VulnerabilitySource::Osv,
        );
        let comp =
            crate::model::Component::new("liba".to_string(), "pkg:npm/liba@1.0.0".to_string());
        let mut detail = crate::diff::VulnerabilityDetail::from_ref(&vref, &comp);
        detail.severity = "Critical".to_string();
        critical.vulnerabilities.introduced.push(detail);

        let (label, _, badge_fg) = compute_risk_level(&critical, &scheme);
        assert_eq!(label, "Critical Risk");
        assert_eq!(badge_fg, scheme.badge_fg_light);

        // Low risk: additions only.
        let mut low = crate::diff::DiffResult::default();
        low.summary.components_added = 1;
        let (label, _, badge_fg) = compute_risk_level(&low, &scheme);
        assert_eq!(label, "Low Risk");
        assert_eq!(badge_fg, scheme.badge_fg_dark);
    }
}

#[cfg(test)]
mod layout_plan_tests {
    use super::*;

    /// Table-driven degradation cascade: shrink header -> drop charts ->
    /// drop insights -> compact strip.
    #[test]
    fn summary_layout_plan_cascade() {
        // 80x24 content height (17): even minimal rows don't fit -> compact.
        let p = summary_layout_plan(17, 6, 5, 8);
        assert!(p.compact, "17 rows must go compact: {p:?}");

        // Demo 120x40 arithmetic: 8+6+5+8+6 = 33 fits exactly with the
        // header shrunk to 8.
        let p = summary_layout_plan(33, 6, 5, 8);
        assert!(!p.compact);
        assert_eq!(p.summary_h, 8);
        assert!(p.show_insights && p.show_charts);

        // Roomy: header keeps its natural clamp.
        let p = summary_layout_plan(40, 6, 5, 8);
        assert!(!p.compact);
        assert_eq!(p.summary_h, 11, "(findings 6 + 5).clamp(7,13)");
        assert!(p.show_insights && p.show_charts);

        // Mid-tier: too tight for charts, keeps insights.
        let p = summary_layout_plan(25, 6, 5, 8);
        assert!(!p.compact, "25 rows is not compact: {p:?}");
        assert!(!p.show_charts, "charts drop first: {p:?}");
        assert!(p.show_insights, "insights survive at 25 rows: {p:?}");
    }
}
