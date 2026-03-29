//! Compliance tab view for diff mode.
//!
//! Shows side-by-side compliance results for old and new SBOMs across all
//! compliance standards, with violation diff (new/resolved/persistent).

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
};

use crate::quality::{ComplianceLevel, ComplianceResult, ViolationSeverity};
use crate::tui::app_states::{ComplianceSeverityFilter, DiffComplianceViewMode};
use crate::tui::render_context::RenderContext;
use crate::tui::shared::compliance as shared_compliance;
use crate::tui::theme::colors;

// ============================================================================
// Grouped violation types
// ============================================================================

/// A single item in the flattened grouped display list.
enum GroupedItem {
    /// A group header row (element name, violation count, expanded state).
    Header {
        element: String,
        count: usize,
        expanded: bool,
    },
    /// A violation row within an expanded group.
    Violation(ViolationEntry),
}

/// Group a flat list of violations by element, preserving insertion order.
fn group_violations(violations: Vec<ViolationEntry>) -> Vec<(String, Vec<ViolationEntry>)> {
    let mut groups: indexmap::IndexMap<String, Vec<ViolationEntry>> = indexmap::IndexMap::new();
    for v in violations {
        let key = if v.element.is_empty() {
            "Document".to_string()
        } else {
            v.element.clone()
        };
        groups.entry(key).or_default().push(v);
    }
    groups.into_iter().collect()
}

/// Flatten grouped violations into a linear display list, respecting expand/collapse state.
fn flatten_grouped(
    groups: Vec<(String, Vec<ViolationEntry>)>,
    expanded_groups: &std::collections::HashSet<String>,
) -> Vec<GroupedItem> {
    let mut items = Vec::new();
    for (element, violations) in groups {
        let expanded = expanded_groups.contains(&element);
        let count = violations.len();
        items.push(GroupedItem::Header {
            element: element.clone(),
            count,
            expanded,
        });
        if expanded {
            for v in violations {
                items.push(GroupedItem::Violation(v));
            }
        }
    }
    items
}

/// Strip a repetitive "Component '{element}' " prefix from a violation message.
fn clean_message(message: &str, element: &str) -> String {
    let prefix_single = format!("Component '{element}' ");
    let prefix_double = format!("Component \"{element}\" ");
    message
        .strip_prefix(&prefix_single)
        .or_else(|| message.strip_prefix(&prefix_double))
        .unwrap_or(message)
        .to_string()
}

// ============================================================================
// Violation count
// ============================================================================

/// Get the count of violations shown in the current view mode (for navigation bounds).
///
/// When grouping is active, this returns the total number of display rows (headers + visible
/// violations) so that navigation bounds are correct.
pub fn diff_compliance_violation_count(ctx: &RenderContext) -> usize {
    let idx = ctx.compliance.selected_standard;
    let Some(old_results) = ctx.old_compliance_results else {
        return 0;
    };
    let Some(new_results) = ctx.new_compliance_results else {
        return 0;
    };
    if idx >= old_results.len() || idx >= new_results.len() {
        return 0;
    }
    let old = &old_results[idx];
    let new = &new_results[idx];

    let sev_filter = ctx.compliance.severity_filter;

    let violations = match ctx.compliance.view_mode {
        DiffComplianceViewMode::Overview => return 0,
        DiffComplianceViewMode::NewViolations => {
            filter_violations(compute_new_violations(old, new), sev_filter)
        }
        DiffComplianceViewMode::ResolvedViolations => {
            filter_violations(compute_resolved_violations(old, new), sev_filter)
        }
        DiffComplianceViewMode::OldViolations => old
            .violations
            .iter()
            .filter(|v| sev_filter.matches(v.severity))
            .map(ViolationEntry::from_violation)
            .collect(),
        DiffComplianceViewMode::NewSbomViolations => new
            .violations
            .iter()
            .filter(|v| sev_filter.matches(v.severity))
            .map(ViolationEntry::from_violation)
            .collect(),
    };

    if ctx.compliance.group_by_element {
        let groups = group_violations(violations);
        let items = flatten_grouped(groups, &ctx.compliance.expanded_groups);
        items.len()
    } else {
        violations.len()
    }
}

// ============================================================================
// Main render
// ============================================================================

/// Main render function for the diff compliance tab.
pub fn render_diff_compliance(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let old_empty = ctx
        .old_compliance_results
        .is_none_or(<[ComplianceResult]>::is_empty);
    let new_empty = ctx
        .new_compliance_results
        .is_none_or(<[ComplianceResult]>::is_empty);
    if old_empty || new_empty {
        crate::tui::widgets::render_empty_state_enhanced(
            frame,
            area,
            "--",
            "No compliance data available",
            Some("Compliance analysis requires both old and new SBOMs"),
            Some("Ensure both SBOMs were successfully parsed"),
        );
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Standard selector
            Constraint::Length(3), // Compact compliance header
            Constraint::Min(10),   // Violations / overview
            Constraint::Length(2), // Help bar
        ])
        .split(area);

    render_standard_selector(frame, chunks[0], ctx);
    render_compliance_header(frame, chunks[1], ctx);
    render_violations_panel(frame, chunks[2], ctx);
    render_help_bar(frame, chunks[3], ctx);

    // Render detail overlay if active
    if ctx.compliance.show_detail
        && let Some(violation) = get_selected_diff_violation(ctx)
    {
        shared_compliance::render_violation_detail_overlay(frame, area, violation);
    }
}

// ============================================================================
// Standard selector
// ============================================================================

fn render_standard_selector(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let levels = ComplianceLevel::all();
    let selected = ctx.compliance.selected_standard;
    let Some(old_results) = ctx.old_compliance_results else {
        return;
    };
    let Some(new_results) = ctx.new_compliance_results else {
        return;
    };

    let titles: Vec<Line> = levels
        .iter()
        .enumerate()
        .map(|(i, level)| {
            let old_ok = old_results.get(i).is_some_and(|r| r.is_compliant);
            let new_ok = new_results.get(i).is_some_and(|r| r.is_compliant);

            let indicator = match (old_ok, new_ok) {
                (true, true) => ("\u{2713}", colors().success),
                (false, true) => ("\u{2191}", colors().success),
                (true, false) => ("\u{2193}", colors().error),
                (false, false) => ("\u{2717}", colors().error),
            };

            let style = if i == selected {
                Style::default()
                    .fg(colors().accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(colors().text_muted)
            };

            Line::from(vec![
                Span::styled(
                    format!("{} ", indicator.0),
                    Style::default().fg(indicator.1),
                ),
                Span::styled(level.short_name(), style),
            ])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors().border))
                .title(Span::styled(
                    " Compliance Standards (\u{2190}/\u{2192}) ",
                    Style::default().fg(colors().text_muted),
                )),
        )
        .select(selected)
        .divider(Span::styled(
            " \u{2502} ",
            Style::default().fg(colors().muted),
        ));

    frame.render_widget(tabs, area);
}

// ============================================================================
// Compact compliance header (Change 1)
// ============================================================================

/// Compute a compliance percentage from a `ComplianceResult`.
fn compliance_pct(result: &ComplianceResult) -> u16 {
    let actionable = result.error_count + result.warning_count;
    if actionable == 0 {
        100
    } else {
        let error_w = result.error_count * 3;
        let warning_w = result.warning_count;
        let max_w = actionable * 3;
        ((max_w.saturating_sub(error_w + warning_w)) * 100 / max_w) as u16
    }
}

/// Render a compact 3-line bordered compliance header card.
fn render_compliance_header(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let idx = ctx.compliance.selected_standard;
    let old = ctx.old_compliance_results.and_then(|r| r.get(idx));
    let new = ctx.new_compliance_results.and_then(|r| r.get(idx));

    let (Some(old_result), Some(new_result)) = (old, new) else {
        return;
    };

    let levels = ComplianceLevel::all();
    let standard_name = levels.get(idx).map_or("Unknown", ComplianceLevel::name);

    let old_status = if old_result.is_compliant {
        "PASS"
    } else {
        "FAIL"
    };
    let new_status = if new_result.is_compliant {
        "PASS"
    } else {
        "FAIL"
    };
    let old_pct = compliance_pct(old_result);
    let new_pct = compliance_pct(new_result);

    let delta_label = if new_pct > old_pct || (!old_result.is_compliant && new_result.is_compliant)
    {
        "improved"
    } else if new_pct < old_pct || (old_result.is_compliant && !new_result.is_compliant) {
        "regressed"
    } else {
        "unchanged"
    };

    // Border color: green if both pass, red if either fails, yellow if status changed
    let border_color = if old_result.is_compliant && new_result.is_compliant {
        colors().success
    } else if old_result.is_compliant != new_result.is_compliant {
        colors().warning
    } else {
        colors().error
    };

    let title = format!(
        " {standard_name}: {old_status} {old_pct}% \u{2192} {new_status} {new_pct}%  {delta_label} "
    );

    // Compute new/resolved counts
    let new_count = compute_new_violations(old_result, new_result).len();
    let resolved_count = compute_resolved_violations(old_result, new_result).len();

    let content = Line::from(vec![
        Span::styled(
            format!("Errors: {} ", new_result.error_count),
            Style::default().fg(colors().error),
        ),
        Span::styled(
            format!(" Warnings: {} ", new_result.warning_count),
            Style::default().fg(colors().warning),
        ),
        Span::styled(
            format!(" Info: {} ", new_result.info_count),
            Style::default().fg(colors().info),
        ),
        Span::styled(" \u{2502} ", Style::default().fg(colors().muted)),
        Span::styled(
            format!(" New: {new_count}"),
            Style::default().fg(if new_count > 0 {
                colors().error
            } else {
                colors().text_muted
            }),
        ),
        Span::styled(
            format!("  Resolved: {resolved_count}"),
            Style::default().fg(if resolved_count > 0 {
                colors().success
            } else {
                colors().text_muted
            }),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(title, Style::default().fg(border_color)));

    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

/// Old side-by-side summary — retained for potential future use.
#[allow(dead_code)]
fn render_sidebyside_summary(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let idx = ctx.compliance.selected_standard;
    let old = ctx.old_compliance_results.and_then(|r| r.get(idx));
    let new = ctx.new_compliance_results.and_then(|r| r.get(idx));

    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Old SBOM panel
    if let Some(result) = old {
        render_compliance_gauge(frame, halves[0], result, "Old SBOM");
    }
    // New SBOM panel
    if let Some(result) = new {
        render_compliance_gauge(frame, halves[1], result, "New SBOM");
    }
}

#[allow(dead_code)]
fn render_compliance_gauge(frame: &mut Frame, area: Rect, result: &ComplianceResult, label: &str) {
    use ratatui::widgets::Gauge;

    let pct = compliance_pct(result);

    let status_color = if result.is_compliant && result.warning_count == 0 {
        colors().success
    } else if result.is_compliant {
        colors().warning
    } else {
        colors().error
    };

    let status_text = if result.is_compliant { "PASS" } else { "FAIL" };

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3)])
        .split(area);

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(status_color))
                .title(Span::styled(
                    format!(" {label} [{status_text}] "),
                    Style::default().fg(status_color),
                )),
        )
        .gauge_style(Style::default().fg(status_color))
        .percent(pct)
        .label(format!("{pct}%"));
    frame.render_widget(gauge, inner[0]);

    let counts = Line::from(vec![
        Span::styled(
            format!(" Errors: {} ", result.error_count),
            Style::default().fg(colors().error),
        ),
        Span::styled(
            format!("Warnings: {} ", result.warning_count),
            Style::default().fg(colors().warning),
        ),
        Span::styled(
            format!("Info: {}", result.info_count),
            Style::default().fg(colors().info),
        ),
    ]);
    let counts_para = Paragraph::new(counts);
    frame.render_widget(counts_para, inner[1]);
}

// ============================================================================
// Violations panel
// ============================================================================

fn render_violations_panel(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let idx = ctx.compliance.selected_standard;
    let Some(old) = ctx.old_compliance_results.and_then(|r| r.get(idx)) else {
        return;
    };
    let Some(new) = ctx.new_compliance_results.and_then(|r| r.get(idx)) else {
        return;
    };

    let mode = ctx.compliance.view_mode;
    let selected = ctx.compliance.selected_violation;

    // Compute viewport height for scroll adjustment (borders=2, header=1, header margin=1)
    let viewport_height = area.height.saturating_sub(4) as usize;
    // Compute scroll_offset locally (read-only -- cannot mutate ctx)
    let mut scroll_offset = ctx.compliance.scroll_offset;
    if viewport_height > 0 {
        if ctx.compliance.selected_violation < scroll_offset {
            scroll_offset = ctx.compliance.selected_violation;
        } else if ctx.compliance.selected_violation >= scroll_offset + viewport_height {
            scroll_offset = ctx.compliance.selected_violation + 1 - viewport_height;
        }
    }

    let sev_filter = ctx.compliance.severity_filter;

    match mode {
        DiffComplianceViewMode::Overview => {
            render_overview(frame, area, old, new);
        }
        DiffComplianceViewMode::NewViolations => {
            let violations = filter_violations(compute_new_violations(old, new), sev_filter);
            render_violations_dispatch(
                frame,
                area,
                violations,
                selected,
                scroll_offset,
                "New Violations (introduced)",
                colors().error,
                ctx,
            );
        }
        DiffComplianceViewMode::ResolvedViolations => {
            let violations = filter_violations(compute_resolved_violations(old, new), sev_filter);
            render_violations_dispatch(
                frame,
                area,
                violations,
                selected,
                scroll_offset,
                "Resolved Violations (fixed)",
                colors().success,
                ctx,
            );
        }
        DiffComplianceViewMode::OldViolations => {
            let violations: Vec<_> = old
                .violations
                .iter()
                .filter(|v| sev_filter.matches(v.severity))
                .map(ViolationEntry::from_violation)
                .collect();
            render_violations_dispatch(
                frame,
                area,
                violations,
                selected,
                scroll_offset,
                "Old SBOM \u{2014} All Violations",
                colors().text_muted,
                ctx,
            );
        }
        DiffComplianceViewMode::NewSbomViolations => {
            let violations: Vec<_> = new
                .violations
                .iter()
                .filter(|v| sev_filter.matches(v.severity))
                .map(ViolationEntry::from_violation)
                .collect();
            render_violations_dispatch(
                frame,
                area,
                violations,
                selected,
                scroll_offset,
                "New SBOM \u{2014} All Violations",
                colors().text_muted,
                ctx,
            );
        }
    }
}

/// Dispatch to grouped or flat violation rendering based on state.
#[allow(clippy::too_many_arguments)]
fn render_violations_dispatch(
    frame: &mut Frame,
    area: Rect,
    violations: Vec<ViolationEntry>,
    selected: usize,
    scroll_offset: usize,
    title: &str,
    title_color: ratatui::style::Color,
    ctx: &RenderContext,
) {
    if violations.is_empty() {
        let idx = ctx.compliance.selected_standard;
        let new_result = ctx.new_compliance_results.and_then(|r| r.get(idx));
        render_rich_empty_state(
            frame,
            area,
            ctx.compliance.view_mode,
            new_result,
            title,
            title_color,
        );
        return;
    }

    if ctx.compliance.group_by_element {
        render_grouped_violation_table(
            frame,
            area,
            violations,
            selected,
            scroll_offset,
            title,
            title_color,
            &ctx.compliance.expanded_groups,
        );
    } else {
        render_violation_table(
            frame,
            area,
            &violations,
            selected,
            scroll_offset,
            title,
            title_color,
        );
    }
}

// ============================================================================
// Rich empty state
// ============================================================================

/// Render a contextual empty state when no violations exist for the current view mode.
///
/// Instead of showing a blank area with "No violations in this category", this renders
/// status context and actionable information depending on the view mode.
fn render_rich_empty_state(
    frame: &mut Frame,
    area: Rect,
    view_mode: DiffComplianceViewMode,
    new_result: Option<&ComplianceResult>,
    title: &str,
    title_color: ratatui::style::Color,
) {
    let scheme = colors();
    let mut lines: Vec<Line> = Vec::new();

    match view_mode {
        DiffComplianceViewMode::ResolvedViolations => {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  No violations were resolved between these SBOMs.",
                Style::default().fg(scheme.muted),
            )));
            lines.push(Line::from(""));

            // Show current status from the new SBOM result
            if let Some(result) = new_result {
                let status = if result.is_compliant { "PASS" } else { "FAIL" };
                let status_color = if result.is_compliant {
                    scheme.success
                } else {
                    scheme.error
                };
                lines.push(Line::from(vec![
                    Span::styled("  Current status: ", Style::default().fg(scheme.muted)),
                    Span::styled(
                        status,
                        Style::default()
                            .fg(status_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(
                            " -- {} Errors, {} Warnings, {} Info items remain",
                            result.error_count, result.warning_count, result.info_count
                        ),
                        Style::default().fg(scheme.muted),
                    ),
                ]));
                lines.push(Line::from(""));

                // Show top issues to fix (errors first, then warnings)
                let top_issues: Vec<_> = result
                    .violations
                    .iter()
                    .filter(|v| {
                        matches!(
                            v.severity,
                            ViolationSeverity::Error | ViolationSeverity::Warning
                        )
                    })
                    .take(5)
                    .collect();

                if !top_issues.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "  --- Top Issues to Fix ---",
                        Style::default()
                            .fg(scheme.accent)
                            .add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));

                    for (i, v) in top_issues.iter().enumerate() {
                        let (sev_label, sev_color) = match v.severity {
                            ViolationSeverity::Error => ("ERROR", scheme.error),
                            ViolationSeverity::Warning => ("WARN ", scheme.warning),
                            ViolationSeverity::Info => ("INFO ", scheme.info),
                        };
                        lines.push(Line::from(vec![
                            Span::styled(
                                format!("  {}. ", i + 1),
                                Style::default().fg(scheme.muted),
                            ),
                            Span::styled(
                                format!("{sev_label:<6}"),
                                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(&v.message, Style::default().fg(scheme.text)),
                        ]));
                        // Show element if present
                        if let Some(ref element) = v.element {
                            lines.push(Line::from(Span::styled(
                                format!("          -> Component: {element}"),
                                Style::default()
                                    .fg(scheme.muted)
                                    .add_modifier(Modifier::ITALIC),
                            )));
                        }
                    }
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Press v to switch to [New] or [All] violations view",
                Style::default()
                    .fg(scheme.muted)
                    .add_modifier(Modifier::ITALIC),
            )));
        }

        DiffComplianceViewMode::NewViolations => {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("\u{2713} ", Style::default().fg(scheme.success)),
                Span::styled(
                    "No new compliance violations were introduced.",
                    Style::default().fg(scheme.success),
                ),
            ]));
            lines.push(Line::from(""));

            // Show existing issue summary from the new SBOM result
            if let Some(result) = new_result {
                if result.error_count + result.warning_count > 0 {
                    let status = if result.is_compliant { "PASS" } else { "FAIL" };
                    let status_color = if result.is_compliant {
                        scheme.success
                    } else {
                        scheme.error
                    };
                    lines.push(Line::from(vec![
                        Span::styled("  Current status: ", Style::default().fg(scheme.muted)),
                        Span::styled(
                            status,
                            Style::default()
                                .fg(status_color)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!(
                                " -- {} Errors, {} Warnings remain from previous SBOM",
                                result.error_count, result.warning_count
                            ),
                            Style::default().fg(scheme.muted),
                        ),
                    ]));
                    lines.push(Line::from(""));

                    // Category breakdown
                    lines.push(Line::from(Span::styled(
                        "  --- Existing Issues by Category ---",
                        Style::default()
                            .fg(scheme.accent)
                            .add_modifier(Modifier::BOLD),
                    )));
                    lines.push(Line::from(""));

                    // Group by category
                    let mut cat_counts: std::collections::BTreeMap<&str, (usize, usize, usize)> =
                        std::collections::BTreeMap::new();
                    for v in &result.violations {
                        let entry = cat_counts.entry(v.category.name()).or_default();
                        match v.severity {
                            ViolationSeverity::Error => entry.0 += 1,
                            ViolationSeverity::Warning => entry.1 += 1,
                            ViolationSeverity::Info => entry.2 += 1,
                        }
                    }
                    for (cat, (errors, warnings, infos)) in &cat_counts {
                        let mut parts: Vec<String> = Vec::new();
                        if *errors > 0 {
                            parts.push(format!("{errors}E"));
                        }
                        if *warnings > 0 {
                            parts.push(format!("{warnings}W"));
                        }
                        if *infos > 0 {
                            parts.push(format!("{infos}I"));
                        }
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {cat:<25}"), Style::default().fg(scheme.text)),
                            Span::styled(parts.join(" "), Style::default().fg(scheme.muted)),
                        ]));
                    }
                } else {
                    lines.push(Line::from(Span::styled(
                        "  All compliance checks passing.",
                        Style::default().fg(scheme.success),
                    )));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Press v to switch to [All] violations view",
                Style::default()
                    .fg(scheme.muted)
                    .add_modifier(Modifier::ITALIC),
            )));
        }

        _ => {
            // Default empty state for other view modes (Old SBOM, New SBOM)
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  No violations in this category",
                Style::default().fg(scheme.success),
            )));
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.border))
        .title(Span::styled(
            format!(" {title} (0) "),
            Style::default().fg(title_color),
        ));
    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

/// Filter a list of `ViolationEntry` by the active severity filter.
fn filter_violations(
    violations: Vec<ViolationEntry>,
    filter: ComplianceSeverityFilter,
) -> Vec<ViolationEntry> {
    if matches!(filter, ComplianceSeverityFilter::All) {
        return violations;
    }
    violations
        .into_iter()
        .filter(|v| match filter {
            ComplianceSeverityFilter::All => true,
            ComplianceSeverityFilter::ErrorsOnly => v.severity == "ERROR",
            ComplianceSeverityFilter::WarningsAndAbove => {
                v.severity == "ERROR" || v.severity == "WARN"
            }
        })
        .collect()
}

// ============================================================================
// Overview panel
// ============================================================================

fn render_overview(frame: &mut Frame, area: Rect, old: &ComplianceResult, new: &ComplianceResult) {
    let new_violations = compute_new_violations(old, new);
    let resolved_violations = compute_resolved_violations(old, new);

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "  Violation Diff:  ",
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    // New violations
    let new_color = if new_violations.is_empty() {
        colors().success
    } else {
        colors().error
    };
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(
            if new_violations.is_empty() {
                "  No new violations  ".to_string()
            } else if new_violations.len() == 1 {
                "  + 1 new violation introduced  ".to_string()
            } else {
                format!("  + {} new violations introduced  ", new_violations.len())
            },
            Style::default().fg(new_color).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Resolved violations
    let resolved_color = if resolved_violations.is_empty() {
        colors().text_muted
    } else {
        colors().success
    };
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(
            if resolved_violations.is_empty() {
                "  No violations resolved  ".to_string()
            } else if resolved_violations.len() == 1 {
                "  - 1 violation resolved  ".to_string()
            } else {
                format!("  - {} violations resolved  ", resolved_violations.len())
            },
            Style::default()
                .fg(resolved_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    // Persistent
    let persistent = new.violations.len().saturating_sub(new_violations.len());
    lines.push(Line::from(vec![
        Span::raw("    "),
        Span::styled(
            if persistent == 1 {
                "  = 1 violation persistent  ".to_string()
            } else {
                format!("  = {persistent} violations persistent  ")
            },
            Style::default().fg(colors().text_muted),
        ),
    ]));

    lines.push(Line::from(""));

    // Delta summary
    let old_errors = old.error_count;
    let new_errors = new.error_count;
    let error_delta = new_errors as i64 - old_errors as i64;
    let delta_str = if error_delta > 0 {
        format!("+{error_delta}")
    } else {
        format!("{error_delta}")
    };
    let delta_color = match error_delta.cmp(&0) {
        std::cmp::Ordering::Greater => colors().error,
        std::cmp::Ordering::Less => colors().success,
        std::cmp::Ordering::Equal => colors().text_muted,
    };

    lines.push(Line::from(vec![
        Span::raw("    Error count:  "),
        Span::styled(
            format!("{old_errors}"),
            Style::default().fg(colors().text_muted),
        ),
        Span::raw(" \u{2192} "),
        Span::styled(format!("{new_errors}"), Style::default().fg(colors().text)),
        Span::raw("  ("),
        Span::styled(delta_str, Style::default().fg(delta_color)),
        Span::raw(")"),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "    Press v to cycle through: Overview \u{2192} New \u{2192} Resolved \u{2192} Old \u{2192} New SBOM",
        Style::default().fg(colors().text_muted),
    )]));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(colors().border))
        .title(Span::styled(
            " Compliance Diff Overview ",
            Style::default().fg(colors().accent),
        ));

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

// ============================================================================
// Violation entry
// ============================================================================

struct ViolationEntry {
    severity: String,
    severity_color: ratatui::style::Color,
    category: String,
    message: String,
    element: String,
}

impl ViolationEntry {
    fn from_violation(v: &crate::quality::Violation) -> Self {
        let (severity, severity_color) = match v.severity {
            ViolationSeverity::Error => ("ERROR", colors().error),
            ViolationSeverity::Warning => ("WARN", colors().warning),
            ViolationSeverity::Info => ("INFO", colors().info),
        };
        Self {
            severity: severity.to_string(),
            severity_color,
            category: v.category.name().to_string(),
            message: v.message.clone(),
            element: v.element.clone().unwrap_or_default(),
        }
    }
}

// ============================================================================
// Flat violation table
// ============================================================================

fn render_violation_table(
    frame: &mut Frame,
    area: Rect,
    violations: &[ViolationEntry],
    selected: usize,
    scroll_offset: usize,
    title: &str,
    title_color: ratatui::style::Color,
) {
    let viewport_height = area.height.saturating_sub(4) as usize;
    let visible_end = (scroll_offset + viewport_height).min(violations.len());

    let header = Row::new(vec![
        Cell::from("Severity").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Category").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Issue").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Element").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = violations
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_end - scroll_offset)
        .map(|(i, v)| {
            let style = if i == selected {
                Style::default().bg(colors().selection)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(v.severity.as_str()).style(Style::default().fg(v.severity_color)),
                Cell::from(v.category.as_str()),
                Cell::from(v.message.as_str()),
                Cell::from(v.element.as_str()).style(Style::default().fg(colors().text_muted)),
            ])
            .style(style)
        })
        .collect();

    // Show scroll position in title when scrolled
    let title_text = if scroll_offset > 0 || visible_end < violations.len() {
        format!(
            " {} ({}) [{}-{}/{}] \u{2014} j/k to navigate ",
            title,
            violations.len(),
            scroll_offset + 1,
            visible_end,
            violations.len(),
        )
    } else {
        format!(
            " {} ({}) \u{2014} j/k to navigate ",
            title,
            violations.len()
        )
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Min(30),
            Constraint::Length(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().border))
            .title(Span::styled(title_text, Style::default().fg(title_color))),
    );

    frame.render_widget(table, area);

    // Render scrollbar
    if violations.len() > viewport_height {
        crate::tui::widgets::render_scrollbar(
            frame,
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            violations.len(),
            scroll_offset,
        );
    }
}

// ============================================================================
// Grouped violation table (Change 2)
// ============================================================================

#[allow(clippy::too_many_arguments)]
fn render_grouped_violation_table(
    frame: &mut Frame,
    area: Rect,
    violations: Vec<ViolationEntry>,
    selected: usize,
    scroll_offset: usize,
    title: &str,
    title_color: ratatui::style::Color,
    expanded_groups: &std::collections::HashSet<String>,
) {
    let total_violations = violations.len();
    let groups = group_violations(violations);
    let items = flatten_grouped(groups, expanded_groups);
    let item_count = items.len();

    let viewport_height = area.height.saturating_sub(4) as usize;
    let visible_end = (scroll_offset + viewport_height).min(item_count);

    let header = Row::new(vec![
        Cell::from("Severity").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Category").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Issue").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Element").style(
            Style::default()
                .fg(colors().text)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = items
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_end - scroll_offset)
        .map(|(i, item)| {
            let is_selected = i == selected;
            let base_style = if is_selected {
                Style::default().bg(colors().selection)
            } else {
                Style::default()
            };

            match item {
                GroupedItem::Header {
                    element,
                    count,
                    expanded,
                } => {
                    let arrow = if *expanded { "\u{25bc}" } else { "\u{25b6}" };
                    let header_text = format!("{arrow} {element} ({count} issues)");
                    Row::new(vec![
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(header_text).style(
                            Style::default()
                                .fg(colors().accent)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Cell::from(""),
                    ])
                    .style(base_style)
                }
                GroupedItem::Violation(v) => {
                    let cleaned = clean_message(&v.message, &v.element);
                    Row::new(vec![
                        Cell::from(format!("  {}", v.severity))
                            .style(Style::default().fg(v.severity_color)),
                        Cell::from(format!("  {}", v.category)),
                        Cell::from(format!("  {cleaned}")),
                        Cell::from(""),
                    ])
                    .style(base_style)
                }
            }
        })
        .collect();

    // Show scroll position in title when scrolled
    let visible_start = scroll_offset + 1;
    let title_text = if scroll_offset > 0 || visible_end < item_count {
        format!(
            " {title} ({total_violations}) [grouped] [{visible_start}-{visible_end}/{item_count}] \u{2014} j/k to navigate "
        )
    } else {
        format!(" {title} ({total_violations}) [grouped] \u{2014} j/k to navigate ")
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Min(30),
            Constraint::Length(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().border))
            .title(Span::styled(title_text, Style::default().fg(title_color))),
    );

    frame.render_widget(table, area);

    // Render scrollbar
    if item_count > viewport_height {
        crate::tui::widgets::render_scrollbar(
            frame,
            area.inner(ratatui::layout::Margin {
                vertical: 1,
                horizontal: 0,
            }),
            item_count,
            scroll_offset,
        );
    }
}

// ============================================================================
// Help bar
// ============================================================================

fn render_help_bar(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let mode_name = match ctx.compliance.view_mode {
        DiffComplianceViewMode::Overview => "Overview",
        DiffComplianceViewMode::NewViolations => "New",
        DiffComplianceViewMode::ResolvedViolations => "Resolved",
        DiffComplianceViewMode::OldViolations => "Old SBOM",
        DiffComplianceViewMode::NewSbomViolations => "New SBOM",
    };

    let filter_label = ctx.compliance.severity_filter.label();
    let violation_count = diff_compliance_violation_count(ctx);
    let group_label = if ctx.compliance.group_by_element {
        "grouped"
    } else {
        "flat"
    };

    let help = Line::from(vec![
        Span::styled("f", Style::default().fg(colors().accent)),
        Span::styled(
            format!(" filter [{filter_label}]  "),
            Style::default().fg(colors().text_muted),
        ),
        Span::styled("g", Style::default().fg(colors().accent)),
        Span::styled(
            format!(" group [{group_label}]  "),
            Style::default().fg(colors().text_muted),
        ),
        Span::styled("\u{2190}/\u{2192}", Style::default().fg(colors().accent)),
        Span::styled(
            " switch standard  ",
            Style::default().fg(colors().text_muted),
        ),
        Span::styled("v", Style::default().fg(colors().accent)),
        Span::styled(
            format!(" cycle view [{mode_name}]  "),
            Style::default().fg(colors().text_muted),
        ),
        Span::styled("j/k", Style::default().fg(colors().accent)),
        Span::styled(
            format!(" navigate ({violation_count})  "),
            Style::default().fg(colors().text_muted),
        ),
        Span::styled("E", Style::default().fg(colors().accent)),
        Span::styled(" export  ", Style::default().fg(colors().text_muted)),
        Span::styled("?", Style::default().fg(colors().accent)),
        Span::styled(" help", Style::default().fg(colors().text_muted)),
    ]);

    let bar = Paragraph::new(help).style(Style::default());
    frame.render_widget(bar, area);
}

// ============================================================================
// Violation diff computation
// ============================================================================

/// Compute violations present in new but not in old (by message matching).
fn compute_new_violations(old: &ComplianceResult, new: &ComplianceResult) -> Vec<ViolationEntry> {
    let old_messages: std::collections::HashSet<&str> =
        old.violations.iter().map(|v| v.message.as_str()).collect();

    new.violations
        .iter()
        .filter(|v| !old_messages.contains(v.message.as_str()))
        .map(ViolationEntry::from_violation)
        .collect()
}

/// Compute violations present in old but not in new (resolved).
fn compute_resolved_violations(
    old: &ComplianceResult,
    new: &ComplianceResult,
) -> Vec<ViolationEntry> {
    let new_messages: std::collections::HashSet<&str> =
        new.violations.iter().map(|v| v.message.as_str()).collect();

    old.violations
        .iter()
        .filter(|v| !new_messages.contains(v.message.as_str()))
        .map(ViolationEntry::from_violation)
        .collect()
}

// ============================================================================
// Selected violation detail lookup
// ============================================================================

/// Resolve the group element name for the currently selected item in grouped mode.
///
/// Returns `Some(element)` if the selected row is a group header, `None` otherwise.
pub fn resolve_selected_group_element(ctx: &RenderContext) -> Option<String> {
    if !ctx.compliance.group_by_element {
        return None;
    }
    let idx = ctx.compliance.selected_standard;
    let old = ctx.old_compliance_results?.get(idx)?;
    let new = ctx.new_compliance_results?.get(idx)?;
    let sev_filter = ctx.compliance.severity_filter;

    let violations = match ctx.compliance.view_mode {
        DiffComplianceViewMode::Overview => return None,
        DiffComplianceViewMode::NewViolations => {
            filter_violations(compute_new_violations(old, new), sev_filter)
        }
        DiffComplianceViewMode::ResolvedViolations => {
            filter_violations(compute_resolved_violations(old, new), sev_filter)
        }
        DiffComplianceViewMode::OldViolations => old
            .violations
            .iter()
            .filter(|v| sev_filter.matches(v.severity))
            .map(ViolationEntry::from_violation)
            .collect(),
        DiffComplianceViewMode::NewSbomViolations => new
            .violations
            .iter()
            .filter(|v| sev_filter.matches(v.severity))
            .map(ViolationEntry::from_violation)
            .collect(),
    };

    let groups = group_violations(violations);
    let items = flatten_grouped(groups, &ctx.compliance.expanded_groups);
    let selected = ctx.compliance.selected_violation;

    items.get(selected).and_then(|item| match item {
        GroupedItem::Header { element, .. } => Some(element.clone()),
        GroupedItem::Violation(_) => None,
    })
}

/// Get the actual Violation reference for the currently selected entry in diff mode.
fn get_selected_diff_violation<'a>(
    ctx: &'a RenderContext,
) -> Option<&'a crate::quality::Violation> {
    let idx = ctx.compliance.selected_standard;
    let old = ctx.old_compliance_results?.get(idx)?;
    let new = ctx.new_compliance_results?.get(idx)?;
    let selected = ctx.compliance.selected_violation;

    match ctx.compliance.view_mode {
        DiffComplianceViewMode::Overview => None,
        DiffComplianceViewMode::NewViolations => {
            let old_messages: std::collections::HashSet<&str> =
                old.violations.iter().map(|v| v.message.as_str()).collect();
            new.violations
                .iter()
                .filter(|v| !old_messages.contains(v.message.as_str()))
                .nth(selected)
        }
        DiffComplianceViewMode::ResolvedViolations => {
            let new_messages: std::collections::HashSet<&str> =
                new.violations.iter().map(|v| v.message.as_str()).collect();
            old.violations
                .iter()
                .filter(|v| !new_messages.contains(v.message.as_str()))
                .nth(selected)
        }
        DiffComplianceViewMode::OldViolations => old.violations.get(selected),
        DiffComplianceViewMode::NewSbomViolations => new.violations.get(selected),
    }
}
