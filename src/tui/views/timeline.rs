//! Timeline analysis view.
//!
//! Displays SBOM evolution over time with version tracking.

use crate::diff::{TimelineResult, VersionChangeType};
use crate::tui::app::{TimelineComponentFilter, TimelineState};
use crate::tui::theme::colors;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
};

/// Render the timeline analysis view
pub fn render_timeline(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
    status: Option<&str>,
) {
    let chunks = if state.show_statistics {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(7), // Statistics panel (3 lines + borders)
                Constraint::Length(8), // Timeline bar
                Constraint::Min(12),   // Main content
                Constraint::Length(3), // Status bar
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Length(8), // Timeline bar
                Constraint::Min(15),   // Main content
                Constraint::Length(3), // Status bar
            ])
            .split(area)
    };

    // Header
    render_header(f, chunks[0], result, state);

    let (bar_chunk, main_chunk, status_chunk) = if state.show_statistics {
        // Render statistics panel
        render_statistics_panel(f, chunks[1], result);
        (chunks[2], chunks[3], chunks[4])
    } else {
        (chunks[1], chunks[2], chunks[3])
    };

    // Timeline visualization
    render_timeline_bar(f, bar_chunk, result, state);

    // Main content - split into versions and component history
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main_chunk);

    render_versions_list(f, main_chunks[0], result, state);
    render_component_history(f, main_chunks[1], result, state);

    // Status bar
    render_status_bar(f, status_chunk, result, state, status);

    // Render overlays
    if state.show_version_diff_modal {
        render_version_diff_modal(f, area, result, state);
    }

    if state.show_component_history {
        render_component_history_modal(f, area, result, state);
    }

    if state.search.active {
        render_search_overlay(f, area, state);
    }

    if state.jump_mode {
        render_jump_overlay(f, area, state);
    }
}

fn render_header(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    let scheme = colors();
    let first = result.sboms.first().map_or("?", |s| s.name.as_str());
    let last = result.sboms.last().map_or("?", |s| s.name.as_str());

    let title = format!(
        " Timeline: {} → {} ({} versions) ",
        first,
        last,
        result.sboms.len()
    );

    let text = vec![Line::from(vec![
        Span::styled(
            title,
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        Span::styled("Sort: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(
                "{} {}",
                state.sort_by.label(),
                state.sort_direction.indicator()
            ),
            Style::default().fg(scheme.accent),
        ),
        Span::raw(" │ "),
        Span::styled("Filter: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            state.component_filter.label(),
            Style::default().fg(scheme.accent),
        ),
        if state.show_statistics {
            Span::styled(" │ Stats", Style::default().fg(scheme.info))
        } else {
            Span::raw("")
        },
    ])];

    let header = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn render_statistics_panel(f: &mut Frame, area: Rect, result: &TimelineResult) {
    let scheme = colors();

    let total_added: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_added)
        .sum();
    let total_removed: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_removed)
        .sum();
    let total_modified: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_modified)
        .sum();

    let avg_components: usize = if result.sboms.is_empty() {
        0
    } else {
        result
            .sboms
            .iter()
            .map(|s| s.component_count)
            .sum::<usize>()
            / result.sboms.len()
    };

    // Compliance trend summary: count how many versions pass CRA Phase 2
    let compliance_trend = &result.evolution_summary.compliance_trend;
    let cra_pass_count = compliance_trend
        .iter()
        .filter(|snap| {
            snap.scores
                .iter()
                .any(|s| s.standard.contains("CRA Phase 2") && s.is_compliant)
        })
        .count();
    let compliance_trend_str = if compliance_trend.is_empty() {
        "N/A".to_string()
    } else {
        format!("{}/{} pass CRA", cra_pass_count, compliance_trend.len())
    };
    let compliance_color =
        if cra_pass_count == compliance_trend.len() && !compliance_trend.is_empty() {
            scheme.success
        } else if cra_pass_count > 0 {
            scheme.warning
        } else {
            scheme.error
        };

    // Build vulnerability trend line from evolution_summary
    let vuln_trend = &result.evolution_summary.vulnerability_trend;
    let vuln_trend_line = if vuln_trend.is_empty() {
        Line::from(vec![
            Span::styled("Vuln trend: ", Style::default().fg(scheme.text_muted)),
            Span::styled("N/A", Style::default().fg(scheme.text_muted)),
        ])
    } else {
        let mut spans = vec![Span::styled(
            "Vuln trend: ",
            Style::default().fg(scheme.text_muted),
        )];
        let first_total = vuln_trend.first().map_or(0, |s| s.counts.total());
        let last_total = vuln_trend.last().map_or(0, |s| s.counts.total());

        for (idx, snap) in vuln_trend.iter().enumerate() {
            let total = snap.counts.total();
            let color = if snap.counts.critical > 0 {
                scheme.critical
            } else if snap.counts.high > 0 {
                scheme.high
            } else if total > 0 {
                scheme.warning
            } else {
                scheme.success
            };
            spans.push(Span::styled(total.to_string(), Style::default().fg(color)));
            if idx < vuln_trend.len() - 1 {
                spans.push(Span::styled(
                    " \u{2192} ",
                    Style::default().fg(scheme.text_muted),
                ));
            }
        }

        // Net change indicator
        if vuln_trend.len() > 1 {
            let net = last_total as isize - first_total as isize;
            let (arrow, color) = if net < 0 {
                ("\u{25bc}", scheme.success) // down arrow = good
            } else if net > 0 {
                ("\u{25b2}", scheme.error) // up arrow = bad
            } else {
                ("\u{25cf}", scheme.text_muted) // dot = unchanged
            };
            spans.push(Span::styled(
                format!("  ({arrow} net {net:+})"),
                Style::default().fg(color),
            ));
        }

        Line::from(spans)
    };

    let text = vec![
        Line::from(vec![
            Span::styled("Total Added: ", Style::default().fg(scheme.added)),
            Span::raw(total_added.to_string()),
            Span::raw("  "),
            Span::styled("Total Removed: ", Style::default().fg(scheme.removed)),
            Span::raw(total_removed.to_string()),
            Span::raw("  "),
            Span::styled("Total Modified: ", Style::default().fg(scheme.modified)),
            Span::raw(total_modified.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Avg Components: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                avg_components.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw("  "),
            Span::styled("Version Changes: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                result.evolution_summary.version_history.len().to_string(),
                Style::default().fg(scheme.accent),
            ),
            Span::raw("  "),
            Span::styled("Compliance: ", Style::default().fg(scheme.text_muted)),
            Span::styled(compliance_trend_str, Style::default().fg(compliance_color)),
            Span::raw("  "),
            Span::styled("License \u{394}: ", Style::default().fg(scheme.text_muted)),
            // evolution_summary.license_changes is never populated by the
            // engine; the real churn lives on each step's diff result.
            Span::styled(
                result
                    .incremental_diffs
                    .iter()
                    .map(|d| d.licenses.component_changes.len())
                    .sum::<usize>()
                    .to_string(),
                Style::default().fg(scheme.accent),
            ),
            {
                let conflicts: usize = result
                    .incremental_diffs
                    .iter()
                    .map(|d| d.licenses.conflicts.len())
                    .sum();
                if conflicts > 0 {
                    Span::styled(
                        format!(" ({conflicts} conflicts)"),
                        Style::default().fg(scheme.error),
                    )
                } else {
                    Span::raw("")
                }
            },
        ]),
        vuln_trend_line,
    ];

    let block = Block::default()
        .title(" Statistics [t: toggle] ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(text).block(block);
    f.render_widget(paragraph, area);
}

fn render_timeline_bar(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    use crate::tui::app::TimelineChartMetric;
    let scheme = colors();
    // Bars stay in chronological raw order (time axis); the highlights map
    // the display-space selection back to raw indices.
    let order = ordered_version_indices(result, state);
    let selected = order.get(state.selected_version).copied().unwrap_or(0);
    let compare_raw = state.compare_version.and_then(|c| order.get(c)).copied();

    // Metric series: fall back to Components when a series is missing.
    let vuln_trend = &result.evolution_summary.vulnerability_trend;
    let dep_trend = &result.evolution_summary.dependency_trend;
    let metric = match state.chart_metric {
        TimelineChartMetric::Vulnerabilities if vuln_trend.len() == result.sboms.len() => {
            TimelineChartMetric::Vulnerabilities
        }
        TimelineChartMetric::Dependencies if dep_trend.len() == result.sboms.len() => {
            TimelineChartMetric::Dependencies
        }
        _ => TimelineChartMetric::Components,
    };
    let value = |i: usize| -> u64 {
        match metric {
            TimelineChartMetric::Components => result.sboms[i].component_count as u64,
            TimelineChartMetric::Vulnerabilities => vuln_trend[i].counts.total() as u64,
            TimelineChartMetric::Dependencies => dep_trend[i].total_edges as u64,
        }
    };

    // Calculate bar width based on zoom level
    let bar_width = 5 + (u16::from(state.chart_zoom) * 2);

    // Calculate visible range based on scroll
    let visible_count = (area.width.saturating_sub(4)) / (bar_width + 1);
    let start_idx = state
        .chart_scroll
        .min(result.sboms.len().saturating_sub(visible_count as usize));
    let end_idx = (start_idx + visible_count as usize).min(result.sboms.len());

    let bars: Vec<Bar> = result
        .sboms
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(end_idx - start_idx)
        .map(|(i, sbom)| {
            let style = if i == selected {
                Style::default().fg(scheme.accent)
            } else if compare_raw == Some(i) {
                Style::default().fg(scheme.warning)
            } else {
                Style::default().fg(scheme.primary)
            };

            // Prefer the timestamp's MM-DD slice (a time axis shows time);
            // fall back to the truncated name.
            let label = sbom
                .timestamp
                .as_deref()
                .and_then(|t| t.get(5..10))
                .map_or_else(
                    || {
                        sbom.name
                            .chars()
                            .take(bar_width as usize - 1)
                            .collect::<String>()
                    },
                    ToString::to_string,
                );

            Bar::default()
                .value(value(i))
                .label(Line::from(label))
                .style(style)
        })
        .collect();

    let title = format!(
        " {} Evolution ({}-{}/{}) [m: metric, +/-: zoom, h/l: scroll] ",
        metric.label(),
        start_idx + 1,
        end_idx,
        result.sboms.len()
    );

    let barchart = BarChart::default()
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.info)),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(bar_width)
        .bar_gap(1)
        .max((0..result.sboms.len()).map(value).max().unwrap_or(100) + 10);

    f.render_widget(barchart, area);
}

/// Display order of version indices for the Versions table. Chronological is
/// the identity; the other keys use the same descending-base +
/// reverse-on-Ascending convention as `ordered_comparison_indices`. The
/// timeline BAR stays in raw chronological order (it is a time axis).
pub(crate) fn ordered_version_indices(
    result: &TimelineResult,
    state: &TimelineState,
) -> Vec<usize> {
    use crate::tui::app::{SortDirection, TimelineSortBy};

    let changes = |i: usize| -> usize {
        if i == 0 {
            0
        } else {
            result
                .incremental_diffs
                .get(i - 1)
                .map_or(0, |d| d.summary.total_changes)
        }
    };

    let mut idx: Vec<usize> = (0..result.sboms.len()).collect();
    match state.sort_by {
        // Descending base = newest-first, so the shared Ascending reverse
        // below yields oldest-first (the identity) under the default.
        TimelineSortBy::Chronological => idx.reverse(),
        TimelineSortBy::Changes => idx.sort_by_key(|b| std::cmp::Reverse(changes(*b))),
        TimelineSortBy::ComponentCount => idx.sort_by(|a, b| {
            result.sboms[*b]
                .component_count
                .cmp(&result.sboms[*a].component_count)
        }),
        TimelineSortBy::Name => {
            idx.sort_by(|a, b| result.sboms[*b].name.cmp(&result.sboms[*a].name));
        }
    }
    if matches!(state.sort_direction, SortDirection::Ascending) {
        idx.reverse();
    }
    idx
}

/// The precomputed diff for a version pair: adjacent steps use
/// `incremental_diffs`; any pair anchored at the baseline (v1) uses
/// `cumulative_from_first` (the engine writes 0->k at index k-1). Everything
/// else has no precomputed diff.
pub(crate) fn resolve_version_diff(
    result: &TimelineResult,
    raw_a: usize,
    raw_b: usize,
) -> Option<&crate::diff::DiffResult> {
    if raw_a == raw_b {
        return None;
    }
    let (lo, hi) = (raw_a.min(raw_b), raw_a.max(raw_b));
    if hi - lo == 1 {
        result.incremental_diffs.get(lo)
    } else if lo == 0 {
        result.cumulative_from_first.get(hi - 1)
    } else {
        None
    }
}

fn render_versions_list(f: &mut Frame, area: Rect, result: &TimelineResult, state: &TimelineState) {
    let scheme = colors();
    let is_active = matches!(state.active_panel, TimelinePanel::Versions);
    let selected = state.selected_version;

    let order = ordered_version_indices(result, state);
    // Date column only when the pane is wide enough (the 40% pane at 120 cols).
    let show_date = area.width >= 46;

    let rows: Vec<Row> = order
        .iter()
        .enumerate()
        .map(|(i, &raw)| {
            let sbom = &result.sboms[raw];
            // Diff info and compliance key off the RAW (chronological) index.
            let (added, removed) = if raw > 0 {
                result.incremental_diffs.get(raw - 1).map_or((0, 0), |d| {
                    (d.summary.components_added, d.summary.components_removed)
                })
            } else {
                (sbom.component_count, 0)
            };

            let is_compare_target = state.compare_version == Some(i);
            let style = if i == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else if is_compare_target {
                Style::default()
                    .bg(scheme.warning)
                    .add_modifier(Modifier::ITALIC)
            } else {
                Style::default()
            };

            // Highlight search matches
            let name_style = if state.search.matches.contains(&i) {
                style.fg(scheme.accent).add_modifier(Modifier::BOLD)
            } else {
                style
            };

            let change_str = if raw == 0 {
                "initial".to_string()
            } else {
                format!("+{added} -{removed}")
            };

            let change_color = match added.cmp(&removed) {
                std::cmp::Ordering::Greater => scheme.added,
                std::cmp::Ordering::Less => scheme.removed,
                std::cmp::Ordering::Equal => scheme.text_muted,
            };

            // CRA Phase 2 compliance indicator for this version
            let compliance_indicator = result.evolution_summary.compliance_trend.get(raw).map_or(
                ("-", scheme.text_muted),
                |snap| {
                    // Find CRA Phase 2 score
                    let cra = snap
                        .scores
                        .iter()
                        .find(|s| s.standard.contains("CRA Phase 2"));
                    match cra {
                        Some(s) if s.is_compliant && s.warning_count == 0 => ("✓", scheme.success),
                        Some(s) if s.is_compliant => ("⚠", scheme.warning),
                        Some(_) => ("✗", scheme.error),
                        None => ("-", scheme.text_muted),
                    }
                },
            );

            // True version numbers stay stable under sort: show raw + 1.
            let mut cells = vec![
                Cell::from(format!("{}.", raw + 1)).style(style),
                Cell::from(sbom.name.clone()).style(name_style),
            ];
            if show_date {
                let date = sbom
                    .timestamp
                    .as_deref()
                    .and_then(|t| t.get(..10))
                    .unwrap_or("-")
                    .to_string();
                cells.push(Cell::from(date).style(style.fg(scheme.text_muted)));
            }
            cells.extend([
                Cell::from(sbom.component_count.to_string()).style(style),
                Cell::from(change_str).style(style.fg(change_color)),
                Cell::from(compliance_indicator.0).style(style.fg(compliance_indicator.1)),
            ]);
            Row::new(cells)
        })
        .collect();

    let header_cells: Vec<&str> = if show_date {
        vec!["#", "Version", "Date", "Comps", "Changes", "CRA"]
    } else {
        vec!["#", "Version", "Comps", "Changes", "CRA"]
    };
    let header = Row::new(header_cells)
        .style(
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let widths: Vec<Constraint> = if show_date {
        vec![
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(4),
        ]
    } else {
        vec![
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(4),
        ]
    };

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };
    let title = " Versions [g: jump, d: diff] ".to_string();

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(table, area);
}

/// The Components panel's display list: added+removed evolutions tagged with
/// `is_removed`, filtered by the active component filter.
///
/// Single source of truth for every consumer that resolves
/// `selected_component` — the panel render, the history modal, and the
/// event-side name lookup — so a filtered display can never desync from the
/// selection index again.
pub(crate) fn filtered_evolution_entries(
    result: &TimelineResult,
    filter: TimelineComponentFilter,
) -> Vec<(&crate::diff::ComponentEvolution, bool)> {
    result
        .evolution_summary
        .components_added
        .iter()
        .map(|e| (e, false)) // (evolution, is_removed)
        .chain(
            result
                .evolution_summary
                .components_removed
                .iter()
                .map(|e| (e, true)),
        )
        .filter(|(evo, is_removed)| match filter {
            TimelineComponentFilter::All => true,
            TimelineComponentFilter::Added => !*is_removed,
            TimelineComponentFilter::Removed => *is_removed,
            TimelineComponentFilter::VersionChanged => {
                evo.current_version.as_ref() != Some(&evo.first_seen_version)
            }
            TimelineComponentFilter::Stable => {
                !*is_removed && evo.current_version.as_ref() == Some(&evo.first_seen_version)
            }
        })
        .collect()
}

fn render_component_history(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
) {
    let scheme = colors();
    let is_active = matches!(state.active_panel, TimelinePanel::Components);
    let selected = state.selected_component;

    let filtered_evolutions = filtered_evolution_entries(result, state.component_filter);
    if filtered_evolutions.is_empty() {
        crate::tui::widgets::render_no_results_state(
            f,
            area,
            "Filter",
            state.component_filter.label(),
        );
        return;
    }

    // Window around the selection sized to the REAL panel height (borders +
    // table header + spacing = 4 rows of chrome): with the selection bounds
    // now populated, the cursor can travel past the fold and must stay
    // visible at any terminal size.
    let visible_rows = (area.height.saturating_sub(4) as usize).max(1);
    let window_start = selected.saturating_sub(visible_rows - 1);
    let rows: Vec<Row> = filtered_evolutions
        .iter()
        .enumerate()
        .skip(window_start)
        .take(visible_rows)
        .map(|(i, (evo, is_removed))| {
            let style = if i == selected {
                Style::default()
                    .bg(scheme.selection)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let status_style = if *is_removed {
                Style::default().fg(scheme.removed)
            } else {
                Style::default().fg(scheme.added)
            };

            let status = if *is_removed { "Removed" } else { "Added" };
            let version_info = if *is_removed {
                format!("{} @ v{}", evo.first_seen_version, evo.first_seen_index + 1)
            } else {
                evo.current_version
                    .clone()
                    .unwrap_or_else(|| evo.first_seen_version.clone())
            };

            Row::new(vec![
                Cell::from(evo.name.clone()).style(style),
                Cell::from(version_info).style(style),
                Cell::from(format!("v{}", evo.first_seen_index + 1)).style(style),
                Cell::from(status).style(status_style),
            ])
        })
        .collect();

    let header = Row::new(vec!["Component", "Version", "Since", "Status"])
        .style(
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1);

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(25),
        Constraint::Percentage(15),
        Constraint::Percentage(20),
    ];

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };

    let unfiltered_total = result.evolution_summary.components_added.len()
        + result.evolution_summary.components_removed.len();
    let title = format!(
        " Component Evolution ({}/{}) [f: filter, Enter: detail] ",
        filtered_evolutions.len(),
        unfiltered_total
    );

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_widget(table, area);
}

fn render_status_bar(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    _state: &TimelineState,
    status: Option<&str>,
) {
    let scheme = colors();
    let total_added: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_added)
        .sum();
    let total_removed: usize = result
        .incremental_diffs
        .iter()
        .map(|d| d.summary.components_removed)
        .sum();

    let mut spans = vec![
        Span::styled("Added: ", Style::default().fg(scheme.text_muted)),
        Span::styled(total_added.to_string(), Style::default().fg(scheme.added)),
        Span::raw("  "),
        Span::styled("Removed: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            total_removed.to_string(),
            Style::default().fg(scheme.removed),
        ),
        Span::raw("  \u{2502}  "),
    ];
    crate::tui::views::matrix_status_tail(&mut spans, area, status, "timeline");

    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(paragraph, area);
}

/// Render version diff modal
fn render_version_diff_modal(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
) {
    let scheme = colors();

    // Modal area
    let modal_width = area.width * 80 / 100;
    let modal_height = area.height * 70 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    // selected/compare are display indices; resolve to raw chronological
    // versions, then orient low -> high so added/removed match the
    // precomputed diff's direction regardless of which endpoint is selected.
    let order = ordered_version_indices(result, state);
    let raw_sel = order.get(state.selected_version).copied().unwrap_or(0);
    let raw_cmp = order
        .get(state.compare_version.unwrap_or(0))
        .copied()
        .unwrap_or(0);
    let (raw_a, raw_b) = (raw_sel.min(raw_cmp), raw_sel.max(raw_cmp));

    let sbom_a = result.sboms.get(raw_a);
    let sbom_b = result.sboms.get(raw_b);

    let (name_a, name_b) = match (sbom_a, sbom_b) {
        (Some(a), Some(b)) => (a.name.clone(), b.name.clone()),
        _ => return,
    };

    let diff_info = resolve_version_diff(result, raw_a, raw_b);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Comparing: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &name_a,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" \u{2192} "),
            Span::styled(
                &name_b,
                Style::default()
                    .fg(scheme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "  (chronological order)",
                Style::default().fg(scheme.text_muted),
            ),
        ]),
        Line::from(""),
    ];

    if let (Some(a), Some(b)) = (sbom_a, sbom_b) {
        lines.push(Line::from(vec![
            Span::styled("Components: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                a.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw(" vs "),
            Span::styled(
                b.component_count.to_string(),
                Style::default().fg(scheme.warning),
            ),
        ]));
    }

    lines.push(Line::from(""));
    if let Some(diff) = diff_info {
        lines.push(Line::from(vec![Span::styled(
            "Changes:",
            Style::default().fg(scheme.text_muted),
        )]));
        lines.push(Line::from(vec![
            Span::styled("  + Added: ", Style::default().fg(scheme.added)),
            Span::raw(diff.summary.components_added.to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  - Removed: ", Style::default().fg(scheme.removed)),
            Span::raw(diff.summary.components_removed.to_string()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  ~ Modified: ", Style::default().fg(scheme.modified)),
            Span::raw(diff.summary.components_modified.to_string()),
        ]));

        // Show some added components
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Added Components:",
            Style::default().fg(scheme.added),
        )]));
        for comp in diff.components.added.iter().take(5) {
            lines.push(Line::from(vec![
                Span::raw("  + "),
                Span::styled(&comp.name, Style::default().fg(scheme.text)),
            ]));
        }

        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Removed Components:",
            Style::default().fg(scheme.removed),
        )]));
        for comp in diff.components.removed.iter().take(5) {
            lines.push(Line::from(vec![
                Span::raw("  - "),
                Span::styled(&comp.name, Style::default().fg(scheme.text)),
            ]));
        }
    } else {
        lines.push(Line::from(vec![Span::styled(
            "No precomputed diff between these versions.",
            Style::default().fg(scheme.text_muted),
        )]));
        lines.push(Line::from(vec![Span::styled(
            "Only adjacent-step and baseline (v1 \u{2192} vN) diffs are precomputed.",
            Style::default().fg(scheme.text_muted),
        )]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("←/→", Style::default().fg(scheme.primary)),
        Span::raw(": change compare version  "),
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Version Diff: {name_a} ↔ {name_b} "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render component history modal
fn render_component_history_modal(
    f: &mut Frame,
    area: Rect,
    result: &TimelineResult,
    state: &TimelineState,
) {
    let scheme = colors();

    let modal_width = area.width * 75 / 100;
    let modal_height = area.height * 60 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    // Resolve the selection through the SAME filtered list the Components
    // panel displays (the unfiltered list opened the wrong component's
    // history whenever a filter was active).
    let entries = filtered_evolution_entries(result, state.component_filter);
    let evo = match entries.get(state.selected_component) {
        Some((e, _)) => *e,
        None => return,
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Component: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &evo.name,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("First Seen: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("v{} ({})", evo.first_seen_index + 1, evo.first_seen_version),
                Style::default().fg(scheme.accent),
            ),
        ]),
    ];

    if let Some(current) = &evo.current_version {
        lines.push(Line::from(vec![
            Span::styled("Current Version: ", Style::default().fg(scheme.text_muted)),
            Span::styled(current, Style::default().fg(scheme.added)),
        ]));
    }

    if let Some(last_seen) = evo.last_seen_index {
        lines.push(Line::from(vec![
            Span::styled("Last Seen: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("v{}", last_seen + 1),
                Style::default().fg(scheme.removed),
            ),
        ]));
    }

    // Show version history if available. The map is keyed by component ID
    // (purl-based canonical id), not display name — the name lookup only
    // worked for components whose id happens to equal their name.
    if let Some(history) = result.evolution_summary.version_history.get(&evo.id) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Version History:",
            Style::default().fg(scheme.text_muted),
        )]));

        for point in history.iter().take(10) {
            let change_style = match point.change_type {
                VersionChangeType::Initial => Style::default().fg(scheme.info),
                VersionChangeType::MajorUpgrade => Style::default().fg(scheme.critical),
                VersionChangeType::MinorUpgrade => Style::default().fg(scheme.added),
                VersionChangeType::PatchUpgrade => Style::default().fg(scheme.primary),
                VersionChangeType::Downgrade => Style::default().fg(scheme.removed),
                VersionChangeType::Changed => Style::default().fg(scheme.warning),
                VersionChangeType::Unchanged => Style::default().fg(scheme.text_muted),
                VersionChangeType::Removed | VersionChangeType::Absent => {
                    Style::default().fg(scheme.muted)
                }
            };

            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(&point.sbom_name, Style::default().fg(scheme.text)),
                Span::raw(": "),
                Span::styled(
                    point.version.as_deref().unwrap_or("-"),
                    Style::default().fg(scheme.accent),
                ),
                Span::raw(" "),
                Span::styled(point.change_type.symbol(), change_style),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Component: {} ", evo.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render search overlay
fn render_search_overlay(f: &mut Frame, area: Rect, state: &TimelineState) {
    crate::tui::views::render_multi_search_bar(f, area, "Search: ", &state.search);
}

/// Render jump overlay
fn render_jump_overlay(f: &mut Frame, area: Rect, state: &TimelineState) {
    let scheme = colors();

    let jump_area = Rect::new(area.x, area.height - 3, area.width, 3);
    f.render_widget(Clear, jump_area);

    let jump_text = Line::from(vec![
        Span::styled("Jump to version: ", Style::default().fg(scheme.text_muted)),
        Span::styled(&state.jump_input, Style::default().fg(scheme.text)),
        Span::styled("│", Style::default().fg(scheme.accent)),
        Span::raw("  "),
        Span::styled(
            format!("(1-{})", state.total_versions),
            Style::default().fg(scheme.text_muted),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.warning))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(jump_text).block(block);
    f.render_widget(paragraph, jump_area);
}

/// Panels in the timeline view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelinePanel {
    Versions,
    Components,
}
