//! Matrix comparison view.
//!
//! Displays N×N SBOM comparison with similarity heatmap.

use crate::diff::MatrixResult;
use crate::tui::app::MatrixState;
use crate::tui::theme::colors;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
};

/// Render the matrix comparison view
pub fn render_matrix(
    f: &mut Frame,
    area: Rect,
    result: &MatrixResult,
    state: &MatrixState,
    status: Option<&str>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(15),   // Main content
            Constraint::Length(8), // Clustering info
            Constraint::Length(3), // Status bar
        ])
        .split(area);

    // Header with filter/sort info
    render_header(f, chunks[0], result, state);

    // Main content - matrix and details
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(chunks[1]);

    render_similarity_matrix(f, main_chunks[0], result, state);
    render_pair_details(f, main_chunks[1], result, state);

    // Clustering info
    render_clustering(f, chunks[2], result, state);

    // Status bar
    render_status_bar(f, chunks[3], result, state, status);

    // Render overlays
    if state.show_pair_diff {
        render_pair_diff_modal(f, area, result, state);
    }

    if state.show_export_options {
        render_export_modal(f, area);
    }

    if state.show_clustering_details {
        render_clustering_detail_modal(f, area, result, state);
    }

    if state.search.active {
        render_search_overlay(f, area, state);
    }
}

fn render_header(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let title = format!(
        " Matrix: {}×{} SBOMs ({} pairs) ",
        result.sboms.len(),
        result.sboms.len(),
        result.num_pairs()
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
        Span::styled("Threshold: ", Style::default().fg(scheme.text_muted)),
        Span::styled(state.threshold.label(), Style::default().fg(scheme.accent)),
        if state.focus_mode {
            Span::styled(" │ Focus Mode", Style::default().fg(scheme.warning))
        } else {
            Span::raw("")
        },
        if state.highlight_row_col {
            Span::styled(" │ Highlight", Style::default().fg(scheme.info))
        } else {
            Span::raw("")
        },
    ])];

    let header = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

/// Display order of SBOM indices for BOTH matrix axes (the matrix stays
/// symmetric: one permutation applied to rows and columns). Same
/// descending-base + reverse-on-Ascending convention as
/// `ordered_comparison_indices`. Cluster sort concatenates cluster members in
/// order, then outliers, producing the block-diagonal heatmap; it is the
/// identity when no clustering was computed.
pub(crate) fn ordered_sbom_indices(result: &MatrixResult, state: &MatrixState) -> Vec<usize> {
    use crate::tui::app::{MatrixSortBy, SortDirection};

    let n = result.sboms.len();
    let avg = |i: usize| -> f64 {
        if n <= 1 {
            return 0.0;
        }
        (0..n)
            .filter(|&j| j != i)
            .map(|j| result.get_similarity(i, j))
            .sum::<f64>()
            / (n - 1) as f64
    };

    let mut idx: Vec<usize> = (0..n).collect();
    match state.sort_by {
        MatrixSortBy::Name => {
            idx.sort_by(|a, b| result.sboms[*b].name.cmp(&result.sboms[*a].name));
        }
        MatrixSortBy::AvgSimilarity => {
            idx.sort_by(|a, b| {
                avg(*b)
                    .partial_cmp(&avg(*a))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        MatrixSortBy::ComponentCount => {
            idx.sort_by(|a, b| {
                result.sboms[*b]
                    .component_count
                    .cmp(&result.sboms[*a].component_count)
            });
        }
        MatrixSortBy::Cluster => {
            if let Some(clustering) = &result.clustering {
                let mut ordered: Vec<usize> = clustering
                    .clusters
                    .iter()
                    .flat_map(|c| c.members.iter().copied())
                    .chain(clustering.outliers.iter().copied())
                    .filter(|&i| i < n)
                    .collect();
                // Guard against engine results that omit an index.
                let mut seen = vec![false; n];
                ordered.retain(|&i| !std::mem::replace(&mut seen[i], true));
                ordered.extend((0..n).filter(|&i| !seen[i]));
                idx = ordered;
            }
        }
    }

    if matches!(state.sort_direction, SortDirection::Ascending) {
        idx.reverse();
    }
    idx
}

fn render_similarity_matrix(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    if result.sboms.len() < 2 {
        crate::tui::widgets::render_empty_state_enhanced(
            f,
            area,
            "\u{2205}",
            "Need at least 2 SBOMs for a matrix comparison",
            None,
            None,
        );
        return;
    }
    let scheme = colors();
    let is_active = matches!(state.active_panel, MatrixPanel::Matrix);
    // selected_row/selected_col/focus_row/focus_col are DISPLAY indices; the
    // permutation maps display -> raw SBOM index for data lookups.
    let order = ordered_sbom_indices(result, state);
    let n = order.len();
    let selected_row = state.selected_row;
    let selected_col = state.selected_col;

    // Stateless column viewport: keep the selected column visible.
    let name_width: u16 = 9;
    let cell_width: u16 = 6;
    let cols_fit =
        usize::from((area.width.saturating_sub(2 + name_width)) / (cell_width + 1)).max(1);
    let col_offset = selected_col.saturating_sub(cols_fit - 1);
    let col_end = (col_offset + cols_fit).min(n);

    // Header row with SBOM names (display order, viewport window)
    let mut header_cells = vec![Cell::from("").style(Style::default().fg(scheme.primary))];
    for (j, &raw_j) in order.iter().enumerate().take(col_end).skip(col_offset) {
        let name: String = result.sboms[raw_j]
            .name
            .chars()
            .take(cell_width as usize)
            .collect();
        let header_style = if state.highlight_row_col && j == selected_col {
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD)
        } else if state.search.matches.contains(&j) {
            Style::default()
                .fg(scheme.warning)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(scheme.primary)
        };
        header_cells.push(Cell::from(name).style(header_style));
    }
    let header = Row::new(header_cells).bottom_margin(1);

    // Matrix rows in display order
    let rows: Vec<Row> = (0..n)
        .filter(|i| {
            if state.focus_mode
                && let Some(focus_row) = state.focus_row
                && state.focus_col.is_none()
            {
                return *i == focus_row;
            }
            true
        })
        .map(|i| {
            let raw_i = order[i];
            let row_sbom = &result.sboms[raw_i];
            let row_name: String = row_sbom.name.chars().take(8).collect();

            let row_name_style = if state.highlight_row_col && i == selected_row {
                Style::default()
                    .fg(scheme.accent)
                    .add_modifier(Modifier::BOLD)
            } else if state.search.matches.contains(&i) {
                Style::default()
                    .fg(scheme.warning)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(scheme.text)
                    .add_modifier(Modifier::BOLD)
            };

            let mut cells = vec![Cell::from(row_name).style(row_name_style)];

            for (j, &raw_j) in order.iter().enumerate().take(col_end).skip(col_offset) {
                let similarity = result.get_similarity(raw_i, raw_j);
                let is_selected = i == selected_row && j == selected_col;
                let is_in_selected_row_or_col =
                    state.highlight_row_col && (i == selected_row || j == selected_col);
                let passes_threshold = state.passes_threshold(similarity);

                // Column focus: dim every cell outside the focused column
                // (except the focused row's cells, so the cross stays readable).
                let focus_dimmed = state.focus_mode
                    && state.focus_col.is_some_and(|fc| j != fc)
                    && state.focus_row.is_none_or(|fr| i != fr);

                let is_diagonal = raw_i == raw_j;
                let cell_style = if is_selected {
                    Style::default()
                        .bg(scheme.accent)
                        .fg(scheme.badge_fg_dark)
                        .add_modifier(Modifier::BOLD)
                } else if is_diagonal || focus_dimmed || !passes_threshold {
                    Style::default().fg(scheme.muted)
                } else if is_in_selected_row_or_col {
                    let bg = similarity_to_color(similarity);
                    Style::default()
                        .bg(bg)
                        .fg(scheme.badge_fg_for(bg))
                        .add_modifier(Modifier::UNDERLINED)
                } else {
                    // Heatmap: bg carries the similarity; the % digits stay
                    // the non-color magnitude cue.
                    let bg = similarity_to_color(similarity);
                    Style::default().bg(bg).fg(scheme.badge_fg_for(bg))
                };

                let cell_text = if is_diagonal {
                    " - ".to_string()
                } else if focus_dimmed
                    || (!passes_threshold && !is_selected && !is_in_selected_row_or_col)
                {
                    "  ·  ".to_string()
                } else {
                    format!("{:.0}%", similarity * 100.0)
                };

                cells.push(Cell::from(cell_text).style(cell_style));
            }

            Row::new(cells)
        })
        .collect();

    let mut constraints = vec![Constraint::Length(name_width)];
    for _ in col_offset..col_end {
        constraints.push(Constraint::Length(cell_width));
    }

    let border_color = if is_active {
        scheme.accent
    } else {
        scheme.text
    };
    let title = if n > cols_fit {
        format!(
            " Similarity Matrix ({}-{}/{}) [z: focus, r: row, c: col, Enter: diff] ",
            col_offset + 1,
            col_end,
            n
        )
    } else {
        " Similarity Matrix [z: focus, r: row, c: col, Enter: diff] ".to_string()
    };

    let table = Table::new(rows, constraints).header(header).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    f.render_widget(table, area);
}

fn render_pair_details(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let order = ordered_sbom_indices(result, state);
    let (Some(&row), Some(&col)) = (order.get(state.selected_row), order.get(state.selected_col))
    else {
        // Degenerate selection: keep the chrome instead of a borderless void.
        let block = Block::default()
            .title(" Pair Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(scheme.info));
        let placeholder = Paragraph::new(Line::from(Span::styled(
            "No pair selected",
            Style::default().fg(scheme.text_muted),
        )))
        .block(block);
        f.render_widget(placeholder, area);
        return;
    };

    let (sbom_a, sbom_b) = (&result.sboms[row], &result.sboms[col]);
    let similarity = result.get_similarity(row, col);

    let mut text = vec![
        Line::from(vec![Span::styled(
            "Comparing: ",
            Style::default().fg(scheme.text_muted),
        )]),
        Line::from(vec![
            Span::styled(&sbom_a.name, Style::default().fg(scheme.primary)),
            Span::raw(" ↔ "),
            Span::styled(&sbom_b.name, Style::default().fg(scheme.primary)),
        ]),
        Line::from(""),
    ];

    if row == col {
        text.push(Line::from(vec![Span::styled(
            "(Same SBOM)",
            Style::default().fg(scheme.text_muted),
        )]));
    } else {
        text.extend(vec![
            Line::from(vec![
                Span::styled("Similarity: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("{:.1}%", similarity * 100.0),
                    Style::default()
                        .fg(similarity_to_color(similarity))
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(&sbom_a.name, Style::default().fg(scheme.text)),
                Span::raw(": "),
                Span::styled(
                    sbom_a.component_count.to_string(),
                    Style::default().fg(scheme.primary),
                ),
                Span::raw(" components"),
            ]),
            Line::from(vec![
                Span::styled(&sbom_b.name, Style::default().fg(scheme.text)),
                Span::raw(": "),
                Span::styled(
                    sbom_b.component_count.to_string(),
                    Style::default().fg(scheme.primary),
                ),
                Span::raw(" components"),
            ]),
        ]);

        // Show diff details if available
        if let Some(diff) = result.get_diff(row, col) {
            text.extend(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Changes:",
                    Style::default().fg(scheme.text_muted),
                )]),
                Line::from(vec![
                    Span::styled(" + Added: ", Style::default().fg(scheme.added)),
                    Span::raw(diff.summary.components_added.to_string()),
                ]),
                Line::from(vec![
                    Span::styled(" - Removed: ", Style::default().fg(scheme.removed)),
                    Span::raw(diff.summary.components_removed.to_string()),
                ]),
                Line::from(vec![
                    Span::styled(" ~ Modified: ", Style::default().fg(scheme.accent)),
                    Span::raw(diff.summary.components_modified.to_string()),
                ]),
            ]);
        }

        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("Press ", Style::default().fg(scheme.text_muted)),
            Span::styled("Enter", Style::default().fg(scheme.primary)),
            Span::styled(" for detailed diff", Style::default().fg(scheme.text_muted)),
        ]));
    }

    let block = Block::default()
        .title(" Pair Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.info));

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn render_clustering(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();
    let text = result.clustering.as_ref().map_or_else(
        || {
            vec![Line::from(vec![Span::styled(
                "No clustering computed",
                Style::default().fg(scheme.text_muted),
            )])]
        },
        |clustering| {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Algorithm: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(&clustering.algorithm, Style::default().fg(scheme.text)),
                    Span::raw("  "),
                    Span::styled("Threshold: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        format!("{:.0}%", clustering.threshold * 100.0),
                        Style::default().fg(scheme.primary),
                    ),
                ]),
                Line::from(""),
            ];

            // Show clusters with selection highlighting
            for (i, cluster) in clustering.clusters.iter().enumerate() {
                let members: Vec<String> = cluster
                    .members
                    .iter()
                    .filter_map(|&idx| result.sboms.get(idx))
                    .map(|s| s.name.clone())
                    .collect();

                let cluster_label = cluster
                    .label
                    .clone()
                    .unwrap_or_else(|| format!("Cluster {}", i + 1));
                let is_selected = i == state.selected_cluster;

                let label_style = if is_selected {
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(scheme.critical)
                        .add_modifier(Modifier::BOLD)
                };

                lines.push(Line::from(vec![
                    Span::styled(format!("{cluster_label}: "), label_style),
                    Span::styled(members.join(", "), Style::default().fg(scheme.text)),
                    Span::raw(" "),
                    Span::styled(
                        format!("({:.0}% similarity)", cluster.internal_similarity * 100.0),
                        Style::default().fg(scheme.text_muted),
                    ),
                ]));
            }

            // Show outliers
            if !clustering.outliers.is_empty() {
                let outliers: Vec<String> = clustering
                    .outliers
                    .iter()
                    .filter_map(|&idx| result.sboms.get(idx))
                    .map(|s| s.name.clone())
                    .collect();

                lines.push(Line::from(vec![
                    Span::styled("Outliers: ", Style::default().fg(scheme.removed)),
                    Span::styled(outliers.join(", "), Style::default().fg(scheme.text)),
                ]));
            }

            lines
        },
    );

    let block = Block::default()
        .title(format!(
            " Clustering ({} clusters) [C: details] ",
            result.clustering.as_ref().map_or(0, |c| c.clusters.len())
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.critical));

    let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn render_status_bar(
    f: &mut Frame,
    area: Rect,
    result: &MatrixResult,
    _state: &MatrixState,
    status: Option<&str>,
) {
    let scheme = colors();
    // Calculate average similarity
    let total_pairs = result.num_pairs();
    let avg_similarity: f64 = if total_pairs > 0 {
        result.similarity_scores.iter().sum::<f64>() / total_pairs as f64
    } else {
        0.0
    };

    let mut spans = vec![
        Span::styled("Pairs: ", Style::default().fg(scheme.text_muted)),
        Span::styled(total_pairs.to_string(), Style::default().fg(scheme.primary)),
        Span::raw("  "),
        Span::styled("Avg: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{:.0}%", avg_similarity * 100.0),
            Style::default().fg(similarity_to_color(avg_similarity)),
        ),
        Span::raw("  \u{2502}  "),
    ];
    extend_with_status_or_hints(&mut spans, area, status, "matrix");

    let block = Block::default().borders(Borders::ALL);
    let paragraph = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(paragraph, area);
}

/// Shared status-bar tail for the multi modes: the pending status message
/// (previously computed by every handler and silently dropped) or the shared
/// footer hints, width-fitted after the count spans.
pub(crate) fn extend_with_status_or_hints(
    spans: &mut Vec<Span<'static>>,
    area: Rect,
    status: Option<&str>,
    mode: &str,
) {
    let scheme = colors();
    if let Some(msg) = status {
        spans.push(Span::styled(
            "\u{2139} ",
            Style::default().fg(scheme.accent),
        ));
        spans.push(Span::styled(
            msg.to_string(),
            Style::default().fg(scheme.accent).bold(),
        ));
        return;
    }
    let hints = crate::tui::theme::FooterHints::for_multi_mode(mode);
    let counts_width = Line::from(spans.clone()).width() as u16;
    let budget = area
        .width
        .saturating_sub(2) // borders
        .saturating_sub(counts_width);
    let (mut kept, mut elided) = crate::tui::theme::fit_footer_hints(&hints, budget);
    // fit_footer_hints never drops the global tail; on narrow status bars
    // with wide counts (multi dashboard at 80 cols) even the globals
    // overflow — degrade from the FRONT so "K keys" and "q quit" survive
    // instead of being clipped mid-word by the border.
    while kept.len() > 1 && crate::tui::theme::footer_hints_width(&kept) > budget {
        kept.remove(0);
        elided = true;
    }
    spans.extend(crate::tui::theme::render_footer_hints(&kept, elided));
}

/// Render pair diff modal
fn render_pair_diff_modal(f: &mut Frame, area: Rect, result: &MatrixResult, state: &MatrixState) {
    let scheme = colors();

    let modal_width = area.width * 80 / 100;
    let modal_height = area.height * 70 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let order = ordered_sbom_indices(result, state);
    let (Some(&row), Some(&col)) = (order.get(state.selected_row), order.get(state.selected_col))
    else {
        return;
    };

    let (Some(sbom_a), Some(sbom_b)) = (result.sboms.get(row), result.sboms.get(col)) else {
        return;
    };

    let similarity = result.get_similarity(row, col);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Comparing: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                &sbom_a.name,
                Style::default()
                    .fg(scheme.primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" ↔ "),
            Span::styled(
                &sbom_b.name,
                Style::default()
                    .fg(scheme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Similarity: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.1}%", similarity * 100.0),
                Style::default()
                    .fg(similarity_to_color(similarity))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(&sbom_a.name, Style::default().fg(scheme.text)),
            Span::raw(": "),
            Span::styled(
                sbom_a.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw(" components"),
        ]),
        Line::from(vec![
            Span::styled(&sbom_b.name, Style::default().fg(scheme.text)),
            Span::raw(": "),
            Span::styled(
                sbom_b.component_count.to_string(),
                Style::default().fg(scheme.primary),
            ),
            Span::raw(" components"),
        ]),
    ];

    if let Some(diff) = result.get_diff(row, col) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Detailed Changes:",
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

        // Vulnerability impact
        if diff.summary.vulnerabilities_introduced > 0 || diff.summary.vulnerabilities_resolved > 0
        {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Vulnerabilities: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("+{}", diff.summary.vulnerabilities_introduced),
                    Style::default().fg(scheme.removed),
                ),
                Span::raw(" introduced, "),
                Span::styled(
                    format!("-{}", diff.summary.vulnerabilities_resolved),
                    Style::default().fg(scheme.added),
                ),
                Span::raw(" resolved"),
            ]));
        }

        // Show sample components
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Added Components:",
            Style::default().fg(scheme.added),
        )]));
        for comp in diff.components.added.iter().take(5) {
            lines.push(Line::from(vec![
                Span::raw("  + "),
                Span::styled(&comp.name, Style::default().fg(scheme.text)),
                Span::raw(" "),
                Span::styled(
                    comp.new_version.as_deref().unwrap_or(""),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
        }
        if diff.components.added.len() > 5 {
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more", diff.components.added.len() - 5),
                Style::default().fg(scheme.text_muted),
            )]));
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
                Span::raw(" "),
                Span::styled(
                    comp.old_version.as_deref().unwrap_or(""),
                    Style::default().fg(scheme.text_muted),
                ),
            ]));
        }
        if diff.components.removed.len() > 5 {
            lines.push(Line::from(vec![Span::styled(
                format!("  ... and {} more", diff.components.removed.len() - 5),
                Style::default().fg(scheme.text_muted),
            )]));
        }

        // Show modified components (version changes)
        if !diff.components.modified.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "Modified Components:",
                Style::default().fg(scheme.modified),
            )]));
            for comp in diff.components.modified.iter().take(5) {
                let version_change = match (&comp.old_version, &comp.new_version) {
                    (Some(old), Some(new)) => format!("{old} \u{2192} {new}"),
                    (None, Some(new)) => format!("? \u{2192} {new}"),
                    (Some(old), None) => format!("{old} \u{2192} ?"),
                    (None, None) => "(changed)".to_string(),
                };
                lines.push(Line::from(vec![
                    Span::raw("  ~ "),
                    Span::styled(&comp.name, Style::default().fg(scheme.text)),
                    Span::raw(" "),
                    Span::styled(version_change, Style::default().fg(scheme.accent)),
                ]));
            }
            if diff.components.modified.len() > 5 {
                lines.push(Line::from(vec![Span::styled(
                    format!("  ... and {} more", diff.components.modified.len() - 5),
                    Style::default().fg(scheme.text_muted),
                )]));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(format!(" Diff: {} \u{2194} {} ", sbom_a.name, sbom_b.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render export modal
fn render_export_modal(f: &mut Frame, area: Rect) {
    let scheme = colors();

    let modal_width = 40;
    let modal_height = 12;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let lines = vec![
        Line::from(vec![Span::styled(
            "Export Matrix As:",
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("c", Style::default().fg(scheme.accent)),
            Span::raw(" - CSV (comma-separated)"),
        ]),
        Line::from(vec![
            Span::styled("j", Style::default().fg(scheme.accent)),
            Span::raw(" - JSON"),
        ]),
        Line::from(vec![
            Span::styled("h", Style::default().fg(scheme.accent)),
            Span::raw(" - HTML (visual heatmap)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Esc", Style::default().fg(scheme.primary)),
            Span::raw(": cancel"),
        ]),
    ];

    let block = Block::default()
        .title(" Export Matrix ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.warning))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, modal_area);
}

/// Render clustering detail modal
fn render_clustering_detail_modal(
    f: &mut Frame,
    area: Rect,
    result: &MatrixResult,
    state: &MatrixState,
) {
    let scheme = colors();

    let modal_width = area.width * 70 / 100;
    let modal_height = area.height * 60 / 100;
    let modal_x = (area.width - modal_width) / 2;
    let modal_y = (area.height - modal_height) / 2;
    let modal_area = Rect::new(modal_x, modal_y, modal_width, modal_height);

    f.render_widget(Clear, modal_area);

    let mut lines = vec![
        Line::from(vec![Span::styled(
            "Clustering Details",
            Style::default()
                .fg(scheme.primary)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

    if let Some(ref clustering) = result.clustering {
        lines.push(Line::from(vec![
            Span::styled("Algorithm: ", Style::default().fg(scheme.text_muted)),
            Span::styled(&clustering.algorithm, Style::default().fg(scheme.text)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Threshold: ", Style::default().fg(scheme.text_muted)),
            Span::styled(
                format!("{:.0}%", clustering.threshold * 100.0),
                Style::default().fg(scheme.primary),
            ),
        ]));
        lines.push(Line::from(""));

        for (i, cluster) in clustering.clusters.iter().enumerate() {
            let is_selected = i == state.selected_cluster;
            let style = if is_selected {
                Style::default()
                    .fg(scheme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(scheme.text)
            };

            let label = cluster
                .label
                .clone()
                .unwrap_or_else(|| format!("Cluster {}", i + 1));
            lines.push(Line::from(vec![Span::styled(format!("{label}:"), style)]));
            lines.push(Line::from(vec![
                Span::styled("  Similarity: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("{:.1}%", cluster.internal_similarity * 100.0),
                    Style::default().fg(similarity_to_color(cluster.internal_similarity)),
                ),
            ]));
            lines.push(Line::from(vec![Span::styled(
                "  Members: ",
                Style::default().fg(scheme.text_muted),
            )]));

            for &member_idx in &cluster.members {
                if let Some(sbom) = result.sboms.get(member_idx) {
                    lines.push(Line::from(vec![
                        Span::raw("    • "),
                        Span::styled(&sbom.name, Style::default().fg(scheme.text)),
                    ]));
                }
            }
            lines.push(Line::from(""));
        }

        if !clustering.outliers.is_empty() {
            lines.push(Line::from(vec![Span::styled(
                "Outliers:",
                Style::default().fg(scheme.removed),
            )]));
            for &outlier_idx in &clustering.outliers {
                if let Some(sbom) = result.sboms.get(outlier_idx) {
                    lines.push(Line::from(vec![
                        Span::raw("  • "),
                        Span::styled(&sbom.name, Style::default().fg(scheme.text)),
                    ]));
                }
            }
        }
    } else {
        lines.push(Line::from(vec![Span::styled(
            "No clustering data available.",
            Style::default().fg(scheme.text_muted),
        )]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("j/k", Style::default().fg(scheme.primary)),
        Span::raw(": navigate clusters  "),
        Span::styled("Esc", Style::default().fg(scheme.primary)),
        Span::raw(": close"),
    ]));

    let block = Block::default()
        .title(" Clustering Details ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.critical))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, modal_area);
}

/// Render search overlay
fn render_search_overlay(f: &mut Frame, area: Rect, state: &MatrixState) {
    render_multi_search_bar(f, area, "Search SBOM: ", &state.search);
}

/// Shared bottom search bar for the multi modes: query + mode badge +
/// match position + the unified [^R]/[n/N] hints, plus regex errors.
pub(crate) fn render_multi_search_bar(
    f: &mut Frame,
    area: Rect,
    label: &str,
    search: &crate::tui::app::MultiViewSearchState,
) {
    let scheme = colors();

    let search_area = Rect::new(area.x, area.height - 3, area.width, 3);
    f.render_widget(Clear, search_area);

    let mode_label = match search.mode {
        crate::tui::app_states::SearchMode::Substring => "[substring]",
        crate::tui::app_states::SearchMode::Regex => "[regex]",
    };
    let mut spans = vec![
        Span::styled(label.to_string(), Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!("{mode_label} "),
            Style::default().fg(scheme.text_muted),
        ),
        Span::styled(search.query.clone(), Style::default().fg(scheme.text)),
        Span::styled("\u{2502}", Style::default().fg(scheme.accent)),
        Span::raw("  "),
        Span::styled(
            search.match_position(),
            Style::default().fg(scheme.text_muted),
        ),
    ];
    if let Some(err) = &search.error {
        spans.push(Span::styled(
            format!("  {err}"),
            Style::default().fg(scheme.error),
        ));
    } else {
        spans.push(Span::styled(
            "  [^R] regex  [n/N] match",
            Style::default().fg(scheme.text_muted),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.muted));

    let paragraph = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(paragraph, search_area);
}

/// Convert similarity score to color
fn similarity_to_color(similarity: f64) -> Color {
    if similarity >= 0.9 {
        colors().added
    } else if similarity >= 0.7 {
        colors().success
    } else if similarity >= 0.5 {
        colors().accent
    } else if similarity >= 0.3 {
        colors().warning
    } else {
        colors().removed
    }
}

/// Panels in the matrix view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixPanel {
    Matrix,
    Details,
}
