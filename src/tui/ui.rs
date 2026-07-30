//! Main UI rendering with enhanced features.

use super::app::{
    App, AppMode, ChangeType, DiffSearchResult, DiffSearchState, SearchMode, TabKind,
    VulnChangeType,
};
use super::events::{Event, EventHandler, handle_key_event, handle_mouse_event};
use super::theme::{FooterHints, colors, render_footer_hints, set_theme};
use super::views;
use super::widgets::{
    MIN_HEIGHT, MIN_WIDTH, check_terminal_size, render_mode_indicator, render_size_warning,
};
use crate::config::TuiPreferences;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};
use std::io::{self, stdout};

#[cfg(test)]
mod frame_dump_tests;
#[cfg(test)]
mod render_snapshot_tests;

/// Run the TUI application
pub fn run_tui(app: &mut App) -> io::Result<()> {
    // Load saved theme preference
    let prefs = TuiPreferences::load();
    set_theme(super::theme::startup_theme(prefs.theme.as_str()));

    // Setup terminal. The guard restores it on drop — covering normal exit, the
    // `?` early-return from the render loop, and panic unwinding. Declared before
    // `terminal` so it is dropped last (after the backend releases stdout).
    super::shared::install_panic_hook();
    let _terminal_guard = super::shared::TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    // Event handler
    let events = EventHandler::default();

    // Main loop
    loop {
        // Pre-render: compute all mutable state before borrowing App read-only
        app.prepare_render();

        // Render
        terminal.draw(|frame| render(frame, app))?;

        // Handle events
        match events.next()? {
            Event::Key(key) => handle_key_event(app, key),
            Event::Mouse(mouse) => handle_mouse_event(app, mouse),
            Event::Resize(_, _) => {}
            Event::Tick => {
                // Update tick for animations
                app.tick += 1;
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Terminal is restored by `_terminal_guard` on drop.
    Ok(())
}

/// Main render function
fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    app.last_frame_area = Some(area);

    // Check minimum terminal size
    if check_terminal_size(area.width, area.height).is_err() {
        render_size_warning(frame, area, MIN_WIDTH, MIN_HEIGHT);
        return;
    }

    // For new multi-comparison modes, use dedicated full-screen views
    match app.mode {
        AppMode::MultiDiff => {
            if let Some(ref result) = app.data.multi_diff_result {
                views::render_multi_dashboard(
                    frame,
                    area,
                    result,
                    &app.tabs.multi_diff,
                    app.status_message.as_deref(),
                );
            }
            render_multi_mode_export_dialog(frame, area, app);
            // Render cross-view overlays
            render_cross_view_overlays(frame, app);
            return;
        }
        AppMode::Timeline => {
            if let Some(ref result) = app.data.timeline_result {
                views::render_timeline(
                    frame,
                    area,
                    result,
                    &app.tabs.timeline,
                    app.status_message.as_deref(),
                );
            }
            render_multi_mode_export_dialog(frame, area, app);
            // Render cross-view overlays
            render_cross_view_overlays(frame, app);
            return;
        }
        AppMode::Matrix => {
            if let Some(ref result) = app.data.matrix_result {
                views::render_matrix(
                    frame,
                    area,
                    result,
                    &app.tabs.matrix,
                    app.status_message.as_deref(),
                );
            }
            render_multi_mode_export_dialog(frame, area, app);
            // Render cross-view overlays
            render_cross_view_overlays(frame, app);
            return;
        }
        // Diff mode uses the tabbed layout below
        AppMode::Diff => {}
    }

    // Main layout: header, tabs, content, status bar, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(1), // Status bar
            Constraint::Length(1), // Footer
        ])
        .split(area);

    // Render header
    render_header(frame, chunks[0], app);

    // Render tabs with shortcuts
    render_tabs(frame, chunks[1], app);

    // Record the side-by-side panel viewport height before the read-only
    // RenderContext is built: content area minus context bar (2) and panel
    // borders (2). The scroll clamp keeps the selected row inside this window.
    if app.active_tab == TabKind::SideBySide {
        let rows = chunks[2].height.saturating_sub(4) as usize;
        app.side_by_side_state_mut().set_viewport_rows(rows);
    }

    // Render content based on active tab.
    // Migrated tabs use RenderContext (read-only); unmigrated tabs still use &mut App.
    match app.active_tab {
        // --- Migrated to RenderContext ---
        TabKind::Summary
        | TabKind::Quality
        | TabKind::GraphChanges
        | TabKind::Compliance
        | TabKind::Components
        | TabKind::Licenses
        | TabKind::SideBySide
        | TabKind::Dependencies
        | TabKind::Vulnerabilities => {
            let ctx = super::render_context::RenderContext::from_app(app);
            match app.active_tab {
                TabKind::Summary => views::render_summary(frame, chunks[2], &ctx),
                TabKind::Quality => views::render_quality(frame, chunks[2], &ctx),
                TabKind::GraphChanges => views::render_graph_changes(frame, chunks[2], &ctx),
                TabKind::Compliance => views::render_diff_compliance(frame, chunks[2], &ctx),
                TabKind::Components => views::render_components(frame, chunks[2], &ctx),
                TabKind::Licenses => views::render_licenses(frame, chunks[2], &ctx),
                TabKind::SideBySide => views::render_sidebyside(frame, chunks[2], &ctx),
                TabKind::Dependencies => views::render_dependencies(frame, chunks[2], &ctx),
                TabKind::Vulnerabilities => views::render_vulnerabilities(frame, chunks[2], &ctx),
                _ => unreachable!(),
            }
        }
        TabKind::Source => views::render_source(frame, chunks[2], app.source_state_mut()),
    }

    // Render status bar
    render_status_bar(frame, chunks[3], app);

    // Render footer
    render_footer(frame, chunks[4], app);

    // Render overlays
    if app.overlays.search.active {
        render_search_overlay(frame, area, &app.overlays.search);
    }

    if app.overlays.show_export {
        let scope = super::export::tab_export_scope(app.active_tab);
        super::shared::export::render_export_dialog(frame, area, scope, centered_rect);
    }

    if app.overlays.show_legend {
        render_legend_overlay(frame, area);
    }

    // Render threshold tuning overlay
    if app.overlays.threshold_tuning.visible {
        super::views::render_threshold_tuning(frame, &app.overlays.threshold_tuning);
    }

    // Quick Filters picker (Components tab, 'Q')
    if app.active_tab == TabKind::Components && app.components_view.quick_filter_picker_open {
        super::views::render_quick_filter_picker(frame, &app.components_state().security_filter);
    }

    // Cross-view overlays (K shortcuts, D deep-dive). The K/D handlers set
    // these visible in Diff/View mode too, but only the multi-mode render
    // branches painted them — leaving an invisible modal swallowing input.
    // Safe unconditionally: each inner renderer self-gates on .visible, and
    // the view switcher's V key is mode-gated to Multi/Timeline/Matrix.
    render_cross_view_overlays(frame, app);
}

/// Build a human-readable label for an SBOM: "name@version" or just "name".
///
/// Tries multiple sources for name+version: primary component, document name
/// + matching component, or just document name.
fn sbom_label(sbom: Option<&crate::model::NormalizedSbom>) -> String {
    let Some(sbom) = sbom else {
        return "SBOM".to_string();
    };

    // 1. Try primary component (most reliable)
    if let Some(comp) = sbom.primary_component() {
        if let Some(ref v) = comp.version
            && !v.is_empty()
        {
            return format!("{}@{v}", comp.name);
        }
        return comp.name.clone();
    }

    // 2. Try document name + find matching component for version
    if let Some(ref doc_name) = sbom.document.name {
        // Look for a component with this name to get its version
        let version = sbom
            .components
            .values()
            .find(|c| c.name == *doc_name)
            .and_then(|c| c.version.as_ref())
            .filter(|v| !v.is_empty());
        if let Some(v) = version {
            return format!("{doc_name}@{v}");
        }
        return doc_name.clone();
    }

    "SBOM".to_string()
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let (mode_name, subtitle) = match app.mode {
        AppMode::Diff => {
            let old_label = sbom_label(app.data.old_sbom.as_ref());
            let new_label = sbom_label(app.data.new_sbom.as_ref());
            ("diff", format!("{old_label} \u{27f7} {new_label}"))
        }
        AppMode::MultiDiff => ("multi-diff", "Multi-Diff Comparison".to_string()),
        AppMode::Timeline => ("timeline", "Timeline Analysis".to_string()),
        AppMode::Matrix => ("matrix", "Matrix Comparison".to_string()),
    };

    let mut spans = vec![
        Span::styled("sbom-tools", Style::default().fg(colors().primary).bold()),
        Span::styled(" ", Style::default()),
        render_mode_indicator(mode_name),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled(subtitle, Style::default().fg(colors().text)),
    ];

    // Enrichment status indicator (item 1.6)
    #[cfg(feature = "enrichment")]
    {
        let has_osv = app
            .data
            .enrichment_stats_old
            .as_ref()
            .is_some_and(|s| s.total_vulns_found > 0)
            || app
                .data
                .enrichment_stats_new
                .as_ref()
                .is_some_and(|s| s.total_vulns_found > 0);
        let has_enrichment =
            app.data.enrichment_stats_old.is_some() || app.data.enrichment_stats_new.is_some();
        if has_enrichment {
            spans.push(Span::styled("  ", Style::default()));
            let label = if has_osv { "OSV: on" } else { "OSV: --" };
            let label_color = if has_osv {
                colors().success
            } else {
                colors().text_muted
            };
            spans.push(Span::styled(
                format!("[{label}]"),
                Style::default().fg(label_color),
            ));
        }
    }

    let header_line = Line::from(spans);
    let header = Paragraph::new(header_line);
    frame.render_widget(header, area);
}

/// The ordered `(kind, key, title)` entries shown in the diff-mode tab bar.
///
/// Single source of truth for the tab set so rendering ([`render_tabs`]) and mouse
/// hit-testing (`events::mouse`) cannot drift — the previous hit-test hardcoded a
/// separate 8-label list and mis-selected in modes with Compliance/Graph/Source.
pub(crate) fn diff_tab_entries(app: &App) -> Vec<(TabKind, &'static str, &'static str)> {
    let mut tabs_data: Vec<(TabKind, &'static str, &'static str)> = vec![
        (TabKind::Summary, "1", "Summary"),
        (TabKind::Components, "2", "Components"),
        (TabKind::Dependencies, "3", "Dependencies"),
        (TabKind::Licenses, "4", "Licenses"),
        (TabKind::Vulnerabilities, "5", "Vulnerabilities"),
        (TabKind::Quality, "6", "Quality"),
    ];

    // Compliance and side-by-side tabs only in diff mode
    if app.mode == AppMode::Diff {
        tabs_data.push((TabKind::Compliance, "7", "Compliance"));
        // "SxS": the view titles itself "Side-by-Side"; a tab named "Diff"
        // inside the diff app identified nothing.
        tabs_data.push((TabKind::SideBySide, "8", "SxS"));
    }

    // Graph changes tab only when graph diff data is available
    let has_graph_changes = app
        .data
        .diff_result
        .as_ref()
        .is_some_and(|r| !r.graph_changes.is_empty());
    if has_graph_changes {
        tabs_data.push((TabKind::GraphChanges, "9", "Graph"));
    }

    // Source tab always available in diff mode.
    // Uses [9] when it's the 9th tab (no graph changes), [0] when it's the 10th.
    if app.mode == AppMode::Diff {
        let source_key = if has_graph_changes { "0" } else { "9" };
        tabs_data.push((TabKind::Source, source_key, "Source"));
    }

    tabs_data
}

/// The tab-title string as rendered in the bar (`"[key] title "`), used for mouse
/// hit-testing. Must match the `Line` built in [`render_tabs`].
pub(crate) fn diff_tab_label(key: &str, title: &str) -> String {
    format!("[{key}] {title} ")
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &mut App) {
    use unicode_width::UnicodeWidthStr;

    let tabs_data = diff_tab_entries(app);

    // Derive selection from the actual entry order (handles the variable
    // GraphChanges/Source positions without a parallel index table).
    let selected_idx = tabs_data
        .iter()
        .position(|(kind, _, _)| *kind == app.active_tab)
        .unwrap_or(0);

    // Window the entries against the real width. The ratatui Tabs widget
    // truncated silently, hiding half the tabs at 80 cols with no indicator.
    let widths: Vec<u16> = tabs_data
        .iter()
        .map(|(_, key, title)| UnicodeWidthStr::width(diff_tab_label(key, title).as_str()) as u16)
        .collect();
    let window = crate::tui::shared::tab_window(&widths, 3, selected_idx, area.width);
    app.tab_window = window;

    let mut spans: Vec<Span> = Vec::new();
    if window.clipped_left {
        spans.push(Span::styled(
            "\u{ab} ",
            Style::default().fg(colors().accent).bold(),
        ));
    }
    for (i, (kind, key, title)) in tabs_data[window.start..window.end].iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(
                " \u{2502} ",
                Style::default().fg(colors().muted),
            ));
        }
        let is_active = *kind == app.active_tab;
        let key_style = if is_active {
            Style::default().fg(colors().accent).bold()
        } else {
            Style::default().fg(colors().muted)
        };
        let title_style = if is_active {
            Style::default().fg(colors().accent).bold()
        } else {
            Style::default().fg(colors().text_muted)
        };
        spans.push(Span::styled(format!("[{key}]"), key_style));
        spans.push(Span::styled(format!(" {title} "), title_style));
    }
    if window.clipped_right {
        spans.push(Span::styled(
            " \u{bb}",
            Style::default().fg(colors().accent).bold(),
        ));
    }

    let tabs = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(colors().border)),
    );

    frame.render_widget(tabs, area);
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let (change_count, vuln_count, score) = match app.mode {
        AppMode::Diff => {
            let result = app.data.diff_result.as_ref();
            let changes = result.map_or(0, |r| r.summary.total_changes);
            let vuln = result.map_or(0, |r| r.summary.vulnerabilities_introduced);
            let score = result.map_or(0.0, |r| r.semantic_score);
            (changes, vuln, Some(score))
        }
        // Multi-comparison modes use their own status bars
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => (0, 0, None),
    };

    let critical_count = match app.mode {
        AppMode::Diff => app.data.diff_result.as_ref().map_or(0, |r| {
            r.vulnerabilities
                .introduced
                .iter()
                .filter(|v| v.severity == "Critical")
                .count()
        }),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
    };

    // Real per-document component counts — "Components:" must never label
    // the change total (which mixes component/dependency/metadata changes).
    let old_comps = app
        .data
        .old_sbom
        .as_ref()
        .map_or(0, crate::model::NormalizedSbom::component_count);
    let new_comps = app
        .data
        .new_sbom
        .as_ref()
        .map_or(0, crate::model::NormalizedSbom::component_count);

    let mut spans = vec![
        Span::styled(" Components: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!("{old_comps}\u{2192}{new_comps}"),
            Style::default().fg(colors().primary).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled("Changes: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            change_count.to_string(),
            Style::default().fg(colors().primary).bold(),
        ),
        Span::styled(" │ ", Style::default().fg(colors().muted)),
        Span::styled("New vulns: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            vuln_count.to_string(),
            if vuln_count > 0 {
                Style::default().fg(colors().error).bold()
            } else {
                Style::default().fg(colors().success)
            },
        ),
    ];

    if critical_count > 0 {
        spans.push(Span::styled(
            format!(" ({critical_count} Critical)"),
            Style::default().fg(colors().critical).bold(),
        ));
    }

    if let Some(s) = score {
        spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
        spans.push(Span::styled(
            "Similarity: ",
            Style::default().fg(colors().text_muted),
        ));

        // Higher similarity = less churn = calmer color.
        let score_color = if s >= 75.0 {
            colors().success
        } else if s >= 50.0 {
            colors().warning
        } else {
            colors().error
        };
        spans.push(Span::styled(
            format!("{s:.0}%"),
            Style::default().fg(score_color).bold(),
        ));
    }

    // Add breadcrumb trail if there's navigation history
    if app.has_navigation_history() {
        spans.push(Span::styled(" │ ", Style::default().fg(colors().muted)));
        spans.push(Span::styled(
            "← ",
            Style::default().fg(colors().accent).bold(),
        ));
        spans.push(Span::styled(
            app.breadcrumb_trail(),
            Style::default().fg(colors().text_muted).italic(),
        ));
        spans.push(Span::styled(
            " [b] back",
            Style::default().fg(colors().accent),
        ));
    }

    let status =
        Paragraph::new(Line::from(spans)).style(Style::default().bg(colors().background_alt));

    frame.render_widget(status, area);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    // Show status message if set, otherwise show tab-specific hints
    if let Some(ref msg) = app.status_message {
        let status_line = Line::from(vec![
            Span::styled("ℹ ", Style::default().fg(colors().accent)),
            Span::styled(msg.as_str(), Style::default().fg(colors().accent).bold()),
        ]);
        let footer = Paragraph::new(status_line)
            .alignment(Alignment::Center)
            .style(Style::default());
        frame.render_widget(footer, area);
        return;
    }

    // Tab-specific hints come from the active tab's ViewState::shortcuts()
    // primaries — the same source that feeds the ?/K overlay, so the footer
    // and the help surface can no longer drift.
    let owned: Vec<(String, String)> = app
        .active_view_state()
        .map(|v| {
            v.shortcuts()
                .into_iter()
                .filter(|s| s.primary)
                .map(|s| (s.key, s.description))
                .collect()
        })
        .unwrap_or_default();
    let mut hints: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, d)| (k.as_str(), d.as_str()))
        .collect();
    // The Components "o CVE" hint is dead when the diff carries no
    // vulnerability data at all (common for CBOM/AI-BOM diffs) — drop it so
    // the footer never advertises a no-op key.
    if app.active_tab == TabKind::Components {
        let has_vulns = app.data.diff_result.as_ref().is_some_and(|r| {
            !r.vulnerabilities.introduced.is_empty()
                || !r.vulnerabilities.resolved.is_empty()
                || !r.vulnerabilities.persistent.is_empty()
        });
        if !has_vulns {
            hints.retain(|(k, d)| !(*k == "o" && *d == "CVE"));
        }
    }
    hints.extend(FooterHints::global());

    // Budget the row: reserve the yank preview's width, keep the global
    // ?/q tail intact by dropping tab-specific hints (marked with a leading
    // ellipsis), and sacrifice the yank preview before the globals.
    let yank_text = super::events::get_yank_text(app);
    let yank_suffix = yank_text.map(|t| {
        if t.len() > 30 {
            let end = super::shared::floor_char_boundary(&t, 27);
            format!("{}...", &t[..end])
        } else {
            t
        }
    });
    let yank_width = yank_suffix.as_ref().map_or(0, |t| {
        use unicode_width::UnicodeWidthStr;
        // " [y] copy " + text
        10 + UnicodeWidthStr::width(t.as_str()) as u16
    });

    let (mut kept, mut elided) =
        crate::tui::theme::fit_footer_hints(&hints, area.width.saturating_sub(yank_width));
    // If even the surviving hints plus the yank preview overflow, drop the
    // yank FIRST and re-offer its width to the tab-specific hints.
    let elision_w = if elided { 2 } else { 0 };
    let yank_suffix =
        if crate::tui::theme::footer_hints_width(&kept) + elision_w + yank_width > area.width {
            let refit = crate::tui::theme::fit_footer_hints(&hints, area.width);
            kept = refit.0;
            elided = refit.1;
            None
        } else {
            yank_suffix
        };
    let mut footer_spans = render_footer_hints(&kept, elided);

    if let Some(truncated) = yank_suffix {
        footer_spans.push(Span::styled(" ", Style::default()));
        footer_spans.push(Span::styled("[y]", Style::default().fg(colors().accent)));
        footer_spans.push(Span::styled(
            format!(" copy {truncated}"),
            Style::default().fg(colors().text_muted),
        ));
    }

    let footer = Paragraph::new(Line::from(footer_spans))
        .alignment(Alignment::Center)
        .style(Style::default().fg(colors().text_muted));

    frame.render_widget(footer, area);
}

fn render_search_overlay(frame: &mut Frame, area: Rect, search_state: &DiffSearchState) {
    // Calculate popup size based on results (add 1 for error line if present)
    let result_count = search_state.results.len().min(10);
    let error_lines = u16::from(search_state.search_error.is_some());
    // With results: input + blank + results + blank + help line + 2 borders
    // (the previous +5 clipped the help hints whenever any result rendered).
    // Without results there is no trailing blank line, so one row less.
    let popup_height = if result_count > 0 {
        result_count as u16 + 6 + error_lines
    } else {
        5 + error_lines
    };

    let popup_area = Rect {
        x: area.x + 2,
        y: area.height.saturating_sub(popup_height + 1),
        width: area.width.saturating_sub(4),
        height: popup_height,
    };

    frame.render_widget(Clear, popup_area);

    let mut lines = Vec::new();

    // Search input line with mode indicator
    let mode_label = match search_state.mode {
        SearchMode::Substring => "[substring]",
        SearchMode::Regex => "[regex]",
    };
    let cursor_char = "│";
    lines.push(Line::from(vec![
        Span::styled("/ ", Style::default().fg(colors().primary)),
        Span::styled(
            format!("{mode_label} "),
            Style::default().fg(colors().text_muted),
        ),
        Span::styled(&search_state.query, Style::default().fg(colors().text)),
        Span::styled(cursor_char, Style::default().fg(colors().accent)),
        if search_state.search_error.is_some() {
            Span::styled("  (invalid pattern)", Style::default().fg(colors().error))
        } else if !search_state.results.is_empty() {
            Span::styled(
                format!("  ({} results)", search_state.results.len()),
                Style::default().fg(colors().text_muted),
            )
        } else if search_state.query.len() >= 2 {
            Span::styled("  (no results)", Style::default().fg(colors().text_muted))
        } else {
            Span::styled(
                "  (type to search)",
                Style::default().fg(colors().text_muted),
            )
        },
    ]));

    // Show regex error if present
    if let Some(ref err) = search_state.search_error {
        lines.push(Line::from(vec![Span::styled(
            format!("  {err}"),
            Style::default().fg(colors().error).italic(),
        )]));
    }

    // Results
    if !search_state.results.is_empty() {
        lines.push(Line::from(""));

        for (i, result) in search_state.results.iter().take(10).enumerate() {
            let is_selected = i == search_state.selected;
            let prefix = if is_selected { "▶ " } else { "  " };

            let line = match result {
                DiffSearchResult::Component {
                    name,
                    version,
                    change_type,
                    ..
                } => {
                    let change_color = match change_type {
                        ChangeType::Added => colors().added,
                        ChangeType::Removed => colors().removed,
                        ChangeType::Modified => colors().modified,
                        ChangeType::Unchanged => colors().muted,
                    };
                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(colors().accent)),
                        Span::styled(
                            format!("[{}] ", change_type.label()),
                            Style::default().fg(change_color),
                        ),
                        Span::styled(
                            name,
                            if is_selected {
                                Style::default().fg(colors().text).bold()
                            } else {
                                Style::default().fg(colors().text)
                            },
                        ),
                        version.as_ref().map_or_else(
                            || Span::raw(""),
                            |v| {
                                Span::styled(
                                    format!(" @ {v}"),
                                    Style::default().fg(colors().text_muted),
                                )
                            },
                        ),
                    ])
                }
                DiffSearchResult::Vulnerability {
                    id,
                    component_name,
                    severity,
                    change_type,
                } => {
                    let change_color = match change_type {
                        VulnChangeType::Introduced => colors().removed,
                        VulnChangeType::Resolved => colors().added,
                    };
                    let sev_color = severity
                        .as_ref()
                        .map_or_else(|| colors().text_muted, |s| colors().severity_color(s));

                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(colors().accent)),
                        Span::styled(
                            format!("[{}] ", change_type.label()),
                            Style::default().fg(change_color),
                        ),
                        Span::styled(
                            id,
                            if is_selected {
                                Style::default().fg(sev_color).bold()
                            } else {
                                Style::default().fg(sev_color)
                            },
                        ),
                        Span::styled(
                            format!(" in {component_name}"),
                            Style::default().fg(colors().text_muted),
                        ),
                    ])
                }
                DiffSearchResult::License {
                    license,
                    component_name,
                    change_type,
                } => {
                    let change_color = match change_type {
                        ChangeType::Added => colors().added,
                        ChangeType::Removed => colors().removed,
                        ChangeType::Modified => colors().modified,
                        ChangeType::Unchanged => colors().muted,
                    };
                    Line::from(vec![
                        Span::styled(prefix, Style::default().fg(colors().accent)),
                        Span::styled(
                            format!("[{}] ", change_type.label()),
                            Style::default().fg(change_color),
                        ),
                        Span::styled(
                            license,
                            if is_selected {
                                Style::default().fg(colors().text).bold()
                            } else {
                                Style::default().fg(colors().text)
                            },
                        ),
                        Span::styled(
                            format!(" ({component_name})"),
                            Style::default().fg(colors().text_muted),
                        ),
                    ])
                }
            };
            lines.push(line);
        }
    }

    // Help line
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[↑↓]", Style::default().fg(colors().accent)),
        Span::raw(" navigate "),
        Span::styled("[Enter]", Style::default().fg(colors().accent)),
        Span::raw(" select "),
        Span::styled("[Esc]", Style::default().fg(colors().accent)),
        Span::raw(" close "),
        Span::styled("[^R]", Style::default().fg(colors().accent)),
        Span::raw(" regex"),
    ]));

    let search = Paragraph::new(lines).block(
        Block::default()
            .title(" Search ")
            .title_style(Style::default().fg(colors().primary).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().primary)),
    );

    frame.render_widget(search, popup_area);
}

fn render_legend_overlay(frame: &mut Frame, area: Rect) {
    let popup_area = centered_rect(50, 60, area);
    frame.render_widget(Clear, popup_area);

    // Legend with accessibility patterns (symbols + colors)
    let legend_text = vec![
        Line::styled(
            "━━━ Color & Symbol Legend ━━━",
            Style::default().fg(colors().accent).bold(),
        ),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Change Status",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  + ■ ", Style::default().fg(colors().added)),
            Span::styled("Added    ", Style::default().fg(colors().text)),
            Span::styled("(new component)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  - ■ ", Style::default().fg(colors().removed)),
            Span::styled("Removed  ", Style::default().fg(colors().text)),
            Span::styled(
                "(component deleted)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ~ ■ ", Style::default().fg(colors().modified)),
            Span::styled("Modified ", Style::default().fg(colors().text)),
            Span::styled(
                "(version/deps changed)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Vulnerability Severity",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled("  C ■ ", Style::default().fg(colors().critical)),
            Span::styled("Critical ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 9.0-10.0)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  H ■ ", Style::default().fg(colors().high)),
            Span::styled("High     ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 7.0-8.9)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  M ■ ", Style::default().fg(colors().medium)),
            Span::styled("Medium   ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 4.0-6.9)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  L ■ ", Style::default().fg(colors().low)),
            Span::styled("Low      ", Style::default().fg(colors().text)),
            Span::styled("(CVSS 0.1-3.9)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "License Categories",
            Style::default().fg(colors().primary).bold(),
        )]),
        Line::from(vec![
            Span::styled(
                format!(
                    "  {} ■ ",
                    crate::tui::shared::licenses::category_glyph_str("permissive")
                ),
                Style::default().fg(colors().permissive),
            ),
            Span::styled("Permissive  ", Style::default().fg(colors().text)),
            Span::styled(
                "(MIT, Apache, BSD)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    "  {} ■ ",
                    crate::tui::shared::licenses::category_glyph_str("copyleft")
                ),
                Style::default().fg(colors().copyleft),
            ),
            Span::styled("Copyleft    ", Style::default().fg(colors().text)),
            Span::styled("(GPL, AGPL)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    "  {} ■ ",
                    crate::tui::shared::licenses::category_glyph_str("weak copyleft")
                ),
                Style::default().fg(colors().weak_copyleft),
            ),
            Span::styled("Weak Copyleft ", Style::default().fg(colors().text)),
            Span::styled("(LGPL, MPL)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled(
                format!(
                    "  {} ■ ",
                    crate::tui::shared::licenses::category_glyph_str("proprietary")
                ),
                Style::default().fg(colors().proprietary),
            ),
            Span::styled("Proprietary ", Style::default().fg(colors().text)),
            Span::styled("(Commercial)", Style::default().fg(colors().text_muted)),
        ]),
        Line::from(vec![
            Span::styled("  ? ■ ", Style::default().fg(colors().text_muted)),
            Span::styled("Unknown     ", Style::default().fg(colors().text)),
            Span::styled(
                "(undeclared/unrecognized)",
                Style::default().fg(colors().text_muted),
            ),
        ]),
        Line::from(""),
        Line::styled(
            "Press any key to close",
            Style::default().fg(colors().text_muted),
        ),
    ];

    let legend = Paragraph::new(legend_text).block(
        Block::default()
            .title(" Legend ")
            .title_style(Style::default().fg(colors().accent).bold())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors().accent)),
    );

    frame.render_widget(legend, popup_area);
}

/// Helper function to create a centered rectangle
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Render the export dialog in the multi-comparison modes. Without this the
/// global 'e' opened an invisible modal that silently swallowed every key.
fn render_multi_mode_export_dialog(frame: &mut Frame, area: Rect, app: &App) {
    if app.overlays.show_export {
        super::shared::export::render_export_dialog(frame, area, "Report", centered_rect);
    }
}

/// Render cross-view overlays (view switcher, shortcuts, component deep dive)
fn render_cross_view_overlays(frame: &mut Frame, app: &mut App) {
    // Render view switcher overlay
    views::render_view_switcher(frame, &app.overlays.view_switcher);

    // Render shortcuts overlay
    views::render_shortcuts_overlay(frame, &mut app.overlays.shortcuts);

    // Render component deep dive modal
    views::render_component_deep_dive(frame, &app.overlays.component_deep_dive);
}
