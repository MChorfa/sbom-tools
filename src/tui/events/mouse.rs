//! Mouse event handlers.

use crate::tui::{App, AppMode};
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

pub fn handle_mouse_event(app: &mut App, mouse: MouseEvent) {
    // Clear status message on any mouse action
    app.clear_status_message();

    // The multi-comparison modes have their own layouts; the tabbed logic
    // below assumes the Diff chrome and mis-routed y<=2 clicks into
    // select_tab.
    match app.mode {
        AppMode::MultiDiff => {
            handle_multi_diff_mouse(app, mouse);
            return;
        }
        AppMode::Timeline => {
            handle_timeline_mouse(app, mouse);
            return;
        }
        AppMode::Matrix => {
            handle_matrix_mouse(app, mouse);
            return;
        }
        AppMode::Diff => {}
    }

    match mouse.kind {
        MouseEventKind::ScrollUp => {
            if app.active_tab == crate::tui::TabKind::Source {
                app.source_state_mut().select_prev();
            } else {
                app.select_up();
            }
        }
        MouseEventKind::ScrollDown => {
            if app.active_tab == crate::tui::TabKind::Source {
                app.source_state_mut().select_next();
            } else {
                app.select_down();
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            let x = mouse.column;
            let y = mouse.row;

            // Close overlays on click
            if app.has_overlay() {
                app.close_overlays();
                return;
            }

            // Tab bar is in the first rows. Derive the clicked tab from the real
            // rendered tab set + geometry so every profile/mode tab is reachable
            // (the old fixed-13-col estimate mis-selected once Compliance/Graph/
            // Source were present).
            if y <= 2 {
                let entries = crate::tui::ui::diff_tab_entries(app);
                let labels: Vec<String> = entries
                    .iter()
                    .map(|(_, key, title)| crate::tui::ui::diff_tab_label(key, title))
                    .collect();
                // Shared geometry with the last render: the stashed window
                // makes marker clicks functional scroll affordances.
                match crate::tui::shared::tab_bar_hit_windowed(&labels, app.tab_window, 0, 3, x) {
                    crate::tui::shared::TabHit::Tab(idx) => app.select_tab(entries[idx].0),
                    crate::tui::shared::TabHit::PrevMarker => {
                        if app.tab_window.start > 0 {
                            app.select_tab(entries[app.tab_window.start - 1].0);
                        }
                    }
                    crate::tui::shared::TabHit::NextMarker => {
                        if app.tab_window.end < entries.len() {
                            app.select_tab(entries[app.tab_window.end].0);
                        }
                    }
                    crate::tui::shared::TabHit::Miss => {}
                }
                return;
            }

            // Handle click on list items
            // Layout: header (2 rows) + filter bar (3 rows) + content
            // Content area starts around row 5, with 1-row header inside tables
            // Clicks inside the Source detail strip must not fall through
            // to the tree-list index math below it.
            if app.active_tab == crate::tui::TabKind::Source
                && let Some(top) = app.source_state().detail_strip_top
                && y >= top
            {
                return;
            }

            if let Some(clicked_index) = diff_click_index(app, y) {
                handle_list_click(app, clicked_index, x);
            }
        }
        // Right-click closes overlays
        MouseEventKind::Down(MouseButton::Right) if app.has_overlay() => {
            app.close_overlays();
        }
        _ => {}
    }
}

/// Handle a click on a list item
pub(super) fn handle_list_click(app: &mut App, clicked_index: usize, _x: u16) {
    match app.active_tab {
        crate::tui::TabKind::Components => {
            if clicked_index < app.components_state().total {
                app.components_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Vulnerabilities => {
            if clicked_index < app.vulnerabilities_state().total {
                app.vulnerabilities_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Dependencies => {
            if clicked_index < app.dependencies_state().total {
                app.dependencies_state_mut().selected = clicked_index;
            }
        }
        crate::tui::TabKind::Source => {
            // Determine which panel from x position (50/50 split)
            let panel = app.source_state_mut().active_panel_mut();
            let max = match panel.view_mode {
                crate::tui::app_states::SourceViewMode::Tree => {
                    panel.ensure_flat_cache();
                    panel.cached_flat_items.len()
                }
                crate::tui::app_states::SourceViewMode::Raw => panel.raw_lines.len(),
            };
            let idx = panel.scroll_offset + clicked_index;
            if idx < max {
                panel.selected = idx;
            }
        }
        _ => {}
    }
}

/// Map a click row to a list index for the active diff tab, reproducing the
/// rendered geometry exactly (chrome heights, per-tab context bars, and
/// ratatui's auto-scroll). Returns None for tabs without a stable 1:1
/// row-to-item mapping (Licenses: two stacked tables with unpersisted
/// offsets; Quality: a line-scrolled paragraph) — a safe no-op beats
/// selecting the wrong row.
fn diff_click_index(app: &App, y: u16) -> Option<usize> {
    let frame_h = app.last_frame_area?.height;
    match app.active_tab {
        crate::tui::TabKind::Components | crate::tui::TabKind::Vulnerabilities => {
            // content row 5 + filter bar 3 + block border 1 + header row 1
            let body_start = 10u16;
            // table area = frame_h - 10, minus 2 borders + 1 header
            let visible_rows = (frame_h.saturating_sub(13)) as usize;
            let row = y.checked_sub(body_start)? as usize;
            if row >= visible_rows {
                return None; // bottom border / status bar / footer
            }
            // Reproduce ratatui's auto-scroll: the persisted offset is always
            // 0, so the effective offset keeps the selection visible.
            let sel = match app.active_tab {
                crate::tui::TabKind::Components => app.components_state().selected,
                _ => app.vulnerabilities_state().selected,
            };
            let offset = sel.saturating_sub(visible_rows.saturating_sub(1));
            Some(offset + row)
        }
        crate::tui::TabKind::Dependencies => {
            // Mirror views/dependencies.rs: context bar 2 (+1 searching,
            // +1 breadcrumbs), then block border + no table header.
            let deps = app.dependencies_state();
            let mut context_height = 2u16;
            if deps.is_searching() || deps.has_search_query() {
                context_height += 1;
            }
            if deps.show_breadcrumbs && !deps.breadcrumb_trail.is_empty() {
                context_height += 1;
            }
            let body_start = 5 + context_height + 1;
            let row = y.checked_sub(body_start)? as usize;
            let viewport = (frame_h.saturating_sub(7 + context_height + 2)) as usize;
            if row >= viewport {
                return None;
            }
            // The render skips by exactly the (pre-clamped) scroll offset.
            Some(deps.scroll_offset + row)
        }
        crate::tui::TabKind::Source => {
            // Panel block top border sits at content row 5.
            let row = y.checked_sub(6)? as usize;
            Some(row)
        }
        _ => None,
    }
}

/// Mouse in the Multi-Diff dashboard: wheel moves the target selection,
/// clicks close modals or select the target row under the cursor.
fn handle_multi_diff_mouse(app: &mut App, mouse: MouseEvent) {
    match mouse.kind {
        // The wheel scrolls the surface it points at: the drill-down modal's
        // list when open, otherwise the targets list. The detail modal has no
        // scrollable selection — the wheel is a no-op there, matching the
        // keyboard's refusal to move the selection under it.
        MouseEventKind::ScrollUp => {
            if app.tabs.multi_diff.show_variable_drill_down {
                app.tabs.multi_diff.select_prev_variable_component();
            } else if !app.tabs.multi_diff.show_detail_modal {
                app.tabs.multi_diff.select_prev();
            }
        }
        MouseEventKind::ScrollDown => {
            if app.tabs.multi_diff.show_variable_drill_down {
                app.tabs.multi_diff.select_next_variable_component();
            } else if !app.tabs.multi_diff.show_detail_modal {
                app.tabs.multi_diff.select_next();
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            if app.has_overlay() {
                app.close_overlays();
                return;
            }
            if app.tabs.multi_diff.show_detail_modal {
                app.tabs.multi_diff.close_detail_modal();
                return;
            }
            if app.tabs.multi_diff.show_variable_drill_down {
                app.tabs.multi_diff.close_variable_drill_down();
                return;
            }
            let Some(area) = app.last_frame_area else {
                return;
            };
            let Some(result) = app.data.multi_diff_result.as_ref() else {
                return;
            };
            // Reproduce render_multi_dashboard's layout exactly.
            let chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Length(5),
                    ratatui::layout::Constraint::Min(15),
                    ratatui::layout::Constraint::Length(3),
                ])
                .split(area);
            let constraints: Vec<ratatui::layout::Constraint> =
                if app.tabs.multi_diff.show_cross_target {
                    vec![
                        ratatui::layout::Constraint::Percentage(25),
                        ratatui::layout::Constraint::Percentage(40),
                        ratatui::layout::Constraint::Percentage(35),
                    ]
                } else {
                    vec![
                        ratatui::layout::Constraint::Percentage(35),
                        ratatui::layout::Constraint::Percentage(65),
                    ]
                };
            let main_chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints(constraints)
                .split(chunks[2]);
            let targets = main_chunks[0];
            // top border + header row + header bottom_margin; stateless table.
            let first_row = targets.y + 3;
            let (x, y) = (mouse.column, mouse.row);
            if x >= targets.x
                && x < targets.right()
                && y >= first_row
                && y < targets.bottom().saturating_sub(1)
            {
                let row = (y - first_row) as usize;
                let display_len =
                    crate::tui::views::ordered_comparison_indices(result, &app.tabs.multi_diff)
                        .len();
                if row < display_len {
                    app.tabs.multi_diff.selected_target = row;
                }
            }
        }
        MouseEventKind::Down(MouseButton::Right) if app.has_overlay() => {
            app.close_overlays();
        }
        _ => {}
    }
}

/// Mouse in the Timeline: wheel moves the panel-aware selection, clicks close
/// modals or select the version row under the cursor.
fn handle_timeline_mouse(app: &mut App, mouse: MouseEvent) {
    let timeline_modal_open = app.tabs.timeline.show_version_diff_modal
        || app.tabs.timeline.show_component_history
        || app.tabs.timeline.jump_mode;
    match mouse.kind {
        // No selection mutation under open modals (the keyboard forbids it).
        MouseEventKind::ScrollUp if !timeline_modal_open => app.tabs.timeline.select_prev(),
        MouseEventKind::ScrollDown if !timeline_modal_open => app.tabs.timeline.select_next(),
        MouseEventKind::Down(MouseButton::Left) => {
            if app.has_overlay() {
                app.close_overlays();
                return;
            }
            if app.tabs.timeline.show_version_diff_modal {
                app.tabs.timeline.close_version_diff_modal();
                return;
            }
            if app.tabs.timeline.show_component_history {
                app.tabs.timeline.close_component_history();
                return;
            }
            let Some(area) = app.last_frame_area else {
                return;
            };
            // Reproduce render_timeline's layout exactly.
            let constraints: Vec<ratatui::layout::Constraint> = if app.tabs.timeline.show_statistics
            {
                vec![
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Length(7),
                    ratatui::layout::Constraint::Length(8),
                    ratatui::layout::Constraint::Min(12),
                    ratatui::layout::Constraint::Length(3),
                ]
            } else {
                vec![
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Length(8),
                    ratatui::layout::Constraint::Min(15),
                    ratatui::layout::Constraint::Length(3),
                ]
            };
            let chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints(constraints)
                .split(area);
            let main = if app.tabs.timeline.show_statistics {
                chunks[3]
            } else {
                chunks[2]
            };
            let main_chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints([
                    ratatui::layout::Constraint::Percentage(40),
                    ratatui::layout::Constraint::Percentage(60),
                ])
                .split(main);
            let versions = main_chunks[0];
            let first_row = versions.y + 3; // border + header + bottom_margin
            let (x, y) = (mouse.column, mouse.row);
            if x >= versions.x
                && x < versions.right()
                && y >= first_row
                && y < versions.bottom().saturating_sub(1)
            {
                let row = (y - first_row) as usize;
                if row < app.tabs.timeline.total_versions {
                    app.tabs.timeline.selected_version = row;
                }
            }
        }
        MouseEventKind::Down(MouseButton::Right) if app.has_overlay() => {
            app.close_overlays();
        }
        _ => {}
    }
}

/// Mouse in the Matrix: the wheel moves the cell selection in both axes;
/// clicks close modals (cell-grid mapping is a gated follow-up).
fn handle_matrix_mouse(app: &mut App, mouse: MouseEvent) {
    let matrix_modal_open = app.tabs.matrix.show_pair_diff
        || app.tabs.matrix.show_export_options
        || app.tabs.matrix.show_clustering_details;
    match mouse.kind {
        // No selection mutation under open modals (the keyboard forbids it).
        MouseEventKind::ScrollUp if !matrix_modal_open => app.tabs.matrix.move_up(),
        MouseEventKind::ScrollDown if !matrix_modal_open => app.tabs.matrix.move_down(),
        MouseEventKind::ScrollLeft if !matrix_modal_open => app.tabs.matrix.move_left(),
        MouseEventKind::ScrollRight if !matrix_modal_open => app.tabs.matrix.move_right(),
        MouseEventKind::Down(MouseButton::Left | MouseButton::Right) => {
            if app.has_overlay() {
                app.close_overlays();
                return;
            }
            if app.tabs.matrix.show_pair_diff {
                app.tabs.matrix.close_pair_diff();
            } else if app.tabs.matrix.show_export_options {
                app.tabs.matrix.close_export_options();
            } else if app.tabs.matrix.show_clustering_details {
                app.tabs.matrix.close_clustering_details();
            }
        }
        _ => {}
    }
}

// ============================================================================
// Cross-View Helper Functions
// ============================================================================

/// Switch to a different multi-comparison view
pub(super) fn switch_to_view(app: &mut App, view: crate::tui::app_states::MultiViewType) {
    match view {
        crate::tui::app_states::MultiViewType::MultiDiff => {
            app.mode = AppMode::MultiDiff;
            app.set_status_message("Switched to Multi-Diff Dashboard".to_string());
        }
        crate::tui::app_states::MultiViewType::Timeline => {
            app.mode = AppMode::Timeline;
            app.set_status_message("Switched to Timeline View".to_string());
        }
        crate::tui::app_states::MultiViewType::Matrix => {
            app.mode = AppMode::Matrix;
            app.set_status_message("Switched to Matrix Comparison".to_string());
        }
    }
}
