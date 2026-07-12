//! Multi-diff mode event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub(super) fn handle_multi_diff_keys(app: &mut App, key: KeyEvent) -> bool {
    // Handle search input mode
    if app.tabs.multi_diff.search.active {
        handle_multi_diff_search(app, key);
        return true;
    }

    // Handle detail modal
    if app.tabs.multi_diff.show_detail_modal {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.multi_diff.close_detail_modal();
            }
            _ => {}
        }
        // Modal swallows all keys so none leak to the global fallback.
        return true;
    }

    // Handle variable component drill-down
    if app.tabs.multi_diff.show_variable_drill_down {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.multi_diff.close_variable_drill_down();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.tabs.multi_diff.select_prev_variable_component();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.tabs.multi_diff.select_next_variable_component();
            }
            _ => {}
        }
        // Drill-down overlay swallows all keys.
        return true;
    }

    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('p') => app.tabs.multi_diff.toggle_panel(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.multi_diff.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.multi_diff.select_next(),

        // Search
        KeyCode::Char('/') => {
            app.tabs.multi_diff.search.start();
        }

        // In-place match cycling after Enter confirmed a search.
        KeyCode::Char('n') if !app.tabs.multi_diff.search.matches.is_empty() => {
            app.tabs.multi_diff.search.next_match();
            if let Some(idx) = app.tabs.multi_diff.search.current_match_index() {
                app.tabs.multi_diff.selected_target = idx;
            }
        }
        KeyCode::Char('N') if !app.tabs.multi_diff.search.matches.is_empty() => {
            app.tabs.multi_diff.search.prev_match();
            if let Some(idx) = app.tabs.multi_diff.search.current_match_index() {
                app.tabs.multi_diff.selected_target = idx;
            }
        }

        // Filter and sort
        KeyCode::Char('f') => {
            app.tabs.multi_diff.toggle_filter();
            // The filter changes how many comparisons are visible; keep the navigation
            // bound (`total_targets`) and the selection in sync with the filtered list.
            if let Some(result) = app.data.multi_diff_result.as_ref() {
                let visible =
                    crate::tui::views::ordered_comparison_indices(result, &app.tabs.multi_diff)
                        .len();
                app.tabs.multi_diff.total_targets = visible;
                if visible > 0 && app.tabs.multi_diff.selected_target >= visible {
                    app.tabs.multi_diff.selected_target = visible - 1;
                }
            }
            // Search matches are display positions; recompute under the new
            // filtered order (n/N consume them after confirm).
            update_multi_diff_search_matches(app);
            app.set_status_message(format!(
                "Filter: {}",
                app.tabs.multi_diff.filter_preset.label()
            ));
        }
        KeyCode::Char('s') => {
            app.tabs.multi_diff.toggle_sort();
            update_multi_diff_search_matches(app);
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.multi_diff.sort_by.label(),
                app.tabs.multi_diff.sort_direction.indicator()
            ));
        }
        KeyCode::Char('S') => {
            app.tabs.multi_diff.toggle_sort_direction();
            update_multi_diff_search_matches(app);
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.multi_diff.sort_by.label(),
                app.tabs.multi_diff.sort_direction.indicator()
            ));
        }

        // Detail modal
        KeyCode::Enter | KeyCode::Char(' ') => {
            app.tabs.multi_diff.toggle_detail_modal();
        }

        // Variable components drill-down
        KeyCode::Char('v') => {
            app.tabs.multi_diff.toggle_variable_drill_down();
        }

        // Cross-target analysis
        KeyCode::Char('x') => {
            app.tabs.multi_diff.toggle_cross_target();
            let status = if app.tabs.multi_diff.show_cross_target {
                "Cross-target analysis: enabled"
            } else {
                "Cross-target analysis: disabled"
            };
            app.set_status_message(status.to_string());
        }

        // Heat map mode
        KeyCode::Char('h') => {
            app.tabs.multi_diff.toggle_heat_map();
            let status = if app.tabs.multi_diff.heat_map_mode {
                "Heat map mode: enabled"
            } else {
                "Heat map mode: disabled"
            };
            app.set_status_message(status.to_string());
        }

        _ => return false,
    }
    true
}

pub(super) fn handle_multi_diff_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.multi_diff.search.cancel();
        }
        KeyCode::Enter => {
            app.tabs.multi_diff.search.confirm();
            if let Some(idx) = app.tabs.multi_diff.search.current_match_index() {
                app.tabs.multi_diff.selected_target = idx;
            }
        }
        KeyCode::Backspace => {
            app.tabs.multi_diff.search.pop();
            update_multi_diff_search_matches(app);
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.tabs.multi_diff.search.toggle_mode();
            update_multi_diff_search_matches(app);
            app.set_status_message(format!(
                "Search mode: {}",
                app.tabs.multi_diff.search.mode.label()
            ));
        }
        // Live preview: Up/Down move the visible selection through the
        // matches before Enter confirms (one mental model everywhere).
        KeyCode::Down => {
            app.tabs.multi_diff.search.next_match();
            if let Some(idx) = app.tabs.multi_diff.search.current_match_index() {
                app.tabs.multi_diff.selected_target = idx;
            }
        }
        KeyCode::Up => {
            app.tabs.multi_diff.search.prev_match();
            if let Some(idx) = app.tabs.multi_diff.search.current_match_index() {
                app.tabs.multi_diff.selected_target = idx;
            }
        }
        KeyCode::Char(c) => {
            app.tabs.multi_diff.search.push(c);
            update_multi_diff_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_multi_diff_search_matches(app: &mut App) {
    let query = &app.tabs.multi_diff.search.query;
    if query.is_empty() {
        app.tabs.multi_diff.search.error = None;
        app.tabs.multi_diff.search.update_matches(vec![]);
        return;
    }

    // Shared matcher: same substring/regex semantics as every other search.
    let matcher = match crate::tui::app_states::SearchMatcher::build(
        query,
        app.tabs.multi_diff.search.mode,
    ) {
        Ok(m) => {
            app.tabs.multi_diff.search.error = None;
            m
        }
        Err(e) => {
            app.tabs.multi_diff.search.error = Some(e);
            app.tabs.multi_diff.search.update_matches(vec![]);
            return;
        }
    };

    // Matches are DISPLAY positions (filter+sort aware).
    let matches: Vec<usize> = app
        .data
        .multi_diff_result
        .as_ref()
        .map_or_else(Vec::new, |result| {
            crate::tui::views::ordered_comparison_indices(result, &app.tabs.multi_diff)
                .iter()
                .enumerate()
                .filter(|(_, raw)| matcher.is_match(&result.comparisons[**raw].target.name))
                .map(|(display, _)| display)
                .collect()
        });

    app.tabs.multi_diff.search.update_matches(matches);
}
