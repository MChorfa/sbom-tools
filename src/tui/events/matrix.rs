//! Matrix mode event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::cell::Cell;

thread_local! {
    /// Pair-diff modal scroll offset, in body lines. Thread-local rather than
    /// a `MatrixState` field: only the render side knows the modal's real
    /// line count, so it clamps and writes the offset back at draw time
    /// (events and render share the TUI thread).
    static PAIR_DIFF_SCROLL: Cell<usize> = const { Cell::new(0) };
}

/// Current pair-diff modal scroll offset.
pub(crate) fn pair_diff_scroll() -> usize {
    PAIR_DIFF_SCROLL.with(Cell::get)
}

/// Store the pair-diff modal scroll offset (the render side calls this with
/// the clamped value so the offset never drifts past the content).
pub(crate) fn set_pair_diff_scroll(offset: usize) {
    PAIR_DIFF_SCROLL.with(|c| c.set(offset));
}

pub(super) fn handle_matrix_keys(app: &mut App, key: KeyEvent) -> bool {
    // Handle search input mode
    if app.tabs.matrix.search.active {
        handle_matrix_search(app, key);
        return true;
    }

    // Handle pair diff modal
    if app.tabs.matrix.show_pair_diff {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.matrix.close_pair_diff();
                set_pair_diff_scroll(0);
            }
            // j/k scroll the modal body so entries beyond the visible window
            // are reachable (#95); the render clamps against line count.
            KeyCode::Down | KeyCode::Char('j') => {
                set_pair_diff_scroll(pair_diff_scroll().saturating_add(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                set_pair_diff_scroll(pair_diff_scroll().saturating_sub(1));
            }
            _ => {}
        }
        // Modal swallows all keys so none leak to the global fallback.
        return true;
    }

    // Handle export options
    if app.tabs.matrix.show_export_options {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.matrix.close_export_options();
            }
            KeyCode::Char('c') => {
                app.tabs.matrix.close_export_options();
                app.export_matrix(crate::tui::export::ExportFormat::Csv);
            }
            KeyCode::Char('j') => {
                app.tabs.matrix.close_export_options();
                app.export_matrix(crate::tui::export::ExportFormat::Json);
            }
            KeyCode::Char('h') => {
                app.tabs.matrix.close_export_options();
                app.export_matrix(crate::tui::export::ExportFormat::Html);
            }
            _ => {}
        }
        return true;
    }

    // Handle clustering details
    if app.tabs.matrix.show_clustering_details {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.matrix.close_clustering_details();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.tabs.matrix.select_prev_cluster();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.tabs.matrix.select_next_cluster();
            }
            _ => {}
        }
        return true;
    }

    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('p') => app.tabs.matrix.toggle_panel(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.matrix.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.matrix.move_down(),
        KeyCode::Left | KeyCode::Char('h') => app.tabs.matrix.move_left(),
        KeyCode::Right | KeyCode::Char('l') => app.tabs.matrix.move_right(),

        // Search
        KeyCode::Char('/') => {
            app.tabs.matrix.search.start();
        }

        // In-place match cycling after Enter confirmed a search.
        KeyCode::Char('n') if !app.tabs.matrix.search.matches.is_empty() => {
            app.tabs.matrix.search.next_match();
            if let Some(idx) = app.tabs.matrix.search.current_match_index() {
                app.tabs.matrix.selected_row = idx;
            }
        }
        KeyCode::Char('N') if !app.tabs.matrix.search.matches.is_empty() => {
            app.tabs.matrix.search.prev_match();
            if let Some(idx) = app.tabs.matrix.search.current_match_index() {
                app.tabs.matrix.selected_row = idx;
            }
        }

        // Sort
        KeyCode::Char('s') => {
            app.tabs.matrix.toggle_sort();
            // focus_row/focus_col and search matches are display indices;
            // they would silently point at different SBOMs after the reorder.
            app.tabs.matrix.clear_focus();
            update_matrix_search_matches(app);
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.matrix.sort_by.label(),
                app.tabs.matrix.sort_direction.indicator()
            ));
        }
        KeyCode::Char('S') => {
            app.tabs.matrix.toggle_sort_direction();
            app.tabs.matrix.clear_focus();
            update_matrix_search_matches(app);
        }

        // Threshold filter
        KeyCode::Char('t') => {
            app.tabs.matrix.toggle_threshold();
            app.set_status_message(format!("Threshold: {}", app.tabs.matrix.threshold.label()));
        }

        // Focus mode (zoom on row/column)
        KeyCode::Char('z') => {
            app.tabs.matrix.toggle_focus_mode();
            let status = if app.tabs.matrix.focus_mode {
                "Focus mode: enabled"
            } else {
                "Focus mode: disabled"
            };
            app.set_status_message(status.to_string());
        }

        // Focus on current row only
        KeyCode::Char('r') => {
            app.tabs.matrix.focus_on_row(app.tabs.matrix.selected_row);
            app.set_status_message(format!(
                "Focused on row {}",
                app.tabs.matrix.selected_row + 1
            ));
        }

        // Focus on current column only
        KeyCode::Char('c') => {
            app.tabs.matrix.focus_on_col(app.tabs.matrix.selected_col);
            app.set_status_message(format!(
                "Focused on column {}",
                app.tabs.matrix.selected_col + 1
            ));
        }

        // Clear focus
        KeyCode::Esc => {
            if app.tabs.matrix.focus_mode {
                app.tabs.matrix.clear_focus();
                app.set_status_message("Focus cleared".to_string());
            }
        }

        // Toggle row/column highlighting
        KeyCode::Char('H') => {
            app.tabs.matrix.toggle_row_col_highlight();
            let status = if app.tabs.matrix.highlight_row_col {
                "Row/column highlight: enabled"
            } else {
                "Row/column highlight: disabled"
            };
            app.set_status_message(status.to_string());
        }

        // Launch diff for selected pair
        KeyCode::Enter | KeyCode::Char('d') => {
            if app.tabs.matrix.selected_row == app.tabs.matrix.selected_col {
                app.set_status_message("Cannot diff same SBOM".to_string());
            } else {
                app.tabs.matrix.toggle_pair_diff();
                // A fresh modal starts at the top.
                set_pair_diff_scroll(0);
            }
        }

        // Export options
        KeyCode::Char('x') => {
            app.tabs.matrix.toggle_export_options();
        }

        // Matrix rows are SBOMs, not components — a component-shaped deep
        // dive modal for an SBOM name would be nonsense. Explain instead of
        // letting the global fallback open a hollow modal.
        KeyCode::Char('D') => {
            app.set_status_message(
                "Deep dive applies to components — press Enter for pair diff".to_string(),
            );
        }

        // Clustering details
        KeyCode::Char('C') => {
            app.tabs.matrix.toggle_clustering_details();
        }

        _ => return false,
    }
    true
}

pub(super) fn handle_matrix_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.matrix.search.cancel();
        }
        KeyCode::Enter => {
            app.tabs.matrix.search.confirm();
            if let Some(idx) = app.tabs.matrix.search.current_match_index() {
                app.tabs.matrix.selected_row = idx;
            }
        }
        KeyCode::Backspace => {
            app.tabs.matrix.search.pop();
            update_matrix_search_matches(app);
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.tabs.matrix.search.toggle_mode();
            update_matrix_search_matches(app);
            app.set_status_message(format!(
                "Search mode: {}",
                app.tabs.matrix.search.mode.label()
            ));
        }
        // Live preview: Up/Down move the visible selection through the
        // matches before Enter confirms (one mental model everywhere).
        KeyCode::Down => {
            app.tabs.matrix.search.next_match();
            if let Some(idx) = app.tabs.matrix.search.current_match_index() {
                app.tabs.matrix.selected_row = idx;
            }
        }
        KeyCode::Up => {
            app.tabs.matrix.search.prev_match();
            if let Some(idx) = app.tabs.matrix.search.current_match_index() {
                app.tabs.matrix.selected_row = idx;
            }
        }
        KeyCode::Char(c) => {
            app.tabs.matrix.search.push(c);
            update_matrix_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_matrix_search_matches(app: &mut App) {
    let query = &app.tabs.matrix.search.query;
    if query.is_empty() {
        app.tabs.matrix.search.error = None;
        app.tabs.matrix.search.update_matches(vec![]);
        return;
    }

    // Shared matcher: same substring/regex semantics as every other search.
    let matcher =
        match crate::tui::app_states::SearchMatcher::build(query, app.tabs.matrix.search.mode) {
            Ok(m) => {
                app.tabs.matrix.search.error = None;
                m
            }
            Err(e) => {
                app.tabs.matrix.search.error = Some(e);
                app.tabs.matrix.search.update_matches(vec![]);
                return;
            }
        };

    // Matches are DISPLAY positions so Enter selects the highlighted row
    // under any sort (mirrors update_multi_diff_search_matches).
    let matches: Vec<usize> = app
        .data
        .matrix_result
        .as_ref()
        .map_or_else(Vec::new, |result| {
            crate::tui::views::ordered_sbom_indices(result, &app.tabs.matrix)
                .iter()
                .enumerate()
                .filter(|(_, raw)| matcher.is_match(&result.sboms[**raw].name))
                .map(|(display, _)| display)
                .collect()
        });

    app.tabs.matrix.search.update_matches(matches);
}
