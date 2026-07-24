//! Cross-view helper functions.

use crate::tui::{App, AppMode};

pub(super) fn get_selected_component_name(app: &App) -> Option<String> {
    match app.mode {
        AppMode::MultiDiff => {
            // Get selected component from multi-diff view
            if let Some(ref result) = app.data.multi_diff_result {
                let idx = app.tabs.multi_diff.selected_variable_component;
                if idx < result.summary.variable_components.len() {
                    return Some(result.summary.variable_components[idx].name.clone());
                }
            }
            None
        }
        AppMode::Timeline => {
            // Resolve through the same filtered list the Components panel
            // displays, so the name matches the highlighted row.
            if let Some(ref result) = app.data.timeline_result {
                let idx = app.tabs.timeline.selected_component;
                let entries = crate::tui::views::filtered_evolution_entries(
                    result,
                    app.tabs.timeline.component_filter,
                );
                if let Some((evo, _)) = entries.get(idx) {
                    return Some(evo.name.clone());
                }
            }
            None
        }
        AppMode::Matrix => {
            // Get SBOM name from selected row in matrix (display -> raw via
            // the sort permutation)
            if let Some(ref result) = app.data.matrix_result {
                let order = crate::tui::views::ordered_sbom_indices(result, &app.tabs.matrix);
                if let Some(&raw) = order.get(app.tabs.matrix.selected_row) {
                    return Some(result.sboms[raw].name.clone());
                }
            }
            None
        }
        AppMode::Diff => {
            // Resolve through the same filtered + sorted list the Components
            // table renders (the raw added->removed->modified concatenation
            // opened the wrong component's deep dive under any sort/filter).
            if app.data.diff_result.is_some() {
                let idx = app.components_state().selected;
                let items = app.diff_component_items(app.components_state().filter);
                if let Some(comp) = items.get(idx) {
                    return Some(comp.name.clone());
                }
            }
            None
        }
    }
}
