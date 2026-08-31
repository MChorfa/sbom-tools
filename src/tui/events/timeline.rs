//! Timeline mode event handlers.

use crate::tui::App;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub(super) fn handle_timeline_keys(app: &mut App, key: KeyEvent) -> bool {
    // Handle search input mode
    if app.tabs.timeline.search.active {
        handle_timeline_search(app, key);
        return true;
    }

    // Handle jump mode
    if app.tabs.timeline.jump_mode {
        handle_timeline_jump(app, key);
        return true;
    }

    // Handle version diff modal
    if app.tabs.timeline.show_version_diff_modal {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.timeline.close_version_diff_modal();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                // Move compare version left
                if let Some(v) = app.tabs.timeline.compare_version
                    && v > 0
                    && v - 1 != app.tabs.timeline.selected_version
                {
                    app.tabs.timeline.set_compare_version(v - 1);
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                // Move compare version right
                if let Some(v) = app.tabs.timeline.compare_version
                    && v + 1 < app.tabs.timeline.total_versions
                    && v + 1 != app.tabs.timeline.selected_version
                {
                    app.tabs.timeline.set_compare_version(v + 1);
                }
            }
            _ => {}
        }
        // Modal swallows all keys so none leak to the global fallback.
        return true;
    }

    // Handle component history modal
    if app.tabs.timeline.show_component_history {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.tabs.timeline.close_component_history();
            }
            _ => {}
        }
        return true;
    }

    match key.code {
        // Navigation
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('p') => app.tabs.timeline.toggle_panel(),
        KeyCode::Up | KeyCode::Char('k') => app.tabs.timeline.select_prev(),
        KeyCode::Down | KeyCode::Char('j') => app.tabs.timeline.select_next(),

        // Search
        KeyCode::Char('/') => {
            app.tabs.timeline.search.start();
        }

        // In-place match cycling after Enter confirmed a search.
        KeyCode::Char('n') if !app.tabs.timeline.search.matches.is_empty() => {
            app.tabs.timeline.search.next_match();
            if let Some(idx) = app.tabs.timeline.search.current_match_index() {
                app.tabs.timeline.selected_version = idx;
            }
        }
        KeyCode::Char('N') if !app.tabs.timeline.search.matches.is_empty() => {
            app.tabs.timeline.search.prev_match();
            if let Some(idx) = app.tabs.timeline.search.current_match_index() {
                app.tabs.timeline.selected_version = idx;
            }
        }

        // Sort and filter
        KeyCode::Char('s') => {
            app.tabs.timeline.toggle_sort();
            // Search matches are display positions; recompute under the new order.
            update_timeline_search_matches(app);
            app.set_status_message(format!(
                "Sort: {} {}",
                app.tabs.timeline.sort_by.label(),
                app.tabs.timeline.sort_direction.indicator()
            ));
        }
        KeyCode::Char('S') => {
            app.tabs.timeline.toggle_sort_direction();
            update_timeline_search_matches(app);
        }
        KeyCode::Char('f') => {
            app.tabs.timeline.toggle_component_filter();
            // The filter changes how many components are visible; keep the
            // navigation bound and the selection in sync with the filtered
            // list (mirrors the multi-diff 'f' resync).
            if let Some(result) = app.data.timeline_result.as_ref() {
                let visible = crate::tui::views::filtered_evolution_entries(
                    result,
                    app.tabs.timeline.component_filter,
                )
                .len();
                app.tabs.timeline.total_components = visible;
                if app.tabs.timeline.selected_component >= visible {
                    app.tabs.timeline.selected_component = visible.saturating_sub(1);
                }
            }
            app.set_status_message(format!(
                "Filter: {}",
                app.tabs.timeline.component_filter.label()
            ));
        }

        // Version diff modal
        KeyCode::Char('d') => {
            app.tabs.timeline.toggle_version_diff_modal();
        }

        // Chart metric
        KeyCode::Char('m') => {
            app.tabs.timeline.chart_metric = app.tabs.timeline.chart_metric.next();
            app.set_status_message(format!(
                "Chart metric: {}",
                app.tabs.timeline.chart_metric.label()
            ));
        }

        // Statistics panel
        KeyCode::Char('t') => {
            app.tabs.timeline.toggle_statistics();
            let status = if app.tabs.timeline.show_statistics {
                "Statistics: shown"
            } else {
                "Statistics: hidden"
            };
            app.set_status_message(status.to_string());
        }

        // Component history detail. Guarded: with a filter yielding zero
        // entries the modal would clear its rect and render nothing — an
        // invisible overlay that swallows every key except Esc/q.
        KeyCode::Enter | KeyCode::Char(' ') => {
            if app.tabs.timeline.total_components > 0 {
                app.tabs.timeline.toggle_component_history();
            } else {
                app.set_status_message("No components match the current filter");
            }
        }

        // Jump to version
        KeyCode::Char('g') => {
            app.tabs.timeline.start_jump_mode();
        }

        // Chart zoom
        KeyCode::Char('+' | '=') => {
            app.tabs.timeline.zoom_in();
            app.set_status_message(format!("Zoom: {}x", app.tabs.timeline.chart_zoom));
        }
        KeyCode::Char('-' | '_') => {
            app.tabs.timeline.zoom_out();
            app.set_status_message(format!("Zoom: {}x", app.tabs.timeline.chart_zoom));
        }

        // Chart scroll
        KeyCode::Left | KeyCode::Char('h') => {
            app.tabs.timeline.scroll_chart_left();
        }
        KeyCode::Right | KeyCode::Char('l') => {
            app.tabs.timeline.scroll_chart_right();
        }

        // Component deep dive on the selected (filtered) component. Handled
        // mode-locally so the modal opens WITH its version history: the
        // global fallback opened it with default collected_data, which
        // rendered a permanently hollow "Versions tracked: 0" modal.
        KeyCode::Char('D') => {
            open_timeline_component_deep_dive(app);
        }

        _ => return false,
    }
    true
}

/// Open the component deep dive for the selected component with the Versions
/// and Vulnerabilities sections filled from the timeline result.
fn open_timeline_component_deep_dive(app: &mut App) {
    use crate::diff::VersionChangeType;
    use crate::tui::app_states::{ComponentVersionEntry, ComponentVulnInfo};

    struct Collected {
        name: String,
        id: String,
        versions: Vec<ComponentVersionEntry>,
        vulns: Vec<ComponentVulnInfo>,
    }

    let collected = app.data.timeline_result.as_ref().and_then(|result| {
        // Resolve through the SAME filtered list the Components panel
        // displays, so the deep dive matches the highlighted row.
        let entries = crate::tui::views::filtered_evolution_entries(
            result,
            app.tabs.timeline.component_filter,
        );
        let (evo, _) = entries.get(app.tabs.timeline.selected_component)?;

        let versions: Vec<ComponentVersionEntry> = result
            .evolution_summary
            .version_history
            .get(&evo.id)
            .map(|history| {
                history
                    .iter()
                    // Absent points (before first appearance / after removal)
                    // carry no information for the version list.
                    .filter(|p| !matches!(p.change_type, VersionChangeType::Absent))
                    .map(|p| ComponentVersionEntry {
                        version: p.version.clone().unwrap_or_else(|| "-".to_string()),
                        sbom_label: p.sbom_name.clone(),
                        date: result
                            .sboms
                            .get(p.sbom_index)
                            .and_then(|s| s.timestamp.clone()),
                        change_type: match p.change_type {
                            VersionChangeType::Initial => "added",
                            VersionChangeType::Removed => "removed",
                            VersionChangeType::Unchanged => "unchanged",
                            VersionChangeType::Absent => "absent",
                            _ => "modified",
                        }
                        .to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut vulns: Vec<ComponentVulnInfo> = Vec::new();
        for diff in &result.incremental_diffs {
            for (status, list) in [
                ("introduced", &diff.vulnerabilities.introduced),
                ("resolved", &diff.vulnerabilities.resolved),
            ] {
                for v in list.iter().filter(|v| v.component_name == evo.name) {
                    vulns.push(ComponentVulnInfo {
                        vuln_id: v.id.clone(),
                        severity: v.severity.clone(),
                        status: status.to_string(),
                        description: None,
                    });
                }
            }
        }
        vulns.sort_by(|a, b| (&a.vuln_id, &a.status).cmp(&(&b.vuln_id, &b.status)));
        vulns.dedup_by(|a, b| a.vuln_id == b.vuln_id && a.status == b.status);

        Some(Collected {
            name: evo.name.clone(),
            id: evo.id.clone(),
            versions,
            vulns,
        })
    });

    if let Some(c) = collected {
        app.overlays.component_deep_dive.open(c.name, Some(c.id));
        let data = &mut app.overlays.component_deep_dive.collected_data;
        data.version_history = c.versions;
        data.vulnerabilities = c.vulns;
    } else {
        app.set_status_message("No component selected for deep dive");
    }
}

pub(super) fn handle_timeline_search(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.timeline.search.cancel();
        }
        KeyCode::Enter => {
            app.tabs.timeline.search.confirm();
            if let Some(idx) = app.tabs.timeline.search.current_match_index() {
                app.tabs.timeline.selected_version = idx;
            }
        }
        KeyCode::Backspace => {
            app.tabs.timeline.search.pop();
            update_timeline_search_matches(app);
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.tabs.timeline.search.toggle_mode();
            update_timeline_search_matches(app);
            app.set_status_message(format!(
                "Search mode: {}",
                app.tabs.timeline.search.mode.label()
            ));
        }
        // Live preview: Up/Down move the visible selection through the
        // matches before Enter confirms (one mental model everywhere).
        KeyCode::Down => {
            app.tabs.timeline.search.next_match();
            if let Some(idx) = app.tabs.timeline.search.current_match_index() {
                app.tabs.timeline.selected_version = idx;
            }
        }
        KeyCode::Up => {
            app.tabs.timeline.search.prev_match();
            if let Some(idx) = app.tabs.timeline.search.current_match_index() {
                app.tabs.timeline.selected_version = idx;
            }
        }
        KeyCode::Char(c) => {
            app.tabs.timeline.search.push(c);
            update_timeline_search_matches(app);
        }
        _ => {}
    }
}

pub(super) fn update_timeline_search_matches(app: &mut App) {
    let query = &app.tabs.timeline.search.query;
    if query.is_empty() {
        app.tabs.timeline.search.error = None;
        app.tabs.timeline.search.update_matches(vec![]);
        return;
    }

    // Shared matcher: same substring/regex semantics as every other search.
    let matcher =
        match crate::tui::app_states::SearchMatcher::build(query, app.tabs.timeline.search.mode) {
            Ok(m) => {
                app.tabs.timeline.search.error = None;
                m
            }
            Err(e) => {
                app.tabs.timeline.search.error = Some(e);
                app.tabs.timeline.search.update_matches(vec![]);
                return;
            }
        };

    // Matches are DISPLAY positions so Enter selects the highlighted row
    // under any sort.
    let matches: Vec<usize> = app
        .data
        .timeline_result
        .as_ref()
        .map_or_else(Vec::new, |result| {
            crate::tui::views::ordered_version_indices(result, &app.tabs.timeline)
                .iter()
                .enumerate()
                .filter(|(_, raw)| matcher.is_match(&result.sboms[**raw].name))
                .map(|(display, _)| display)
                .collect()
        });

    app.tabs.timeline.search.update_matches(matches);
}

pub(super) fn handle_timeline_jump(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.tabs.timeline.cancel_jump_mode();
        }
        KeyCode::Enter => {
            // Validate the input BEFORE execute_jump: a rejected jump leaves
            // the (display-index) selection untouched, and remapping it as if
            // it were a raw version would relocate the selection and lie.
            let target = app
                .tabs
                .timeline
                .jump_input
                .parse::<usize>()
                .ok()
                .map(|v| v.saturating_sub(1))
                .filter(|t| *t < app.tabs.timeline.total_versions);
            app.tabs.timeline.execute_jump();
            if let Some(raw) = target {
                // execute_jump sets a RAW (chronological) version; the
                // selection is a display index — map through the permutation.
                if let Some(result) = app.data.timeline_result.as_ref()
                    && let Some(display) =
                        crate::tui::views::ordered_version_indices(result, &app.tabs.timeline)
                            .iter()
                            .position(|&r| r == raw)
                {
                    app.tabs.timeline.selected_version = display;
                }
                app.set_status_message(format!("Jumped to version {}", raw + 1));
            } else {
                app.set_status_message("Invalid version number".to_string());
            }
        }
        KeyCode::Backspace => {
            app.tabs.timeline.jump_pop();
        }
        KeyCode::Char(c) => {
            app.tabs.timeline.jump_push(c);
        }
        _ => {}
    }
}
#[cfg(test)]
mod deep_dive_tests {
    use crate::tui::events::handle_key_event;
    use crate::tui::test_support::{demo_timeline, pin_theme};
    use crate::tui::{App, TabKind};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// 'D' in Timeline mode opens the deep dive WITH the component's real id
    /// and version history (it used to open with default collected_data and
    /// render "Versions tracked: 0 / No version history available" forever).
    #[test]
    fn deep_dive_opens_with_version_history() {
        pin_theme();
        let mut app = App::new_timeline(demo_timeline());
        app.active_tab = TabKind::Summary; // deterministic tab dispatch

        let expected = {
            let result = app.data.timeline_result.as_ref().expect("timeline data");
            crate::tui::views::filtered_evolution_entries(
                result,
                app.tabs.timeline.component_filter,
            )[0]
            .0
            .name
            .clone()
        };

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE),
        );
        let dive = &app.overlays.component_deep_dive;
        assert!(dive.visible, "'D' must open the deep dive");
        assert_eq!(
            dive.component_name, expected,
            "must resolve the same entry the Components panel highlights"
        );
        assert!(
            dive.component_id.is_some(),
            "the modal must not render 'ID: Unknown'"
        );
        assert!(
            !dive.collected_data.version_history.is_empty(),
            "the Versions section must carry the timeline's real history"
        );
    }
}
