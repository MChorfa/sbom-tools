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

        // Component deep dive on the selected variable component. Handled
        // mode-locally so the modal opens WITH data: the global fallback
        // opened it with default collected_data, which rendered a permanently
        // hollow "Versions tracked: 0 / Targets present: 0" modal.
        KeyCode::Char('D') => {
            open_variable_component_deep_dive(app);
        }

        _ => return false,
    }
    true
}

/// Open the component deep dive for the selected variable component with its
/// data sections filled from the multi-diff result: per-SBOM versions, target
/// presence (from the engine's presence map — never from diff buckets, where
/// "removed" means the target LACKS the component), and the component's
/// vulnerability appearances across the pairwise diffs.
fn open_variable_component_deep_dive(app: &mut App) {
    use crate::tui::app_states::{
        ComponentTargetPresence, ComponentVersionEntry, ComponentVulnInfo,
    };

    struct Collected {
        name: String,
        id: String,
        presence: Vec<ComponentTargetPresence>,
        versions: Vec<ComponentVersionEntry>,
        vulns: Vec<ComponentVulnInfo>,
    }

    let collected = app.data.multi_diff_result.as_ref().and_then(|result| {
        let vc = result
            .summary
            .variable_components
            .get(app.tabs.multi_diff.selected_variable_component)?;

        let mut versions = vec![ComponentVersionEntry {
            version: vc
                .version_spread
                .baseline
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            sbom_label: result.baseline.name.clone(),
            date: result.baseline.timestamp.clone(),
            change_type: "baseline".to_string(),
        }];
        let mut presence = Vec::new();
        let mut vulns: Vec<ComponentVulnInfo> = Vec::new();

        for comp in &result.comparisons {
            let is_present = vc
                .targets_with_component
                .iter()
                .any(|t| t == &comp.target.name);
            // The target's own version: the pairwise change entry when the
            // diff touched it, else unchanged from baseline.
            let change = comp
                .diff
                .components
                .modified
                .iter()
                .map(|c| (c, "modified"))
                .chain(comp.diff.components.added.iter().map(|c| (c, "added")))
                .find(|(c, _)| crate::diff::strip_purl_version(&c.id) == vc.id);
            let version = change.and_then(|(c, _)| c.new_version.clone()).or_else(|| {
                if is_present {
                    vc.version_spread.baseline.clone()
                } else {
                    None
                }
            });

            if is_present {
                versions.push(ComponentVersionEntry {
                    version: version.clone().unwrap_or_else(|| "-".to_string()),
                    sbom_label: comp.target.name.clone(),
                    date: comp.target.timestamp.clone(),
                    change_type: change.map_or("unchanged", |(_, ct)| ct).to_string(),
                });
            }
            presence.push(ComponentTargetPresence {
                target_name: comp.target.name.clone(),
                version: version.clone(),
                is_present,
                deviation_from_baseline: result
                    .summary
                    .deviation_scores
                    .get(&comp.target.name)
                    .map(|d| format!("target deviates {:.1}%", d * 100.0)),
            });

            for (status, list) in [
                ("introduced", &comp.diff.vulnerabilities.introduced),
                ("resolved", &comp.diff.vulnerabilities.resolved),
            ] {
                for v in list.iter().filter(|v| v.component_name == vc.name) {
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
            name: vc.name.clone(),
            id: vc.id.clone(),
            presence,
            versions,
            vulns,
        })
    });

    if let Some(c) = collected {
        app.overlays.component_deep_dive.open(c.name, Some(c.id));
        let data = &mut app.overlays.component_deep_dive.collected_data;
        data.target_presence = c.presence;
        data.version_history = c.versions;
        data.vulnerabilities = c.vulns;
    } else {
        app.set_status_message("No variable component selected for deep dive");
    }
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
#[cfg(test)]
mod deep_dive_tests {
    use crate::tui::events::handle_key_event;
    use crate::tui::test_support::{demo_multi_diff, pin_theme};
    use crate::tui::{App, TabKind};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// 'D' in MultiDiff mode opens the deep dive WITH data: real component id,
    /// per-SBOM versions, and presence that never counts a removed-from-target
    /// component as present.
    #[test]
    fn deep_dive_opens_populated_and_presence_honest() {
        pin_theme();
        let mut app = App::new_multi_diff(demo_multi_diff());
        app.active_tab = TabKind::Summary; // deterministic tab dispatch

        let idx = app
            .data
            .multi_diff_result
            .as_ref()
            .expect("multi-diff data")
            .summary
            .variable_components
            .iter()
            .position(|vc| vc.name == "acme-webapp")
            .expect("acme-webapp is variable in the demo fixture");
        app.tabs.multi_diff.selected_variable_component = idx;

        handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE),
        );
        let dive = &app.overlays.component_deep_dive;
        assert!(dive.visible, "'D' must open the deep dive");
        assert_eq!(dive.component_name, "acme-webapp");
        assert!(
            dive.component_id.is_some(),
            "the modal must not render 'ID: Unknown'"
        );

        let data = &dive.collected_data;
        assert!(
            !data.version_history.is_empty(),
            "'Versions tracked: 0' hollow modal must be gone"
        );
        let webapp = data
            .target_presence
            .iter()
            .find(|p| p.target_name == "webapp")
            .expect("webapp presence entry");
        assert!(webapp.is_present);
        assert_eq!(webapp.version.as_deref(), Some("2.0.0"));
        let ai = data
            .target_presence
            .iter()
            .find(|p| p.target_name == "ai-service")
            .expect("ai-service presence entry");
        assert!(
            !ai.is_present,
            "ai-service lacks acme-webapp; presence must not be derived from \
             the pair diff's removed bucket"
        );
    }
}
