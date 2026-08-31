//! Cross-view helper functions.

use crate::tui::{App, AppMode};

/// What the deep dive should open, resolved from the ACTIVE tab's own
/// selection (#203). Tabs whose rows are not component-shaped (Licenses,
/// Quality, Compliance, Summary, SideBySide, Source) have no target.
enum DeepDiveTarget {
    /// The Components tab's own filtered+sorted list index.
    ComponentsSelection,
    /// A component resolved by id + name from another tab's selected row
    /// (Graph Changes, Vulnerabilities).
    Named { id: String, name: String },
}

/// Open the component deep dive for the active tab's current selection,
/// populated from the loaded diff: old/new version entries, per-side
/// presence, attached vulnerabilities, and dependency edges. Shared by the
/// global 'D' binding and Enter on the Components tab.
///
/// The target is resolved from the ACTIVE tab's context: Components uses its
/// own selection, Graph Changes and Vulnerabilities use their selected row's
/// component, and tabs with no component-shaped selection get an explanatory
/// status message instead of silently opening the hidden Components-tab
/// selection (#203).
pub(super) fn open_diff_component_deep_dive(app: &mut App) {
    use crate::tui::app::TabKind;
    use crate::tui::app_states::{
        ComponentTargetPresence, ComponentVersionEntry, ComponentVulnInfo,
    };

    struct Collected {
        name: String,
        id: String,
        versions: Vec<ComponentVersionEntry>,
        presence: Vec<ComponentTargetPresence>,
        vulns: Vec<ComponentVulnInfo>,
        dependencies: Vec<String>,
        dependents: Vec<String>,
    }

    let target = match app.active_tab {
        TabKind::Components => DeepDiveTarget::ComponentsSelection,
        TabKind::GraphChanges => {
            let idx = app.graph_changes_state().selected;
            let selected = app
                .data
                .diff_result
                .as_ref()
                .and_then(|r| r.graph_changes.get(idx))
                .map(|gc| (gc.component_id.to_string(), gc.component_name.clone()));
            match selected {
                Some((id, name)) => DeepDiveTarget::Named { id, name },
                None => {
                    app.set_status_message("No graph change selected for deep dive");
                    return;
                }
            }
        }
        TabKind::Vulnerabilities => match selected_vulnerability_component(app) {
            Some((id, name)) => DeepDiveTarget::Named { id, name },
            None => {
                app.set_status_message("No vulnerability selected for deep dive");
                return;
            }
        },
        _ => {
            app.set_status_message("Deep dive: select a component on the Components tab");
            return;
        }
    };
    // Remember the Named target's name so a miss (component present in the
    // SBOMs but absent from the change lists) can be explained by name.
    let named = match &target {
        DeepDiveTarget::Named { name, .. } => Some(name.clone()),
        DeepDiveTarget::ComponentsSelection => None,
    };

    let collected = app.data.diff_result.as_ref().and_then(|result| {
        let comp = match &target {
            DeepDiveTarget::ComponentsSelection => {
                let idx = app.components_state().selected;
                let items = app.diff_component_items(app.components_state().filter);
                items.get(idx).copied()
            }
            DeepDiveTarget::Named { id, name } => result
                .components
                .added
                .iter()
                .chain(result.components.removed.iter())
                .chain(result.components.modified.iter())
                .find(|c| c.id == *id || c.name == *name),
        }?;

        let change_label = match comp.change_type {
            crate::diff::ChangeType::Added => "added",
            crate::diff::ChangeType::Removed => "removed",
            crate::diff::ChangeType::Modified => "modified",
            crate::diff::ChangeType::Unchanged => "unchanged",
        };
        let side_label = |sbom: Option<&crate::model::NormalizedSbom>, fallback: &str| {
            sbom.and_then(|s| s.document.name.clone())
                .unwrap_or_else(|| fallback.to_string())
        };
        let old_label = side_label(app.data.old_sbom.as_ref(), "Old SBOM");
        let new_label = side_label(app.data.new_sbom.as_ref(), "New SBOM");

        let in_old = comp.change_type != crate::diff::ChangeType::Added;
        let in_new = comp.change_type != crate::diff::ChangeType::Removed;

        let mut versions = Vec::new();
        if in_old {
            versions.push(ComponentVersionEntry {
                version: comp.old_version.clone().unwrap_or_else(|| "-".to_string()),
                sbom_label: old_label.clone(),
                date: None,
                change_type: if in_new { "modified" } else { "removed" }.to_string(),
            });
        }
        if in_new {
            versions.push(ComponentVersionEntry {
                version: comp.new_version.clone().unwrap_or_else(|| "-".to_string()),
                sbom_label: new_label.clone(),
                date: None,
                change_type: change_label.to_string(),
            });
        }

        let presence = vec![
            ComponentTargetPresence {
                target_name: old_label,
                version: comp.old_version.clone(),
                is_present: in_old,
                deviation_from_baseline: None,
            },
            ComponentTargetPresence {
                target_name: new_label,
                version: comp.new_version.clone(),
                is_present: in_new,
                deviation_from_baseline: None,
            },
        ];

        let mut vulns = Vec::new();
        for (status, list) in [
            ("introduced", &result.vulnerabilities.introduced),
            ("resolved", &result.vulnerabilities.resolved),
            ("persistent", &result.vulnerabilities.persistent),
        ] {
            for v in list.iter().filter(|v| v.component_id == comp.id) {
                vulns.push(ComponentVulnInfo {
                    vuln_id: v.id.clone(),
                    severity: v.severity.clone(),
                    status: status.to_string(),
                    description: v.description.clone(),
                });
            }
        }

        let deps_state = app.dependencies_state();
        let dependencies = deps_state
            .cached_graph
            .get(comp.id.as_str())
            .cloned()
            .unwrap_or_default();
        let dependents = deps_state
            .cached_reverse_graph
            .get(comp.id.as_str())
            .cloned()
            .unwrap_or_default();

        Some(Collected {
            name: comp.name.clone(),
            id: comp.id.clone(),
            versions,
            presence,
            vulns,
            dependencies,
            dependents,
        })
    });

    if let Some(c) = collected {
        app.overlays.component_deep_dive.open(c.name, Some(c.id));
        let data = &mut app.overlays.component_deep_dive.collected_data;
        data.version_history = c.versions;
        data.target_presence = c.presence;
        data.vulnerabilities = c.vulns;
        data.dependencies = c.dependencies;
        data.dependents = c.dependents;
    } else if let Some(name) = named {
        // The row resolved to a component, but it has no entry in the change
        // lists (e.g. a persistent vulnerability on an unchanged component).
        app.set_status_message(format!("Deep dive: {name} is unchanged in this diff"));
    } else {
        app.set_status_message("No component selected for deep dive");
    }
}

/// Resolve the Vulnerabilities tab's selected row to its component
/// `(id, name)`, honoring flat vs grouped display.
///
/// The grouped walk mirrors `resolve_grouped_selection` in
/// `events::vulnerabilities` (private to that module): groups keyed by
/// component name in first-seen order, sorted by best (lowest-rank) severity,
/// each header followed by its vulnerabilities only when expanded. A header
/// row resolves to the group's component.
fn selected_vulnerability_component(app: &mut App) -> Option<(String, String)> {
    use crate::tui::shared::vulnerabilities::severity_rank;

    let selected = app.vulnerabilities_state().selected;
    app.ensure_vulnerability_cache();
    let items = app.diff_vulnerability_items_from_cache();

    if !app.vulnerabilities_state().group_by_component {
        let item = items.get(selected)?;
        return Some((
            item.vuln.component_id.clone(),
            item.vuln.component_name.clone(),
        ));
    }

    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    let mut group_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, item) in items.iter().enumerate() {
        let name = &item.vuln.component_name;
        if let Some(&group_idx) = group_map.get(name) {
            groups[group_idx].1.push(idx);
        } else {
            group_map.insert(name.clone(), groups.len());
            groups.push((name.clone(), vec![idx]));
        }
    }
    groups.sort_by(|a, b| {
        let best = |g: &(String, Vec<usize>)| {
            g.1.iter()
                .filter_map(|&i| items.get(i))
                .map(|it| severity_rank(&it.vuln.severity))
                .min()
                .unwrap_or(99)
        };
        best(a).cmp(&best(b))
    });

    let mut pos = 0;
    for (comp_name, vuln_indices) in &groups {
        let first = vuln_indices.first().and_then(|&i| items.get(i))?;
        if pos == selected {
            return Some((first.vuln.component_id.clone(), comp_name.clone()));
        }
        pos += 1;
        if app.vulnerabilities_state().is_group_expanded(comp_name) {
            for &idx in vuln_indices {
                if pos == selected {
                    let item = items.get(idx)?;
                    return Some((
                        item.vuln.component_id.clone(),
                        item.vuln.component_name.clone(),
                    ));
                }
                pos += 1;
            }
        }
    }
    None
}

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
