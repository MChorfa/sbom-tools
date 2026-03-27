//! Search-related methods for App.

use super::app::{App, TabKind};
use super::app_states::{
    ChangeType, ComponentFilter, DiffSearchResult, SearchMode, VulnChangeType, VulnFilter, VulnSort,
};

impl App {
    /// Start searching
    pub fn start_search(&mut self) {
        self.overlays.search.active = true;
        self.overlays.search.clear();
        self.overlays.show_help = false;
        self.overlays.show_export = false;
        self.overlays.show_legend = false;
    }

    /// Stop searching
    pub const fn stop_search(&mut self) {
        self.overlays.search.active = false;
    }

    /// Add character to search query
    pub fn search_push(&mut self, c: char) {
        self.overlays.search.push_char(c);
    }

    /// Remove character from search query
    pub fn search_pop(&mut self) {
        self.overlays.search.pop_char();
    }

    /// Execute search with current query
    pub fn execute_search(&mut self) {
        if self.overlays.search.query.len() < 2 {
            self.overlays.search.results.clear();
            return;
        }

        let query = &self.overlays.search.query;
        let query_lower = query.to_lowercase();
        let search_mode = self.overlays.search.mode;

        // Build a regex matcher when in regex mode; fall back to substring on
        // invalid patterns so the user sees an empty result set rather than a
        // panic.
        let regex_matcher = if search_mode == SearchMode::Regex {
            regex::RegexBuilder::new(query)
                .case_insensitive(true)
                .build()
                .ok()
        } else {
            None
        };

        // Closure that performs the appropriate match depending on mode.
        let matches_query = |text: &str| -> bool {
            match search_mode {
                SearchMode::Substring => text.to_lowercase().contains(&query_lower),
                SearchMode::Regex => regex_matcher.as_ref().is_some_and(|re| re.is_match(text)),
            }
        };

        let mut results = Vec::new();

        // Search through diff results if available (Diff mode)
        if let Some(ref diff) = self.data.diff_result {
            // Search added components
            for comp in &diff.components.added {
                if matches_query(&comp.name) {
                    results.push(DiffSearchResult::Component {
                        name: comp.name.clone(),
                        version: comp.new_version.clone(),
                        change_type: ChangeType::Added,
                    });
                }
            }

            // Search removed components
            for comp in &diff.components.removed {
                if matches_query(&comp.name) {
                    results.push(DiffSearchResult::Component {
                        name: comp.name.clone(),
                        version: comp.old_version.clone(),
                        change_type: ChangeType::Removed,
                    });
                }
            }

            // Search modified components
            for change in &diff.components.modified {
                if matches_query(&change.name) {
                    results.push(DiffSearchResult::Component {
                        name: change.name.clone(),
                        version: change.new_version.clone(),
                        change_type: ChangeType::Modified,
                    });
                }
            }

            // Search introduced vulnerabilities
            for vuln in &diff.vulnerabilities.introduced {
                if matches_query(&vuln.id) {
                    results.push(DiffSearchResult::Vulnerability {
                        id: vuln.id.clone(),
                        component_name: vuln.component_name.clone(),
                        severity: Some(vuln.severity.clone()),
                        change_type: VulnChangeType::Introduced,
                    });
                }
            }

            // Search resolved vulnerabilities
            for vuln in &diff.vulnerabilities.resolved {
                if matches_query(&vuln.id) {
                    results.push(DiffSearchResult::Vulnerability {
                        id: vuln.id.clone(),
                        component_name: vuln.component_name.clone(),
                        severity: Some(vuln.severity.clone()),
                        change_type: VulnChangeType::Resolved,
                    });
                }
            }

            // Search license changes (new licenses)
            for lic_change in &diff.licenses.new_licenses {
                if matches_query(&lic_change.license) {
                    let component_name = lic_change
                        .components
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "multiple".to_string());
                    results.push(DiffSearchResult::License {
                        license: lic_change.license.clone(),
                        component_name,
                        change_type: ChangeType::Added,
                    });
                }
            }

            // Search license changes (removed licenses)
            for lic_change in &diff.licenses.removed_licenses {
                if matches_query(&lic_change.license) {
                    let component_name = lic_change
                        .components
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "multiple".to_string());
                    results.push(DiffSearchResult::License {
                        license: lic_change.license.clone(),
                        component_name,
                        change_type: ChangeType::Removed,
                    });
                }
            }
        }

        // Search through single SBOM if available (View mode)
        if self.data.diff_result.is_none()
            && let Some(ref sbom) = self.data.sbom
        {
            // Search components by name
            for comp in sbom.components.values() {
                if matches_query(&comp.name) {
                    results.push(DiffSearchResult::Component {
                        name: comp.name.clone(),
                        version: comp.version.clone(),
                        change_type: ChangeType::Added, // reuse Added as "present"
                    });
                }
            }

            // Search vulnerabilities
            for comp in sbom.components.values() {
                for vuln in &comp.vulnerabilities {
                    if matches_query(&vuln.id) {
                        results.push(DiffSearchResult::Vulnerability {
                            id: vuln.id.clone(),
                            component_name: comp.name.clone(),
                            severity: vuln.severity.as_ref().map(|s| format!("{s:?}")),
                            change_type: VulnChangeType::Introduced, // reuse as "present"
                        });
                    }
                }
            }

            // Search licenses
            for comp in sbom.components.values() {
                for lic in &comp.licenses.declared {
                    if matches_query(&lic.expression) {
                        results.push(DiffSearchResult::License {
                            license: lic.expression.clone(),
                            component_name: comp.name.clone(),
                            change_type: ChangeType::Added, // reuse as "present"
                        });
                    }
                }
            }
        }

        // F2: Filter component results to match the current component filter.
        // Vulnerability and license results are kept regardless.
        let comp_filter = self.components_state().filter;
        if comp_filter != ComponentFilter::All {
            results.retain(|r| match r {
                DiffSearchResult::Component { change_type, .. } => match comp_filter {
                    ComponentFilter::Added => *change_type == ChangeType::Added,
                    ComponentFilter::Removed => *change_type == ChangeType::Removed,
                    ComponentFilter::Modified => *change_type == ChangeType::Modified,
                    // EolOnly/EolRisk don't map to search change types — keep all
                    _ => true,
                },
                // Keep vulnerability and license results regardless of filter
                DiffSearchResult::Vulnerability { .. } | DiffSearchResult::License { .. } => true,
            });
        }

        // Limit results
        results.truncate(50);
        self.overlays.search.results = results;
        self.overlays.search.selected = 0;
    }

    /// Jump to the currently selected search result
    pub fn jump_to_search_result(&mut self) {
        if let Some(result) = self
            .overlays
            .search
            .results
            .get(self.overlays.search.selected)
            .cloned()
        {
            match result {
                DiffSearchResult::Component {
                    name,
                    version,
                    change_type,
                    ..
                } => {
                    // Prefer matching by change type + version when possible
                    if let Some(index) =
                        self.find_component_index_all(&name, Some(change_type), version.as_deref())
                    {
                        self.components_state_mut().filter = ComponentFilter::All;
                        self.components_state_mut().selected = index;
                        self.select_tab(TabKind::Components);
                        self.stop_search();
                        return;
                    }

                    // Fall back to name-only match across all components
                    if let Some(index) = self.find_component_index_all(&name, None, None) {
                        self.components_state_mut().filter = ComponentFilter::All;
                        self.components_state_mut().selected = index;
                        self.select_tab(TabKind::Components);
                        self.stop_search();
                        return;
                    }

                    self.components_state_mut().filter = ComponentFilter::All;
                    self.select_tab(TabKind::Components);
                }
                DiffSearchResult::Vulnerability {
                    id, change_type, ..
                } => {
                    // Align filter/sort so the selection is stable
                    self.vulnerabilities_state_mut().sort_by = VulnSort::Id;
                    self.vulnerabilities_state_mut().filter = match change_type {
                        VulnChangeType::Introduced => VulnFilter::Introduced,
                        VulnChangeType::Resolved => VulnFilter::Resolved,
                    };

                    if let Some(index) = self.find_vulnerability_index(&id) {
                        self.vulnerabilities_state_mut().selected = index;
                    }

                    self.select_tab(TabKind::Vulnerabilities);
                }
                DiffSearchResult::License { license, .. } => {
                    // Find the license index
                    if let Some(ref diff) = self.data.diff_result {
                        let mut index = 0;

                        // Search new licenses first
                        for lic in &diff.licenses.new_licenses {
                            if lic.license == license {
                                self.licenses_state_mut().selected = index;
                                self.select_tab(TabKind::Licenses);
                                self.stop_search();
                                return;
                            }
                            index += 1;
                        }

                        // Then removed licenses
                        for lic in &diff.licenses.removed_licenses {
                            if lic.license == license {
                                self.licenses_state_mut().selected = index;
                                self.select_tab(TabKind::Licenses);
                                self.stop_search();
                                return;
                            }
                            index += 1;
                        }
                    }
                    self.select_tab(TabKind::Licenses);
                }
            }
            self.stop_search();
        }
    }
}
