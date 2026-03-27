//! Vulnerabilities state types.

use crate::tui::state::ListNavigation;

pub struct VulnerabilitiesState {
    pub selected: usize,
    pub total: usize,
    pub filter: VulnFilter,
    pub sort_by: VulnSort,
    /// Whether to group vulnerabilities by component
    pub group_by_component: bool,
    /// Set of expanded group component IDs
    pub expanded_groups: std::collections::HashSet<String>,
    /// Cached filter+sort key for invalidation
    pub cached_key: Option<(VulnFilter, VulnSort)>,
    /// Cached indices: (status, `index_into_status_vec`)
    pub cached_indices: Vec<(DiffVulnStatus, usize)>,
    /// Cached attack paths for the currently selected vulnerability: (component_name, paths)
    pub(crate) cached_attack_paths: Option<(String, Vec<crate::tui::security::AttackPath>)>,
    /// Hash of (filter, sort, group_by_component, expanded_groups) for grouped render cache invalidation.
    /// Updated in `invalidate_grouped_cache()` when any grouping-relevant state changes.
    pub(crate) grouped_cache_generation: u64,
    /// Advanced composable filter applied on top of the primary `VulnFilter`.
    pub advanced_filter: VulnFilterSpec,
}

impl VulnerabilitiesState {
    pub fn new(total: usize) -> Self {
        Self {
            selected: 0,
            total,
            filter: VulnFilter::All,
            sort_by: VulnSort::Severity,
            group_by_component: false,
            expanded_groups: std::collections::HashSet::new(),
            cached_key: None,
            cached_indices: Vec::new(),
            cached_attack_paths: None,
            grouped_cache_generation: 0,
            advanced_filter: VulnFilterSpec::default(),
        }
    }

    /// Invalidate the cached vulnerability indices.
    pub fn invalidate_cache(&mut self) {
        self.cached_key = None;
        self.cached_indices.clear();
        self.invalidate_grouped_cache();
    }

    /// Compute a hash of the current grouped-render-relevant state.
    fn compute_grouped_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.filter.hash(&mut hasher);
        self.sort_by.hash(&mut hasher);
        self.group_by_component.hash(&mut hasher);
        self.expanded_groups.len().hash(&mut hasher);
        // Hash expanded groups in sorted order for determinism
        let mut sorted: Vec<&String> = self.expanded_groups.iter().collect();
        sorted.sort();
        for g in sorted {
            g.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Bump the grouped cache generation if the grouping state has changed.
    /// Call this after any mutation to filter, sort, group_by_component, or expanded_groups.
    pub(crate) fn invalidate_grouped_cache(&mut self) {
        self.grouped_cache_generation = self.compute_grouped_hash();
    }

    /// Toggle grouped display mode
    pub fn toggle_grouped_mode(&mut self) {
        self.group_by_component = !self.group_by_component;
        self.selected = 0;
        self.invalidate_grouped_cache();
    }

    /// Toggle expansion of a group
    pub fn toggle_group(&mut self, component_id: &str) {
        if self.expanded_groups.contains(component_id) {
            self.expanded_groups.remove(component_id);
        } else {
            self.expanded_groups.insert(component_id.to_string());
        }
        self.invalidate_grouped_cache();
    }

    /// Expand all groups
    pub fn expand_all_groups(&mut self, group_ids: &[String]) {
        for id in group_ids {
            self.expanded_groups.insert(id.clone());
        }
        self.invalidate_grouped_cache();
    }

    /// Collapse all groups
    pub fn collapse_all_groups(&mut self) {
        self.expanded_groups.clear();
        self.invalidate_grouped_cache();
    }

    /// Check if a group is expanded
    pub fn is_group_expanded(&self, component_id: &str) -> bool {
        self.expanded_groups.contains(component_id)
    }

    pub fn toggle_filter(&mut self) {
        self.filter = self.filter.next();
        self.selected = 0;
        self.invalidate_cache();
    }

    pub fn toggle_sort(&mut self) {
        self.sort_by = self.sort_by.next();
        self.selected = 0;
        self.invalidate_cache();
    }
}

impl ListNavigation for VulnerabilitiesState {
    fn selected(&self) -> usize {
        self.selected
    }

    fn set_selected(&mut self, idx: usize) {
        self.selected = idx;
    }

    fn total(&self) -> usize {
        self.total
    }

    fn set_total(&mut self, total: usize) {
        self.total = total;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VulnFilter {
    All,
    Introduced,
    Resolved,
    Critical,
    High,
    /// Filter to KEV (Known Exploited Vulnerabilities) only
    Kev,
    /// Filter to direct dependencies only (depth == 1)
    Direct,
    /// Filter to transitive dependencies only (depth > 1)
    Transitive,
    /// Filter to VEX-actionable vulnerabilities (Affected, `UnderInvestigation`, or no VEX status)
    VexActionable,
}

impl VulnFilter {
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Introduced => "Introduced",
            Self::Resolved => "Resolved",
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Kev => "KEV",
            Self::Direct => "Direct",
            Self::Transitive => "Transitive",
            Self::VexActionable => "VEX Actionable",
        }
    }

    /// Cycle to next filter option
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::Introduced,
            Self::Introduced => Self::Resolved,
            Self::Resolved => Self::Critical,
            Self::Critical => Self::High,
            Self::High => Self::Kev,
            Self::Kev => Self::Direct,
            Self::Direct => Self::Transitive,
            Self::Transitive => Self::VexActionable,
            Self::VexActionable => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VulnSort {
    #[default]
    Severity,
    Id,
    Component,
    /// Sort by fix urgency (severity × blast radius)
    FixUrgency,
    /// Sort by CVSS score (highest first)
    CvssScore,
    /// Sort by SLA urgency (most overdue first)
    SlaUrgency,
}

impl VulnSort {
    pub const fn next(self) -> Self {
        match self {
            Self::Severity => Self::FixUrgency,
            Self::FixUrgency => Self::CvssScore,
            Self::CvssScore => Self::SlaUrgency,
            Self::SlaUrgency => Self::Component,
            Self::Component => Self::Id,
            Self::Id => Self::Severity,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Severity => "Severity",
            Self::FixUrgency => "Fix Urgency",
            Self::CvssScore => "CVSS Score",
            Self::SlaUrgency => "SLA Urgency",
            Self::Component => "Component",
            Self::Id => "ID",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffVulnStatus {
    Introduced,
    Resolved,
    Persistent,
}

impl DiffVulnStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Introduced => "Introduced",
            Self::Resolved => "Resolved",
            Self::Persistent => "Persistent",
        }
    }
}

pub struct DiffVulnItem<'a> {
    pub status: DiffVulnStatus,
    pub vuln: &'a crate::diff::VulnerabilityDetail,
}

/// Composable vulnerability filter with multiple criteria.
///
/// Applied as a secondary filter on top of the primary `VulnFilter` cycle.
/// When all fields are at their defaults the spec has no effect.
#[derive(Debug, Clone, Default)]
pub struct VulnFilterSpec {
    /// Filter by severity level (None = any severity).
    pub severity: Option<String>,
    /// Filter by change status (None = any status).
    pub status: Option<DiffVulnStatus>,
    /// Only show KEV (Known Exploited Vulnerabilities).
    pub kev_only: bool,
    /// Only show actionable vulns (exclude VEX `NotAffected`/`Fixed`).
    pub actionable_only: bool,
}

impl VulnFilterSpec {
    /// Returns `true` when no criteria are set (pass-through).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.severity.is_none() && self.status.is_none() && !self.kev_only && !self.actionable_only
    }

    /// Check whether a vulnerability item passes all active criteria.
    #[must_use]
    pub fn matches(&self, item: &DiffVulnItem<'_>) -> bool {
        // Severity filter
        if let Some(ref sev) = self.severity
            && !item.vuln.severity.eq_ignore_ascii_case(sev)
        {
            return false;
        }
        // Status filter
        if let Some(status) = self.status
            && item.status != status
        {
            return false;
        }
        // KEV filter
        if self.kev_only && !item.vuln.is_kev {
            return false;
        }
        // Actionable filter (exclude VEX NotAffected/Fixed)
        if self.actionable_only
            && let Some(ref vex) = item.vuln.vex_state
            && matches!(
                vex,
                crate::model::VexState::NotAffected | crate::model::VexState::Fixed
            )
        {
            return false;
        }
        true
    }
}
