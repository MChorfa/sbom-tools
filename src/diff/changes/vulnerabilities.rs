//! Vulnerability change computer implementation.

use crate::diff::VulnerabilityDetail;
use crate::diff::result::VexStatusChange;
use crate::diff::traits::{ChangeComputer, ComponentMatches, VulnerabilityChangeSet};
use crate::model::{CanonicalId, NormalizedSbom};
use std::collections::{HashMap, HashSet, VecDeque};

/// Computes vulnerability-level changes between SBOMs.
pub struct VulnerabilityChangeComputer;

impl VulnerabilityChangeComputer {
    /// Create a new vulnerability change computer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for VulnerabilityChangeComputer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute component depths from SBOM dependency edges using BFS.
/// Returns a map of component ID -> depth (1 = direct, 2+ = transitive).
fn compute_depths(sbom: &NormalizedSbom) -> HashMap<CanonicalId, u32> {
    let mut depths = HashMap::with_capacity(sbom.components.len());

    // Build forward edge map: parent -> [children]
    let mut edges: HashMap<&CanonicalId, Vec<&CanonicalId>> =
        HashMap::with_capacity(sbom.components.len());
    let mut has_parents: HashSet<&CanonicalId> = HashSet::with_capacity(sbom.components.len());

    for edge in &sbom.edges {
        edges.entry(&edge.from).or_default().push(&edge.to);
        has_parents.insert(&edge.to);
    }

    // Find roots (components with no incoming edges)
    let roots: Vec<&CanonicalId> = sbom
        .components
        .keys()
        .filter(|id| !has_parents.contains(id))
        .collect();

    // BFS from roots to compute minimum depths
    let mut queue: VecDeque<(&CanonicalId, u32)> = VecDeque::new();

    // Roots are at depth 0 (the "product" level)
    for root in &roots {
        queue.push_back((*root, 0));
    }

    while let Some((id, depth)) = queue.pop_front() {
        // Skip if we've already found a shorter path
        if let Some(&existing) = depths.get(id)
            && depth >= existing
        {
            continue;
        }
        depths.insert(id.clone(), depth);

        // Process children at depth + 1
        if let Some(children) = edges.get(id) {
            for child in children {
                let child_depth = depth + 1;
                // Only queue if we haven't seen a shorter path
                if depths.get(*child).is_none_or(|&d| d > child_depth) {
                    queue.push_back((*child, child_depth));
                }
            }
        }
    }

    depths
}

impl ChangeComputer for VulnerabilityChangeComputer {
    type ChangeSet = VulnerabilityChangeSet;

    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        _matches: &ComponentMatches,
    ) -> VulnerabilityChangeSet {
        let mut result = VulnerabilityChangeSet::new();

        // Compute component depths for both SBOMs
        let old_depths = compute_depths(old);
        let new_depths = compute_depths(new);

        // Estimate vulnerability counts for pre-allocation
        let old_vuln_count: usize = old
            .components
            .values()
            .map(|c| c.vulnerabilities.len())
            .sum();
        let new_vuln_count: usize = new
            .components
            .values()
            .map(|c| c.vulnerabilities.len())
            .sum();

        // Collect old vulnerabilities with depth info
        let mut old_vulns: HashMap<String, VulnerabilityDetail> =
            HashMap::with_capacity(old_vuln_count);
        for (id, comp) in &old.components {
            let depth = old_depths.get(id).copied();
            for vuln in &comp.vulnerabilities {
                let key = format!("{}:{}", vuln.id, id);
                old_vulns.insert(
                    key,
                    VulnerabilityDetail::from_ref_with_depth(vuln, comp, depth),
                );
            }
        }

        // Collect new vulnerabilities with depth info
        let mut new_vulns: HashMap<String, VulnerabilityDetail> =
            HashMap::with_capacity(new_vuln_count);
        for (id, comp) in &new.components {
            let depth = new_depths.get(id).copied();
            for vuln in &comp.vulnerabilities {
                let key = format!("{}:{}", vuln.id, id);
                new_vulns.insert(
                    key,
                    VulnerabilityDetail::from_ref_with_depth(vuln, comp, depth),
                );
            }
        }

        // Find introduced vulnerabilities (in new but not old)
        for detail in new_vulns.values() {
            // Check by vuln ID only (component might have been renamed/matched)
            let vuln_id = &detail.id;
            let exists_in_old = old_vulns.values().any(|v| &v.id == vuln_id);
            if !exists_in_old {
                result.introduced.push(detail.clone());
            }
        }

        // Find resolved vulnerabilities (in old but not new)
        for detail in old_vulns.values() {
            let vuln_id = &detail.id;
            let exists_in_new = new_vulns.values().any(|v| &v.id == vuln_id);
            if !exists_in_new {
                result.resolved.push(detail.clone());
            }
        }

        // Find persistent vulnerabilities (in both)
        let mut vex_changes = Vec::new();
        for (key, detail) in &new_vulns {
            let vuln_id = &detail.id;
            let exists_in_old = old_vulns.values().any(|v| &v.id == vuln_id);
            if exists_in_old {
                result.persistent.push(detail.clone());

                // Compare VEX states between old and new for this vuln+component pair
                if let Some(old_detail) = old_vulns.get(key)
                    && old_detail.vex_state != detail.vex_state
                {
                    vex_changes.push(VexStatusChange {
                        vuln_id: detail.id.clone(),
                        component_name: detail.component_name.clone(),
                        old_state: old_detail.vex_state.clone(),
                        new_state: detail.vex_state.clone(),
                    });
                }
            }
        }
        result.vex_changes = vex_changes;

        // Sort by severity
        result.sort_by_severity();

        result
    }

    fn name(&self) -> &'static str {
        "VulnerabilityChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_change_computer_default() {
        let computer = VulnerabilityChangeComputer;
        assert_eq!(computer.name(), "VulnerabilityChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = VulnerabilityChangeComputer;
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }

    #[test]
    fn test_vex_state_change_detection() {
        use crate::model::{Component, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource};

        let computer = VulnerabilityChangeComputer;

        // Build old SBOM with a vuln that has VexState::NotAffected
        let mut old_comp = Component::new("libfoo".to_string(), "pkg:npm/libfoo@1.0".to_string());
        let old_vuln = VulnerabilityRef::new("CVE-2023-1234".to_string(), VulnerabilitySource::Osv)
            .with_vex_status(VexStatus::new(VexState::NotAffected));
        old_comp.vulnerabilities.push(old_vuln);

        let mut old_sbom = NormalizedSbom::default();
        let old_id = old_comp.canonical_id.clone();
        old_sbom.components.insert(old_id, old_comp);

        // Build new SBOM with the same vuln but VexState::Affected
        let mut new_comp = Component::new("libfoo".to_string(), "pkg:npm/libfoo@1.0".to_string());
        let new_vuln = VulnerabilityRef::new("CVE-2023-1234".to_string(), VulnerabilitySource::Osv)
            .with_vex_status(VexStatus::new(VexState::Affected));
        new_comp.vulnerabilities.push(new_vuln);

        let mut new_sbom = NormalizedSbom::default();
        let new_id = new_comp.canonical_id.clone();
        new_sbom.components.insert(new_id, new_comp);

        let matches = ComponentMatches::new();
        let result = computer.compute(&old_sbom, &new_sbom, &matches);

        // The vuln should appear as persistent (present in both SBOMs)
        assert_eq!(result.persistent.len(), 1);
        assert!(result.introduced.is_empty());
        assert!(result.resolved.is_empty());

        // A VEX state change should be detected
        assert_eq!(result.vex_changes.len(), 1);
        let change = &result.vex_changes[0];
        assert_eq!(change.vuln_id, "CVE-2023-1234");
        assert_eq!(change.component_name, "libfoo");
        assert_eq!(change.old_state, Some(VexState::NotAffected));
        assert_eq!(change.new_state, Some(VexState::Affected));
    }

    #[test]
    fn test_no_vex_change_when_states_equal() {
        use crate::model::{Component, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource};

        let computer = VulnerabilityChangeComputer;

        // Both SBOMs have the same VEX state
        let mut old_comp = Component::new("libbar".to_string(), "pkg:npm/libbar@2.0".to_string());
        let old_vuln = VulnerabilityRef::new("CVE-2023-5678".to_string(), VulnerabilitySource::Nvd)
            .with_vex_status(VexStatus::new(VexState::Fixed));
        old_comp.vulnerabilities.push(old_vuln);

        let mut old_sbom = NormalizedSbom::default();
        let old_id = old_comp.canonical_id.clone();
        old_sbom.components.insert(old_id, old_comp);

        let mut new_comp = Component::new("libbar".to_string(), "pkg:npm/libbar@2.0".to_string());
        let new_vuln = VulnerabilityRef::new("CVE-2023-5678".to_string(), VulnerabilitySource::Nvd)
            .with_vex_status(VexStatus::new(VexState::Fixed));
        new_comp.vulnerabilities.push(new_vuln);

        let mut new_sbom = NormalizedSbom::default();
        let new_id = new_comp.canonical_id.clone();
        new_sbom.components.insert(new_id, new_comp);

        let matches = ComponentMatches::new();
        let result = computer.compute(&old_sbom, &new_sbom, &matches);

        assert_eq!(result.persistent.len(), 1);
        // No VEX changes since both have the same state
        assert!(result.vex_changes.is_empty());
    }

    #[test]
    fn test_vex_state_change_from_none_to_some() {
        use crate::model::{Component, VexState, VexStatus, VulnerabilityRef, VulnerabilitySource};

        let computer = VulnerabilityChangeComputer;

        // Old SBOM: vuln without any VEX status
        let mut old_comp = Component::new("libqux".to_string(), "pkg:npm/libqux@1.0".to_string());
        let old_vuln =
            VulnerabilityRef::new("CVE-2024-0001".to_string(), VulnerabilitySource::Ghsa);
        old_comp.vulnerabilities.push(old_vuln);

        let mut old_sbom = NormalizedSbom::default();
        let old_id = old_comp.canonical_id.clone();
        old_sbom.components.insert(old_id, old_comp);

        // New SBOM: same vuln now has VEX status UnderInvestigation
        let mut new_comp = Component::new("libqux".to_string(), "pkg:npm/libqux@1.0".to_string());
        let new_vuln =
            VulnerabilityRef::new("CVE-2024-0001".to_string(), VulnerabilitySource::Ghsa)
                .with_vex_status(VexStatus::new(VexState::UnderInvestigation));
        new_comp.vulnerabilities.push(new_vuln);

        let mut new_sbom = NormalizedSbom::default();
        let new_id = new_comp.canonical_id.clone();
        new_sbom.components.insert(new_id, new_comp);

        let matches = ComponentMatches::new();
        let result = computer.compute(&old_sbom, &new_sbom, &matches);

        assert_eq!(result.persistent.len(), 1);
        assert_eq!(result.vex_changes.len(), 1);
        let change = &result.vex_changes[0];
        assert_eq!(change.vuln_id, "CVE-2024-0001");
        assert_eq!(change.old_state, None);
        assert_eq!(change.new_state, Some(VexState::UnderInvestigation));
    }
}
