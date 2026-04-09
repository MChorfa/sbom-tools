//! Dependency change computer implementation.

use crate::diff::DependencyChange;
use crate::diff::traits::{ChangeComputer, ComponentMatches, DependencyChangeSet};
use crate::model::{DependencyEdge, NormalizedSbom};
use std::collections::HashSet;

type EdgeKey = (String, String, String, Option<String>);

/// Build a normalized edge key, optionally mapping IDs through component matches.
fn edge_key(edge: &DependencyEdge, matches: Option<&ComponentMatches>) -> EdgeKey {
    let from = if let Some(m) = matches {
        m.get(&edge.from)
            .and_then(|v| v.as_ref())
            .map_or_else(|| edge.from.to_string(), ToString::to_string)
    } else {
        edge.from.to_string()
    };
    let to = if let Some(m) = matches {
        m.get(&edge.to)
            .and_then(|v| v.as_ref())
            .map_or_else(|| edge.to.to_string(), ToString::to_string)
    } else {
        edge.to.to_string()
    };
    (
        from,
        to,
        edge.relationship.to_string(),
        edge.scope.as_ref().map(ToString::to_string),
    )
}

/// Computes dependency-level changes between SBOMs.
pub struct DependencyChangeComputer;

impl DependencyChangeComputer {
    /// Create a new dependency change computer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for DependencyChangeComputer {
    fn default() -> Self {
        Self::new()
    }
}

impl ChangeComputer for DependencyChangeComputer {
    type ChangeSet = DependencyChangeSet;

    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        matches: &ComponentMatches,
    ) -> DependencyChangeSet {
        let mut result = DependencyChangeSet::new();

        // Normalize old edges (map through component matches)
        let normalized_old_edges: HashSet<EdgeKey> = old
            .edges
            .iter()
            .map(|e| edge_key(e, Some(matches)))
            .collect();

        // Normalize new edges (no match mapping needed)
        let normalized_new_edges: HashSet<EdgeKey> =
            new.edges.iter().map(|e| edge_key(e, None)).collect();

        // Find added dependencies (in new but not in old)
        for edge in &new.edges {
            let key = edge_key(edge, None);
            if !normalized_old_edges.contains(&key) {
                result.added.push(DependencyChange::added(edge));
            }
        }

        // Find removed dependencies (in old but not in new)
        for edge in &old.edges {
            let key = edge_key(edge, Some(matches));
            if !normalized_new_edges.contains(&key) {
                result.removed.push(DependencyChange::removed(edge));
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "DependencyChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_change_computer_default() {
        let computer = DependencyChangeComputer;
        assert_eq!(computer.name(), "DependencyChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = DependencyChangeComputer;
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }
}
