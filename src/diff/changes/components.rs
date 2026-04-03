//! Component change computer implementation.

use crate::diff::traits::{ChangeComputer, ComponentChangeSet, ComponentMatches};
use crate::diff::{ComponentChange, CostModel, FieldChange};
use crate::model::{Component, NormalizedSbom};
use std::collections::HashSet;

/// Computes component-level changes between SBOMs.
pub struct ComponentChangeComputer {
    cost_model: CostModel,
}

impl ComponentChangeComputer {
    /// Create a new component change computer with the given cost model.
    #[must_use]
    pub const fn new(cost_model: CostModel) -> Self {
        Self { cost_model }
    }

    fn serialize_optional<T: serde::Serialize>(value: &Option<T>) -> Option<String> {
        value.as_ref().map(|value| {
            serde_json::to_string(value)
                .unwrap_or_else(|_| String::from("\"<serialization-error>\""))
        })
    }

    fn push_serialized_change<T: serde::Serialize>(
        changes: &mut Vec<FieldChange>,
        field: &str,
        old: &Option<T>,
        new: &Option<T>,
        total_cost: &mut u32,
        field_cost: u32,
    ) {
        let old_value = Self::serialize_optional(old);
        let new_value = Self::serialize_optional(new);

        if old_value != new_value {
            changes.push(FieldChange {
                field: field.to_string(),
                old_value,
                new_value,
            });
            *total_cost += field_cost;
        }
    }

    /// Compute individual field changes between two components.
    fn compute_field_changes(&self, old: &Component, new: &Component) -> (Vec<FieldChange>, u32) {
        let mut changes = Vec::new();
        let mut total_cost = 0u32;

        // Version change
        if old.version != new.version {
            changes.push(FieldChange {
                field: "version".to_string(),
                old_value: old.version.clone(),
                new_value: new.version.clone(),
            });
            total_cost += self
                .cost_model
                .version_change_cost(&old.semver, &new.semver);
        }

        // License change
        let old_licenses: HashSet<_> = old
            .licenses
            .declared
            .iter()
            .map(|l| &l.expression)
            .collect();
        let new_licenses: HashSet<_> = new
            .licenses
            .declared
            .iter()
            .map(|l| &l.expression)
            .collect();
        if old_licenses != new_licenses {
            changes.push(FieldChange {
                field: "licenses".to_string(),
                old_value: Some(
                    old.licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                new_value: Some(
                    new.licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            });
            total_cost += self.cost_model.license_changed;
        }

        // Supplier change
        if old.supplier != new.supplier {
            changes.push(FieldChange {
                field: "supplier".to_string(),
                old_value: old.supplier.as_ref().map(|s| s.name.clone()),
                new_value: new.supplier.as_ref().map(|s| s.name.clone()),
            });
            total_cost += self.cost_model.supplier_changed;
        }

        // Hash change (same version but different hash = integrity concern)
        if old.version == new.version && !old.hashes.is_empty() && !new.hashes.is_empty() {
            let old_hashes: HashSet<_> = old.hashes.iter().map(|h| &h.value).collect();
            let new_hashes: HashSet<_> = new.hashes.iter().map(|h| &h.value).collect();
            if old_hashes.is_disjoint(&new_hashes) {
                changes.push(FieldChange {
                    field: "hashes".to_string(),
                    old_value: Some(
                        old.hashes
                            .first()
                            .map(|h| h.value.clone())
                            .unwrap_or_default(),
                    ),
                    new_value: Some(
                        new.hashes
                            .first()
                            .map(|h| h.value.clone())
                            .unwrap_or_default(),
                    ),
                });
                total_cost += self.cost_model.hash_mismatch;
            }
        }

        Self::push_serialized_change(
            &mut changes,
            "ml_model",
            &old.ml_model,
            &new.ml_model,
            &mut total_cost,
            self.cost_model.supplier_changed,
        );
        Self::push_serialized_change(
            &mut changes,
            "dataset",
            &old.dataset,
            &new.dataset,
            &mut total_cost,
            self.cost_model.supplier_changed,
        );

        (changes, total_cost)
    }
}

impl Default for ComponentChangeComputer {
    fn default() -> Self {
        Self::new(CostModel::default())
    }
}

impl ChangeComputer for ComponentChangeComputer {
    type ChangeSet = ComponentChangeSet;

    fn compute(
        &self,
        old: &NormalizedSbom,
        new: &NormalizedSbom,
        matches: &ComponentMatches,
    ) -> ComponentChangeSet {
        let mut result = ComponentChangeSet::new();
        let matched_new_ids: HashSet<_> = matches
            .values()
            .filter_map(std::clone::Clone::clone)
            .collect();

        // Find removed components
        for (old_id, new_id_opt) in matches {
            if new_id_opt.is_none()
                && let Some(old_comp) = old.components.get(old_id)
            {
                result.removed.push(ComponentChange::removed(
                    old_comp,
                    self.cost_model.component_removed,
                ));
            }
        }

        // Find added components
        for new_id in new.components.keys() {
            if !matched_new_ids.contains(new_id)
                && let Some(new_comp) = new.components.get(new_id)
            {
                result.added.push(ComponentChange::added(
                    new_comp,
                    self.cost_model.component_added,
                ));
            }
        }

        // Find modified components
        for (old_id, new_id_opt) in matches {
            if let Some(new_id) = new_id_opt
                && let (Some(old_comp), Some(new_comp)) =
                    (old.components.get(old_id), new.components.get(new_id))
            {
                // Check if component was actually modified
                if old_comp.content_hash != new_comp.content_hash {
                    let (field_changes, cost) = self.compute_field_changes(old_comp, new_comp);
                    if !field_changes.is_empty() {
                        result.modified.push(ComponentChange::modified(
                            old_comp,
                            new_comp,
                            field_changes,
                            cost,
                        ));
                    }
                }
            }
        }

        result
    }

    fn name(&self) -> &'static str {
        "ComponentChangeComputer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_change_computer_default() {
        let computer = ComponentChangeComputer::default();
        assert_eq!(computer.name(), "ComponentChangeComputer");
    }

    #[test]
    fn test_empty_sboms() {
        let computer = ComponentChangeComputer::default();
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let matches = ComponentMatches::new();

        let result = computer.compute(&old, &new, &matches);
        assert!(result.is_empty());
    }
}
