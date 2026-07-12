//! Small shared helpers reused across the compliance checkers.

use crate::model::{Component, NormalizedSbom};

/// Components whose external references can carry manufacturer-level
/// evidence (security contact, CVD policy, disclosure process): the primary
/// component when one is identified, otherwise the root components (no
/// incoming dependency edge).
///
/// SBOM generators routinely copy upstream registry metadata — a third-party
/// dependency's own GitHub advisories or support URL — onto dependency
/// components; such references say nothing about the *manufacturer's*
/// obligations and must not satisfy them.
pub(crate) fn manufacturer_scope_components(sbom: &NormalizedSbom) -> Vec<&Component> {
    if let Some(primary) = sbom
        .primary_component_id
        .as_ref()
        .and_then(|id| sbom.components.get(id))
    {
        return vec![primary];
    }
    let mut incoming = std::collections::HashSet::new();
    for edge in &sbom.edges {
        incoming.insert(&edge.to);
    }
    sbom.components
        .iter()
        .filter(|(id, _)| !incoming.contains(id))
        .map(|(_, c)| c)
        .collect()
}

/// Render a slice of names as a comma-separated list, truncated with
/// "…and N more" once `max` items are emitted. Keeps long-tail violation
/// messages bounded for terminal/SARIF output.
pub(crate) fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        let head = items[..max].join(", ");
        let rest = items.len() - max;
        format!("{head}, …and {rest} more")
    }
}

/// Return the trimmed value only when it carries real information.
///
/// SPDX and CycloneDX producers emit sentinel markers when a field is
/// asserted-as-unknown rather than omitted (`NOASSERTION`, `NONE`,
/// `UNKNOWN`); those and empty/whitespace-only strings count as absent so
/// they cannot satisfy required-element gates.
pub(crate) fn known_value(value: Option<&str>) -> Option<&str> {
    let v = value?.trim();
    if v.is_empty()
        || v.eq_ignore_ascii_case("NOASSERTION")
        || v.eq_ignore_ascii_case("NONE")
        || v.eq_ignore_ascii_case("UNKNOWN")
    {
        return None;
    }
    Some(v)
}

/// `known_value` convenience for `Option<String>` model fields.
pub(crate) fn has_known_value(value: &Option<String>) -> bool {
    known_value(value.as_deref()).is_some()
}

/// Whether a component carries real supplier/author attribution: a supplier
/// organization or author whose name is not a placeholder sentinel.
pub(crate) fn has_known_supplier(
    supplier: &Option<crate::model::Organization>,
    author: &Option<String>,
) -> bool {
    supplier
        .as_ref()
        .is_some_and(|s| known_value(Some(s.name.as_str())).is_some())
        || has_known_value(author)
}

/// Simple email format validation (checks basic structure, not full RFC 5322)
pub(crate) fn is_valid_email_format(email: &str) -> bool {
    // Basic checks: contains @, has local and domain parts, no spaces
    if email.contains(' ') || email.is_empty() {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must not be empty
    if local.is_empty() {
        return false;
    }

    // Domain must contain at least one dot and not start/end with dot
    if domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return false;
    }

    true
}
