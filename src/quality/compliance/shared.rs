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
    let mut incoming = std::collections::HashSet::new();
    for edge in &sbom.edges {
        incoming.insert(&edge.to);
    }
    let primary = sbom.primary_component_id.as_ref();
    // The primary component plus every root (no incoming edge): an SPDX
    // document can DESCRIBE several sibling products, and each is
    // manufacturer-scoped evidence — not just the first one the parser
    // happened to promote to primary.
    let scope: Vec<&Component> = sbom
        .components
        .iter()
        .filter(|(id, _)| primary.is_some_and(|p| p == *id) || !incoming.contains(id))
        .map(|(_, c)| c)
        .collect();
    if scope.is_empty() {
        // Fully cyclic graph with no identified primary: no component is
        // provably a dependency-only node, so fall back to scanning all
        // components rather than making manufacturer evidence unsatisfiable.
        return sbom.components.values().collect();
    }
    scope
}

/// Whether a component's name is real. Empty/whitespace and the SPDX
/// `NOASSERTION` sentinel never count. `none`/`unknown` are placeholder-ish
/// but are also genuine package names (npm ships both), so they count when
/// corroborated by a unique identifier whose name segment matches.
pub(crate) fn known_component_name(comp: &Component) -> bool {
    let name = comp.name.trim();
    if name.is_empty() || name.eq_ignore_ascii_case("NOASSERTION") {
        return false;
    }
    if !(name.eq_ignore_ascii_case("NONE") || name.eq_ignore_ascii_case("UNKNOWN")) {
        return true;
    }
    // Suspicious placeholder spelling: require a corroborating identifier
    // (e.g. pkg:npm/none@1.0.0 corroborates a component named "none").
    comp.identifiers.purl.as_deref().is_some_and(|purl| {
        purl.rsplit('/')
            .next()
            .and_then(|seg| seg.split('@').next())
            .is_some_and(|purl_name| purl_name.eq_ignore_ascii_case(name))
    })
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
