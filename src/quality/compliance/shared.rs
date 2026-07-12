//! Small shared helpers reused across the compliance checkers.

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
