//! View-specific rendering for the `ViewApp`.

mod ai_readiness;
mod algorithms;
mod certificates;
mod compliance;
mod crypto;
mod datasets;
mod dependencies;
mod keys;
mod licenses;
mod models;
mod overview;
mod pqc_compliance;
mod protocols;
mod quality;
mod source;
mod tree;
mod vulnerabilities;

pub use ai_readiness::render_ai_readiness;
pub use algorithms::render_algorithms;
pub use certificates::render_certificates;
pub(crate) use compliance::build_groups;
pub use compliance::{StandardComplianceState, compute_compliance_results, render_compliance};
pub use crypto::render_crypto;
pub use datasets::render_datasets;
pub(crate) use dependencies::DependencyGraph;
pub use dependencies::{FlatDepNode, render_dependencies};
pub use keys::render_keys;
pub use licenses::render_licenses;
pub(crate) use licenses::{build_license_data_from_app, get_first_component_id_for_license};
pub use models::render_models;
pub use overview::render_overview;
pub use pqc_compliance::render_pqc_compliance;
pub use protocols::render_protocols;
pub use quality::render_quality;
pub use source::render_source;
pub(crate) use source::{SourceLink, resolve_source_reference};
pub use tree::render_tree;
pub(crate) use vulnerabilities::build_vuln_cache;
pub use vulnerabilities::{
    VulnCache, VulnCacheRef, VulnDisplayItem, VulnRow, build_display_items, render_vulnerabilities,
};

/// Replace the shared renderer's generic "ML / Dataset" section header with a
/// context-appropriate one ("Model Card" on the Models tab, "Dataset" on the
/// Datasets tab). `render_ml_dataset_lines` emits `[blank, header, ...]`.
pub(crate) fn relabel_ml_section_header(lines: &mut [ratatui::text::Line<'static>], title: &str) {
    use ratatui::style::Style;
    use ratatui::text::{Line, Span};
    let scheme = crate::tui::theme::colors();
    if lines.len() >= 2 {
        lines[1] = Line::from(vec![
            Span::styled(
                "\u{2501}\u{2501}\u{2501} ",
                Style::default().fg(scheme.border),
            ),
            Span::styled(title.to_string(), Style::default().fg(scheme.accent).bold()),
            Span::styled(
                " \u{2501}\u{2501}\u{2501}",
                Style::default().fg(scheme.border),
            ),
        ]);
    }
}

/// Copy of a `DatasetInfo` with the tautological generic type removed:
/// "Dataset Type: dataset" restates the CycloneDX default and carries no
/// information, so the row is dropped entirely.
pub(crate) fn without_generic_dataset_type(
    ds: &crate::model::DatasetInfo,
) -> crate::model::DatasetInfo {
    let mut ds = ds.clone();
    if ds
        .dataset_type
        .as_deref()
        .is_some_and(|t| t.eq_ignore_ascii_case("dataset"))
    {
        ds.dataset_type = None;
    }
    ds
}

/// Display width of already-built spans (prefix of a toolbar/hint line).
pub(crate) fn spans_width(spans: &[ratatui::text::Span<'_>]) -> usize {
    use unicode_width::UnicodeWidthStr;
    spans
        .iter()
        .map(|s| UnicodeWidthStr::width(s.content.as_ref()))
        .sum()
}

/// Append `[key] label` hint pairs to `spans`, dropping WHOLE trailing hints
/// that would not fit in `max_width` columns (total line width including the
/// already-present prefix spans).
///
/// The View toolbars render inside the left panel column; without budgeting,
/// ratatui clips the paragraph mid-token at the panel seam ("[f] filter" →
/// "[f] f"), which reads as a rendering bug and hides real keys. Dropped
/// hints are marked with a muted `…` so the omission is visible.
pub(crate) fn push_fitted_hints(
    spans: &mut Vec<ratatui::text::Span<'static>>,
    hints: &[(&'static str, &'static str)],
    max_width: usize,
) {
    use ratatui::style::Style;
    use ratatui::text::Span;
    let scheme = crate::tui::theme::colors();
    let mut used = spans_width(spans);
    let mut first = true;
    let mut dropped = false;
    for (keycap, label) in hints {
        // "[key] label" plus a 2-col gap between hints.
        let gap = if first { 0 } else { 2 };
        let w = gap + keycap.len() + 1 + label.len();
        if used + w > max_width {
            dropped = true;
            break;
        }
        if gap > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(
            (*keycap).to_string(),
            Style::default().fg(scheme.accent),
        ));
        spans.push(Span::raw(format!(" {label}")));
        used += w;
        first = false;
    }
    if dropped && used + 2 <= max_width {
        spans.push(Span::styled(" \u{2026}", Style::default().fg(scheme.muted)));
    }
}
