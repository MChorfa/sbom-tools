//! Components view with master-detail layout.

use crate::diff::ComponentChange;
use crate::tui::app::{AppMode, ComponentFilter};
use crate::tui::render_context::RenderContext;
use crate::tui::theme::colors;
use crate::tui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};

/// Pre-built component list to avoid rebuilding on each render call.
/// Built once per frame in `render_components` and passed to sub-functions.
pub enum ComponentListData<'a> {
    Diff(Vec<&'a ComponentChange>),
    Empty,
}

/// Classify an AI/dataset/crypto field-change key into a severity badge label
/// and color, or `None` for fields that should render generically.
///
/// `old_is_none` distinguishes additions (no old value) from removals for the
/// per-classification keys the diff engine emits one row per value for
/// (`ml_training_dataset`, `dataset_sensitivity`). The keys mirror the field
/// strings produced in `diff/changes/components.rs` (#244):
/// - `ml_training_dataset` removal = provenance loss (red)
/// - `dataset_sensitivity` addition = new PII/sensitive tag (warning)
/// - `crypto_downgrade` / `ml_quantization` = security/precision downgrade
fn field_change_severity(field: &str, old_is_none: bool) -> Option<(&'static str, Color, Color)> {
    let scheme = colors();
    // Badge foreground follows the theme convention: light text on dark
    // `error` backgrounds, dark text on bright `warning` ones.
    match field {
        // Training-data removal drops model provenance — the highest-cost ML
        // signal. An addition is benign and renders generically.
        "ml_training_dataset" if !old_is_none => {
            Some(("PROVENANCE LOSS", scheme.error, scheme.badge_fg_light))
        }
        // A dataset newly gaining a sensitivity classification (e.g. `pii`) is a
        // data-governance escalation; losing one renders generically.
        "dataset_sensitivity" if old_is_none => Some(("PII", scheme.warning, scheme.badge_fg_dark)),
        // Explicit classical-security-bit downgrade detected by the diff engine.
        "crypto_downgrade" => Some(("DOWNGRADE", scheme.error, scheme.badge_fg_light)),
        // Quantization changes can reduce model precision; quantum-level changes
        // alter post-quantum posture. Flag both as downgrades to draw the eye.
        "ml_quantization" | "crypto_quantum_level" => {
            Some(("DOWNGRADE", scheme.warning, scheme.badge_fg_dark))
        }
        // Algorithm / protocol / key-state churn is security-relevant.
        "crypto_algorithm"
        | "crypto_protocol_version"
        | "crypto_key_state"
        | "crypto_cert_expiry"
        | "crypto_asset_type" => Some(("CRYPTO", scheme.warning, scheme.badge_fg_dark)),
        _ => None,
    }
}

/// True when either side of the diff was profiled as a CBOM or AI-BOM at
/// load time (the quality reports carry the `BomProfile::detect` result).
/// For these profiles the component TYPE (algorithm/certificate/ml-model/…)
/// is the primary identity signal, not the package ecosystem.
pub(crate) fn is_typed_bom_diff(
    old_quality: Option<&crate::quality::QualityReport>,
    new_quality: Option<&crate::quality::QualityReport>,
) -> bool {
    use crate::quality::ScoringProfile;
    [new_quality, old_quality].into_iter().flatten().any(|q| {
        matches!(
            q.profile,
            ScoringProfile::Cbom | ScoringProfile::AiReadiness
        )
    })
}

/// Resolve a changed component's display type from the loaded SBOMs (new
/// side first so a changed type shows its current value; removed components
/// fall back to the old side).
pub(crate) fn component_display_type(
    old_sbom: Option<&crate::model::NormalizedSbom>,
    new_sbom: Option<&crate::model::NormalizedSbom>,
    format_id: &str,
) -> Option<String> {
    let canonical_id = crate::model::CanonicalId::from_format_id(format_id);
    let comp = new_sbom
        .and_then(|sbom| sbom.components.get(&canonical_id))
        .or_else(|| old_sbom.and_then(|sbom| sbom.components.get(&canonical_id)))?;
    Some(component_type_label(comp))
}

/// Human display type for a component. CBOM crypto assets use their
/// CycloneDX cryptoProperties assetType (algorithm/certificate/protocol/…) —
/// far more informative than the uniform "cryptographic" component type —
/// with related-crypto-material narrowed to its material type (public-key,
/// private-key, …) when declared. ML models and datasets get their short
/// AI-BOM names; everything else keeps its CycloneDX component type.
fn component_type_label(comp: &crate::model::Component) -> String {
    use crate::model::{ComponentType, CryptoAssetType};
    if let Some(cp) = &comp.crypto_properties {
        if cp.asset_type == CryptoAssetType::RelatedCryptoMaterial
            && let Some(mat) = &cp.related_crypto_material_properties
        {
            return mat.material_type.to_string();
        }
        return cp.asset_type.to_string();
    }
    match &comp.component_type {
        ComponentType::MachineLearningModel => "ml-model".to_string(),
        ComponentType::Data if comp.dataset.is_some() => "dataset".to_string(),
        other => other.to_string(),
    }
}

pub fn render_components(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(widgets::FILTER_BAR_HEIGHT),
            Constraint::Min(10),
        ])
        .split(area);

    // Render filter bar with badges
    render_filter_bar(frame, chunks[0], ctx);

    // Totals and clamp_selection are done in prepare_render().
    // Compute total_unfiltered for empty-state display only.
    let total_unfiltered = match ctx.mode {
        AppMode::Diff => ctx.diff_result.map_or(0, |r| r.components.total()),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => 0,
    };

    // Build the list data once for rendering
    let component_data = match ctx.mode {
        AppMode::Diff => ComponentListData::Diff(ctx.diff_component_items()),
        AppMode::MultiDiff | AppMode::Timeline | AppMode::Matrix => ComponentListData::Empty,
    };

    // Master-detail layout
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(widgets::MASTER_DETAIL_SPLIT)
        .split(chunks[1]);

    // Render component table (master)
    render_component_table(
        frame,
        content_chunks[0],
        ctx,
        &component_data,
        total_unfiltered,
    );
    // Render detail panel
    render_detail_panel(frame, content_chunks[1], ctx, &component_data);
}

/// Render the Quick Filters picker modal (Components tab, 'Q').
///
/// While it is open, digits 1-8 toggle the corresponding security quick
/// filter and 0 clears them all; outside it, digits always jump tabs.
pub fn render_quick_filter_picker(
    frame: &mut Frame,
    security_filter: &crate::tui::viewmodel::security_filter::SecurityFilterState,
) {
    use crate::tui::viewmodel::security_filter::QuickFilter;
    use ratatui::widgets::Clear;

    let scheme = colors();
    let area = frame.area();
    let width = 44u16.min(area.width.saturating_sub(4));
    // 8 filters + title spacing + footer + borders
    let height = (QuickFilter::all().len() as u16 + 6).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let popup = Rect::new(x, y, width, height);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Quick Filters ")
        .title_style(Style::default().fg(scheme.accent).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            "Toggle security quick filters:",
            Style::default().fg(scheme.text_muted),
        )),
        Line::from(""),
    ];
    for (i, qf) in QuickFilter::all().iter().enumerate() {
        let active = qf.is_active(&security_filter.criteria);
        let marker = if active { "\u{25cf}" } else { " " };
        let label_style = if active {
            Style::default().fg(scheme.accent).bold()
        } else {
            Style::default().fg(scheme.text)
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" [{}] ", i + 1), Style::default().fg(scheme.accent)),
            Span::styled(format!("{marker} "), Style::default().fg(scheme.accent)),
            Span::styled(qf.label(), label_style),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("[0]", Style::default().fg(scheme.accent)),
        Span::styled(" clear all  ", Style::default().fg(scheme.text_muted)),
        Span::styled("[Esc/Q]", Style::default().fg(scheme.accent)),
        Span::styled(" close", Style::default().fg(scheme.text_muted)),
    ]));

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_filter_bar(frame: &mut Frame, area: Rect, ctx: &RenderContext) {
    use crate::tui::viewmodel::security_filter::QuickFilter;

    let filter = ctx.components.filter;
    let sort = &ctx.components.sort_by;
    let multi_select = ctx.components.multi_select_mode;
    let selection_count = ctx.components.selection_count();

    let mut filter_spans = vec![
        Span::styled("Filter: ", Style::default().fg(colors().text_muted)),
        status_badge(filter.label(), filter_color(filter)),
        Span::raw("  "),
        Span::styled("Sort: ", Style::default().fg(colors().text_muted)),
        Span::styled(
            format!("{sort:?}"),
            Style::default().fg(colors().accent).bold(),
        ),
    ];

    // Show multi-selection mode indicator
    if multi_select {
        filter_spans.push(Span::raw("  "));
        filter_spans.push(Span::styled(
            format!(" ✓ SELECT: {selection_count} "),
            Style::default()
                .fg(colors().badge_fg_dark)
                .bg(colors().secondary)
                .bold(),
        ));
    }

    // Show quick filter chips
    let security_filter = &ctx.components.security_filter;
    if security_filter.has_active_filters() {
        filter_spans.push(Span::raw("  "));
        filter_spans.push(Span::styled("│", Style::default().fg(colors().border)));
        filter_spans.push(Span::raw(" "));

        for quick_filter in QuickFilter::all() {
            if quick_filter.is_active(&security_filter.criteria) {
                let label = quick_filter.label();
                filter_spans.push(Span::styled(
                    format!(" {label} "),
                    Style::default()
                        .fg(colors().badge_fg_dark)
                        .bg(colors().accent)
                        .bold(),
                ));
                filter_spans.push(Span::raw(" "));
            }
        }
    }

    filter_spans.extend(vec![
        Span::raw("  │  "),
        Span::styled("[f]", Style::default().fg(colors().accent)),
        Span::styled(" filter  ", Style::default().fg(colors().text_muted)),
        Span::styled("[s]", Style::default().fg(colors().accent)),
        Span::styled(" sort  ", Style::default().fg(colors().text_muted)),
        Span::styled("[Q]", Style::default().fg(colors().accent)),
        Span::styled(" quick filters  ", Style::default().fg(colors().text_muted)),
        Span::styled("[v]", Style::default().fg(colors().accent)),
        Span::styled(
            if multi_select {
                " exit select"
            } else {
                " multi-select"
            },
            Style::default().fg(colors().text_muted),
        ),
    ]);

    let paragraph = Paragraph::new(Line::from(filter_spans))
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors().border)),
        )
        .style(Style::default());

    frame.render_widget(paragraph, area);
}

fn filter_color(filter: ComponentFilter) -> Color {
    match filter {
        ComponentFilter::All => colors().primary,
        ComponentFilter::Added => colors().added,
        ComponentFilter::Removed => colors().removed,
        ComponentFilter::Modified => colors().modified,
        ComponentFilter::EolOnly => colors().critical,
        ComponentFilter::EolRisk => colors().high,
    }
}

fn status_badge(text: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!(" {text} "),
        Style::default().fg(colors().badge_fg_dark).bg(color).bold(),
    )
}

/// Responsive column layout for the diff components table.
///
/// Versions are the data this tab exists to show, so they get priority
/// width: at narrow widths the Ecosystem/Changes columns are dropped (and
/// the status badge collapses to its symbol) before a version column ever
/// shrinks below a readable width. The Name column absorbs the remainder
/// and is ellipsis-truncated instead of silently clipped.
struct DiffTableLayout {
    compact_status: bool,
    show_ecosystem: bool,
    /// Component TYPE column for CBOM/AI-BOM diffs (algorithm/certificate/
    /// ml-model/…): for those profiles the type identifies the asset, so it
    /// replaces the (mostly "unknown") Ecosystem column and outlives the
    /// Changes column when width runs out.
    show_type: bool,
    show_changes: bool,
    name_width: u16,
    version_width: u16,
}

impl DiffTableLayout {
    const STATUS_W: u16 = 12;
    const COMPACT_STATUS_W: u16 = 3;
    const VERSION_W: u16 = 11;
    const COMPACT_VERSION_W: u16 = 9;
    const ECO_W: u16 = 9;
    const TYPE_W: u16 = 11; // "certificate" exactly; longer types elide
    const CHANGES_W: u16 = 7;

    fn for_width(area_width: u16, want_type: bool) -> Self {
        // Borders (2) + highlight symbol (2).
        let avail = area_width.saturating_sub(4);
        let fits = |cols: &[u16]| -> Option<u16> {
            let fixed: u16 = cols.iter().sum::<u16>() + cols.len() as u16; // +1 gap per col
            avail.checked_sub(fixed).filter(|w| *w >= 12)
        };

        if want_type {
            if let Some(name_width) = fits(&[
                Self::STATUS_W,
                Self::TYPE_W,
                Self::VERSION_W,
                Self::VERSION_W,
                Self::CHANGES_W,
            ]) {
                return Self {
                    compact_status: false,
                    show_ecosystem: false,
                    show_type: true,
                    show_changes: true,
                    name_width,
                    version_width: Self::VERSION_W,
                };
            }
            if let Some(name_width) = fits(&[
                Self::STATUS_W,
                Self::TYPE_W,
                Self::VERSION_W,
                Self::VERSION_W,
            ]) {
                return Self {
                    compact_status: false,
                    show_ecosystem: false,
                    show_type: true,
                    show_changes: false,
                    name_width,
                    version_width: Self::VERSION_W,
                };
            }
            // Too narrow even for the type column: fall through to the
            // untyped ladder (the detail pane still shows the type).
        }

        if let Some(name_width) = fits(&[
            Self::STATUS_W,
            Self::VERSION_W,
            Self::VERSION_W,
            Self::ECO_W,
            Self::CHANGES_W,
        ]) {
            return Self {
                compact_status: false,
                show_ecosystem: true,
                show_type: false,
                show_changes: true,
                name_width,
                version_width: Self::VERSION_W,
            };
        }
        if let Some(name_width) = fits(&[
            Self::STATUS_W,
            Self::VERSION_W,
            Self::VERSION_W,
            Self::CHANGES_W,
        ]) {
            return Self {
                compact_status: false,
                show_ecosystem: false,
                show_type: false,
                show_changes: true,
                name_width,
                version_width: Self::VERSION_W,
            };
        }
        if let Some(name_width) = fits(&[Self::STATUS_W, Self::VERSION_W, Self::VERSION_W]) {
            return Self {
                compact_status: false,
                show_ecosystem: false,
                show_type: false,
                show_changes: false,
                name_width,
                version_width: Self::VERSION_W,
            };
        }
        let name_width = fits(&[
            Self::COMPACT_STATUS_W,
            Self::COMPACT_VERSION_W,
            Self::COMPACT_VERSION_W,
        ])
        .unwrap_or(10);
        Self {
            compact_status: true,
            show_ecosystem: false,
            show_type: false,
            show_changes: false,
            name_width,
            version_width: Self::COMPACT_VERSION_W,
        }
    }

    fn constraints(&self) -> Vec<Constraint> {
        let mut w = vec![
            Constraint::Length(if self.compact_status {
                Self::COMPACT_STATUS_W
            } else {
                Self::STATUS_W
            }),
            Constraint::Min(self.name_width),
        ];
        if self.show_type {
            w.push(Constraint::Length(Self::TYPE_W));
        }
        w.push(Constraint::Length(self.version_width));
        w.push(Constraint::Length(self.version_width));
        if self.show_ecosystem {
            w.push(Constraint::Length(Self::ECO_W));
        }
        if self.show_changes {
            w.push(Constraint::Length(Self::CHANGES_W));
        }
        w
    }

    fn header(&self) -> Vec<&'static str> {
        let mut h = vec!["", "Name"];
        if self.show_type {
            h.push("Type");
        }
        h.push("Old Ver");
        h.push("New Ver");
        if self.show_ecosystem {
            h.push("Ecosystem");
        }
        if self.show_changes {
            h.push("Changes");
        }
        h
    }
}

fn render_component_table(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    component_data: &ComponentListData,
    total_unfiltered: usize,
) {
    let is_diff = matches!(component_data, ComponentListData::Diff(_));
    let want_type = is_diff && is_typed_bom_diff(ctx.old_quality, ctx.new_quality);
    let layout = DiffTableLayout::for_width(area.width, want_type);
    let header_cells: Vec<Cell> = if is_diff {
        layout
            .header()
            .into_iter()
            .map(|h| Cell::from(h).style(Style::default().fg(colors().accent).bold()))
            .collect()
    } else {
        ["", "Name", "Version", "", "Ecosystem", "Staleness", "EOL"]
            .into_iter()
            .map(|h| Cell::from(h).style(Style::default().fg(colors().accent).bold()))
            .collect()
    };
    let header = Row::new(header_cells).height(1);

    // Use pre-built component list (state already updated in prepare_render)
    let rows: Vec<Row> = match component_data {
        ComponentListData::Diff(components) => get_diff_rows(ctx, components, &layout),
        ComponentListData::Empty => vec![],
    };

    // Check for empty states
    if rows.is_empty() {
        if total_unfiltered == 0 {
            // No components at all
            widgets::render_empty_state_enhanced(
                frame,
                area,
                "--",
                "No components found",
                Some("The SBOM contains no component entries"),
                None,
            );
        } else {
            // Filter is hiding everything
            widgets::render_no_results_state(frame, area, "Filter", ctx.components.filter.label());
        }
        return;
    }

    let widths: Vec<Constraint> = if is_diff {
        layout.constraints()
    } else {
        vec![
            Constraint::Length(12),
            Constraint::Min(14),
            Constraint::Length(10),
            Constraint::Length(0),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(12),
        ]
    };

    let selected_idx = ctx.components.selected;
    let scheme = colors();
    let table_focused = !ctx.components.focus_detail;
    let table_border_color = if table_focused {
        scheme.border_focused
    } else {
        scheme.border
    };
    let table_title_style = if table_focused {
        Style::default().fg(scheme.border_focused).bold()
    } else {
        Style::default().fg(scheme.text_muted)
    };

    let table = Table::new(rows.clone(), widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Components ({}) ", rows.len()))
                .title_style(table_title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(table_border_color)),
        )
        .row_highlight_style(
            Style::default()
                .bg(colors().selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = TableState::default()
        .with_offset(ctx.components.scroll_offset)
        .with_selected(Some(selected_idx));

    frame.render_stateful_widget(table, area, &mut state);

    // Render scrollbar
    let scroll_offset = state.offset();
    if rows.len() > area.height.saturating_sub(3) as usize {
        widgets::render_scrollbar(
            frame,
            area.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            rows.len(),
            scroll_offset,
        );
    }
}

fn render_detail_panel(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    component_data: &ComponentListData,
) {
    match component_data {
        ComponentListData::Diff(components) => render_diff_detail(frame, area, ctx, components),
        ComponentListData::Empty => {}
    }
}

fn render_diff_detail(
    frame: &mut Frame,
    area: Rect,
    ctx: &RenderContext,
    components: &[&ComponentChange],
) {
    let selected = ctx.components.selected;

    if let Some(comp) = components.get(selected) {
        let change_type = &comp.change_type;
        let (status_text, status_color, status_symbol) = match change_type {
            crate::diff::ChangeType::Added => ("ADDED", colors().added, "+"),
            crate::diff::ChangeType::Removed => ("REMOVED", colors().removed, "-"),
            crate::diff::ChangeType::Modified => ("MODIFIED", colors().modified, "~"),
            crate::diff::ChangeType::Unchanged => ("UNCHANGED", colors().muted, "="),
        };

        let mut lines = vec![
            // Status badge with symbol for accessibility
            Line::from(vec![
                Span::styled(
                    format!(" {status_symbol} {status_text} "),
                    Style::default()
                        .fg(colors().badge_fg_dark)
                        .bg(status_color)
                        .bold(),
                ),
                Span::styled(
                    format!("  Change Weight: {}", comp.cost),
                    Style::default().fg(colors().text_muted),
                ),
            ]),
            Line::from(""),
            // Component name
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(colors().text_muted)),
                Span::styled(&comp.name, Style::default().fg(colors().text).bold()),
            ]),
            // ID (canonical)
            Line::from(vec![
                Span::styled("ID: ", Style::default().fg(colors().text_muted)),
                Span::styled(&comp.id, Style::default().fg(colors().text)),
            ]),
        ];
        // CBOM/AI-BOM: the CycloneDX type (algorithm/certificate/ml-model/…)
        // identifies what kind of asset this is — surface it instead of
        // leaving it buried inside the ID string (#80).
        if is_typed_bom_diff(ctx.old_quality, ctx.new_quality)
            && let Some(type_label) = component_display_type(ctx.old_sbom, ctx.new_sbom, &comp.id)
        {
            lines.push(Line::from(vec![
                Span::styled("Type: ", Style::default().fg(colors().text_muted)),
                Span::styled(type_label, Style::default().fg(colors().text)),
            ]));
        }
        if ctx.diff_result.is_some_and(|r| {
            r.ml_regressions
                .iter()
                .any(|reg| reg.component == comp.name)
        }) {
            lines.insert(
                1,
                Line::from(vec![Span::styled(
                    " \u{25bc} ML REGRESSION ",
                    Style::default()
                        .fg(colors().badge_fg_light)
                        .bg(colors().error)
                        .bold(),
                )]),
            );
        }

        // Version info with visual diff
        match (&comp.old_version, &comp.new_version) {
            (Some(old), Some(new)) if old != new => {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(old, Style::default().fg(colors().removed)),
                    Span::styled(" → ", Style::default().fg(colors().text_muted)),
                    Span::styled(new, Style::default().fg(colors().added)),
                ]));
            }
            (Some(old), None) => {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(old, Style::default().fg(colors().removed)),
                    Span::styled(" (removed)", Style::default().fg(colors().text_muted)),
                ]));
            }
            (None, Some(new)) => {
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(new, Style::default().fg(colors().added)),
                    Span::styled(" (new)", Style::default().fg(colors().text_muted)),
                ]));
            }
            (Some(ver), Some(_)) => {
                // Same version in both
                lines.push(Line::from(vec![
                    Span::styled("Version: ", Style::default().fg(colors().text_muted)),
                    Span::styled(ver, Style::default().fg(colors().text)),
                ]));
            }
            _ => {}
        }

        // Downgrade attack detection
        if let (Some(old_ver), Some(new_ver)) = (&comp.old_version, &comp.new_version) {
            use crate::tui::security::{
                VersionChange, analyze_downgrade, detect_version_downgrade,
            };
            let version_change = detect_version_downgrade(old_ver, new_ver);
            if version_change == VersionChange::Downgrade {
                let downgrade_severity = analyze_downgrade(old_ver, new_ver);
                let (warning_text, warning_color) = match downgrade_severity {
                    Some(crate::tui::security::DowngradeSeverity::Major) => (
                        "⚠ MAJOR DOWNGRADE - Supply chain attack risk!",
                        colors().critical,
                    ),
                    Some(crate::tui::security::DowngradeSeverity::Suspicious) => (
                        "⚠ SUSPICIOUS - Security patch may be removed!",
                        colors().critical,
                    ),
                    Some(crate::tui::security::DowngradeSeverity::Minor) => {
                        ("⚠ Version Downgrade Detected", colors().warning)
                    }
                    None => ("⚠ Downgrade", colors().warning),
                };
                lines.push(Line::from(vec![Span::styled(
                    format!(" {warning_text} "),
                    Style::default()
                        .fg(colors().badge_fg_dark)
                        .bg(warning_color)
                        .bold(),
                )]));
            }
        }

        // Ecosystem
        if let Some(eco) = &comp.ecosystem {
            lines.push(Line::from(vec![
                Span::styled("Ecosystem: ", Style::default().fg(colors().text_muted)),
                Span::styled(eco, Style::default().fg(colors().secondary)),
            ]));
        }

        // Depth from dependency graph
        let depth = ctx
            .dependencies
            .cached_depths
            .get(comp.id.as_str())
            .copied();
        if let Some(d) = depth {
            let label = match d {
                0 => "Root",
                1 => "Direct",
                _ => "Transitive",
            };
            let depth_color = match d {
                0 => colors().primary,
                1 => colors().accent,
                _ => colors().text_muted,
            };
            lines.push(Line::from(vec![
                Span::styled("Depth: ", Style::default().fg(colors().text_muted)),
                Span::styled(format!("D{d}"), Style::default().fg(depth_color).bold()),
                Span::styled(
                    format!(" ({label})"),
                    Style::default().fg(colors().text_muted),
                ),
            ]));
        }

        // Dependency counts from cached graphs
        let deps_out = ctx
            .dependencies
            .cached_graph
            .get(comp.id.as_str())
            .map_or(0, Vec::len);
        let deps_in = ctx
            .dependencies
            .cached_reverse_graph
            .get(comp.id.as_str())
            .map_or(0, Vec::len);
        if deps_out > 0 || deps_in > 0 {
            lines.push(Line::from(vec![
                Span::styled("Dependencies: ", Style::default().fg(colors().text_muted)),
                Span::styled(deps_out.to_string(), Style::default().fg(colors().primary)),
                Span::styled("  Dependents: ", Style::default().fg(colors().text_muted)),
                Span::styled(deps_in.to_string(), Style::default().fg(colors().primary)),
            ]));
        }

        // Hashes (look up component in new SBOM)
        let full_component = ctx.new_sbom.as_ref().and_then(|sbom| {
            let canonical_id = crate::model::CanonicalId::from_format_id(&comp.id);
            sbom.components.get(&canonical_id)
        });
        if let Some(full_comp) = full_component
            && !full_comp.hashes.is_empty()
        {
            for hash in full_comp.hashes.iter().take(2) {
                let truncated_value = if hash.value.len() > 16 {
                    format!("{}...", &hash.value[..16])
                } else {
                    hash.value.clone()
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{}: ", hash.algorithm),
                        Style::default().fg(colors().text_muted),
                    ),
                    Span::styled(truncated_value, Style::default().fg(colors().text)),
                ]));
            }
            if full_comp.hashes.len() > 2 {
                lines.push(Line::styled(
                    format!("    ... and {} more", full_comp.hashes.len() - 2),
                    Style::default().fg(colors().text_muted),
                ));
            }
        }

        // ML model / dataset metadata (CycloneDX ML BOM, SPDX 3.0 AI). Resolve from the
        // new SBOM, falling back to the old one so removed components still display.
        let ml_comp = full_component.or_else(|| {
            ctx.old_sbom.as_ref().and_then(|sbom| {
                sbom.components
                    .get(&crate::model::CanonicalId::from_format_id(&comp.id))
            })
        });
        if let Some(fc) = ml_comp {
            lines.extend(crate::tui::shared::components::render_ml_dataset_lines(
                fc.ml_model.as_ref(),
                fc.dataset.as_ref(),
                area.width,
            ));
        }

        // Match confidence (item 1.5) — show how old/new components were correlated
        if let Some(match_info) = &comp.match_info {
            let scheme = colors();
            // Band on the worst-case bound: a fuzzy 0.75 with a wide CI must
            // not paint like a near-exact 0.75.
            let banding = match_info
                .confidence_interval
                .as_ref()
                .map_or(match_info.score, |ci| ci.lower);
            let score_color = if banding >= 0.9 {
                scheme.success
            } else if banding >= 0.7 {
                scheme.warning
            } else {
                scheme.error
            };
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(scheme.border)),
                Span::styled("Match", Style::default().fg(scheme.accent).bold()),
                Span::styled(" ━━━", Style::default().fg(scheme.border)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Score: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    format!("{:.2}", match_info.score),
                    Style::default().fg(score_color).bold(),
                ),
                Span::styled(" via ", Style::default().fg(scheme.text_muted)),
                Span::styled(&match_info.method, Style::default().fg(scheme.secondary)),
            ]));
            if let Some(ci) = &match_info.confidence_interval
                && ci.width() > 0.0
            {
                // A point score outside its own displayed interval must be
                // annotated, not left to contradict the CI line above it
                // (e.g. "Score: 1.00" over "CI: 0.83–0.99").
                let ci_line = if match_info.score < ci.lower || match_info.score > ci.upper {
                    format!(
                        "CI: {:.2}\u{2013}{:.2} ({:.0}%; score outside CI: {} match)",
                        ci.lower,
                        ci.upper,
                        ci.level * 100.0,
                        match_info.method
                    )
                } else {
                    format!(
                        "CI: {:.2}\u{2013}{:.2} ({:.0}%)",
                        ci.lower,
                        ci.upper,
                        ci.level * 100.0
                    )
                };
                lines.push(Line::styled(
                    widgets::truncate_str(&ci_line, (area.width as usize).saturating_sub(4)),
                    Style::default().fg(scheme.text_muted),
                ));
            }
            if !match_info.reason.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Reason: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        widgets::truncate_str(&match_info.reason, area.width as usize - 10),
                        Style::default().fg(scheme.text),
                    ),
                ]));
            }
            // Show top score breakdown components (up to 3)
            for sc in match_info.score_breakdown.iter().take(3) {
                lines.push(Line::from(vec![
                    Span::styled("  \u{2022} ", Style::default().fg(scheme.text_muted)),
                    Span::styled(&sc.name, Style::default().fg(scheme.accent)),
                    Span::styled(
                        format!(" {:.2} (w={:.1})", sc.raw_score, sc.weight),
                        Style::default().fg(scheme.text_muted),
                    ),
                ]));
            }
            if !match_info.normalizations.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("Normalized: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        widgets::truncate_str(
                            &match_info.normalizations.join(", "),
                            (area.width as usize).saturating_sub(14),
                        ),
                        Style::default().fg(scheme.text_muted),
                    ),
                ]));
            }
        }

        // Field changes for modified components (skip version-only changes since
        // the version diff is already shown above)
        let non_version_changes: Vec<_> = comp
            .field_changes
            .iter()
            .filter(|c| c.field != "version")
            .collect();
        if !non_version_changes.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled("Changes", Style::default().fg(colors().modified).bold()),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));

            for change in &non_version_changes {
                let old_val = change.old_value.as_deref().unwrap_or("(none)");
                let new_val = change.new_value.as_deref().unwrap_or("(none)");

                // ML/dataset/crypto field changes (#244) carry security and
                // governance weight a flat "field: old -> new" row hides. Give
                // the high-signal ones a colored severity badge so a PII
                // escalation or training-data removal stands out from a benign
                // model-card URL change.
                let scheme = colors();
                let mut field_line =
                    vec![Span::styled("  • ", Style::default().fg(scheme.text_muted))];
                let field_color = if let Some((badge, color, badge_fg)) =
                    field_change_severity(&change.field, change.old_value.is_none())
                {
                    field_line.push(Span::styled(
                        format!(" {badge} "),
                        Style::default().fg(badge_fg).bg(color).bold(),
                    ));
                    field_line.push(Span::raw(" "));
                    color
                } else {
                    scheme.accent
                };
                field_line.push(Span::styled(
                    &change.field,
                    Style::default().fg(field_color),
                ));
                lines.push(Line::from(field_line));

                // ml_metric:* fields are direction-aware: a metric moving the
                // adverse way must never paint green (the arrow is its own
                // span so truncation can't eat the direction cue).
                #[derive(Clone, Copy, PartialEq)]
                enum MetricDirection {
                    Regressed,
                    Improved,
                    Equal,
                }
                let ml_direction = change
                    .field
                    .strip_prefix("ml_metric:")
                    .and_then(crate::diff::ml_metric_higher_is_better)
                    .and_then(|hib| {
                        let old: f64 = change.old_value.as_deref()?.parse().ok()?;
                        let new: f64 = change.new_value.as_deref()?.parse().ok()?;
                        // NaN/inf compare as "not regressed, not equal" and
                        // would fall through to green "improved".
                        if !old.is_finite() || !new.is_finite() {
                            return None;
                        }
                        Some(if (hib && new < old) || (!hib && new > old) {
                            MetricDirection::Regressed
                        } else if new == old {
                            MetricDirection::Equal
                        } else {
                            MetricDirection::Improved
                        })
                    });
                let (old_color, new_color, arrow) = match ml_direction {
                    Some(MetricDirection::Regressed) => {
                        (scheme.text_muted, scheme.error, Some(" \u{25bc}"))
                    }
                    Some(MetricDirection::Improved) => {
                        (scheme.text_muted, scheme.success, Some(" \u{25b2}"))
                    }
                    Some(MetricDirection::Equal) => (scheme.text_muted, scheme.text, None),
                    None => (colors().removed, colors().added, None),
                };
                lines.push(Line::from(vec![
                    Span::styled("    - ", Style::default().fg(old_color)),
                    Span::styled(
                        widgets::truncate_str(old_val, area.width as usize - 8),
                        Style::default().fg(old_color),
                    ),
                ]));
                let mut new_line = vec![
                    Span::styled("    + ", Style::default().fg(new_color)),
                    Span::styled(
                        widgets::truncate_str(new_val, area.width as usize - 8),
                        Style::default().fg(new_color),
                    ),
                ];
                if let Some(arrow) = arrow {
                    new_line.push(Span::styled(arrow, Style::default().fg(new_color)));
                }
                lines.push(Line::from(new_line));
            }
        }

        // Related vulnerabilities - look up by ID, not by name
        let related_vulns: Vec<_> = ctx
            .diff_result
            .map(|r| {
                r.vulnerabilities
                    .introduced
                    .iter()
                    .filter(|v| v.component_id == comp.id) // ID-based lookup
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if !related_vulns.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("━━━ ", Style::default().fg(colors().border)),
                Span::styled(
                    format!("⚠ Vulnerabilities ({})", related_vulns.len()),
                    Style::default().fg(colors().high).bold(),
                ),
                Span::styled(" ━━━", Style::default().fg(colors().border)),
            ]));

            let vuln_entries: Vec<(&str, &str, Option<&str>)> = related_vulns
                .iter()
                .map(|v| (v.severity.as_str(), v.id.as_str(), v.description.as_deref()))
                .collect();
            lines.extend(
                crate::tui::shared::components::render_vulnerability_list_lines(
                    &vuln_entries,
                    5,
                    related_vulns.len(),
                    area.width,
                ),
            );
        }

        // Security Analysis section (Diff mode)
        let reverse_graph = &ctx.dependencies.cached_reverse_graph;
        let (direct_deps, transitive_count) =
            crate::tui::shared::components::compute_blast_radius(&comp.name, reverse_graph);
        // Resolve the license from the new SBOM, falling back to the old one
        // so REMOVED components stop resolving to nothing. A component with
        // no declared license at all gets a neutral "No license declared"
        // (LicenseRisk::None) — absence is not copyleft risk, and crypto
        // assets/datasets legitimately carry no license.
        let canonical_id = crate::model::CanonicalId::from_format_id(&comp.id);
        let license_text = ctx
            .new_sbom
            .and_then(|sbom| sbom.components.get(&canonical_id))
            .or_else(|| {
                ctx.old_sbom
                    .and_then(|sbom| sbom.components.get(&canonical_id))
            })
            .and_then(|c| c.licenses.declared.first())
            .map_or("No license declared", |l| l.expression.as_str());
        lines.extend(
            crate::tui::shared::components::render_security_analysis_lines(
                related_vulns.len(),
                direct_deps,
                transitive_count,
                license_text,
            ),
        );

        // Flagged indicator and analyst notes
        let is_flagged = ctx.security_cache.is_flagged(&comp.name);
        lines.extend(crate::tui::shared::components::render_flagged_lines(
            is_flagged,
            ctx.security_cache.get_note(&comp.name),
            area.width,
            "",
        ));

        lines.extend(crate::tui::shared::components::render_quick_actions_hint(
            !related_vulns.is_empty(),
        ));

        crate::tui::shared::components::render_detail_block(
            frame,
            area,
            lines,
            " Component Details ",
            ctx.components.focus_detail,
        );
    } else {
        render_empty_detail(frame, area, ctx.components.focus_detail);
    }
}

fn render_empty_detail(frame: &mut Frame, area: Rect, focused: bool) {
    crate::tui::shared::components::render_empty_detail_panel(
        frame,
        area,
        " Component Details ",
        "--",
        "Select a component to view details",
        &[("[↑↓]", " navigate  "), ("[p]", " toggle focus")],
        focused,
    );
}

fn get_diff_rows(
    ctx: &RenderContext,
    components: &[&ComponentChange],
    layout: &DiffTableLayout,
) -> Vec<Row<'static>> {
    let multi_select = ctx.components.multi_select_mode;

    components
        .iter()
        .enumerate()
        .map(|(idx, comp)| {
            let is_selected = ctx.components.is_selected(idx);
            let checkbox = if multi_select {
                if is_selected { "☑ " } else { "☐ " }
            } else {
                ""
            };

            let scheme = colors();
            let (label, compact_label, status_bg, status_fg, row_style) = match comp.change_type {
                crate::diff::ChangeType::Added => (
                    " + ADDED    ",
                    " + ",
                    scheme.added,
                    scheme.badge_fg_dark,
                    Style::default().fg(scheme.added),
                ),
                crate::diff::ChangeType::Removed => (
                    " - REMOVED  ",
                    " - ",
                    scheme.removed,
                    scheme.badge_fg_light,
                    Style::default().fg(scheme.removed),
                ),
                crate::diff::ChangeType::Modified => (
                    " ~ MODIFIED ",
                    " ~ ",
                    scheme.modified,
                    scheme.badge_fg_dark,
                    Style::default().fg(scheme.modified),
                ),
                crate::diff::ChangeType::Unchanged => (
                    " = SAME     ",
                    " = ",
                    scheme.muted,
                    scheme.badge_fg_light,
                    Style::default().fg(scheme.text),
                ),
            };
            let label = if layout.compact_status {
                compact_label
            } else {
                label
            };

            let row_style = if is_selected {
                row_style.bg(scheme.selection)
            } else {
                row_style
            };

            let version_budget = layout.version_width as usize;
            let version_cell = |v: &Option<String>| {
                Cell::from(v.as_deref().map_or_else(
                    || "\u{2014}".to_string(),
                    |v| widgets::truncate_str(v, version_budget),
                ))
            };

            // Detect version downgrades for the "New Version" cell
            let new_version_cell = if let (Some(old_ver), Some(new_ver)) =
                (&comp.old_version, &comp.new_version)
            {
                use crate::tui::security::{VersionChange, detect_version_downgrade};
                if detect_version_downgrade(old_ver, new_ver) == VersionChange::Downgrade {
                    Cell::from(Line::from(vec![
                        Span::raw(widgets::truncate_str(
                            new_ver,
                            version_budget.saturating_sub(4),
                        )),
                        Span::styled(" \u{2193}DG", Style::default().fg(colors().critical).bold()),
                    ]))
                } else {
                    version_cell(&comp.new_version)
                }
            } else {
                version_cell(&comp.new_version)
            };

            // Ellipsis-truncate the name to its real budget: ratatui clips
            // cells silently, which made distinct crypto asset names
            // ("SLH-DSA-SHAKE-256s"/"-128s") indistinguishable.
            let mut cells = vec![
                Cell::from(Span::styled(
                    format!("{checkbox}{label}"),
                    Style::default().fg(status_fg).bg(status_bg).bold(),
                )),
                Cell::from(widgets::truncate_str(
                    &comp.name,
                    layout.name_width as usize,
                )),
            ];
            if layout.show_type {
                cells.push(Cell::from(
                    component_display_type(ctx.old_sbom, ctx.new_sbom, &comp.id).map_or_else(
                        || "-".to_string(),
                        |t| widgets::truncate_str(&t, DiffTableLayout::TYPE_W as usize),
                    ),
                ));
            }
            cells.push(version_cell(&comp.old_version));
            cells.push(new_version_cell);
            if layout.show_ecosystem {
                cells.push(Cell::from(
                    comp.ecosystem.clone().unwrap_or_else(|| "-".to_string()),
                ));
            }
            if layout.show_changes {
                cells.push(Cell::from(if comp.field_changes.is_empty() {
                    "-".to_string()
                } else {
                    comp.field_changes.len().to_string()
                }));
            }
            Row::new(cells).style(row_style)
        })
        .collect()
}

#[cfg(test)]
mod field_badge_tests {
    use super::*;

    /// Badge foregrounds must come from the theme (light on dark `error`
    /// backgrounds, dark on bright `warning` ones), not hardcoded black.
    #[test]
    fn field_change_severity_returns_theme_badge_fg() {
        crate::tui::test_support::pin_theme();
        let scheme = colors();

        let (_, _, fg) = field_change_severity("ml_training_dataset", false)
            .expect("training-data removal is flagged");
        assert_eq!(fg, scheme.badge_fg_light, "error-background badge");

        let (_, _, fg) =
            field_change_severity("dataset_sensitivity", true).expect("new PII tag is flagged");
        assert_eq!(fg, scheme.badge_fg_dark, "warning-background badge");

        assert!(
            field_change_severity("description", false).is_none(),
            "benign fields render generically"
        );
    }
}
