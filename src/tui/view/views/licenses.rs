//! License view for `ViewApp`.

use crate::tui::license_utils::LicenseCategory;
use crate::tui::shared::licenses::category_color;
use crate::tui::theme::colors;
use crate::tui::view::app::{LicenseGroupBy, ViewApp};
use crate::tui::widgets::extract_display_name;
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Table, TableState,
    },
};
use std::collections::{BTreeMap, HashMap};

/// Component info for detail panel display.
struct ComponentInfo {
    display_name: String,
    version: Option<String>,
    component_type: String,
}

pub fn render_licenses(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Build license data once, not per sub-panel
    let license_data = build_license_data(app);

    // Lazily cache the pairwise compatibility report (SBOM is immutable in
    // view mode; "Unknown" is the synthetic no-license bucket, not an SPDX id).
    if app.license_state.compat_report.is_none() {
        let exprs: Vec<&str> = license_data
            .iter()
            .map(|(l, _, _)| l.as_str())
            .filter(|l| *l != "Unknown")
            .collect();
        app.license_state.compat_report = Some(std::sync::Arc::new(
            crate::tui::license_utils::analyze_license_compatibility(&exprs),
        ));
    }
    let report = app.license_state.compat_report.clone();

    render_license_list(frame, chunks[0], app, &license_data, report.as_deref());
    render_license_details(frame, chunks[1], app, &license_data);
}

fn render_license_list(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    license_data: &[(String, usize, LicenseCategory)],
    report: Option<&crate::tui::license_utils::LicenseCompatibilityReport>,
) {
    let scheme = colors();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Filter bar with risk summary (Phase 4)
    let group_label = match app.license_state.group_by {
        LicenseGroupBy::License => "License",
        LicenseGroupBy::Category => "Category",
    };

    // Compute risk summary
    let (permissive, copyleft, unknown) = compute_risk_summary(license_data);

    let filter_line1 = Line::from(vec![
        Span::styled("Group: ", Style::default().fg(scheme.muted)),
        Span::styled(
            format!(" {group_label} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.success)
                .bold(),
        ),
        Span::raw("  │  "),
        Span::styled("[g]", Style::default().fg(scheme.accent)),
        Span::raw(" toggle  "),
        Span::styled("[Enter]", Style::default().fg(scheme.accent)),
        Span::raw(" inspect"),
    ]);

    let mut filter_line2 = Line::from(vec![
        Span::styled(
            format!("✓ {permissive}"),
            Style::default().fg(scheme.success),
        ),
        Span::raw("  "),
        Span::styled(format!("⚠ {copyleft}"), Style::default().fg(scheme.warning)),
        Span::raw("  "),
        Span::styled(
            format!("? {unknown}"),
            Style::default().fg(scheme.text_muted),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("{} total", license_data.len()),
            Style::default().fg(scheme.text_muted),
        ),
    ]);
    if let Some(report) = report
        && !report.issues.is_empty()
    {
        let color = if report
            .issues
            .iter()
            .any(|i| i.severity == crate::tui::license_utils::IssueSeverity::Error)
        {
            scheme.error
        } else {
            scheme.warning
        };
        filter_line2.push_span(Span::raw("  │  "));
        filter_line2.push_span(Span::styled(
            format!("⚡ {} conflicts", report.issues.len()),
            Style::default().fg(color),
        ));
    }

    let filter_bar = Paragraph::new(vec![filter_line1, filter_line2]);
    frame.render_widget(filter_bar, chunks[0]);

    // Update total and clamp selection to valid bounds
    app.license_state.total = license_data.len();
    app.license_state.clamp_selection();

    // Phase 3: Full license expressions (no truncation), use Min() constraint
    let rows: Vec<Row> = license_data
        .iter()
        .enumerate()
        .map(|(i, (license, count, category))| {
            let cat_color = category_color(*category);

            // Show distribution bar in count column
            let max_count = license_data.first().map_or(1, |d| d.1.max(1));
            let bar_width = ((*count as f64 / max_count as f64) * 8.0).ceil() as usize;
            let bar = "█".repeat(bar_width);

            let count_cell = Line::from(vec![
                Span::styled(format!("{count:>4} "), Style::default().fg(scheme.text)),
                Span::styled(bar, Style::default().fg(cat_color)),
            ]);

            // Highlight copyleft/unknown licenses
            let license_style = if i == app.license_state.selected {
                Style::default()
            } else if matches!(
                category,
                LicenseCategory::Unknown | LicenseCategory::Proprietary
            ) {
                Style::default().fg(scheme.text_muted)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(Span::styled(license.as_str(), license_style)),
                Cell::from(count_cell),
                Cell::from(Span::styled(
                    format!(
                        "{} {}",
                        crate::tui::shared::licenses::category_glyph(*category),
                        category.as_str()
                    ),
                    Style::default().fg(cat_color),
                )),
            ])
        })
        .collect();

    let header = Row::new(vec!["License", "Count", "Category"])
        .style(Style::default().fg(scheme.accent).bold());

    let widths = [
        Constraint::Min(20),
        Constraint::Length(14),
        Constraint::Length(15),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(" Licenses ({}) ", license_data.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.success)),
        )
        .row_highlight_style(
            Style::default()
                .bg(scheme.selection)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    // Use scroll_offset to maintain scroll position
    let mut state = TableState::default()
        .with_offset(app.license_state.scroll_offset)
        .with_selected(if license_data.is_empty() {
            None
        } else {
            Some(app.license_state.selected)
        });

    frame.render_stateful_widget(table, chunks[1], &mut state);

    // Save the scroll offset for next frame
    app.license_state.scroll_offset = state.offset();

    // Table scrollbar
    if license_data.len() > chunks[1].height.saturating_sub(3) as usize {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"));
        let sb_area = Rect {
            x: chunks[1].x + chunks[1].width - 1,
            y: chunks[1].y + 1,
            width: 1,
            height: chunks[1].height.saturating_sub(2),
        };
        let mut sb_state =
            ScrollbarState::new(license_data.len()).position(app.license_state.selected);
        frame.render_stateful_widget(scrollbar, sb_area, &mut sb_state);
    }
}

/// Pairwise compatibility of the selected license against every other
/// distinct license in the SBOM. Runs O(unique) `from_spdx` parses per
/// selected-pane render; the full O(unique^2) report is cached separately on
/// `LicenseViewState::compat_report`.
fn selected_license_conflicts(
    selected: &str,
    license_data: &[(String, usize, LicenseCategory)],
) -> Vec<(String, crate::tui::license_utils::CompatibilityResult)> {
    license_data
        .iter()
        .filter(|(l, _, _)| l != selected && l != "Unknown")
        .filter_map(|(l, _, _)| {
            let res = crate::tui::license_utils::check_compatibility(selected, l);
            (!res.compatible || res.score < 70).then(|| (l.clone(), res))
        })
        .collect()
}

fn render_license_details(
    frame: &mut Frame,
    area: Rect,
    app: &mut ViewApp,
    license_data: &[(String, usize, LicenseCategory)],
) {
    let scheme = colors();

    // Safely get the selected license with bounds checking
    let selected_idx = app
        .license_state
        .selected
        .min(license_data.len().saturating_sub(1));
    if let Some((license, count, _category)) = license_data.get(selected_idx) {
        let components = get_components_with_license(app, license);
        app.license_state.component_total = components.len();

        let info = crate::tui::license_utils::LicenseInfo::from_spdx(license);
        let is_dual = crate::tui::license_utils::SpdxExpression::parse(license).is_choice();

        let mut lines = crate::tui::shared::licenses::render_license_metadata_lines(
            license,
            info.category,
            info.risk_level,
            info.family,
            *count,
            is_dual,
        );

        // Phase 3: Show parsed SPDX expression structure for compound licenses
        if is_dual || license.contains(" AND ") {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Expression: ", Style::default().fg(scheme.text_muted)),
                Span::styled(
                    render_spdx_structure(license),
                    Style::default().fg(scheme.accent),
                ),
            ]));
        }

        lines.push(Line::from(""));

        // License characteristics
        lines.extend(crate::tui::shared::licenses::render_license_characteristics_lines(license));

        // Compatibility against the other licenses in this SBOM (the engine
        // computes pairwise SPDX conflicts; view mode previously discarded them)
        let distinct = license_data
            .iter()
            .filter(|(l, _, _)| l != "Unknown")
            .count();
        // Height-gated: at 80x24 the header block already fills the panel, so
        // the section would render as a dangling header with its verdict (and
        // the component list) below the unscrollable fold — the conflict badge
        // in the list header carries the signal at small sizes.
        if license != "Unknown" && distinct >= 2 && area.height >= 20 {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                "Compatibility:",
                Style::default().fg(scheme.primary).bold(),
            ));
            let conflicts = selected_license_conflicts(license, license_data);
            if conflicts.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("  ✓ ", Style::default().fg(scheme.success)),
                    Span::styled(
                        format!("No conflicts with {} other licenses", distinct - 1),
                        Style::default().fg(scheme.success),
                    ),
                ]));
            } else {
                for (other, res) in conflicts.iter().take(3) {
                    let (icon, color) = if res.compatible {
                        ("⚠", scheme.warning)
                    } else {
                        ("✗", scheme.error)
                    };
                    let first_warning = res.warnings.first().map_or("", |w| w.as_str());
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {icon} "), Style::default().fg(color)),
                        Span::styled(
                            format!("vs {other}: {first_warning}"),
                            Style::default().fg(color),
                        ),
                    ]));
                }
                if conflicts.len() > 3 {
                    lines.push(Line::styled(
                        format!("  … and {} more", conflicts.len() - 3),
                        Style::default().fg(scheme.muted),
                    ));
                }
            }
        }

        lines.push(Line::from(""));

        // Phase 5: Group components by type
        let grouped = group_components_by_type(&components);
        let total_groups = grouped.len();

        // Calculate available space for components. Count the header lines *after
        // wrapping* at the panel width (the paragraph renders with Wrap) so a wrapped
        // header doesn't cause the component list to over-fill and overflow the panel.
        let inner_width = area.width.saturating_sub(2); // borders
        let header_lines = crate::tui::shared::text::wrapped_line_count(&lines, inner_width) + 2; // +2 for block borders
        let available = (area.height as usize)
            .saturating_sub(header_lines + 2)
            .max(3);

        // Components header with scroll info
        let scroll_offset = app.license_state.component_scroll;
        let flat_items = flatten_grouped_components(&grouped);
        let total_items = flat_items.len();

        let page_info = if total_items > available {
            format!(" ({}/{})", scroll_offset + 1, total_items)
        } else {
            String::new()
        };

        lines.push(Line::from(vec![
            Span::styled("Components:", Style::default().fg(scheme.primary).bold()),
            Span::styled(format!(" {count}"), Style::default().fg(scheme.text_muted)),
            Span::styled(page_info, Style::default().fg(scheme.muted)),
        ]));

        // Phase 4: Navigation hint
        if !components.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("[Enter]", Style::default().fg(scheme.accent)),
                Span::raw(" jump to component  "),
                Span::styled("[K/J]", Style::default().fg(scheme.accent)),
                Span::raw(" scroll"),
            ]));
        }

        // Render grouped components with scroll
        if total_groups > 1 {
            // Multiple type groups — show grouped
            for item in flat_items.iter().skip(scroll_offset).take(available) {
                lines.push(item.clone());
            }
        } else {
            // Single group or simple list — show flat
            for comp in components.iter().skip(scroll_offset).take(available) {
                let type_icon = component_type_symbol(&comp.component_type);
                let version_str = comp
                    .version
                    .as_deref()
                    .map_or(String::new(), |v| format!("@{v}"));
                lines.push(Line::from(vec![
                    Span::styled(format!("  {type_icon} "), Style::default().fg(scheme.muted)),
                    Span::styled(comp.display_name.clone(), Style::default().fg(scheme.text)),
                    Span::styled(version_str, Style::default().fg(scheme.text_muted)),
                ]));
            }
        }

        // Scroll indicator
        let item_count = if total_groups > 1 {
            total_items
        } else {
            components.len()
        };
        if scroll_offset > 0 || scroll_offset + available < item_count {
            let indicator = if scroll_offset > 0 && scroll_offset + available < item_count {
                "  ↑↓ more"
            } else if scroll_offset > 0 {
                "  ↑ scroll up"
            } else {
                "  ↓ more below"
            };
            lines.push(Line::styled(indicator, Style::default().fg(scheme.muted)));
        }

        let detail = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" License Details ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(scheme.critical)),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(detail, area);

        // Render scrollbar if there are many items
        let scroll_total = if total_groups > 1 {
            total_items
        } else {
            components.len()
        };
        if scroll_total > available {
            let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"));

            let scrollbar_area = Rect {
                x: area.x + area.width - 1,
                y: area.y + 1,
                width: 1,
                height: area.height.saturating_sub(2),
            };

            let mut scrollbar_state = ScrollbarState::new(scroll_total).position(scroll_offset);

            frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
        }
    } else {
        // Phase 2: Distribution chart when nothing selected
        render_distribution_overview(frame, area, license_data);
    }
}

/// Phase 2: Render license distribution chart as empty/overview state.
fn render_distribution_overview(
    frame: &mut Frame,
    area: Rect,
    license_data: &[(String, usize, LicenseCategory)],
) {
    let scheme = colors();

    if license_data.is_empty() {
        crate::tui::shared::components::render_empty_detail_panel(
            frame,
            area,
            " License Details ",
            "",
            "No license data available",
            &[],
            false,
        );
        return;
    }

    let mut lines = vec![];
    lines.push(Line::from(vec![Span::styled(
        "License Distribution",
        Style::default().fg(scheme.text).bold(),
    )]));
    lines.push(Line::from(""));

    // Category breakdown, iterated in the enum's risk-gradient order.
    let mut cat_counts: BTreeMap<LicenseCategory, usize> = BTreeMap::new();
    for (_, count, category) in license_data {
        *cat_counts.entry(*category).or_insert(0) += count;
    }
    let total: usize = cat_counts.values().sum();

    for (cat, count) in &cat_counts {
        let pct = if total > 0 {
            (*count as f64 / total as f64 * 100.0) as usize
        } else {
            0
        };
        let bar_width = (pct as f64 / 100.0 * 20.0).ceil() as usize;
        let bar = "█".repeat(bar_width);
        let cat_color = category_color(*cat);
        let cat = cat.as_str();

        lines.push(Line::from(vec![
            Span::styled(
                format!("{cat:>15} "),
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(bar, Style::default().fg(cat_color)),
            Span::styled(
                format!(" {count} ({pct}%)"),
                Style::default().fg(scheme.text),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Total: ", Style::default().fg(scheme.text_muted)),
        Span::styled(
            total.to_string(),
            Style::default().fg(scheme.primary).bold(),
        ),
        Span::styled(
            " component-licenses",
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    lines.push(Line::from(""));
    lines.push(Line::styled(
        "Select a license to view details →",
        Style::default().fg(scheme.muted),
    ));

    let detail = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" License Overview ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.accent)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    frame.render_widget(detail, area);
}

/// Build license data from a ViewApp (public for cross-module access).
pub fn build_license_data_from_app(app: &ViewApp) -> Vec<(String, usize, LicenseCategory)> {
    build_license_data(app)
}

fn build_license_data(app: &ViewApp) -> Vec<(String, usize, LicenseCategory)> {
    let mut license_map: HashMap<String, usize> = HashMap::new();

    for comp in app.sbom.components.values() {
        if comp.licenses.declared.is_empty() {
            *license_map.entry("Unknown".to_string()).or_insert(0) += 1;
        } else {
            for lic in &comp.licenses.declared {
                *license_map.entry(lic.expression.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut data: Vec<_> = license_map
        .into_iter()
        .map(|(license, count)| {
            let category = crate::tui::license_utils::LicenseInfo::from_spdx(&license).category;
            (license, count, category)
        })
        .collect();

    data.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    data
}

/// Phase 1: Return rich component info instead of just names.
fn get_components_with_license(app: &ViewApp, license: &str) -> Vec<ComponentInfo> {
    let mut components = Vec::new();

    for comp in app.sbom.components.values() {
        let has_license = if license == "Unknown" {
            comp.licenses.declared.is_empty()
        } else {
            comp.licenses
                .declared
                .iter()
                .any(|l| l.expression == license)
        };

        if has_license {
            components.push(ComponentInfo {
                display_name: extract_display_name(&comp.name),
                version: comp.version.clone(),
                component_type: format!("{:?}", comp.component_type),
            });
        }
    }

    components.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    components
}

/// Phase 4: Get the canonical ID of the first component for the selected license.
pub fn get_first_component_id_for_license(app: &ViewApp, license: &str) -> Option<String> {
    for comp in app.sbom.components.values() {
        let has_license = if license == "Unknown" {
            comp.licenses.declared.is_empty()
        } else {
            comp.licenses
                .declared
                .iter()
                .any(|l| l.expression == license)
        };
        if has_license {
            return Some(comp.canonical_id.value().to_string());
        }
    }
    None
}

/// Phase 4: Compute risk summary counts for filter bar.
///
/// Matches on the enum exhaustively — the previous string match compared
/// against `"Strong Copyleft"`, which `LicenseCategory::StrongCopyleft`
/// never produces (`as_str()` is `"Copyleft"`), so every GPL component was
/// silently counted as "unknown".
fn compute_risk_summary(
    license_data: &[(String, usize, LicenseCategory)],
) -> (usize, usize, usize) {
    let mut permissive = 0usize;
    let mut copyleft = 0usize;
    let mut unknown = 0usize;

    for (_, count, category) in license_data {
        match category {
            LicenseCategory::Permissive | LicenseCategory::PublicDomain => permissive += count,
            LicenseCategory::WeakCopyleft
            | LicenseCategory::StrongCopyleft
            | LicenseCategory::NetworkCopyleft => copyleft += count,
            LicenseCategory::Proprietary | LicenseCategory::Unknown => unknown += count,
        }
    }

    (permissive, copyleft, unknown)
}

/// Phase 3: Render SPDX expression structure as readable string.
fn render_spdx_structure(license: &str) -> String {
    if license.contains(" OR ") {
        let parts: Vec<&str> = license.split(" OR ").collect();
        format!("Choice: {}", parts.join(" | "))
    } else if license.contains(" AND ") {
        let parts: Vec<&str> = license.split(" AND ").collect();
        format!("All required: {}", parts.join(" + "))
    } else {
        license.to_string()
    }
}

/// Phase 5: Group components by their type.
fn group_components_by_type(components: &[ComponentInfo]) -> BTreeMap<String, Vec<&ComponentInfo>> {
    let mut groups: BTreeMap<String, Vec<&ComponentInfo>> = BTreeMap::new();
    for comp in components {
        let group_name = match comp.component_type.as_str() {
            "File" => "Files",
            "Library" => "Libraries",
            "Application" => "Applications",
            "Framework" => "Frameworks",
            "Container" => "Containers",
            "Firmware" => "Firmware",
            "Data" => "Data",
            _ => "Other",
        };
        groups.entry(group_name.to_string()).or_default().push(comp);
    }
    groups
}

/// Phase 5: Flatten grouped components into display lines.
fn flatten_grouped_components(
    groups: &BTreeMap<String, Vec<&ComponentInfo>>,
) -> Vec<Line<'static>> {
    let scheme = colors();
    let mut lines = Vec::new();

    for (group_name, comps) in groups {
        // Group header
        lines.push(Line::from(vec![
            Span::styled(
                format!("  ┌ {group_name}"),
                Style::default().fg(scheme.accent).bold(),
            ),
            Span::styled(
                format!(" ({})", comps.len()),
                Style::default().fg(scheme.text_muted),
            ),
        ]));

        for (i, comp) in comps.iter().enumerate() {
            let connector = if i == comps.len() - 1 { "└" } else { "├" };
            let type_icon = component_type_symbol(&comp.component_type);
            let version_str = comp
                .version
                .as_deref()
                .map_or(String::new(), |v| format!("@{v}"));

            lines.push(Line::from(vec![
                Span::styled(
                    format!("  │ {connector} {type_icon} "),
                    Style::default().fg(scheme.muted),
                ),
                Span::styled(comp.display_name.clone(), Style::default().fg(scheme.text)),
                Span::styled(version_str, Style::default().fg(scheme.text_muted)),
            ]));
        }
    }

    lines
}

/// Get a symbol for a component type (consistent with TUI Unicode style).
fn component_type_symbol(component_type: &str) -> &'static str {
    match component_type {
        "File" => "f",
        "Library" => "L",
        "Application" => "A",
        "Framework" => "F",
        "Container" => "C",
        "Firmware" => "W",
        "Data" => "D",
        _ => "·",
    }
}

#[cfg(test)]
mod risk_summary_tests {
    use super::*;

    fn entry(expr: &str, count: usize) -> (String, usize, LicenseCategory) {
        let category = crate::tui::license_utils::LicenseInfo::from_spdx(expr).category;
        (expr.to_string(), count, category)
    }

    /// Regression for the GPL miscount: the old string match compared against
    /// "Strong Copyleft", which `as_str()` never produces ("Copyleft"), so
    /// every GPL component fell through to the unknown bucket.
    #[test]
    fn gpl_and_agpl_count_as_copyleft_not_unknown() {
        let data = vec![
            entry("GPL-3.0-only", 3),
            entry("AGPL-3.0-only", 2),
            entry("CC0-1.0", 1),
            entry("MIT", 4),
        ];

        let (permissive, copyleft, unknown) = compute_risk_summary(&data);
        assert_eq!(permissive, 5, "MIT + CC0 (public domain)");
        assert_eq!(copyleft, 5, "GPL (strong) + AGPL (network)");
        assert_eq!(unknown, 0, "no unknowns in this set");
    }

    /// The engine flags GPL-2.0's patent-clause clash with Apache-2.0; the
    /// per-selection helper must surface it (and stay quiet for MIT).
    #[test]
    fn selected_license_conflicts_flags_gpl2_apache_patent_clash() {
        let data = vec![entry("GPL-2.0-only", 1), entry("Apache-2.0", 1)];
        let conflicts = selected_license_conflicts("Apache-2.0", &data);
        assert_eq!(conflicts.len(), 1, "exactly one conflicting pair");
        assert_eq!(conflicts[0].0, "GPL-2.0-only");
        assert!(
            conflicts[0]
                .1
                .warnings
                .first()
                .is_some_and(|w| w.contains("patent clauses")),
            "first warning must name the patent clash: {:?}",
            conflicts[0].1.warnings
        );

        let data = vec![entry("MIT", 1), entry("Apache-2.0", 1)];
        assert!(
            selected_license_conflicts("MIT", &data).is_empty(),
            "MIT vs Apache-2.0 is conflict-free"
        );
    }
}
