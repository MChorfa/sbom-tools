//! Source tab rendering for `ViewApp` with SBOM Map panel.

use crate::model::{Component, CreatorType, NormalizedSbom};
use crate::tui::app_states::source::{JsonTreeNode, SourceViewMode};
use crate::tui::shared::source::{render_source_panel, render_str};
use crate::tui::theme::colors;
use crate::tui::view::app::{FocusPanel, SbomStats, ViewApp, ViewTab};
use ratatui::{
    buffer::Buffer,
    prelude::*,
    widgets::{Block, Borders},
};
use std::collections::HashMap;
use std::fmt::Write;

/// Render the source tab for a single SBOM with map panel.
pub fn render_source(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    // Pre-compute link labels for navigable references (visible items only)
    app.source_state.ensure_flat_cache();
    let scroll = app.source_state.scroll_offset;
    let visible = app.source_state.viewport_height.max(50);
    let mut labels = HashMap::new();
    // Build bom-ref → component name lookup for dependency resolution
    let bomref_names: HashMap<String, String> = app
        .sbom
        .components
        .values()
        .filter_map(|c| {
            let bomref = &c.identifiers.format_id;
            if bomref.is_empty() {
                None
            } else {
                let label = c
                    .version
                    .as_ref()
                    .map_or_else(|| c.name.clone(), |v| format!("{}@{v}", c.name));
                Some((bomref.clone(), label))
            }
        })
        .collect();

    // Resolve dependency previews: replace bom-ref UUIDs with component names
    // Dependency items have node_ids like "root.dependencies.[N]"
    for item in &mut app.source_state.cached_flat_items {
        if item.is_expandable
            && !item.preview.is_empty()
            && item.node_id.starts_with("root.dependencies.[")
        {
            // Preview format: "uuid → N deps" — resolve the UUID part
            if let Some(arrow_pos) = item.preview.find(" \u{2192} ") {
                let ref_part = &item.preview[..arrow_pos];
                if let Some(name) = bomref_names.get(ref_part) {
                    let rest = &item.preview[arrow_pos..];
                    item.preview = format!("{name}{rest}");
                }
            }
        }
    }

    match app.source_state.view_mode {
        SourceViewMode::Tree => {
            let range_end = (scroll + visible + 5).min(app.source_state.cached_flat_items.len());
            for idx in scroll.saturating_sub(2)..range_end {
                if let Some(item) = app.source_state.cached_flat_items.get(idx)
                    // Skip expandable objects — their labels are already shown as smart previews
                    && !item.is_expandable
                    && let Some(link) = resolve_source_reference(item, &app.sbom)
                {
                    labels.insert(idx, link.display_label);
                }
            }
        }
        SourceViewMode::Raw => {
            let range_end = (scroll + visible + 5).min(app.source_state.raw_lines.len());
            for line_idx in scroll.saturating_sub(2)..range_end {
                // First try the tree-based resolution
                let mut resolved = false;
                if let Some(node_id) = app
                    .source_state
                    .raw_line_node_ids
                    .get(line_idx)
                    .filter(|nid| !nid.is_empty())
                    && let Some(item) = app
                        .source_state
                        .cached_flat_items
                        .iter()
                        .find(|i| i.node_id == *node_id)
                    && let Some(link) = resolve_source_reference(item, &app.sbom)
                {
                    labels.insert(line_idx, link.display_label);
                    resolved = true;
                }
                // Fallback: directly resolve bom-ref UUIDs from raw line content
                if !resolved && let Some(line) = app.source_state.raw_lines.get(line_idx) {
                    let trimmed = line.trim();
                    // Match "ref": "uuid" or bare "uuid" in dependsOn arrays
                    let val = if let Some(rest) = trimmed.strip_prefix("\"ref\": \"") {
                        rest.strip_suffix(['"', ','])
                    } else if trimmed.starts_with('"')
                        && !trimmed.contains(':')
                        && app
                            .source_state
                            .raw_line_node_ids
                            .get(line_idx)
                            .is_some_and(|nid| nid.contains("dependsOn"))
                    {
                        trimmed.trim_matches(['"', ',']).into()
                    } else {
                        None
                    };
                    if let Some(ref_val) = val
                        && let Some(name) = bomref_names.get(ref_val)
                    {
                        labels.insert(line_idx, name.clone());
                    }
                }
            }
        }
    }
    app.source_state.link_labels = labels;

    let is_source_focused = app.focus_panel == FocusPanel::Left;
    // Pre-compute render state to avoid mutations inside the render path
    app.source_state
        .prepare_source_render(chunks[0].height.saturating_sub(2) as usize);
    render_source_panel(
        frame,
        chunks[0],
        &mut app.source_state,
        "SBOM Source",
        is_source_focused,
    );
    render_source_map(frame, chunks[1], app, !is_source_focused);
}

/// A section in the SBOM map derived from the JSON tree root's children.
struct MapSection {
    key: String,
    is_expandable: bool,
    /// True if Object ({}), false if Array ([])
    is_object: bool,
    child_count: usize,
    line_start: usize,
}

/// Build map sections from the JSON tree root's children.
fn build_map_sections(state: &crate::tui::app_states::source::SourcePanelState) -> Vec<MapSection> {
    let Some(tree) = &state.json_tree else {
        return Vec::new();
    };

    let Some(children) = tree.children() else {
        return Vec::new();
    };

    let line_starts = compute_raw_line_starts(&state.raw_lines);

    children
        .iter()
        .map(|child| {
            let key = match child {
                JsonTreeNode::Object { key, .. }
                | JsonTreeNode::Array { key, .. }
                | JsonTreeNode::Leaf { key, .. } => key.clone(),
            };
            let is_expandable = child.is_expandable();
            let is_object = matches!(child, JsonTreeNode::Object { .. });
            let child_count = match child {
                JsonTreeNode::Object { children, .. } => children.len(),
                JsonTreeNode::Array { len, .. } => *len,
                JsonTreeNode::Leaf { .. } => 0,
            };
            let line_start = line_starts
                .iter()
                .find(|(k, _)| k == &key)
                .map_or(0, |(_, l)| *l);

            MapSection {
                key,
                is_expandable,
                is_object,
                child_count,
                line_start,
            }
        })
        .collect()
}

/// Find the starting line number for each top-level key in pretty-printed JSON.
fn compute_raw_line_starts(raw_lines: &[String]) -> Vec<(String, usize)> {
    let mut result = Vec::new();
    for (i, line) in raw_lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if line.starts_with("  \"")
            && !line.starts_with("    ")
            && let Some(end) = trimmed.find("\":")
        {
            let key = trimmed[1..end].to_string();
            result.push((key, i));
        }
    }
    result
}

/// Determine which section the cursor is currently inside (tree mode).
fn current_section_from_node_id(node_id: &str) -> Option<String> {
    let parts: Vec<&str> = node_id.split('.').collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Determine which section a raw line belongs to.
fn current_section_for_raw_line(line_idx: usize, sections: &[MapSection]) -> Option<String> {
    let mut current = None;
    for s in sections {
        if s.line_start <= line_idx {
            current = Some(s.key.clone());
        } else {
            break;
        }
    }
    current
}

/// Extract the array index from a `node_id` if inside a section array.
/// e.g., "root.components.[42].name" => Some(42)
fn extract_array_index(node_id: &str) -> Option<usize> {
    let parts: Vec<&str> = node_id.split('.').collect();
    if parts.len() >= 3 {
        let idx_part = parts[2];
        if idx_part.starts_with('[') && idx_part.ends_with(']') {
            idx_part[1..idx_part.len() - 1].parse().ok()
        } else {
            None
        }
    } else {
        None
    }
}

/// Build a semantic breadcrumb from a `node_id`, replacing array indices with labels.
/// e.g., "root.components.[5].name" → "components > lodash@4.17.21 > name"
fn semantic_breadcrumb(node_id: &str, sbom: &NormalizedSbom) -> String {
    let parts: Vec<&str> = node_id.split('.').collect();
    if parts.len() < 2 {
        return "root".to_string();
    }

    let mut result = Vec::new();
    let mut prev_section = "";

    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.starts_with('[') && part.ends_with(']') {
            if let Ok(idx) = part[1..part.len() - 1].parse::<usize>() {
                let label = match prev_section {
                    "components" => sbom.components.values().nth(idx).map(|c| {
                        c.version
                            .as_ref()
                            .map_or_else(|| c.name.clone(), |v| format!("{}@{}", c.name, v))
                    }),
                    _ => None,
                };
                result.push(label.unwrap_or_else(|| part.to_string()));
            } else {
                result.push(part.to_string());
            }
        } else {
            if i == 1 {
                prev_section = part;
            }
            result.push(part.to_string());
        }
    }

    result.join(" > ")
}

// ============================================================================
// Cross-Tab Reference Resolution
// ============================================================================

/// A resolved cross-tab reference from the Source tab.
#[derive(Debug, Clone)]
pub(crate) struct SourceLink {
    /// Which tab to navigate to
    pub tab: ViewTab,
    /// Entity ID to select in the target tab (canonical component ID or vuln ID)
    pub entity_id: String,
    /// Human-readable label for status message
    pub display_label: String,
}

/// Try to resolve a `FlatJsonItem` into a navigable cross-tab link.
///
/// Recognizes:
/// - `ref` / `bom-ref` fields pointing to components (CycloneDX)
/// - `spdxElementId` / `SPDXID` fields pointing to components (SPDX)
/// - `dependsOn` array entries (dependency refs → component)
/// - `id` inside vulnerabilities section (CVE IDs → Vulnerabilities tab)
/// - `affects.[n].ref` inside vulnerabilities (affected component → Tree tab)
/// - Expandable component objects (components.[N]) → Tree tab
pub(crate) fn resolve_source_reference(
    item: &crate::tui::shared::source::FlatJsonItem,
    sbom: &NormalizedSbom,
) -> Option<SourceLink> {
    // --- Expandable component/vulnerability objects ---
    if item.is_expandable {
        return resolve_expandable_object(item, sbom);
    }

    if item.value_preview.is_empty() {
        return None;
    }
    // Strip surrounding quotes from the value
    let val = item.value_preview.trim_matches('"');
    if val.is_empty() {
        return None;
    }

    let node_id = &item.node_id;
    let key = &item.display_key;
    let section = current_section_from_node_id(node_id);

    // --- Vulnerability ID (e.g., CVE-2024-1234) ---
    if section.as_deref() == Some("vulnerabilities") && key == "id" {
        return Some(SourceLink {
            tab: ViewTab::Vulnerabilities,
            entity_id: val.to_string(),
            display_label: val.to_string(),
        });
    }

    // --- Component references (bom-ref, SPDXID, ref, dependsOn entries) ---
    let is_ref_field = matches!(
        key.as_str(),
        "ref" | "bom-ref" | "spdxElementId" | "SPDXID" | "spdxElement"
    );
    let is_depends_on_entry = node_id.contains("dependsOn.");

    if is_ref_field || is_depends_on_entry {
        // Try to resolve the reference value to a component
        if let Some((cid, comp)) = find_component_by_format_id(sbom, val) {
            let label = comp
                .version
                .as_ref()
                .map_or_else(|| comp.name.clone(), |v| format!("{}@{v}", comp.name));
            return Some(SourceLink {
                tab: ViewTab::Tree,
                entity_id: cid,
                display_label: label,
            });
        }
    }

    None
}

/// Resolve an expandable object node (e.g., components.[3], vulnerabilities.[0]).
///
/// Uses the array index from the node_id to look up the corresponding entity.
fn resolve_expandable_object(
    item: &crate::tui::shared::source::FlatJsonItem,
    sbom: &NormalizedSbom,
) -> Option<SourceLink> {
    let section = current_section_from_node_id(&item.node_id)?;
    let idx = extract_array_index(&item.node_id)?;

    match section.as_str() {
        "components" => {
            let (cid, comp) = sbom.components.iter().nth(idx)?;
            let label = comp
                .version
                .as_ref()
                .map_or_else(|| comp.name.clone(), |v| format!("{}@{v}", comp.name));
            Some(SourceLink {
                tab: ViewTab::Tree,
                entity_id: cid.value().to_string(),
                display_label: label,
            })
        }
        "vulnerabilities" => {
            let vuln = sbom
                .components
                .values()
                .flat_map(|c| &c.vulnerabilities)
                .nth(idx)?;
            Some(SourceLink {
                tab: ViewTab::Vulnerabilities,
                entity_id: vuln.id.clone(),
                display_label: vuln.id.clone(),
            })
        }
        _ => None,
    }
}

/// Find a component by its format-specific ID (bom-ref, SPDXID).
fn find_component_by_format_id<'a>(
    sbom: &'a NormalizedSbom,
    format_id: &str,
) -> Option<(String, &'a Component)> {
    sbom.components
        .iter()
        .find(|(_, c)| c.identifiers.format_id == format_id)
        .map(|(id, c)| (id.value().to_string(), c))
}

/// Pre-compute search match counts per section.
/// Requires flat cache to be warm (call `ensure_flat_cache()` before this).
fn compute_section_match_counts(
    state: &crate::tui::app_states::source::SourcePanelState,
    sections: &[MapSection],
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    if state.search_matches.is_empty() {
        return counts;
    }

    match state.view_mode {
        SourceViewMode::Tree => {
            for &idx in &state.search_matches {
                if let Some(item) = state.cached_flat_items.get(idx)
                    && let Some(section) = current_section_from_node_id(&item.node_id)
                {
                    *counts.entry(section).or_insert(0) += 1;
                }
            }
        }
        SourceViewMode::Raw => {
            for &line_idx in &state.search_matches {
                if let Some(section) = current_section_for_raw_line(line_idx, sections) {
                    *counts.entry(section).or_insert(0) += 1;
                }
            }
        }
    }

    counts
}

/// Get the current section based on cursor position and view mode.
/// Requires flat cache to be warm (call `ensure_flat_cache()` before this).
fn get_current_section(app: &ViewApp, sections: &[MapSection]) -> Option<String> {
    match app.source_state.view_mode {
        SourceViewMode::Tree => app
            .source_state
            .cached_flat_items
            .get(app.source_state.selected)
            .and_then(|item| current_section_from_node_id(&item.node_id)),
        SourceViewMode::Raw => current_section_for_raw_line(app.source_state.selected, sections),
    }
}

// ============================================================================
// Map Panel Rendering
// ============================================================================

/// Render the SBOM map panel on the right side.
fn render_source_map(frame: &mut Frame, area: Rect, app: &mut ViewApp, is_focused: bool) {
    // Ensure flat cache is warm (normally already done by render_source_panel)
    app.source_state.ensure_flat_cache();

    let scheme = colors();
    let border_color = if is_focused {
        scheme.accent
    } else {
        scheme.border
    };

    let block = Block::default()
        .title(" SBOM Map ")
        .title_style(Style::default().fg(border_color).bold())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width < 6 || inner.height < 4 {
        return;
    }

    let sections = build_map_sections(&app.source_state);

    // Non-JSON empty state
    if sections.is_empty() && app.source_state.json_tree.is_none() {
        render_non_json_map(frame.buffer_mut(), inner, app, is_focused, &scheme);
        return;
    }

    // Clamp map_selected
    let navigable_count = sections.iter().filter(|s| s.is_expandable).count();
    if navigable_count > 0 && app.source_state.map_selected >= navigable_count {
        app.source_state.map_selected = navigable_count - 1;
    }

    // Determine current section from cursor position
    let current_section = get_current_section(app, &sections);

    // Pre-compute search match counts per section
    let section_match_counts = if app.source_state.search_matches.is_empty() {
        HashMap::new()
    } else {
        compute_section_match_counts(&app.source_state, &sections)
    };

    // Compute effective total for progress bar
    let effective_total = if app.source_state.view_mode == SourceViewMode::Raw {
        app.source_state.raw_lines.len()
    } else if app.source_state.visible_count > 0 {
        app.source_state.visible_count
    } else {
        app.source_state.total_node_count
    };

    let buf = frame.buffer_mut();
    let mut y = inner.y;
    let max_y = inner.y + inner.height;
    let x = inner.x;
    let width = inner.width;
    let right_edge = x + width;

    // Reserve bottom rows for progress bar + hints
    let hints_rows: u16 = u16::from(is_focused);
    let progress_y = max_y.saturating_sub(1 + hints_rows);
    let context_max_y = progress_y;

    // === Compact Header (1-2 lines) ===
    y = render_compact_header(buf, x, y, width, app, &scheme);

    if y >= context_max_y {
        render_progress_bar(
            buf,
            x,
            progress_y,
            width,
            app.source_state.selected,
            effective_total,
            &scheme,
        );
        if is_focused {
            render_hints(buf, x, max_y - 1, width, &scheme);
        }
        return;
    }

    // === Separator ===
    render_separator(buf, x, y, width, &scheme);
    y += 1;

    if y >= context_max_y {
        render_progress_bar(
            buf,
            x,
            progress_y,
            width,
            app.source_state.selected,
            effective_total,
            &scheme,
        );
        if is_focused {
            render_hints(buf, x, max_y - 1, width, &scheme);
        }
        return;
    }

    // === Sections (single-line per section, scrollable) ===
    let total_expandable = navigable_count;

    // Reserve space below sections: 1 separator + at least 2 context rows
    let section_end_y = context_max_y.saturating_sub(3);
    let available_rows = section_end_y.saturating_sub(y) as usize;

    if total_expandable > available_rows && available_rows > 2 {
        // Scrolling needed — reserve up to 2 rows for indicators
        let capacity = available_rows.saturating_sub(2);

        // Adjust scroll offset to keep selected visible
        if capacity > 0 {
            if app.source_state.map_selected >= app.source_state.map_scroll_offset + capacity {
                app.source_state.map_scroll_offset = app.source_state.map_selected + 1 - capacity;
            }
            if app.source_state.map_selected < app.source_state.map_scroll_offset {
                app.source_state.map_scroll_offset = app.source_state.map_selected;
            }
            app.source_state.map_scroll_offset = app
                .source_state
                .map_scroll_offset
                .min(total_expandable.saturating_sub(capacity));
        }

        // Scroll-up indicator
        if app.source_state.map_scroll_offset > 0 && y < section_end_y {
            render_str(
                buf,
                x,
                y,
                " \u{25b2} more",
                width,
                Style::default().fg(scheme.text_muted),
            );
            y += 1;
        }
    } else {
        app.source_state.map_scroll_offset = 0;
    }

    let capacity = if total_expandable > available_rows {
        available_rows.saturating_sub(2)
    } else {
        total_expandable
    };
    let mut nav_idx = 0usize;
    let mut rendered = 0usize;

    // Pre-compute max count width for column alignment
    let max_count_width = sections
        .iter()
        .filter(|s| s.is_expandable)
        .map(|s| {
            if s.is_object {
                format!("{{{}}}", s.child_count).len()
            } else {
                format!("[{}]", s.child_count).len()
            }
        })
        .max()
        .unwrap_or(0);

    for section in &sections {
        if !section.is_expandable {
            continue;
        }

        // Skip sections before scroll offset
        if nav_idx < app.source_state.map_scroll_offset {
            nav_idx += 1;
            continue;
        }

        // Stop when capacity reached
        if rendered >= capacity || y >= section_end_y {
            break;
        }

        let is_current = current_section.as_deref() == Some(&section.key);
        let is_map_selected = is_focused && nav_idx == app.source_state.map_selected;
        let match_count = section_match_counts.get(&section.key).copied().unwrap_or(0);

        // Build section line components
        let count_str = if section.is_object {
            format!("{{{}}}", section.child_count)
        } else {
            format!("[{}]", section.child_count)
        };
        // Right-pad count to fixed width for column alignment
        let count_padded = format!("{count_str:>max_count_width$}");
        let match_str = if match_count > 0 {
            format!(" ({match_count})")
        } else {
            String::new()
        };
        let marker = if is_current { " \u{25c0}" } else { "" };
        let badge = section_badge(
            &section.key,
            &app.stats,
            &app.sbom,
            (width as usize).saturating_sub(
                section.key.len() + count_padded.len() + match_str.len() + marker.len() + 8,
            ),
        );

        // Left side: " ▸ key_name"
        let left = format!(" \u{25b8} {}", section.key);
        let style = if is_map_selected {
            Style::default().fg(scheme.primary).bold()
        } else if match_count > 0 {
            Style::default().fg(scheme.accent)
        } else {
            Style::default().fg(scheme.text)
        };
        render_str(buf, x, y, &left, width, style);

        // Right side: " count match  badge marker" — right-aligned
        let mut right = format!(" {count_padded}{match_str}");
        if !badge.is_empty() {
            let _ = write!(right, "  {badge}");
        }
        right.push_str(marker);

        let right_len = right.len() as u16;
        if width > right_len {
            let rx = right_edge - right_len;

            // Render count portion (padded for alignment)
            let count_full = format!(" {count_padded}");
            let count_style = if is_current {
                Style::default().fg(scheme.accent)
            } else {
                Style::default().fg(scheme.muted)
            };
            render_str(buf, rx, y, &count_full, right_edge - rx, count_style);

            let mut cx = rx + count_full.len() as u16;

            // Render match count in accent
            if match_count > 0 {
                render_str(
                    buf,
                    cx,
                    y,
                    &match_str,
                    right_edge - cx,
                    Style::default().fg(scheme.accent),
                );
                cx += match_str.len() as u16;
            }

            // Render badge in muted
            if !badge.is_empty() {
                let bt = format!("  {badge}");
                render_str(
                    buf,
                    cx,
                    y,
                    &bt,
                    right_edge - cx,
                    Style::default().fg(scheme.muted),
                );
                cx += bt.len() as u16;
            }

            // Render marker in accent bold
            if is_current {
                render_str(
                    buf,
                    cx,
                    y,
                    marker,
                    right_edge - cx,
                    Style::default().fg(scheme.accent).bold(),
                );
            }
        }

        // Highlight selected row with readable contrast
        if is_map_selected {
            for col in x..right_edge {
                if let Some(cell) = buf.cell_mut((col, y)) {
                    cell.set_bg(scheme.selection);
                    // Override muted fg colors so text stays readable
                    if cell.fg == scheme.muted
                        || cell.fg == scheme.text_muted
                        || cell.fg == scheme.border
                    {
                        cell.set_fg(scheme.text);
                    }
                }
            }
        }

        y += 1;
        nav_idx += 1;
        rendered += 1;
    }

    // Scroll-down indicator
    let remaining_expandable = total_expandable - app.source_state.map_scroll_offset - rendered;
    if remaining_expandable > 0 && y < section_end_y {
        render_str(
            buf,
            x,
            y,
            " \u{25bc} more",
            width,
            Style::default().fg(scheme.text_muted),
        );
        y += 1;
    }

    if y >= context_max_y {
        render_progress_bar(
            buf,
            x,
            progress_y,
            width,
            app.source_state.selected,
            effective_total,
            &scheme,
        );
        if is_focused {
            render_hints(buf, x, max_y - 1, width, &scheme);
        }
        return;
    }

    // === Separator before context ===
    render_separator(buf, x, y, width, &scheme);
    y += 1;

    // === Context area (dynamic, fills remaining space) ===
    render_context(buf, x, y, width, context_max_y, app, &sections, &scheme);

    // === Progress bar (bottom-anchored) ===
    render_progress_bar(
        buf,
        x,
        progress_y,
        width,
        app.source_state.selected,
        effective_total,
        &scheme,
    );

    // === Keyboard hints (when focused) ===
    if is_focused {
        render_hints(buf, x, max_y - 1, width, &scheme);
    }
}

// ============================================================================
// Header
// ============================================================================

/// Compact 2-line header: format+version+date, tool name.
fn render_compact_header(
    buf: &mut Buffer,
    x: u16,
    mut y: u16,
    width: u16,
    app: &ViewApp,
    scheme: &crate::tui::theme::ColorScheme,
) -> u16 {
    let doc = &app.sbom.document;

    // Line 1: format + version + date
    let format_line = format!(
        " {} {} \u{2502} {}",
        doc.format,
        doc.format_version,
        doc.created.format("%Y-%m-%d"),
    );
    render_str(
        buf,
        x,
        y,
        &format_line,
        width,
        Style::default().fg(scheme.primary).bold(),
    );
    y += 1;

    // Line 2: tool name (optional)
    if let Some(tool) = doc
        .creators
        .iter()
        .find(|c| c.creator_type == CreatorType::Tool)
    {
        let tool_line = format!(
            " Tool: {}",
            truncate_map_str(&tool.name, (width as usize).saturating_sub(8))
        );
        render_str(
            buf,
            x,
            y,
            &tool_line,
            width,
            Style::default().fg(scheme.text_muted),
        );
        y += 1;
    }

    y
}

// ============================================================================
// Section Badge
// ============================================================================

/// Compute inline badge text for a section line.
///
/// Returns a compact summary string to display next to the section count:
/// - components: top ecosystem names (e.g., "npm maven")
/// - vulnerabilities: severity counts (e.g., "2C 1H 3M")
/// - metadata: tool short name
fn section_badge(key: &str, stats: &SbomStats, sbom: &NormalizedSbom, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }

    match key {
        "components" => {
            let mut ecosystems: Vec<_> = stats.ecosystem_counts.iter().collect();
            ecosystems.sort_by(|a, b| b.1.cmp(a.1));

            let mut badge = String::new();
            for (eco, _) in ecosystems.iter().take(3) {
                if !badge.is_empty() {
                    badge.push(' ');
                }
                if badge.len() + eco.len() > max_len {
                    break;
                }
                badge.push_str(eco);
            }
            badge
        }
        "vulnerabilities" => {
            let mut parts = Vec::new();
            if stats.critical_count > 0 {
                parts.push(format!("{}C", stats.critical_count));
            }
            if stats.high_count > 0 {
                parts.push(format!("{}H", stats.high_count));
            }
            if stats.medium_count > 0 {
                parts.push(format!("{}M", stats.medium_count));
            }
            if stats.low_count > 0 {
                parts.push(format!("{}L", stats.low_count));
            }
            let result = parts.join(" ");
            if result.len() > max_len {
                truncate_map_str(&result, max_len)
            } else {
                result
            }
        }
        "metadata" => sbom
            .document
            .creators
            .iter()
            .find(|c| c.creator_type == CreatorType::Tool)
            .map(|c| truncate_map_str(&c.name, max_len.min(12)))
            .unwrap_or_default(),
        "dependencies" | "relationships" => {
            let edge_count = sbom.edges.len();
            if edge_count > 0 {
                let label = format!("{edge_count} edges");
                truncate_map_str(&label, max_len)
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

// ============================================================================
// Context Area
// ============================================================================

/// Render the dynamic context area below sections.
///
/// Shows semantic breadcrumb + contextual information:
/// - Component details when inside components section
/// - Vulnerability info when inside vulnerabilities section
/// - Document summary at root level or generic sections
#[allow(clippy::too_many_arguments)]
fn render_context(
    buf: &mut Buffer,
    x: u16,
    mut y: u16,
    width: u16,
    max_y: u16,
    app: &ViewApp,
    sections: &[MapSection],
    scheme: &crate::tui::theme::ColorScheme,
) {
    if y >= max_y {
        return;
    }

    // Get selected node info (uses cached flat items, already warm from render_source_panel)
    let (section_name, array_idx, node_id_full) = match app.source_state.view_mode {
        SourceViewMode::Tree => app
            .source_state
            .cached_flat_items
            .get(app.source_state.selected)
            .map_or((None, None, None), |item| {
                let section = current_section_from_node_id(&item.node_id);
                let idx = extract_array_index(&item.node_id);
                (section, idx, Some(item.node_id.clone()))
            }),
        SourceViewMode::Raw => {
            let section = current_section_for_raw_line(app.source_state.selected, sections);
            // Extract array_idx from raw_line_node_ids mapping
            let (idx, nid) = app
                .source_state
                .raw_line_node_ids
                .get(app.source_state.selected)
                .filter(|nid| !nid.is_empty())
                .map_or((None, None), |nid| {
                    (extract_array_index(nid), Some(nid.clone()))
                });
            (section, idx, nid)
        }
    };

    // Semantic breadcrumb
    let breadcrumb = node_id_full.as_ref().map_or_else(
        || {
            section_name
                .as_ref()
                .map_or_else(|| "root".to_string(), String::clone)
        },
        |nid| {
            let bc = semantic_breadcrumb(nid, &app.sbom);
            if bc.is_empty() {
                "root".to_string()
            } else {
                bc
            }
        },
    );
    render_str(
        buf,
        x,
        y,
        &format!(
            " {}",
            truncate_map_str(&breadcrumb, (width as usize).saturating_sub(2))
        ),
        width,
        Style::default().fg(scheme.text).bold(),
    );
    y += 1;
    if y >= max_y {
        return;
    }

    // Raw mode: compact line info (line number + preview on single line)
    if app.source_state.view_mode == SourceViewMode::Raw {
        let line_num = app.source_state.selected + 1;
        let total = app.source_state.raw_lines.len();
        let preview = app
            .source_state
            .raw_lines
            .get(app.source_state.selected)
            .map(|l| l.trim())
            .filter(|t| !t.is_empty())
            .unwrap_or("");
        let line_info = format!(" L{line_num}/{total}");
        if preview.is_empty() {
            render_str(
                buf,
                x,
                y,
                &line_info,
                width,
                Style::default().fg(scheme.muted),
            );
        } else {
            let info_len = line_info.len() + 3; // " · " separator
            let remaining = (width as usize).saturating_sub(info_len);
            let truncated = truncate_map_str(preview, remaining);
            render_str(
                buf,
                x,
                y,
                &format!("{line_info} \u{00b7} {truncated}"),
                width,
                Style::default().fg(scheme.muted),
            );
        }
        y += 1;
        if y >= max_y {
            return;
        }
        // Fall through to component/vulnerability detail below
    }

    // Component context
    if let (Some(section), Some(idx)) = (&section_name, array_idx) {
        if section == "components"
            && let Some(comp) = app.sbom.components.values().nth(idx)
        {
            let is_primary = app
                .sbom
                .primary_component_id
                .as_ref()
                .is_some_and(|pid| pid == &comp.canonical_id);

            // Name + version + ecosystem
            let name_ver = comp.version.as_ref().map_or_else(
                || {
                    if is_primary {
                        format!(" \u{2605} {}", comp.name)
                    } else {
                        format!(" {}", comp.name)
                    }
                },
                |v| {
                    if is_primary {
                        format!(" \u{2605} {}@{}", comp.name, v)
                    } else {
                        format!(" {}@{}", comp.name, v)
                    }
                },
            );
            let eco_suffix = comp
                .ecosystem
                .as_ref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default();
            render_str(
                buf,
                x,
                y,
                &format!("{name_ver}{eco_suffix}"),
                width,
                Style::default().fg(scheme.primary),
            );
            y += 1;
            if y >= max_y {
                return;
            }

            // License
            let license = if comp.licenses.declared.is_empty() {
                "Unknown".to_string()
            } else {
                comp.licenses
                    .declared
                    .iter()
                    .map(|l| l.expression.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            render_str(
                buf,
                x,
                y,
                &format!(
                    " License: {}",
                    truncate_map_str(&license, (width as usize).saturating_sub(11))
                ),
                width,
                Style::default().fg(scheme.success),
            );
            y += 1;
            if y >= max_y {
                return;
            }

            // Vulnerability count
            let vuln_count = comp.vulnerabilities.len();
            if vuln_count > 0 {
                render_str(
                    buf,
                    x,
                    y,
                    &format!(
                        " {} vulnerabilit{}",
                        vuln_count,
                        if vuln_count == 1 { "y" } else { "ies" }
                    ),
                    width,
                    Style::default().fg(scheme.error),
                );
            } else {
                render_str(
                    buf,
                    x,
                    y,
                    " No vulnerabilities",
                    width,
                    Style::default().fg(scheme.muted),
                );
            }
            y += 1;
            if y >= max_y {
                return;
            }

            // PURL
            if let Some(ref purl) = comp.identifiers.purl {
                render_str(
                    buf,
                    x,
                    y,
                    &format!(
                        " purl: {}",
                        truncate_map_str(purl, (width as usize).saturating_sub(8))
                    ),
                    width,
                    Style::default().fg(scheme.text_muted),
                );
                y += 1;
                if y >= max_y {
                    return;
                }
            }

            // Extras: type, supplier, hashes, refs
            let mut extras = Vec::new();
            extras.push(format!("type:{}", comp.component_type));
            if let Some(ref supplier) = comp.supplier {
                extras.push(format!("supplier:{}", truncate_map_str(&supplier.name, 12)));
            }
            if !comp.hashes.is_empty() {
                extras.push(format!("{}h", comp.hashes.len()));
            }
            if !comp.external_refs.is_empty() {
                extras.push(format!("{}refs", comp.external_refs.len()));
            }
            render_str(
                buf,
                x,
                y,
                &format!(
                    " {}",
                    truncate_map_str(&extras.join("  "), (width as usize).saturating_sub(2))
                ),
                width,
                Style::default().fg(scheme.text_muted),
            );
            return;
        }

        if section == "vulnerabilities" {
            // Try to find the vulnerability at this index
            let vuln = app
                .sbom
                .components
                .values()
                .flat_map(|c| &c.vulnerabilities)
                .nth(idx);
            if let Some(v) = vuln {
                // CVE ID + severity
                let severity = v.severity.as_ref().map_or("unknown", |s| match s {
                    crate::model::Severity::Critical => "critical",
                    crate::model::Severity::High => "high",
                    crate::model::Severity::Medium => "medium",
                    crate::model::Severity::Low => "low",
                    crate::model::Severity::Info => "info",
                    crate::model::Severity::None => "none",
                    crate::model::Severity::Unknown => "unknown",
                });
                let sev_color = match severity {
                    "critical" => scheme.error,
                    "high" => scheme.warning,
                    "medium" => scheme.accent,
                    "low" => scheme.muted,
                    _ => scheme.text_muted,
                };
                render_str(
                    buf,
                    x,
                    y,
                    &format!(" {} ({severity})", v.id),
                    width,
                    Style::default().fg(sev_color).bold(),
                );
                y += 1;
                if y >= max_y {
                    return;
                }

                // Description (truncated)
                if let Some(ref desc) = v.description {
                    let trunc = truncate_map_str(desc, (width as usize).saturating_sub(2));
                    render_str(
                        buf,
                        x,
                        y,
                        &format!(" {trunc}"),
                        width,
                        Style::default().fg(scheme.text_muted),
                    );
                    y += 1;
                    if y >= max_y {
                        return;
                    }
                }

                // CWEs if present
                if !v.cwes.is_empty() {
                    let cwes = v.cwes.join(", ");
                    render_str(
                        buf,
                        x,
                        y,
                        &format!(
                            " CWE: {}",
                            truncate_map_str(&cwes, (width as usize).saturating_sub(7))
                        ),
                        width,
                        Style::default().fg(scheme.text_muted),
                    );
                    y += 1;
                    if y >= max_y {
                        return;
                    }
                }

                // Affected component name
                if let Some(comp) = app
                    .sbom
                    .components
                    .values()
                    .find(|c| c.vulnerabilities.iter().any(|vv| vv.id == v.id))
                {
                    render_str(
                        buf,
                        x,
                        y,
                        &format!(
                            " Affects: {}",
                            truncate_map_str(&comp.name, (width as usize).saturating_sub(11))
                        ),
                        width,
                        Style::default().fg(scheme.primary),
                    );
                    y += 1;
                    if y >= max_y {
                        return;
                    }
                }

                // KEV badge if actively exploited
                if v.is_kev {
                    render_str(
                        buf,
                        x,
                        y,
                        " \u{26a0} KEV: Actively Exploited",
                        width,
                        Style::default().fg(scheme.error).bold(),
                    );
                }
            } else {
                render_str(
                    buf,
                    x,
                    y,
                    &format!(" Vulnerability [{idx}]"),
                    width,
                    Style::default().fg(scheme.warning),
                );
            }
            return;
        }

        // Dependency context: resolve the ref to a component and show its deps
        if section == "dependencies" {
            // Try to resolve the dependency's ref to a component
            let dep_ref = app.sbom.components.values().nth(idx).or_else(|| {
                // Find by bom-ref from the dependency object's ref field
                // The JSON dependency array items have a "ref" field with a bom-ref
                node_id_full.as_ref().and_then(|nid| {
                    // Get the ref value from the raw lines or flat items
                    app.source_state
                        .cached_flat_items
                        .iter()
                        .find(|i| i.node_id.starts_with(nid) && i.display_key == "ref")
                        .and_then(|ref_item| {
                            let val = ref_item.value_preview.trim_matches('"');
                            app.sbom
                                .components
                                .values()
                                .find(|c| c.identifiers.format_id == val)
                        })
                })
            });

            if let Some(comp) = dep_ref {
                // Show component name
                let name_ver = comp.version.as_ref().map_or_else(
                    || format!(" {}", comp.name),
                    |v| format!(" {}@{v}", comp.name),
                );
                render_str(
                    buf,
                    x,
                    y,
                    &truncate_map_str(&name_ver, (width as usize).saturating_sub(1)),
                    width,
                    Style::default().fg(scheme.primary),
                );
                y += 1;
                if y >= max_y {
                    return;
                }

                // Show dependency count (from edges)
                let dep_count = app
                    .sbom
                    .edges
                    .iter()
                    .filter(|e| e.from == comp.canonical_id)
                    .count();
                render_str(
                    buf,
                    x,
                    y,
                    &format!(" Dependencies: {dep_count}"),
                    width,
                    Style::default().fg(scheme.text),
                );
                y += 1;
                if y >= max_y {
                    return;
                }

                // Show vulnerability summary
                let vuln_count = comp.vulnerabilities.len();
                if vuln_count > 0 {
                    render_str(
                        buf,
                        x,
                        y,
                        &format!(" {vuln_count} vulnerabilities"),
                        width,
                        Style::default().fg(scheme.error),
                    );
                } else {
                    render_str(
                        buf,
                        x,
                        y,
                        " No vulnerabilities",
                        width,
                        Style::default().fg(scheme.muted),
                    );
                }
                y += 1;
                if y >= max_y {
                    return;
                }

                // Show license
                let license = if comp.licenses.declared.is_empty() {
                    "Unknown".to_string()
                } else {
                    comp.licenses
                        .declared
                        .iter()
                        .map(|l| l.expression.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                render_str(
                    buf,
                    x,
                    y,
                    &format!(
                        " License: {}",
                        truncate_map_str(&license, (width as usize).saturating_sub(11))
                    ),
                    width,
                    Style::default().fg(scheme.success),
                );
            } else {
                render_str(
                    buf,
                    x,
                    y,
                    &format!(" Dependency [{idx}]"),
                    width,
                    Style::default().fg(scheme.text_muted),
                );
            }
            return;
        }
    }

    // Document summary (root level or non-component section)
    render_str(
        buf,
        x,
        y,
        &format!(" {} components", app.stats.component_count),
        width,
        Style::default().fg(scheme.text),
    );
    y += 1;
    if y >= max_y {
        return;
    }

    if app.stats.vuln_count > 0 {
        render_str(
            buf,
            x,
            y,
            &format!(" {} vulnerabilities", app.stats.vuln_count),
            width,
            Style::default().fg(scheme.error),
        );
        y += 1;
        if y >= max_y {
            return;
        }
    }

    render_str(
        buf,
        x,
        y,
        &format!(" {} licenses", app.stats.license_count),
        width,
        Style::default().fg(scheme.text_muted),
    );
    y += 1;
    if y >= max_y {
        return;
    }

    let edge_count = app.sbom.edges.len();
    if edge_count > 0 {
        render_str(
            buf,
            x,
            y,
            &format!(" {edge_count} dependency edges"),
            width,
            Style::default().fg(scheme.text_muted),
        );
    }
}

// ============================================================================
// Progress Bar
// ============================================================================

/// Render a progress bar showing document position.
/// Format: ` ░░░▓▓░░░░░░░░░  12/77  16%`
fn render_progress_bar(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    current: usize,
    total: usize,
    scheme: &crate::tui::theme::ColorScheme,
) {
    if width < 10 || total == 0 {
        return;
    }

    let pos = current + 1; // 1-indexed
    let pct = (pos * 100) / total;

    // Right-aligned text: "  12/77  16%"
    let right_text = format!("  {pos}/{total}  {pct}%");
    let right_len = right_text.len() as u16;

    // Bar takes remaining width
    let bar_width = width.saturating_sub(right_len + 2) as usize; // 1 padding each side

    if bar_width < 3 {
        // No room for bar, just show numbers
        let text = format!(" {pos}/{total}  {pct}%");
        render_str(
            buf,
            x,
            y,
            &text,
            width,
            Style::default().fg(scheme.text_muted),
        );
        return;
    }

    let filled = ((bar_width * pos) / total).min(bar_width);

    let mut bar = String::with_capacity(bar_width + 1);
    bar.push(' '); // leading space
    for i in 0..bar_width {
        if i < filled {
            bar.push('\u{2593}'); // ▓
        } else {
            bar.push('\u{2591}'); // ░
        }
    }

    // Render bar
    render_str(buf, x, y, &bar, width, Style::default().fg(scheme.muted));

    // Render right text (right-aligned)
    let right_x = x + width - right_len;
    render_str(
        buf,
        right_x,
        y,
        &right_text,
        right_len,
        Style::default().fg(scheme.text_muted),
    );
}

// ============================================================================
// Helpers
// ============================================================================

/// Render a horizontal separator line.
fn render_separator(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let sep: String = "\u{2500}".repeat(width as usize);
    render_str(buf, x, y, &sep, width, Style::default().fg(scheme.muted));
}

/// Render inline keyboard hints for the map panel.
fn render_hints(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    scheme: &crate::tui::theme::ColorScheme,
) {
    render_str(
        buf,
        x,
        y,
        " Enter:jump  t:tree  u:vulns",
        width,
        Style::default().fg(scheme.text_muted),
    );
}

/// Render map panel content for non-JSON formats.
fn render_non_json_map(
    buf: &mut Buffer,
    inner: Rect,
    app: &ViewApp,
    is_focused: bool,
    scheme: &crate::tui::theme::ColorScheme,
) {
    let width = inner.width;
    let max_y = inner.y + inner.height;
    let x = inner.x;
    let mut y = inner.y + 1;

    // Reserve bottom rows
    let hints_rows: u16 = u16::from(is_focused);
    let progress_y = max_y.saturating_sub(1 + hints_rows);

    // Format info
    render_str(
        buf,
        x,
        y,
        &format!(" Format: {}", app.sbom.document.format),
        width,
        Style::default().fg(scheme.primary).bold(),
    );
    y += 1;
    if y >= progress_y {
        render_progress_bar(
            buf,
            x,
            progress_y,
            width,
            app.source_state.selected,
            app.source_state.raw_lines.len(),
            scheme,
        );
        if is_focused {
            render_hints(buf, x, max_y - 1, width, scheme);
        }
        return;
    }

    let line_count = app.source_state.raw_lines.len();
    render_str(
        buf,
        x,
        y,
        &format!(" {line_count} lines (raw mode only)"),
        width,
        Style::default().fg(scheme.text_muted),
    );
    y += 1;
    if y >= progress_y {
        render_progress_bar(
            buf,
            x,
            progress_y,
            width,
            app.source_state.selected,
            line_count,
            scheme,
        );
        if is_focused {
            render_hints(buf, x, max_y - 1, width, scheme);
        }
        return;
    }

    // Separator
    render_separator(buf, x, y, width, scheme);
    y += 1;
    if y >= progress_y {
        render_progress_bar(
            buf,
            x,
            progress_y,
            width,
            app.source_state.selected,
            line_count,
            scheme,
        );
        if is_focused {
            render_hints(buf, x, max_y - 1, width, scheme);
        }
        return;
    }

    // Stats
    render_str(
        buf,
        x,
        y,
        &format!(" {} components", app.stats.component_count),
        width,
        Style::default().fg(scheme.text),
    );
    y += 1;

    if y < progress_y && app.stats.vuln_count > 0 {
        render_str(
            buf,
            x,
            y,
            &format!(" {} vulnerabilities", app.stats.vuln_count),
            width,
            Style::default().fg(scheme.error),
        );
        y += 1;
    }

    if y < progress_y {
        render_str(
            buf,
            x,
            y,
            &format!(" {} unique licenses", app.stats.license_count),
            width,
            Style::default().fg(scheme.text_muted),
        );
    }

    // Progress bar
    render_progress_bar(
        buf,
        x,
        progress_y,
        width,
        app.source_state.selected,
        line_count,
        scheme,
    );

    // Hints
    if is_focused {
        render_hints(buf, x, max_y - 1, width, scheme);
    }
}

/// Truncate a string for map display (Unicode-safe).
fn truncate_map_str(s: &str, max_len: usize) -> String {
    crate::tui::widgets::truncate_str(s, max_len)
}
