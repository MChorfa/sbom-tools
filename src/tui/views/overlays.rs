//! Shared overlays for cross-view UI components.
//!
//! Contains rendering functions for view switcher, shortcuts overlay,
//! context bar, and breadcrumbs that can be used across all views.

use crate::tui::app::{
    ComponentDeepDiveState, ShortcutsContext, ShortcutsOverlayState, ViewSwitcherState,
};
use crate::tui::theme::colors;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Render the view switcher overlay
pub fn render_view_switcher(f: &mut Frame, state: &ViewSwitcherState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a centered overlay
    let overlay_width = 50;
    let overlay_height = 10;
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let block = Block::default()
        .title(" Switch View (V) ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Render view options
    let mut lines = vec![
        Line::from(Span::styled(
            "Select a view to switch to:",
            Style::default().fg(scheme.text_muted),
        )),
        Line::from(""),
    ];

    for (i, view) in state.available_views.iter().enumerate() {
        let is_selected = i == state.selected;
        let prefix = if is_selected { "> " } else { "  " };
        let style = if is_selected {
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(scheme.text)
        };

        lines.push(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(
                format!("[{}] ", view.shortcut()),
                Style::default().fg(scheme.text_muted),
            ),
            Span::styled(view.icon(), style),
            Span::raw(" "),
            Span::styled(view.label(), style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Enter", Style::default().fg(scheme.accent)),
        Span::styled(" select  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" cancel", Style::default().fg(scheme.text_muted)),
    ]));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner_area);
}

/// Render the keyboard shortcuts overlay
pub fn render_shortcuts_overlay(f: &mut Frame, state: &mut ShortcutsOverlayState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Get shortcuts for the current context, minus anything the active tab
    // has taken over (see `shadow_tab_claimed_keys`).
    let shortcuts = shadow_tab_claimed_keys(
        get_shortcuts_for_context(state.context, state.profile),
        &state.tab_items,
    );

    let mut lines: Vec<Line> = Vec::new();

    // This-Tab section: the active tab's ViewState::shortcuts(), the same
    // source that renders the footer primaries — one place to edit a binding.
    if !state.tab_items.is_empty() {
        let title = state.tab_title.as_deref().map_or_else(
            || "This Tab".to_string(),
            |t| format!("This Tab \u{2014} {t}"),
        );
        lines.push(Line::from(Span::styled(
            title,
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        for (key, description) in &state.tab_items {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{key:>12}"),
                    Style::default()
                        .fg(scheme.primary)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ", Style::default()),
                Span::styled(description.clone(), Style::default().fg(scheme.text)),
            ]));
        }
        lines.push(Line::from(""));
    }

    for section in shortcuts {
        // Section header
        lines.push(Line::from(Span::styled(
            section.title,
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));

        // Shortcuts in this section
        for (key, description) in section.items {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("{key:>12}"),
                    Style::default()
                        .fg(scheme.primary)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ", Style::default()),
                Span::styled(description, Style::default().fg(scheme.text)),
            ]));
        }
        lines.push(Line::from(""));
    }

    // Footer
    lines.push(Line::from(vec![
        Span::styled("Press ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(", ", Style::default().fg(scheme.text_muted)),
        Span::styled("?", Style::default().fg(scheme.accent)),
        Span::styled(" or ", Style::default().fg(scheme.text_muted)),
        Span::styled("K", Style::default().fg(scheme.accent)),
        Span::styled(" to close", Style::default().fg(scheme.text_muted)),
    ]));

    // Create a larger centered overlay
    let overlay_width = 70;
    let overlay_height = 30.min(area.height.saturating_sub(4));
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Measure the content against the box and clamp the scroll offset so
    // the event handler can step through exactly the hidden rows.
    let total_lines = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let inner_height = overlay_area.height.saturating_sub(2);
    state.max_scroll = total_lines.saturating_sub(inner_height);
    if state.scroll > state.max_scroll {
        state.scroll = state.max_scroll;
    }

    // Create the block
    let title = format!(" Keyboard Shortcuts ({}) ", context_name(state.context));
    let mut block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));
    if state.max_scroll > 0 {
        let below = state.max_scroll - state.scroll;
        let hint = if below > 0 {
            format!(" \u{2193} {below} more \u{2014} \u{2191}\u{2193}/j/k scroll ")
        } else {
            " \u{2191}\u{2193}/j/k scroll ".to_string()
        };
        block = block.title_bottom(
            Line::from(Span::styled(hint, Style::default().fg(scheme.text_muted))).right_aligned(),
        );
    }

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true })
        .scroll((state.scroll, 0));
    f.render_widget(paragraph, inner_area);
}

/// Render the component deep dive modal
pub fn render_component_deep_dive(f: &mut Frame, state: &ComponentDeepDiveState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a large centered overlay
    let overlay_width = 80.min(area.width.saturating_sub(4));
    let overlay_height = 35.min(area.height.saturating_sub(4));
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let title = format!(" Component Deep Dive: {} ", state.component_name);
    let block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Split into tabs and content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(inner_area);

    // Render section tabs
    render_deep_dive_tabs(f, chunks[0], state);

    // Render section content
    render_deep_dive_content(f, chunks[1], state);

    // Render footer
    let footer = Line::from(vec![
        Span::styled("Tab/Arrow", Style::default().fg(scheme.accent)),
        Span::styled(" switch section  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" close", Style::default().fg(scheme.text_muted)),
    ]);
    let footer_para = Paragraph::new(footer).alignment(Alignment::Center);
    f.render_widget(footer_para, chunks[2]);
}

fn render_deep_dive_tabs(f: &mut Frame, area: Rect, state: &ComponentDeepDiveState) {
    let scheme = colors();
    let labels = ComponentDeepDiveState::section_labels();

    let tabs: Vec<Span> = labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let is_selected = i == state.active_section;
            if is_selected {
                Span::styled(
                    format!(" {label} "),
                    Style::default()
                        .bg(scheme.accent)
                        .fg(scheme.badge_fg_dark)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(format!(" {label} "), Style::default().fg(scheme.text_muted))
            }
        })
        .collect();

    let mut line_spans = vec![Span::raw("  ")];
    for (i, tab) in tabs.into_iter().enumerate() {
        line_spans.push(tab);
        if i < labels.len() - 1 {
            line_spans.push(Span::raw(" | "));
        }
    }

    let line = Line::from(line_spans);
    let para = Paragraph::new(line).alignment(Alignment::Center);
    f.render_widget(para, area);
}

fn render_deep_dive_content(f: &mut Frame, area: Rect, state: &ComponentDeepDiveState) {
    let scheme = colors();
    let data = &state.collected_data;

    let lines: Vec<Line> = match state.active_section {
        0 => {
            // Overview
            vec![
                Line::from(Span::styled(
                    "Component Overview",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Name: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(&state.component_name, Style::default().fg(scheme.text)),
                ]),
                Line::from(vec![
                    Span::styled("ID: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        state.component_id.as_deref().unwrap_or("Unknown"),
                        Style::default().fg(scheme.text),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Versions tracked: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        data.version_history.len().to_string(),
                        Style::default().fg(scheme.primary),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Targets present: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        data.target_presence
                            .iter()
                            .filter(|t| t.is_present)
                            .count()
                            .to_string(),
                        Style::default().fg(scheme.primary),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Vulnerabilities: ", Style::default().fg(scheme.text_muted)),
                    Span::styled(
                        data.vulnerabilities.len().to_string(),
                        Style::default().fg(if data.vulnerabilities.is_empty() {
                            scheme.added
                        } else {
                            scheme.warning
                        }),
                    ),
                ]),
            ]
        }
        1 => {
            // Versions
            let mut lines = vec![
                Line::from(Span::styled(
                    "Version History",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if data.version_history.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No version history available",
                    Style::default().fg(scheme.text_muted),
                )));
            } else {
                for entry in data.version_history.iter().take(15) {
                    let change_style = match entry.change_type.as_str() {
                        "added" => Style::default().fg(scheme.added),
                        "removed" => Style::default().fg(scheme.removed),
                        "modified" => Style::default().fg(scheme.modified),
                        _ => Style::default().fg(scheme.text_muted),
                    };

                    lines.push(Line::from(vec![
                        Span::styled(&entry.version, Style::default().fg(scheme.text)),
                        Span::raw(" - "),
                        Span::styled(&entry.sbom_label, Style::default().fg(scheme.text_muted)),
                        Span::raw(" ["),
                        Span::styled(&entry.change_type, change_style),
                        Span::raw("]"),
                    ]));
                }
            }
            lines
        }
        2 => {
            // Dependencies
            let mut lines = vec![
                Line::from(Span::styled(
                    "Dependencies",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            lines.push(Line::from(Span::styled(
                "Direct Dependencies:",
                Style::default().fg(scheme.text_muted),
            )));
            if data.dependencies.is_empty() {
                lines.push(Line::from("  (none)"));
            } else {
                for dep in data.dependencies.iter().take(10) {
                    lines.push(Line::from(format!("  - {dep}")));
                }
            }

            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Dependents (packages that depend on this):",
                Style::default().fg(scheme.text_muted),
            )));
            if data.dependents.is_empty() {
                lines.push(Line::from("  (none)"));
            } else {
                for dep in data.dependents.iter().take(10) {
                    lines.push(Line::from(format!("  - {dep}")));
                }
            }
            lines
        }
        3 => {
            // Vulnerabilities
            let mut lines = vec![
                Line::from(Span::styled(
                    "Associated Vulnerabilities",
                    Style::default()
                        .fg(scheme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
            ];

            if data.vulnerabilities.is_empty() {
                lines.push(Line::from(Span::styled(
                    "No vulnerabilities found",
                    Style::default().fg(scheme.added),
                )));
            } else {
                for vuln in data.vulnerabilities.iter().take(15) {
                    let severity_style = match vuln.severity.to_lowercase().as_str() {
                        "critical" => Style::default()
                            .fg(scheme.removed)
                            .add_modifier(Modifier::BOLD),
                        "high" => Style::default().fg(scheme.removed),
                        "medium" => Style::default().fg(scheme.warning),
                        "low" => Style::default().fg(scheme.modified),
                        _ => Style::default().fg(scheme.text_muted),
                    };

                    lines.push(Line::from(vec![
                        Span::styled(&vuln.vuln_id, Style::default().fg(scheme.primary)),
                        Span::raw(" ["),
                        Span::styled(&vuln.severity, severity_style),
                        Span::raw("] - "),
                        Span::styled(&vuln.status, Style::default().fg(scheme.text_muted)),
                    ]));
                }
            }
            lines
        }
        _ => vec![],
    };

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

// Helper functions

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

const fn context_name(context: ShortcutsContext) -> &'static str {
    match context {
        ShortcutsContext::Global => "Global",
        ShortcutsContext::MultiDiff => "Multi-Diff",
        ShortcutsContext::Timeline => "Timeline",
        ShortcutsContext::Matrix => "Matrix",
        ShortcutsContext::Diff => "Diff",
        ShortcutsContext::View => "View",
    }
}

struct ShortcutSection {
    title: &'static str,
    items: Vec<(String, String)>,
}

/// Owned `(key, description)` pair for a shortcut row.
fn item(key: &str, desc: &str) -> (String, String) {
    (key.to_string(), desc.to_string())
}

/// Split a shortcut label into the individual keys it advertises.
///
/// Labels are written as `j/k`, `g/G`, `!/@/#`, … — a slash-separated list of
/// alternatives. Anything without a slash is a single key.
fn shortcut_keys(label: &str) -> impl Iterator<Item = &str> {
    label.split('/').map(str::trim).filter(|k| !k.is_empty())
}

/// Drop Global/Navigation rows for keys the active tab has taken over.
///
/// The dispatcher gives the active tab first refusal on every key, so a
/// global row is only true where no tab handler consumes it. Listing them
/// unconditionally let one frame assert both `l  Color legend` and
/// `h/l  Collapse/expand` on a tab where `l` switches standards — the
/// overlay contradicting the This-Tab section printed directly above it.
///
/// The active tab's own rows (`tab_items`, the same `ViewState::shortcuts()`
/// the footer renders) are the authority for what it claims, so this needs no
/// per-tab table: bind a key in a tab and the shadowed global row disappears
/// on its own. Rows that advertise several keys keep the ones still free
/// (`g/G` becomes `G` on a tab that binds `g`) and are dropped only when the
/// tab claims all of them.
fn shadow_tab_claimed_keys(
    sections: Vec<ShortcutSection>,
    tab_items: &[(String, String)],
) -> Vec<ShortcutSection> {
    if tab_items.is_empty() {
        return sections;
    }
    let claimed: std::collections::HashSet<&str> = tab_items
        .iter()
        .flat_map(|(key, _)| shortcut_keys(key))
        .collect();

    sections
        .into_iter()
        .map(|mut section| {
            section.items.retain_mut(|(key, _)| {
                let free: Vec<&str> = shortcut_keys(key)
                    .filter(|k| !claimed.contains(k))
                    .collect();
                if free.is_empty() {
                    return false;
                }
                *key = free.join("/");
                true
            });
            section
        })
        .filter(|section| !section.items.is_empty())
        .collect()
}

fn get_shortcuts_for_context(
    context: ShortcutsContext,
    profile: Option<crate::model::BomProfile>,
) -> Vec<ShortcutSection> {
    // The View context lists ONLY the true View-app global keys; everything
    // tab-specific lives in each tab's toolbar (kept truthful there).
    if context == ShortcutsContext::View {
        let jump_hint = profile.map_or_else(
            || "1-8".to_string(),
            |p| {
                let n = crate::tui::view::ViewTab::tabs_for_profile(p).len();
                if n <= 1 {
                    "1".to_string()
                } else {
                    format!("1-{n}")
                }
            },
        );
        let mut sections = vec![ShortcutSection {
            title: "Global",
            items: vec![
                item("?", "Toggle help"),
                item("Tab/Shift-Tab", "Next/previous tab"),
                (jump_hint, "Jump to tab".to_string()),
                item("j/k", "Up/Down"),
                item("/", "Search"),
                item("e", "Export dialog"),
                item("l", "Color legend"),
                item("y", "Copy selected to clipboard"),
                item("P", "Cycle profile (SBOM → CBOM → AI-BOM)"),
                item("b/Backspace", "Navigate back"),
                item("T", "Toggle theme"),
                item("q/Esc", "Quit / close overlay"),
            ],
        }];
        if let Some(p) = profile {
            let tabs = crate::tui::view::ViewTab::tabs_for_profile(p);
            let items = tabs
                .iter()
                .enumerate()
                .map(|(i, tab)| item(&(i + 1).to_string(), tab.title()))
                .collect();
            sections.push(ShortcutSection {
                title: "Tabs (this profile)",
                items,
            });
        }
        sections.push(ShortcutSection {
            title: "Tab-specific actions are shown in each tab's toolbar",
            items: vec![],
        });
        return sections;
    }

    let is_multi = matches!(
        context,
        ShortcutsContext::MultiDiff | ShortcutsContext::Timeline | ShortcutsContext::Matrix
    );

    // Navigation rows are built per context so no mode advertises movement
    // keys that are dead (g/G, PgUp/PgDn in multi modes) or rebound there
    // (h/l = chart scroll / cell movement / heat map).
    let mut nav_items = match context {
        ShortcutsContext::Matrix => vec![item("j/k", "Up/Down"), item("h/l", "Left/Right (cell)")],
        ShortcutsContext::MultiDiff | ShortcutsContext::Timeline => vec![item("j/k", "Up/Down")],
        _ => vec![
            item("j/k", "Up/Down"),
            item("g/G", "First/Last"),
            item("PgUp/PgDn", "Page up/down"),
            item("Home/End", "Jump to start/end"),
        ],
    };
    // Tab-switching rows only exist in the tabbed modes; the multi modes bind
    // Tab to panel switching (documented in their own sections) and digits are
    // gated off there.
    if !is_multi {
        // The Diff tab bar binds 1-9 plus 0 (Source shifts to 0 when the
        // Graph tab appears) — digits always jump tabs, on every tab.
        nav_items.push(item("Tab", "Next tab"));
        // Honest everywhere: no tab shadows the digits anymore.
        nav_items.push(item("1-9/0", "Jump to tab"));
    }

    // Global rows, gated per context so every listed key really works there:
    // the legend renders only in Diff, 'V' is bound only in the multi modes,
    // deep dive rows are dishonest in Matrix (rows are SBOMs), and 'b'
    // breadcrumb-back only exists in Diff.
    let mut global_items = vec![
        item("q", "Quit application"),
        item("?", "Toggle help"),
        item("e", "Export dialog"),
    ];
    if context == ShortcutsContext::Diff {
        global_items.push(item("l", "Color legend"));
    }
    global_items.extend([
        item("T", "Toggle theme"),
        item("/", "Search"),
        item("K", "Keyboard shortcuts"),
    ]);
    if is_multi {
        global_items.push(item("V", "View switcher"));
    }
    if context != ShortcutsContext::Matrix {
        global_items.push(item("D", "Component deep dive"));
    }
    global_items.push(item("y/Ctrl+C", "Copy selected to clipboard"));
    global_items.push(item("Shift+drag", "Select text with mouse"));
    if context == ShortcutsContext::Diff {
        global_items.push(item("b/Backspace", "Navigate back"));
    }

    let mut sections = vec![
        ShortcutSection {
            title: "Global",
            items: global_items,
        },
        ShortcutSection {
            title: "Navigation",
            items: nav_items,
        },
    ];

    match context {
        ShortcutsContext::MultiDiff => {
            sections.push(ShortcutSection {
                title: "Multi-Diff View",
                items: vec![
                    item("p/Tab", "Switch panel"),
                    item("Enter", "View details"),
                    item("f", "Cycle filter preset"),
                    item("s", "Cycle sort field"),
                    item("S", "Toggle sort direction"),
                    item("v", "Variable components drill-down"),
                    item("x", "Toggle cross-target analysis"),
                    item("h", "Toggle heat map mode"),
                    item("Ctrl+R", "Toggle regex (in search)"),
                    item("n/N", "Next/prev search match"),
                ],
            });
        }
        ShortcutsContext::Timeline => {
            sections.push(ShortcutSection {
                title: "Timeline View",
                items: vec![
                    item("p/Tab", "Switch panel"),
                    item("d", "Compare versions"),
                    item("t", "Toggle statistics"),
                    item("g", "Jump to version"),
                    item("+/-", "Zoom chart"),
                    item("h/l", "Scroll chart"),
                    item("f", "Filter components"),
                    item("s", "Sort components"),
                    item("Ctrl+R", "Toggle regex (in search)"),
                    item("n/N", "Next/prev search match"),
                ],
            });
        }
        ShortcutsContext::Matrix => {
            sections.push(ShortcutSection {
                title: "Matrix View",
                items: vec![
                    item("p/Tab", "Switch panel"),
                    item("Enter", "View pair diff"),
                    item("t", "Cycle threshold"),
                    item("z", "Toggle focus mode"),
                    item("H", "Toggle row/col highlight"),
                    item("C", "Show cluster details"),
                    item("x", "Export options"),
                    item("Ctrl+R", "Toggle regex (in search)"),
                    item("n/N", "Next/prev search match"),
                ],
            });
        }
        ShortcutsContext::Diff => {
            sections.push(ShortcutSection {
                title: "Diff View",
                items: vec![
                    item("f", "Filter/toggle options"),
                    item("s", "Sort/cycle options"),
                    item("d", "Go to Dependencies (components)"),
                    item("t", "Tune match threshold (Dependencies tab: transitive)"),
                    item("v", "Multi-select mode"),
                    item("Q", "Quick filters picker (components)"),
                    item("Enter", "View details / deep dive (list tabs)"),
                    item("n/N", "Next/prev search match (source/deps/side-by-side)"),
                    item("c", "Go to component (dependencies)"),
                    item("F", "Flag for review (components)"),
                    item("o", "Open CVE in browser (components)"),
                    item("n", "Cycle security note (components)"),
                    item("p", "Toggle panel focus (Summary: cycle policy)"),
                    item("h/l", "Collapse/expand (tree tabs)"),
                    item("E", "Export compliance (compliance tab)"),
                ],
            });
        }
        ShortcutsContext::View | ShortcutsContext::Global => {}
    }

    sections
}

/// State for the threshold tuning overlay.
///
/// Allows users to interactively adjust the match threshold and see
/// a preview of how it affects component matching.
#[derive(Debug, Clone)]
pub struct ThresholdTuningState {
    /// Is the overlay visible
    pub visible: bool,
    /// Current threshold value (0.0 - 1.0)
    pub threshold: f64,
    /// Original threshold (before tuning started)
    pub original_threshold: f64,
    /// Preview: estimated matches at current threshold
    pub estimated_matches: usize,
    /// Preview: total components being compared
    pub total_components: usize,
    /// Step size for adjustment (default 0.05)
    pub step: f64,
}

impl Default for ThresholdTuningState {
    fn default() -> Self {
        Self {
            visible: false,
            threshold: 0.85,
            original_threshold: 0.85,
            estimated_matches: 0,
            total_components: 0,
            step: 0.05,
        }
    }
}

impl ThresholdTuningState {
    /// Create a new threshold tuning state with initial values.
    pub(crate) const fn new(threshold: f64, total_components: usize) -> Self {
        Self {
            visible: true,
            threshold,
            original_threshold: threshold,
            estimated_matches: 0,
            total_components,
            step: 0.05,
        }
    }

    /// Increase threshold (stricter matching).
    pub(crate) fn increase(&mut self) {
        self.threshold = (self.threshold + self.step).min(0.99);
    }

    /// Decrease threshold (more permissive matching).
    pub(crate) fn decrease(&mut self) {
        self.threshold = (self.threshold - self.step).max(0.50);
    }

    /// Fine increase (smaller step).
    pub(crate) fn fine_increase(&mut self) {
        self.threshold = (self.threshold + 0.01).min(0.99);
    }

    /// Fine decrease (smaller step).
    pub(crate) fn fine_decrease(&mut self) {
        self.threshold = (self.threshold - 0.01).max(0.50);
    }

    /// Reset to original value.
    pub(crate) const fn reset(&mut self) {
        self.threshold = self.original_threshold;
    }

    /// Update the estimated matches preview.
    pub(crate) const fn set_estimated_matches(&mut self, matches: usize) {
        self.estimated_matches = matches;
    }

    /// Get the match ratio as a percentage.
    pub(crate) fn match_percentage(&self) -> f64 {
        if self.total_components == 0 {
            0.0
        } else {
            (self.estimated_matches as f64 / self.total_components as f64) * 100.0
        }
    }
}

/// Render the threshold tuning overlay.
///
/// Shows current threshold, estimated matches, and keyboard shortcuts.
pub fn render_threshold_tuning(f: &mut Frame, state: &ThresholdTuningState) {
    if !state.visible {
        return;
    }

    let scheme = colors();
    let area = f.area();

    // Create a centered overlay
    let overlay_width = 60;
    let overlay_height = 14;
    let overlay_area = centered_rect(overlay_width, overlay_height, area);

    // Clear the background
    f.render_widget(Clear, overlay_area);

    // Create the block
    let block = Block::default()
        .title(" Threshold Tuning ")
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(scheme.accent))
        .style(Style::default().bg(scheme.background_alt));

    let inner_area = block.inner(overlay_area);
    f.render_widget(block, overlay_area);

    // Render content
    let mut lines = vec![
        Line::from(Span::styled(
            "Adjust matching threshold to control match sensitivity",
            Style::default().fg(scheme.text_muted),
        )),
        Line::from(""),
    ];

    // Current threshold display
    lines.push(Line::from(vec![
        Span::styled("Current threshold: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("{:.0}%", state.threshold * 100.0),
            Style::default()
                .fg(scheme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  (was {:.0}%)", state.original_threshold * 100.0),
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    // Visual slider
    let slider_width = 40;
    let filled_width = ((state.threshold - 0.5) / 0.49 * slider_width as f64) as usize;
    let empty_width = slider_width - filled_width;

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("50% ", Style::default().fg(scheme.text_muted)),
        Span::styled("▓".repeat(filled_width), Style::default().fg(scheme.accent)),
        Span::styled(
            "░".repeat(empty_width),
            Style::default().fg(scheme.text_muted),
        ),
        Span::styled(" 99%", Style::default().fg(scheme.text_muted)),
    ]));

    // Preview statistics
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Preview: ", Style::default().fg(scheme.text)),
        Span::styled(
            format!("~{} components", state.estimated_matches),
            Style::default().fg(scheme.primary),
        ),
        Span::styled(
            format!(" would match ({:.1}%)", state.match_percentage()),
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    // Threshold presets hints
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Presets: ", Style::default().fg(scheme.text_muted)),
        Span::styled("95%", Style::default().fg(scheme.text)),
        Span::styled("=strict  ", Style::default().fg(scheme.text_muted)),
        Span::styled("85%", Style::default().fg(scheme.text)),
        Span::styled("=balanced  ", Style::default().fg(scheme.text_muted)),
        Span::styled("70%", Style::default().fg(scheme.text)),
        Span::styled("=permissive", Style::default().fg(scheme.text_muted)),
    ]));

    // Controls — must list exactly what the handler binds (events/mod.rs):
    // Up/Down or j/k step, Left/Right or +/- fine, r reset, Enter, Esc/q.
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("↑↓/j/k", Style::default().fg(scheme.accent)),
        Span::styled(" adjust  ", Style::default().fg(scheme.text_muted)),
        Span::styled("←→/+/-", Style::default().fg(scheme.accent)),
        Span::styled(" fine  ", Style::default().fg(scheme.text_muted)),
        Span::styled("r", Style::default().fg(scheme.accent)),
        Span::styled(" reset  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Enter", Style::default().fg(scheme.accent)),
        Span::styled(" apply  ", Style::default().fg(scheme.text_muted)),
        Span::styled("Esc", Style::default().fg(scheme.accent)),
        Span::styled(" cancel", Style::default().fg(scheme.text_muted)),
    ]));

    let paragraph = Paragraph::new(lines)
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, inner_area);
}

#[cfg(test)]
mod tests {
    use super::{ShortcutsContext, get_shortcuts_for_context};

    /// A Global/Navigation row must never contradict the This-Tab section
    /// printed directly above it. The dispatcher gives the active tab first
    /// refusal, so a key the tab binds is simply not global there.
    ///
    /// Four rows were false on specific tabs before this: `l Color legend`
    /// (Compliance switches standards, Source expands), `h/l Collapse/expand`
    /// (Dependencies toggles highlighting), `K Keyboard shortcuts`
    /// (Side-by-Side scrolls), and `g/G First/Last` (Licenses, Vulnerabilities
    /// and Compliance bind `g` to grouping).
    #[test]
    fn tab_claimed_keys_are_shadowed_from_global_rows() {
        use super::shadow_tab_claimed_keys;

        let tab_items = vec![
            ("h".to_string(), "toggle highlighting".to_string()),
            ("g".to_string(), "group".to_string()),
            ("J/K".to_string(), "scroll".to_string()),
        ];
        let sections = shadow_tab_claimed_keys(
            get_shortcuts_for_context(ShortcutsContext::Diff, None),
            &tab_items,
        );

        let rows: Vec<&(String, String)> = sections.iter().flat_map(|s| s.items.iter()).collect();
        for (key, desc) in &rows {
            for k in key.split('/') {
                assert!(
                    !["h", "g", "J", "K"].contains(&k),
                    "global row {key:?} ({desc}) advertises {k:?}, which the active tab binds"
                );
            }
        }
        // A multi-key row keeps the alternatives the tab did NOT claim.
        assert!(
            rows.iter().any(|(key, _)| key == "G"),
            "`g/G` should survive as `G` when the tab binds only `g`: {rows:?}"
        );
    }

    /// With no tab context (multi modes, or a tab that binds nothing) the
    /// global rows are untouched.
    #[test]
    fn no_tab_items_leaves_global_rows_intact() {
        use super::shadow_tab_claimed_keys;
        let before = get_shortcuts_for_context(ShortcutsContext::Diff, None);
        let count: usize = before.iter().map(|s| s.items.len()).sum();
        let after = shadow_tab_claimed_keys(before, &[]);
        assert_eq!(after.iter().map(|s| s.items.len()).sum::<usize>(), count);
    }
    use crate::model::BomProfile;

    /// Collect every `(key, description)` pair across all sections.
    fn flatten(context: ShortcutsContext, profile: Option<BomProfile>) -> Vec<(String, String)> {
        get_shortcuts_for_context(context, profile)
            .into_iter()
            .flat_map(|s| s.items)
            .collect()
    }

    fn descriptions(items: &[(String, String)]) -> Vec<String> {
        items.iter().map(|(_, d)| d.clone()).collect()
    }

    fn jump_range(items: &[(String, String)]) -> String {
        items
            .iter()
            .find(|(_, d)| d == "Jump to tab")
            .map(|(k, _)| k.clone())
            .expect("a Jump to tab hint should always be present")
    }

    #[test]
    fn aibom_overlay_lists_ai_tabs_not_sbom_tabs() {
        let items = flatten(ShortcutsContext::View, Some(BomProfile::AiBom));
        let descs = descriptions(&items);

        // AI-BOM profile tabs (ViewTab::tabs_for_profile): Overview, Models,
        // Datasets, AI-Readiness, Compliance, Source.
        for expected in ["Overview", "Models", "Datasets", "AI-Readiness"] {
            assert!(
                descs.iter().any(|d| d == expected),
                "AI-BOM overlay should list the {expected} tab; got {descs:?}"
            );
        }

        // It must NOT advertise SBOM-only tabs the user cannot reach.
        for sbom_only in ["Components", "Vulnerabilities", "Licenses", "Dependencies"] {
            assert!(
                !descs.iter().any(|d| d == sbom_only),
                "AI-BOM overlay must not list the SBOM-only {sbom_only} tab"
            );
        }

        // 6 AI-BOM tabs -> "1-6", never the generic "1-8".
        assert_eq!(jump_range(&items), "1-6");
    }

    #[test]
    fn sbom_overlay_lists_sbom_tabs_and_full_range() {
        let items = flatten(ShortcutsContext::View, Some(BomProfile::Sbom));
        let descs = descriptions(&items);
        for expected in [
            "Components",
            "Vulnerabilities",
            "Licenses",
            "Dependencies",
            "Compliance",
        ] {
            assert!(
                descs.iter().any(|d| d == expected),
                "SBOM overlay should list the {expected} tab; got {descs:?}"
            );
        }
        assert_eq!(jump_range(&items), "1-8");
    }

    #[test]
    fn cbom_overlay_lists_crypto_tabs() {
        let items = flatten(ShortcutsContext::View, Some(BomProfile::Cbom));
        let descs = descriptions(&items);
        for expected in ["Algorithms", "Certificates", "Keys", "Protocols"] {
            assert!(
                descs.iter().any(|d| d == expected),
                "CBOM overlay should list the {expected} tab; got {descs:?}"
            );
        }
        assert_eq!(jump_range(&items), "1-8");
    }

    /// The Diff section documents the components security loop (F/o/n) and
    /// scopes the n/N description to where the binding is real — the 80x24
    /// K-overlay snapshot clips before this section, so a snapshot can't
    /// guard it.
    #[test]
    fn diff_section_documents_security_loop_and_scoped_match_nav() {
        let items = flatten(ShortcutsContext::Diff, None);
        let has = |k: &str, frag: &str| {
            items
                .iter()
                .any(|(key, desc)| key == k && desc.contains(frag))
        };
        assert!(has("F", "Flag for review"));
        assert!(has("o", "Open CVE"));
        assert!(has("n", "Cycle security note"));
        assert!(has("n/N", "source/deps/side-by-side"));
        assert!(has("c", "Go to component"));
        assert!(
            !items
                .iter()
                .any(|(_, d)| d == "Navigate to next/prev match"),
            "the unscoped n/N description must be gone"
        );
        // Rows folded in from the deleted prose help overlay.
        assert!(
            flatten(ShortcutsContext::Global, None)
                .iter()
                .chain(items.iter())
                .any(|(k, _)| k == "Home/End"),
            "Home/End must survive the help-overlay deletion"
        );
    }

    #[test]
    fn no_profile_falls_back_to_generic_hint_without_tab_section() {
        // Diff-mode passes None: the hint documents the real diff digit
        // targets (1-9 plus 0 when the Graph tab appears) and there is no
        // profile-specific tab listing.
        let sections = get_shortcuts_for_context(ShortcutsContext::Diff, None);
        assert!(
            sections.iter().all(|s| s.title != "Tabs (this profile)"),
            "no profile -> no profile-tab section"
        );
        let items: Vec<_> = sections.into_iter().flat_map(|s| s.items).collect();
        assert_eq!(jump_range(&items), "1-9/0");
    }

    /// The multi modes have no visible tabs — Tab switches panels there — so
    /// the Navigation section must not advertise tab switching or digit
    /// jumping in those contexts.
    #[test]
    fn multi_contexts_do_not_advertise_tab_switching() {
        for ctx in [
            ShortcutsContext::MultiDiff,
            ShortcutsContext::Timeline,
            ShortcutsContext::Matrix,
        ] {
            let items = flatten(ctx, None);
            assert!(
                !items.iter().any(|(_, d)| d == "Next tab"),
                "{ctx:?} must not advertise a Next tab row"
            );
            assert!(
                !items.iter().any(|(_, d)| d == "Jump to tab"),
                "{ctx:?} must not advertise a Jump to tab row"
            );
        }
    }

    /// Multi-mode overlays must not advertise keys that are dead or rebound
    /// there: no color legend (never rendered outside Diff), no dedup row,
    /// no g/G / PgUp/PgDn / Home/End (inert), and no 'D' deep dive in Matrix
    /// (its rows are SBOMs, not components).
    #[test]
    fn multi_contexts_gate_dead_global_keys() {
        for ctx in [
            ShortcutsContext::MultiDiff,
            ShortcutsContext::Timeline,
            ShortcutsContext::Matrix,
        ] {
            let items = flatten(ctx, None);
            assert!(
                !items.iter().any(|(_, d)| d == "Color legend"),
                "{ctx:?} must not advertise the Diff-only legend"
            );
            assert!(
                !items.iter().any(|(_, d)| d.contains("deduplication")),
                "{ctx:?} must not advertise deduplication"
            );
            for key in ["g/G", "PgUp/PgDn", "Home/End"] {
                assert!(
                    !items.iter().any(|(k, _)| k == key),
                    "{ctx:?} must not advertise inert '{key}'"
                );
            }
            assert!(
                items.iter().any(|(k, d)| k == "e" && d == "Export dialog"),
                "{ctx:?} export dialog is real now and should be listed"
            );
            assert!(
                items.iter().any(|(k, _)| k == "V"),
                "{ctx:?} binds the view switcher"
            );
        }

        assert!(
            !flatten(ShortcutsContext::Matrix, None)
                .iter()
                .any(|(k, _)| k == "D"),
            "Matrix must not advertise the component deep dive"
        );
        for ctx in [ShortcutsContext::MultiDiff, ShortcutsContext::Timeline] {
            assert!(
                flatten(ctx, None).iter().any(|(k, _)| k == "D"),
                "{ctx:?} keeps the (populated) deep dive row"
            );
        }
    }

    /// The Diff section documents the rebound keys and drops the fictional
    /// deduplication row.
    #[test]
    fn diff_section_matches_rebound_keys() {
        let items = flatten(ShortcutsContext::Diff, None);
        assert!(
            !items.iter().any(|(_, d)| d.contains("deduplication")),
            "no Diff tab implements deduplication"
        );
        assert!(
            items
                .iter()
                .any(|(k, d)| k == "Q" && d.contains("Quick filters")),
            "the Q picker must be documented"
        );
        assert!(
            items
                .iter()
                .any(|(k, d)| k == "t" && d.contains("threshold")),
            "the threshold-tuning binding must be documented"
        );
        assert!(
            items.iter().any(|(k, _)| k == "l" || k == "b/Backspace"),
            "Diff keeps legend and breadcrumb-back rows"
        );
    }

    /// The View section lists only true View-app globals: no Diff-only K/V/D
    /// rows, and the profile cycle is documented.
    #[test]
    fn view_section_lists_only_view_globals() {
        let items = flatten(ShortcutsContext::View, Some(BomProfile::Sbom));
        for key in ["K", "V", "D"] {
            assert!(
                !items.iter().any(|(k, _)| k == key),
                "'{key}' is Diff-only and must not appear in the View overlay"
            );
        }
        assert!(
            items.iter().any(|(k, d)| k == "P" && d.contains("profile")),
            "the P profile cycle must be documented"
        );
        assert!(
            items.iter().any(|(k, _)| k == "Tab/Shift-Tab"),
            "tab switching must be documented"
        );
    }

    /// The MultiDiff/Timeline/Matrix sections must document the phase-6
    /// unified search: the Ctrl+R regex toggle and n/N match cycling
    /// (get_shortcuts_for_context). No snapshot renders the overlay in a
    /// multi mode, so deleting those rows would otherwise pass the suite.
    #[test]
    fn multi_contexts_document_search_capabilities() {
        for ctx in [
            ShortcutsContext::MultiDiff,
            ShortcutsContext::Timeline,
            ShortcutsContext::Matrix,
        ] {
            let items = flatten(ctx, None);
            assert!(
                items
                    .iter()
                    .any(|(k, d)| k == "Ctrl+R" && d.contains("regex")),
                "{ctx:?} section must document the Ctrl+R regex toggle"
            );
            assert!(
                items
                    .iter()
                    .any(|(k, d)| k == "n/N" && d.contains("search match")),
                "{ctx:?} section must document n/N search-match cycling"
            );
        }
    }
}
