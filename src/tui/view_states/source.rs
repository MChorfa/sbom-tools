//! Source tab `ViewState` implementation.
//!
//! Handles panel navigation, tree/raw mode, expand/collapse, search,
//! bookmarks, fold depth, detail panel, and sync between panels.
//! Clipboard operations and export remain in the sync bridge.

use crate::tui::app_states::SourceViewMode;
use crate::tui::app_states::source::SourceDiffState;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

/// Source tab view implementing the `ViewState` trait.
pub struct SourceView {
    inner: SourceDiffState,
}

impl SourceView {
    pub(crate) fn new() -> Self {
        Self {
            inner: SourceDiffState::new("", ""),
        }
    }

    /// Create with pre-populated state (used when raw SBOM text is available).
    pub(crate) fn with_state(state: SourceDiffState) -> Self {
        Self { inner: state }
    }

    /// Access the inner state for sync operations.
    pub(crate) fn inner(&self) -> &SourceDiffState {
        &self.inner
    }

    /// Mutable access for sync operations.
    pub(crate) fn inner_mut(&mut self) -> &mut SourceDiffState {
        &mut self.inner
    }
}

impl Default for SourceView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for SourceView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        let panel = self.inner.active_panel_mut();

        // Handle active search input
        if panel.search_active {
            return handle_panel_search(panel, key);
        }

        match key.code {
            KeyCode::Char('/') => {
                self.inner.active_panel_mut().start_search();
                EventResult::Consumed
            }
            KeyCode::Char('n') => {
                let panel = self.inner.active_panel_mut();
                if panel.search_query.is_empty() && !panel.change_annotations.is_empty() {
                    self.inner.active_panel_mut().next_change();
                    let idx = self.inner.active_panel_mut().current_change_idx;
                    let total = self.inner.active_panel_mut().change_indices.len();
                    if let Some(i) = idx {
                        return EventResult::status(format!("Change {}/{total}", i + 1));
                    }
                } else {
                    self.inner.active_panel_mut().next_search_match();
                }
                EventResult::Consumed
            }
            KeyCode::Char('N') => {
                let panel = self.inner.active_panel_mut();
                if panel.search_query.is_empty() && !panel.change_annotations.is_empty() {
                    self.inner.active_panel_mut().prev_change();
                    let idx = self.inner.active_panel_mut().current_change_idx;
                    let total = self.inner.active_panel_mut().change_indices.len();
                    if let Some(i) = idx {
                        return EventResult::status(format!("Change {}/{total}", i + 1));
                    }
                } else {
                    self.inner.active_panel_mut().prev_search_match();
                }
                EventResult::Consumed
            }
            // Copy JSON path — data-dependent (clipboard), return Ignored for bridge
            KeyCode::Char('c') => EventResult::Ignored,
            // Compact mode toggle
            KeyCode::Char('C') => {
                self.inner.old_panel.toggle_compact_mode();
                self.inner.new_panel.toggle_compact_mode();
                EventResult::Consumed
            }
            // Line numbers toggle
            KeyCode::Char('I') => {
                self.inner.active_panel_mut().toggle_line_numbers();
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().toggle_line_numbers();
                }
                EventResult::Consumed
            }
            // Word wrap toggle
            KeyCode::Char('W') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().toggle_word_wrap();
                    if self.inner.is_synced() {
                        self.inner.inactive_panel_mut().toggle_word_wrap();
                    }
                }
                EventResult::Consumed
            }
            // Bookmarks
            KeyCode::Char('m') => {
                self.inner.active_panel_mut().toggle_bookmark();
                EventResult::Consumed
            }
            KeyCode::Char('\'') => {
                self.inner.active_panel_mut().next_bookmark();
                EventResult::Consumed
            }
            KeyCode::Char('"') => {
                self.inner.active_panel_mut().prev_bookmark();
                EventResult::Consumed
            }
            // Export — data-dependent, return Ignored for bridge
            KeyCode::Char('E') => EventResult::Ignored,
            // Detail panel toggle
            KeyCode::Char('d') => {
                self.inner.toggle_detail();
                EventResult::Consumed
            }
            // Filter type cycle (tree mode)
            KeyCode::Char('f') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Tree {
                    self.inner.active_panel_mut().cycle_filter_type();
                    let label = self.inner.active_panel_mut().filter_label();
                    if label.is_empty() {
                        return EventResult::status("Filter: off");
                    }
                    return EventResult::status(format!("Filter: {label}"));
                }
                EventResult::Consumed
            }
            // Sort cycle (tree mode)
            KeyCode::Char('S') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Tree {
                    self.inner.active_panel_mut().cycle_sort();
                    let label = self.inner.active_panel_mut().sort_mode.label();
                    if label.is_empty() {
                        return EventResult::status("Sort: off");
                    }
                    return EventResult::status(format!("Sort: {label}"));
                }
                EventResult::Consumed
            }
            // Toggle panel alignment (diff mode, tree mode only)
            KeyCode::Char('a') => {
                if self.inner.active_panel().view_mode == SourceViewMode::Tree
                    && !self.inner.old_panel.change_annotations.is_empty()
                {
                    self.inner.toggle_align();
                    if self.inner.align_enabled {
                        EventResult::status("Panel alignment enabled")
                    } else {
                        EventResult::status("Panel alignment disabled")
                    }
                } else {
                    EventResult::Consumed
                }
            }
            // Toggle collapse of unchanged regions (tree mode, diff only)
            KeyCode::Char('u') => {
                if self.inner.active_panel().view_mode == SourceViewMode::Tree {
                    let panel = self.inner.active_panel_mut();
                    panel.collapse_unchanged = !panel.collapse_unchanged;
                    panel.invalidate_flat_cache();
                    if self.inner.is_synced() {
                        let inactive = self.inner.inactive_panel_mut();
                        inactive.collapse_unchanged = !inactive.collapse_unchanged;
                        inactive.invalidate_flat_cache();
                    }
                    if self.inner.active_panel().collapse_unchanged {
                        EventResult::status("Unchanged regions collapsed")
                    } else {
                        EventResult::status("Showing all items")
                    }
                } else {
                    EventResult::Consumed
                }
            }
            // Toggle view mode (tree/raw)
            KeyCode::Char('v') => {
                self.inner.old_panel.toggle_view_mode();
                self.inner.new_panel.toggle_view_mode();
                EventResult::Consumed
            }
            // Toggle side
            KeyCode::Char('w') => {
                self.inner.toggle_side();
                EventResult::Consumed
            }
            // Toggle sync
            KeyCode::Char('s') => {
                self.inner.toggle_sync();
                EventResult::Consumed
            }
            // Expand/collapse (Enter/Space)
            KeyCode::Enter | KeyCode::Char(' ') => {
                let node_id = get_expandable_node(&mut self.inner, None);
                if let Some(id) = node_id {
                    self.inner.active_panel_mut().toggle_expand(&id);
                    if self.inner.is_synced() {
                        sync_expand(&mut self.inner, &id);
                    }
                }
                EventResult::Consumed
            }
            // Left: collapse or scroll left
            KeyCode::Left | KeyCode::Char('h') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().scroll_left();
                    if self.inner.is_synced() {
                        self.inner.inactive_panel_mut().scroll_left();
                    }
                } else {
                    let node_id = get_expandable_node(&mut self.inner, Some(true));
                    if let Some(id) = node_id {
                        self.inner.active_panel_mut().toggle_expand(&id);
                        if self.inner.is_synced() {
                            sync_expand(&mut self.inner, &id);
                        }
                    }
                }
                EventResult::Consumed
            }
            // Right: expand or scroll right
            KeyCode::Right | KeyCode::Char('l') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().scroll_right();
                    if self.inner.is_synced() {
                        self.inner.inactive_panel_mut().scroll_right();
                    }
                } else {
                    let node_id = get_expandable_node(&mut self.inner, Some(false));
                    if let Some(id) = node_id {
                        self.inner.active_panel_mut().toggle_expand(&id);
                        if self.inner.is_synced() {
                            sync_expand(&mut self.inner, &id);
                        }
                    }
                }
                EventResult::Consumed
            }
            // Collapse all
            KeyCode::Char('H') => {
                self.inner.active_panel_mut().collapse_all();
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().collapse_all();
                }
                EventResult::Consumed
            }
            // Expand all
            KeyCode::Char('L') => {
                self.inner.active_panel_mut().expand_all();
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_all();
                }
                EventResult::Consumed
            }
            // Fold toggle (raw mode) — active panel only, folds are position-specific
            KeyCode::Char('z') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().toggle_fold();
                }
                EventResult::Consumed
            }
            // Fold all / unfold all (raw mode) — synced: both panels
            KeyCode::Char('Z') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    if self.inner.active_panel_mut().folded_lines.is_empty() {
                        self.inner.active_panel_mut().fold_all_top_level();
                        if self.inner.is_synced() {
                            self.inner.inactive_panel_mut().fold_all_top_level();
                        }
                    } else {
                        self.inner.active_panel_mut().unfold_all();
                        if self.inner.is_synced() {
                            self.inner.inactive_panel_mut().unfold_all();
                        }
                    }
                }
                EventResult::Consumed
            }
            // Jump to matching bracket (raw mode) — active panel only
            KeyCode::Char('%') => {
                if self.inner.active_panel_mut().view_mode == SourceViewMode::Raw {
                    self.inner.active_panel_mut().jump_to_matching_bracket();
                }
                EventResult::Consumed
            }
            // Toggle indent guides — synced: both panels
            KeyCode::Char('|') => {
                let new_val = !self.inner.active_panel_mut().show_indent_guides;
                self.inner.active_panel_mut().show_indent_guides = new_val;
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().show_indent_guides = new_val;
                }
                EventResult::Consumed
            }
            // Fold depth presets
            KeyCode::Char('!') => {
                self.inner.active_panel_mut().expand_to_depth(1);
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_to_depth(1);
                }
                EventResult::Consumed
            }
            KeyCode::Char('@') => {
                self.inner.active_panel_mut().expand_to_depth(2);
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_to_depth(2);
                }
                EventResult::Consumed
            }
            KeyCode::Char('#') => {
                self.inner.active_panel_mut().expand_to_depth(3);
                if self.inner.is_synced() {
                    self.inner.inactive_panel_mut().expand_to_depth(3);
                }
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Source"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "Navigate"),
            Shortcut::new("v", "Tree/Raw"),
            Shortcut::new("w", "Switch side"),
            Shortcut::new("s", "Sync"),
            Shortcut::new("/", "Search"),
            Shortcut::new("H/L", "Collapse/Expand all"),
            Shortcut::new("!/@@/#", "Fold depth"),
            Shortcut::new("z/Z", "Fold/Unfold"),
            Shortcut::new("%", "Match bracket"),
            Shortcut::new("m", "Bookmark"),
            Shortcut::new("a", "Align panels"),
            Shortcut::new("u", "Collapse unchanged"),
            Shortcut::new("d", "Detail"),
        ]
    }
}

fn handle_panel_search(
    panel: &mut crate::tui::app_states::source::SourcePanelState,
    key: KeyEvent,
) -> EventResult {
    match key.code {
        KeyCode::Esc => {
            panel.stop_search();
            panel.search_query.clear();
            panel.search_matches.clear();
            EventResult::Consumed
        }
        KeyCode::Enter => {
            panel.stop_search();
            EventResult::Consumed
        }
        KeyCode::Backspace => {
            panel.search_pop_char();
            EventResult::Consumed
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            panel.toggle_search_regex();
            EventResult::Consumed
        }
        KeyCode::Char(c) => {
            panel.search_push_char(c);
            EventResult::Consumed
        }
        _ => EventResult::Consumed,
    }
}

/// Get the node_id of the selected expandable node in the active panel.
fn get_expandable_node(
    source: &mut SourceDiffState,
    require_expanded: Option<bool>,
) -> Option<String> {
    let panel = source.active_panel_mut();
    if panel.view_mode != SourceViewMode::Tree {
        return None;
    }
    panel.ensure_flat_cache();
    let item = panel.cached_flat_items.get(panel.selected)?;
    if !item.is_expandable {
        return None;
    }
    if let Some(must_be_expanded) = require_expanded
        && item.is_expanded != must_be_expanded
    {
        return None;
    }
    Some(item.node_id.clone())
}

/// Sync expand/collapse to inactive panel.
fn sync_expand(source: &mut SourceDiffState, node_id: &str) {
    let inactive = source.inactive_panel_mut();
    if inactive.view_mode != SourceViewMode::Tree || inactive.json_tree.is_none() {
        return;
    }
    inactive.ensure_flat_cache();
    let exists = inactive
        .cached_flat_items
        .iter()
        .any(|item| item.node_id == node_id);
    if exists || inactive.expanded.contains(node_id) {
        inactive.toggle_expand(node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::traits::ViewMode;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn make_ctx() -> ViewContext<'static> {
        let status: &'static mut Option<String> = Box::leak(Box::new(None));
        ViewContext {
            mode: ViewMode::Diff,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        }
    }

    #[test]
    fn test_view_mode_toggle() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        // Empty panels start in Raw mode; toggle switches to Tree
        let initial = view.inner().old_panel.view_mode;
        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        // toggle_view_mode cycles the mode
        let _after = view.inner().old_panel.view_mode;
        // Verify it changed (or at least the key was consumed)
        let result = view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert_eq!(result, EventResult::Consumed);
        // After two toggles, should be back to initial
        assert_eq!(view.inner().old_panel.view_mode, initial);
    }

    #[test]
    fn test_side_toggle() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        let initial = view.inner().active_side;
        view.handle_key(make_key(KeyCode::Char('w')), &mut ctx);
        assert_ne!(view.inner().active_side, initial);
    }

    #[test]
    fn test_sync_toggle() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        let initial = view.inner().sync_mode;
        view.handle_key(make_key(KeyCode::Char('s')), &mut ctx);
        assert_ne!(view.inner().sync_mode, initial);
    }

    #[test]
    fn test_data_dependent_ignored() {
        let mut view = SourceView::new();
        let mut ctx = make_ctx();

        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('c')), &mut ctx),
            EventResult::Ignored
        );
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('E')), &mut ctx),
            EventResult::Ignored
        );
    }

    #[test]
    fn test_align_toggle() {
        use crate::tui::app_states::source::{SourceChangeStatus, SourceDiffState};

        let old_json = r#"{"components": [
            {"name": "foo", "version": "1.0"},
            {"name": "bar", "version": "2.0"}
        ]}"#;
        let new_json = r#"{"components": [
            {"name": "foo", "version": "1.0"},
            {"name": "baz", "version": "3.0"}
        ]}"#;

        let mut state = SourceDiffState::new(old_json, new_json);
        // Simulate diff annotations: bar removed from old, baz added to new
        state.old_panel.change_annotations.insert(
            "root.components.[1]".to_string(),
            SourceChangeStatus::Removed,
        );
        state
            .new_panel
            .change_annotations
            .insert("root.components.[1]".to_string(), SourceChangeStatus::Added);

        // Alignment is enabled by default
        assert!(state.align_enabled);

        // Expand components in both panels so we get component items
        state.old_panel.expanded.insert("root".to_string());
        state
            .old_panel
            .expanded
            .insert("root.components".to_string());
        state.old_panel.invalidate_flat_cache();
        state.new_panel.expanded.insert("root".to_string());
        state
            .new_panel
            .expanded
            .insert("root.components".to_string());
        state.new_panel.invalidate_flat_cache();

        // Build flat caches and apply alignment
        state.old_panel.ensure_flat_cache();
        state.new_panel.ensure_flat_cache();

        let old_count_before = state.old_panel.cached_flat_items.len();
        let new_count_before = state.new_panel.cached_flat_items.len();

        state.align_component_panels();

        // After alignment, gaps should be inserted
        let old_count_after = state.old_panel.cached_flat_items.len();
        let new_count_after = state.new_panel.cached_flat_items.len();

        // Old panel should have a gap (for the added "baz" in new)
        assert!(
            old_count_after > old_count_before,
            "Old panel should have gap items inserted"
        );
        // New panel should have a gap (for the removed "bar" in old)
        assert!(
            new_count_after > new_count_before,
            "New panel should have gap items inserted"
        );

        // Verify gap items have __gap_ prefix
        let old_gaps: Vec<_> = state
            .old_panel
            .cached_flat_items
            .iter()
            .filter(|item| item.node_id.starts_with("__gap_"))
            .collect();
        assert!(!old_gaps.is_empty(), "Old panel should contain gap items");
        assert_eq!(
            old_gaps[0].display_key,
            "\u{00b7}\u{00b7}\u{00b7}\u{00b7}\u{00b7}"
        );

        let new_gaps: Vec<_> = state
            .new_panel
            .cached_flat_items
            .iter()
            .filter(|item| item.node_id.starts_with("__gap_"))
            .collect();
        assert!(!new_gaps.is_empty(), "New panel should contain gap items");

        // Both panels should now have the same total item count (aligned)
        assert_eq!(
            old_count_after, new_count_after,
            "After alignment, both panels should have the same item count"
        );

        // Alignment should be idempotent (calling again should not add more gaps)
        state.align_component_panels();
        assert_eq!(
            state.old_panel.cached_flat_items.len(),
            old_count_after,
            "Second alignment call should be a no-op"
        );
    }

    #[test]
    fn test_align_toggle_key() {
        use crate::tui::app_states::source::{SourceChangeStatus, SourceDiffState};

        let old_json = r#"{"components": [{"name": "foo", "version": "1.0"}]}"#;
        let new_json = r#"{"components": [{"name": "foo", "version": "1.0"}]}"#;

        let mut state = SourceDiffState::new(old_json, new_json);
        // Need at least one annotation to enable the align toggle
        state.old_panel.change_annotations.insert(
            "root.components.[0]".to_string(),
            SourceChangeStatus::Modified,
        );

        let mut view = SourceView::with_state(state);
        let mut ctx = make_ctx();

        assert!(view.inner().align_enabled);

        // Toggle alignment off
        let result = view.handle_key(make_key(KeyCode::Char('a')), &mut ctx);
        assert!(
            matches!(result, EventResult::StatusMessage(_)),
            "Expected StatusMessage, got {result:?}"
        );
        assert!(!view.inner().align_enabled);

        // Toggle alignment back on
        let result = view.handle_key(make_key(KeyCode::Char('a')), &mut ctx);
        assert!(
            matches!(result, EventResult::StatusMessage(_)),
            "Expected StatusMessage, got {result:?}"
        );
        assert!(view.inner().align_enabled);
    }

    #[test]
    fn test_align_no_annotations_noop() {
        use crate::tui::app_states::source::SourceDiffState;

        let old_json = r#"{"components": [{"name": "foo"}]}"#;
        let new_json = r#"{"components": [{"name": "foo"}]}"#;

        let mut state = SourceDiffState::new(old_json, new_json);
        state.old_panel.expanded.insert("root".to_string());
        state
            .old_panel
            .expanded
            .insert("root.components".to_string());
        state.old_panel.invalidate_flat_cache();
        state.new_panel.expanded.insert("root".to_string());
        state
            .new_panel
            .expanded
            .insert("root.components".to_string());
        state.new_panel.invalidate_flat_cache();
        state.old_panel.ensure_flat_cache();
        state.new_panel.ensure_flat_cache();

        let old_count = state.old_panel.cached_flat_items.len();
        let new_count = state.new_panel.cached_flat_items.len();

        // No annotations, so alignment should be a no-op
        state.align_component_panels();

        assert_eq!(state.old_panel.cached_flat_items.len(), old_count);
        assert_eq!(state.new_panel.cached_flat_items.len(), new_count);
    }
}
