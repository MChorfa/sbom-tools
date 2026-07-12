//! Side-by-side tab `ViewState` implementation.
//!
//! Handles panel scrolling, alignment mode, sync mode, filter toggles,
//! change/search navigation, and detail modal. Search match computation
//! remains in the sync bridge since it needs `app.data.diff_result`.

use crate::tui::app_states::sidebyside::{AlignmentMode, SideBySideState};
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

/// Status hint shown when a row-cursor action is pressed in Grouped mode,
/// which has no row selection.
const GROUPED_HINT: &str = "Row actions need a row cursor — press [a] for Aligned mode";

/// Side-by-side tab view implementing the `ViewState` trait.
pub struct SideBySideView {
    inner: SideBySideState,
}

impl SideBySideView {
    pub(crate) fn new() -> Self {
        Self {
            inner: SideBySideState::new(),
        }
    }

    /// Access the inner state for sync operations.
    pub(crate) fn inner(&self) -> &SideBySideState {
        &self.inner
    }

    /// Mutable access for sync operations.
    pub(crate) fn inner_mut(&mut self) -> &mut SideBySideState {
        &mut self.inner
    }
}

impl Default for SideBySideView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for SideBySideView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        // Handle search input mode
        if self.inner.search_active {
            return self.handle_search_key(key);
        }

        // Handle detail modal
        if self.inner.show_detail_modal {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.inner.close_detail_modal();
                    return EventResult::Consumed;
                }
                _ => return EventResult::Consumed,
            }
        }

        match key.code {
            // Toggle focus between panels. `Tab` is reserved for global tab
            // switching; `p`/arrows toggle panel focus here. Unified renders
            // a single panel, so there is nothing to focus-toggle.
            KeyCode::Char('p') | KeyCode::Left | KeyCode::Right => {
                if self.inner.alignment_mode == AlignmentMode::Unified {
                    EventResult::status("Unified view is a single panel")
                } else {
                    self.inner.toggle_focus();
                    EventResult::Consumed
                }
            }
            // Scroll
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.scroll_up();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.scroll_down();
                EventResult::Consumed
            }
            KeyCode::PageUp => {
                self.inner.page_up();
                EventResult::Consumed
            }
            KeyCode::PageDown => {
                self.inner.page_down();
                EventResult::Consumed
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.inner.go_to_top();
                EventResult::Consumed
            }
            KeyCode::Char('G') => {
                self.inner.go_to_bottom();
                EventResult::Consumed
            }
            // Synchronized scroll. In row-selection modes the panels already
            // move in lockstep with the selection (raw offset nudges would be
            // snapped back by the per-frame clamp), so J/K move the cursor.
            KeyCode::Char('K') => {
                if self.inner.alignment_mode.uses_row_selection() {
                    self.inner.scroll_up();
                } else {
                    self.inner.scroll_both_up();
                }
                EventResult::Consumed
            }
            KeyCode::Char('J') => {
                if self.inner.alignment_mode.uses_row_selection() {
                    self.inner.scroll_down();
                } else {
                    self.inner.scroll_both_down();
                }
                EventResult::Consumed
            }
            // Toggle alignment mode
            KeyCode::Char('a') => {
                self.inner.toggle_alignment();
                EventResult::status(format!(
                    "Alignment mode: {}",
                    self.inner.alignment_mode.name()
                ))
            }
            // Toggle sync mode
            KeyCode::Char('s') => {
                self.inner.toggle_sync();
                EventResult::status(format!("Sync mode: {}", self.inner.sync_mode.name()))
            }
            // Start search
            KeyCode::Char('/') => {
                self.inner.start_search();
                EventResult::Consumed
            }
            // n/N navigate a pinned (confirmed) search when one exists, like
            // every pager; otherwise they jump between changes. ]/[ stay pure
            // change-navigation so change-jumping remains reachable while a
            // search is pinned. Match navigation is Aligned-only: the match
            // indices are computed over the aligned row order, which neither
            // Unified (different sorted list) nor Grouped (no row cursor)
            // share.
            KeyCode::Char('n') => {
                if self.inner.alignment_mode == AlignmentMode::Aligned
                    && self.inner.search_query.is_some()
                    && !self.inner.search_matches.is_empty()
                {
                    self.inner.next_match();
                    EventResult::status(format!("Match {}", self.inner.match_position()))
                } else if self.inner.alignment_mode == AlignmentMode::Grouped {
                    EventResult::status(GROUPED_HINT)
                } else {
                    self.inner.next_change();
                    EventResult::status(format!("Change {}", self.inner.change_position()))
                }
            }
            KeyCode::Char('N') => {
                if self.inner.alignment_mode == AlignmentMode::Aligned
                    && self.inner.search_query.is_some()
                    && !self.inner.search_matches.is_empty()
                {
                    self.inner.prev_match();
                    EventResult::status(format!("Match {}", self.inner.match_position()))
                } else if self.inner.alignment_mode == AlignmentMode::Grouped {
                    EventResult::status(GROUPED_HINT)
                } else {
                    self.inner.prev_change();
                    EventResult::status(format!("Change {}", self.inner.change_position()))
                }
            }
            KeyCode::Char(']') => {
                if self.inner.alignment_mode == AlignmentMode::Grouped {
                    EventResult::status(GROUPED_HINT)
                } else {
                    self.inner.next_change();
                    EventResult::status(format!("Change {}", self.inner.change_position()))
                }
            }
            KeyCode::Char('[') => {
                if self.inner.alignment_mode == AlignmentMode::Grouped {
                    EventResult::status(GROUPED_HINT)
                } else {
                    self.inner.prev_change();
                    EventResult::status(format!("Change {}", self.inner.change_position()))
                }
            }
            // Filter toggles
            KeyCode::Char('1') => {
                self.inner.filter.toggle_added();
                let status = if self.inner.filter.show_added {
                    "Added: shown"
                } else {
                    "Added: hidden"
                };
                EventResult::status(status)
            }
            KeyCode::Char('2') => {
                self.inner.filter.toggle_removed();
                let status = if self.inner.filter.show_removed {
                    "Removed: shown"
                } else {
                    "Removed: hidden"
                };
                EventResult::status(status)
            }
            KeyCode::Char('3') => {
                self.inner.filter.toggle_modified();
                let status = if self.inner.filter.show_modified {
                    "Modified: shown"
                } else {
                    "Modified: hidden"
                };
                EventResult::status(status)
            }
            KeyCode::Char('0') => {
                self.inner.filter.show_all();
                EventResult::status("Showing all changes")
            }
            // Detail modal — needs a row cursor, which Grouped mode lacks.
            KeyCode::Enter | KeyCode::Char(' ') => {
                if self.inner.alignment_mode == AlignmentMode::Grouped {
                    EventResult::status(GROUPED_HINT)
                } else {
                    self.inner.toggle_detail_modal();
                    EventResult::Consumed
                }
            }
            // Yank: data-dependent, return Ignored for bridge (except in
            // Grouped mode, where the bridge would yank an invisible row 0).
            KeyCode::Char('y') => {
                if self.inner.alignment_mode == AlignmentMode::Grouped {
                    EventResult::status(GROUPED_HINT)
                } else {
                    EventResult::Ignored
                }
            }
            // Esc clears a pinned search; otherwise falls through to the
            // global overlay-close fallback.
            KeyCode::Esc => {
                if self.inner.search_query.is_some() {
                    self.inner.cancel_search();
                    EventResult::status("Search cleared")
                } else {
                    EventResult::Ignored
                }
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Side-by-Side"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("a", "align"),
            Shortcut::primary("n/N", "change"),
            Shortcut::primary("Enter", "detail"),
            Shortcut::primary("\u{2190}\u{2192}/p", "panel"),
            Shortcut::primary("J/K", "scroll"),
            Shortcut::new("j/k", "Scroll"),
            Shortcut::new("s", "Sync mode"),
            Shortcut::new("/", "Search"),
            Shortcut::new("1-3", "Filter toggles"),
        ]
    }
}

impl SideBySideView {
    fn handle_search_key(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Esc => {
                self.inner.cancel_search();
                EventResult::Consumed
            }
            KeyCode::Enter => {
                self.inner.confirm_search();
                if !self.inner.search_matches.is_empty() {
                    return EventResult::status(format!("Match {}", self.inner.match_position()));
                }
                EventResult::Consumed
            }
            KeyCode::Backspace => {
                self.inner.search_pop();
                // Bridge will update search matches
                EventResult::Consumed
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.inner.next_match();
                EventResult::Consumed
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.inner.prev_match();
                EventResult::Consumed
            }
            KeyCode::Down => {
                self.inner.next_match();
                EventResult::Consumed
            }
            KeyCode::Up => {
                self.inner.prev_match();
                EventResult::Consumed
            }
            KeyCode::Char(c) => {
                self.inner.search_push(c);
                // Bridge will update search matches
                EventResult::Consumed
            }
            _ => EventResult::Consumed,
        }
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
    fn test_panel_toggle() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        // `p` toggles panel focus. `Tab` is intentionally NOT handled here — it
        // is reserved for global tab switching in the diff dispatcher.
        assert!(!view.inner().focus_right);
        view.handle_key(make_key(KeyCode::Char('p')), &mut ctx);
        assert!(view.inner().focus_right);

        // `Tab` must be ignored by the view so it falls through to the global
        // fallback (next-tab) instead of toggling focus.
        assert_eq!(
            view.handle_key(make_key(KeyCode::Tab), &mut ctx),
            EventResult::Ignored
        );
        assert!(view.inner().focus_right, "Tab must not toggle panel focus");
    }

    #[test]
    fn test_alignment_toggle() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        let result = view.handle_key(make_key(KeyCode::Char('a')), &mut ctx);
        assert!(matches!(result, EventResult::StatusMessage(_)));
    }

    #[test]
    fn test_filter_toggles() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        assert!(view.inner().filter.show_added);
        view.handle_key(make_key(KeyCode::Char('1')), &mut ctx);
        assert!(!view.inner().filter.show_added);
    }

    #[test]
    fn test_search_mode() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        view.handle_key(make_key(KeyCode::Char('/')), &mut ctx);
        assert!(view.inner().search_active);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().search_active);
    }

    #[test]
    fn test_detail_modal() {
        let mut view = SideBySideView::new();
        let mut ctx = make_ctx();

        assert!(!view.inner().show_detail_modal);
        view.handle_key(make_key(KeyCode::Enter), &mut ctx);
        assert!(view.inner().show_detail_modal);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().show_detail_modal);
    }
}

#[cfg(test)]
mod grouped_gating_tests {
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

    fn grouped_view() -> SideBySideView {
        let mut view = SideBySideView::new();
        view.inner_mut().alignment_mode = AlignmentMode::Grouped;
        view
    }

    /// Row actions must not fire invisibly in Grouped mode — they explain
    /// themselves instead of toggling state on an invisible row 0.
    #[test]
    fn grouped_gates_row_actions_with_hint() {
        let mut ctx = make_ctx();

        let mut view = grouped_view();
        let result = view.handle_key(make_key(KeyCode::Enter), &mut ctx);
        assert!(
            !view.inner().show_detail_modal,
            "Enter must not open the detail modal in Grouped mode"
        );
        assert!(
            matches!(&result, EventResult::StatusMessage(m) if m.contains("Aligned")),
            "Enter returns the Grouped hint, got {result}"
        );

        let result = view.handle_key(make_key(KeyCode::Char('y')), &mut ctx);
        assert!(
            matches!(&result, EventResult::StatusMessage(m) if m.contains("Aligned")),
            "'y' returns the Grouped hint, got {result}"
        );

        let result = view.handle_key(make_key(KeyCode::Char('n')), &mut ctx);
        assert!(
            matches!(&result, EventResult::StatusMessage(m) if m.contains("Aligned")),
            "'n' returns the Grouped hint, got {result}"
        );
    }

    /// n/N navigate a pinned search; ]/[ keep jumping between changes.
    #[test]
    fn n_navigates_pinned_search_matches() {
        let mut ctx = make_ctx();
        let mut view = SideBySideView::new(); // Aligned default
        {
            let inner = view.inner_mut();
            // Seed real rows: recompute derives totals/change_indices from
            // aligned_rows, so set_totals alone leaves change nav empty.
            inner.aligned_rows = (0..12)
                .map(|_| crate::tui::app_states::AlignedRow {
                    left_name: Some("pkg".to_string()),
                    left_version: Some("1.0".to_string()),
                    right_name: Some("pkg".to_string()),
                    right_version: Some("2.0".to_string()),
                    change_type: crate::diff::ChangeType::Modified,
                    component_id: None,
                })
                .collect();
            inner.recompute_row_model();
            inner.start_search();
            if let Some(q) = inner.search_query.as_mut() {
                q.push('x');
            }
            inner.update_search_matches(vec![2, 5, 9]);
            inner.confirm_search();
        }

        view.handle_key(make_key(KeyCode::Char('n')), &mut ctx);
        assert_eq!(view.inner().current_match_idx, 1, "'n' advances the match");
        view.handle_key(make_key(KeyCode::Char('n')), &mut ctx);
        assert_eq!(view.inner().current_match_idx, 2);
        assert_eq!(
            view.inner().current_change_idx,
            None,
            "match navigation must not consume change navigation"
        );

        view.handle_key(make_key(KeyCode::Char(']')), &mut ctx);
        assert!(
            view.inner().current_change_idx.is_some(),
            "']' still jumps between changes while a search is pinned"
        );
    }

    /// Esc clears a pinned search once, then falls through.
    #[test]
    fn esc_clears_pinned_search() {
        let mut ctx = make_ctx();
        let mut view = SideBySideView::new();
        {
            let inner = view.inner_mut();
            inner.start_search();
            inner.update_search_matches(vec![1]);
            inner.confirm_search();
        }

        let result = view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(matches!(result, EventResult::StatusMessage(_)));
        assert!(view.inner().search_query.is_none(), "search cleared");

        let result = view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert_eq!(
            result,
            EventResult::Ignored,
            "second Esc falls through to the global fallback"
        );
    }

    /// Pins: 'p'/Left/Right in Unified mode must NOT toggle panel focus
    /// (Unified renders a single panel) and must explain themselves with the
    /// "Unified view is a single panel" status; Aligned keeps the toggle.
    #[test]
    fn unified_gates_panel_focus_toggle_with_status() {
        let mut ctx = make_ctx();
        let mut view = SideBySideView::new();
        view.inner_mut().alignment_mode = AlignmentMode::Unified;

        for code in [KeyCode::Char('p'), KeyCode::Left, KeyCode::Right] {
            let result = view.handle_key(make_key(code), &mut ctx);
            assert!(
                !view.inner().focus_right,
                "{code:?} must not toggle panel focus in Unified mode"
            );
            assert!(
                matches!(&result, EventResult::StatusMessage(m) if m.contains("single panel")),
                "{code:?} must return the single-panel status, got {result}"
            );
        }

        // Control: Aligned mode still toggles focus through 'p', so the guard
        // cannot pass by disabling the binding outright.
        view.inner_mut().alignment_mode = AlignmentMode::Aligned;
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('p')), &mut ctx),
            EventResult::Consumed
        );
        assert!(
            view.inner().focus_right,
            "'p' must still toggle panel focus in Aligned mode"
        );
    }
}
