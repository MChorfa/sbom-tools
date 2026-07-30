//! Components tab `ViewState` implementation.
//!
//! Handles filter/sort toggles, multi-select, and security filter toggles.
//! Data-dependent operations (clipboard, browser, flagging) remain in the
//! sync bridge since they need access to `App` data and security cache.

use crate::tui::app_states::components::ComponentsState;
use crate::tui::traits::{EventResult, Shortcut, TabTarget, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};

/// Components tab view implementing the `ViewState` trait.
pub struct ComponentsView {
    inner: ComponentsState,
    /// Quick Filters picker modal ('Q'). While open, digits 1-8 toggle the
    /// corresponding security quick filter and 0 clears all — bare digits
    /// outside the modal always jump tabs, matching the tab bar.
    pub(crate) quick_filter_picker_open: bool,
}

impl ComponentsView {
    pub(crate) fn new() -> Self {
        Self {
            inner: ComponentsState::new(0),
            quick_filter_picker_open: false,
        }
    }

    /// Access the inner state.
    pub(crate) fn inner(&self) -> &ComponentsState {
        &self.inner
    }

    /// Mutable access to the inner state.
    pub(crate) fn inner_mut(&mut self) -> &mut ComponentsState {
        &mut self.inner
    }
}

impl Default for ComponentsView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for ComponentsView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        // Quick Filters picker modal: digits toggle filters only while it is
        // open, so the bare digit keys stay honest tab jumps everywhere else.
        if self.quick_filter_picker_open {
            return match key.code {
                KeyCode::Char(c @ '1'..='8') => {
                    let idx = (c as u8 - b'1') as usize;
                    self.inner.security_filter.toggle_by_index(idx);
                    EventResult::status(self.inner.security_filter.summary())
                }
                KeyCode::Char('0') => {
                    self.inner.security_filter.clear_all();
                    EventResult::status("All quick filters cleared")
                }
                KeyCode::Esc | KeyCode::Char('Q' | 'q') => {
                    self.quick_filter_picker_open = false;
                    EventResult::Consumed
                }
                // Modal: swallow everything else so no key leaks behind it.
                _ => EventResult::Consumed,
            };
        }

        match key.code {
            KeyCode::Char('Q') => {
                self.quick_filter_picker_open = true;
                EventResult::Consumed
            }
            KeyCode::Char('f') => {
                self.inner.toggle_filter();
                EventResult::Consumed
            }
            KeyCode::Char('s') => {
                self.inner.toggle_sort();
                EventResult::Consumed
            }
            KeyCode::Char('v') => {
                self.inner.toggle_multi_select_mode();
                EventResult::Consumed
            }
            // `p` toggles panel focus; `Tab` is reserved for global tab switching.
            KeyCode::Char('p') => {
                self.inner.toggle_focus();
                EventResult::Consumed
            }
            KeyCode::Char(' ') if self.inner.multi_select_mode => {
                self.inner.toggle_current_selection();
                EventResult::Consumed
            }
            KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.inner.select_all();
                EventResult::Consumed
            }
            KeyCode::Char('A') => {
                self.inner.select_all();
                EventResult::Consumed
            }
            KeyCode::Esc if self.inner.multi_select_mode => {
                self.inner.toggle_multi_select_mode();
                EventResult::Consumed
            }
            KeyCode::Char('d') => {
                // Navigate to Dependencies tab for the selected component
                EventResult::NavigateTo(TabTarget::Dependencies)
            }
            // Data-dependent actions return Ignored so the bridge handles them
            KeyCode::Char('y' | 'F' | 'o' | 'n') => EventResult::Ignored,
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Components"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("f", "filter"),
            Shortcut::primary("s", "sort"),
            Shortcut::primary("F", "flag"),
            Shortcut::primary("o", "CVE"),
            Shortcut::primary("n", "note"),
            Shortcut::new("j/k", "Navigate"),
            Shortcut::new("Enter", "Component deep dive"),
            Shortcut::new("d", "Dependencies"),
            Shortcut::new("v", "Multi-select"),
            Shortcut::new("Q", "Quick filters"),
            Shortcut::new("y", "Copy"),
        ]
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

    fn make_ctx(mode: ViewMode) -> ViewContext<'static> {
        let status: &'static mut Option<String> = Box::leak(Box::new(None));
        ViewContext {
            mode,
            focused: true,
            width: 80,
            height: 24,
            tick: 0,
            status_message: status,
        }
    }

    #[test]
    fn test_filter_toggle() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        let initial = view.inner().filter;
        view.handle_key(make_key(KeyCode::Char('f')), &mut ctx);
        assert_ne!(view.inner().filter, initial);
    }

    #[test]
    fn test_multi_select() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        assert!(!view.inner().multi_select_mode);
        view.handle_key(make_key(KeyCode::Char('v')), &mut ctx);
        assert!(view.inner().multi_select_mode);

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.inner().multi_select_mode);
    }

    #[test]
    fn test_data_dependent_keys_ignored() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        // These should return Ignored so the bridge handles them
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('y')), &mut ctx),
            EventResult::Ignored
        );
        assert_eq!(
            view.handle_key(make_key(KeyCode::Char('F')), &mut ctx),
            EventResult::Ignored
        );
    }

    /// Bare digits must NOT be consumed by the Components tab: they fall
    /// through to the global digit tab-select, matching the tab bar labels.
    #[test]
    fn digits_fall_through_to_tab_select() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        for c in ['1', '5', '8', '0'] {
            assert_eq!(
                view.handle_key(make_key(KeyCode::Char(c)), &mut ctx),
                EventResult::Ignored,
                "'{c}' must fall through to the global tab-select"
            );
        }
        assert!(!view.inner().security_filter.has_active_filters());
    }

    /// 'Q' opens the quick-filter picker; inside it digits toggle filters,
    /// '0' clears all, and Esc/'Q' closes.
    #[test]
    fn quick_filter_picker_flow() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        view.handle_key(make_key(KeyCode::Char('Q')), &mut ctx);
        assert!(view.quick_filter_picker_open, "'Q' opens the picker");

        let result = view.handle_key(make_key(KeyCode::Char('1')), &mut ctx);
        assert!(matches!(result, EventResult::StatusMessage(_)));
        assert!(
            view.inner().security_filter.has_active_filters(),
            "digit 1 toggles the first quick filter while the picker is open"
        );

        let result = view.handle_key(make_key(KeyCode::Char('0')), &mut ctx);
        assert!(matches!(result, EventResult::StatusMessage(_)));
        assert!(!view.inner().security_filter.has_active_filters());

        view.handle_key(make_key(KeyCode::Esc), &mut ctx);
        assert!(!view.quick_filter_picker_open, "Esc closes the picker");

        view.handle_key(make_key(KeyCode::Char('Q')), &mut ctx);
        view.handle_key(make_key(KeyCode::Char('Q')), &mut ctx);
        assert!(!view.quick_filter_picker_open, "'Q' toggles closed too");
    }

    #[test]
    fn test_d_navigates_to_dependencies() {
        let mut view = ComponentsView::new();
        let mut ctx = make_ctx(ViewMode::Diff);

        let result = view.handle_key(make_key(KeyCode::Char('d')), &mut ctx);
        assert_eq!(result, EventResult::NavigateTo(TabTarget::Dependencies));
    }
}
