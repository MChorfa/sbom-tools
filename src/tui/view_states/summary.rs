//! Summary tab `ViewState` implementation.
//!
//! The Summary tab scrolls its All Changes list; every other key passes
//! through to the global handler.

use crate::tui::app_states::SummaryState;
use crate::tui::state::ListNavigation;
use crate::tui::traits::{EventResult, Shortcut, ViewContext, ViewState};
use crossterm::event::{KeyCode, KeyEvent, MouseEvent};

/// Summary tab view implementing the `ViewState` trait.
pub struct SummaryView {
    inner: SummaryState,
}

impl SummaryView {
    pub(crate) const fn new() -> Self {
        Self {
            inner: SummaryState::new(),
        }
    }

    /// Access the inner state.
    pub(crate) const fn inner(&self) -> &SummaryState {
        &self.inner
    }

    /// Mutable access to the inner state.
    pub(crate) const fn inner_mut(&mut self) -> &mut SummaryState {
        &mut self.inner
    }
}

impl Default for SummaryView {
    fn default() -> Self {
        Self::new()
    }
}

impl ViewState for SummaryView {
    fn handle_key(&mut self, key: KeyEvent, _ctx: &mut ViewContext) -> EventResult {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.inner.select_prev();
                EventResult::Consumed
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.inner.select_next();
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
            KeyCode::Home => {
                self.inner.go_first();
                EventResult::Consumed
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.inner.go_last();
                EventResult::Consumed
            }
            _ => EventResult::Ignored,
        }
    }

    fn handle_mouse(&mut self, _mouse: MouseEvent, _ctx: &mut ViewContext) -> EventResult {
        EventResult::Ignored
    }

    fn title(&self) -> &'static str {
        "Summary"
    }

    fn shortcuts(&self) -> Vec<Shortcut> {
        vec![
            Shortcut::primary("j/k", "scroll"),
            Shortcut::new("Home/End", "Jump to start/end"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::traits::ViewMode;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

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

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// j/k/G scroll the All Changes list and clamp to its bounds.
    #[test]
    fn summary_view_scrolls_and_clamps() {
        let mut view = SummaryView::new();
        let mut ctx = make_ctx();
        view.inner_mut().set_total(10);

        assert_eq!(
            view.handle_key(key(KeyCode::Char('j')), &mut ctx),
            EventResult::Consumed
        );
        assert_eq!(view.inner().scroll_offset, 1);

        view.handle_key(key(KeyCode::Char('k')), &mut ctx);
        assert_eq!(view.inner().scroll_offset, 0);

        view.handle_key(key(KeyCode::Char('G')), &mut ctx);
        assert_eq!(view.inner().scroll_offset, 9, "G jumps to the last line");

        view.handle_key(key(KeyCode::Char('j')), &mut ctx);
        assert_eq!(
            view.inner().scroll_offset,
            9,
            "offset never exceeds total-1"
        );
    }

    /// Unrelated keys pass through to the global handler.
    #[test]
    fn unrelated_keys_remain_ignored() {
        let mut view = SummaryView::new();
        let mut ctx = make_ctx();
        assert_eq!(
            view.handle_key(key(KeyCode::Char('x')), &mut ctx),
            EventResult::Ignored
        );
    }
}
