//! Summary tab state types.

use crate::tui::state::ListNavigation;

/// Scroll state for the Summary tab's All Changes list.
///
/// `scroll_offset` is the ListNavigation "selection": j/k/PgUp/PgDn/Home/End
/// move it, and the render path clamps it against the visible window.
pub struct SummaryState {
    pub scroll_offset: usize,
    pub total_lines: usize,
}

impl SummaryState {
    pub const fn new() -> Self {
        Self {
            scroll_offset: 0,
            total_lines: 0,
        }
    }
}

impl ListNavigation for SummaryState {
    fn selected(&self) -> usize {
        self.scroll_offset
    }

    fn set_selected(&mut self, idx: usize) {
        self.scroll_offset = idx;
    }

    fn total(&self) -> usize {
        self.total_lines
    }

    fn set_total(&mut self, total: usize) {
        self.total_lines = total;
        self.clamp_selection();
    }
}

impl Default for SummaryState {
    fn default() -> Self {
        Self::new()
    }
}
