//! Shared rendering functions used by both App (diff mode) and `ViewApp` (view mode).
//!
//! These pure rendering functions take domain types directly (`&QualityReport`,
//! `&Violation`) with no app-specific dependencies, enabling both TUIs to
//! delegate to common code.

pub mod compliance;
pub mod components;
pub mod export;
pub mod licenses;
pub mod quality;
pub mod source;
pub mod text;
pub mod vulnerabilities;

use crossterm::{
    event::DisableMouseCapture,
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode},
};

/// Restore the terminal to its normal state (cooked mode, main screen,
/// mouse capture off).
///
/// Errors are ignored so this is safe to call from a panic hook and
/// idempotent with the normal TUI exit path.
pub(crate) fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

/// Install a panic hook that restores the terminal before delegating to the
/// previously installed hook, so a panic inside the TUI doesn't leave the
/// shell in raw mode with the backtrace swallowed by the alternate screen.
///
/// Installs at most once per process; subsequent calls are no-ops.
pub(crate) fn install_panic_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
    });
}

/// Find the largest byte index <= `index` that is on a UTF-8 char boundary.
///
/// Equivalent to `str::floor_char_boundary` (stabilized in Rust 1.94,
/// but our MSRV is 1.88).
pub(crate) const fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        s.len()
    } else {
        let bytes = s.as_bytes();
        let mut i = index;
        // Walk backwards to find a leading byte (0xxxxxxx or 11xxxxxx).
        while i > 0 && bytes[i] & 0b1100_0000 == 0b1000_0000 {
            i -= 1;
        }
        i
    }
}

/// RAII guard that switches the terminal into raw + alternate-screen mode on
/// construction and restores it on drop.
///
/// The run loop returns `io::Error` via `?` from `terminal.draw` / `events.next`,
/// which previously skipped the manual teardown and left the shell in raw mode (the
/// panic hook only covers unwinds). Because `Drop` runs on normal return, on the `?`
/// early-return, and during panic unwinding, this restores the terminal on every exit
/// path — and de-duplicates the enter/leave sequence shared by `run_tui` and
/// `run_view_tui`.
pub(crate) struct TerminalGuard;

impl TerminalGuard {
    /// Enter raw + alternate-screen mode with mouse capture.
    pub(crate) fn enter() -> std::io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::EnterAlternateScreen,
            crossterm::event::EnableMouseCapture
        )?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort restore; ignore errors (nothing useful to do on failure, and
        // Drop must not panic).
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture,
            crossterm::cursor::Show
        );
    }
}

/// A horizontal window over the tab list: which entries render, and whether
/// either side is clipped (rendered as a "« "/" »" marker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TabWindow {
    pub start: usize,
    pub end: usize,
    pub clipped_left: bool,
    pub clipped_right: bool,
}

/// What a click on the windowed tab bar hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabHit {
    /// A visible tab (GLOBAL index into the full entry list).
    Tab(usize),
    /// The leading "«" overflow marker.
    PrevMarker,
    /// The trailing "»" overflow marker.
    NextMarker,
    /// A divider or dead space.
    Miss,
}

/// Compute the window of tab labels that fits `avail` columns, always keeping
/// `selected` visible and growing greedily around it. Two columns per clipped
/// side are reserved for the "« "/" »" markers.
///
/// The single geometry contract shared by both render paths and both mouse
/// hit-tests — the ratatui `Tabs` widget's internal truncation silently hid
/// tabs past the width with no indicator.
#[must_use]
pub fn tab_window(
    label_widths: &[u16],
    divider_width: u16,
    selected: usize,
    avail: u16,
) -> TabWindow {
    let n = label_widths.len();
    if n == 0 {
        return TabWindow::default();
    }
    let selected = selected.min(n - 1);

    let fits = |start: usize, end: usize| -> bool {
        let labels: u16 = label_widths[start..end].iter().sum();
        let dividers = divider_width * (end - start).saturating_sub(1) as u16;
        let markers = u16::from(start > 0) * 2 + u16::from(end < n) * 2;
        labels + dividers + markers <= avail
    };

    // Everything fits: no window, no markers.
    let full: u16 = label_widths.iter().sum::<u16>() + divider_width * (n - 1) as u16;
    if full <= avail {
        return TabWindow {
            start: 0,
            end: n,
            clipped_left: false,
            clipped_right: false,
        };
    }

    let (mut start, mut end) = (selected, selected + 1);
    loop {
        let can_right = end < n && fits(start, end + 1);
        let can_left = start > 0 && fits(start - 1, end);
        if can_right {
            end += 1;
        } else if can_left {
            start -= 1;
        } else {
            break;
        }
    }

    TabWindow {
        start,
        end,
        clipped_left: start > 0,
        clipped_right: end < n,
    }
}

/// Hit-test a click against the WINDOWED tab bar. Mirrors the hand-rolled
/// render exactly: optional 2-col "« " marker, then `labels[start..end]`
/// joined by `divider_width`-col dividers, then an optional 2-col " »".
/// Returned tab indices are GLOBAL (offset by `window.start`).
#[must_use]
pub fn tab_bar_hit_windowed(
    labels: &[String],
    window: TabWindow,
    left: u16,
    divider_width: u16,
    click_x: u16,
) -> TabHit {
    use unicode_width::UnicodeWidthStr;

    if click_x < left {
        return TabHit::Miss;
    }
    let mut cursor = left;
    if window.clipped_left {
        if click_x < cursor + 2 {
            return TabHit::PrevMarker;
        }
        cursor += 2;
    }
    let visible = &labels[window.start..window.end];
    for (i, label) in visible.iter().enumerate() {
        let span = UnicodeWidthStr::width(label.as_str()) as u16;
        if click_x >= cursor && click_x < cursor.saturating_add(span) {
            return TabHit::Tab(window.start + i);
        }
        cursor = cursor.saturating_add(span);
        if i + 1 != visible.len() {
            cursor = cursor.saturating_add(divider_width);
        }
    }
    if window.clipped_right && click_x >= cursor && click_x < cursor + 2 {
        return TabHit::NextMarker;
    }
    TabHit::Miss
}

#[cfg(test)]
mod tab_window_tests {
    use super::{TabHit, TabWindow, tab_bar_hit_windowed, tab_window};

    const W: &[u16] = &[12, 14, 16, 12, 18, 11, 14, 8, 9, 9]; // 10 tabs

    #[test]
    fn tab_window_no_markers_when_fits() {
        let w = tab_window(W, 3, 0, 400);
        assert_eq!((w.start, w.end), (0, 10));
        assert!(!w.clipped_left && !w.clipped_right);
    }

    #[test]
    fn tab_window_keeps_selected_visible() {
        for avail in [40u16, 60, 80, 120, 200] {
            for selected in [0usize, 4, 9] {
                let w = tab_window(W, 3, selected, avail);
                assert!(
                    (w.start..w.end).contains(&selected),
                    "selected {selected} outside window {w:?} at avail {avail}"
                );
                // Rendered width must fit the budget.
                let labels: u16 = W[w.start..w.end].iter().sum();
                let dividers = 3 * (w.end - w.start).saturating_sub(1) as u16;
                let markers = u16::from(w.clipped_left) * 2 + u16::from(w.clipped_right) * 2;
                assert!(
                    labels + dividers + markers <= avail,
                    "window {w:?} overflows {avail}"
                );
            }
        }
    }

    #[test]
    fn tab_window_marks_clipped_sides() {
        let w = tab_window(W, 3, 4, 60);
        assert!(w.clipped_left, "tabs before the window need a « marker");
        assert!(w.clipped_right, "tabs after the window need a » marker");
    }

    #[test]
    fn tab_bar_hit_windowed_respects_offset() {
        let labels: Vec<String> = (0..10).map(|i| format!("[{i}] Tab{i} ")).collect();
        let window = TabWindow {
            start: 3,
            end: 6,
            clipped_left: true,
            clipped_right: true,
        };
        // Click on the « marker cell.
        assert_eq!(
            tab_bar_hit_windowed(&labels, window, 0, 3, 0),
            TabHit::PrevMarker
        );
        // First visible label starts after the 2-col marker; its hit returns
        // the GLOBAL index 3.
        assert_eq!(
            tab_bar_hit_windowed(&labels, window, 0, 3, 3),
            TabHit::Tab(3)
        );
    }
}
