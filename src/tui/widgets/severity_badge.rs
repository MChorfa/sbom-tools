//! Severity badge widget for consistent severity display.

use crate::tui::theme::colors;
use ratatui::{prelude::*, widgets::Widget};

/// A styled badge showing vulnerability severity.
#[derive(Debug, Clone)]
pub struct SeverityBadge {
    severity: String,
    compact: bool,
}

impl SeverityBadge {
    /// Get the style for a severity level (uses theme colors).
    pub(crate) fn style_for(severity: &str) -> Style {
        let scheme = colors();
        let bg_color = scheme.severity_color(severity);
        let fg_color = scheme.severity_badge_fg(severity);

        let style = Style::default().fg(fg_color).bg(bg_color);
        match severity.to_lowercase().as_str() {
            "critical" | "high" => style.bold(),
            _ => style,
        }
    }

    /// Get just the foreground color for a severity level (uses theme colors).
    pub(crate) fn fg_color(severity: &str) -> Color {
        colors().severity_color(severity)
    }

    /// Get a single-char indicator for severity.
    pub(crate) fn indicator(severity: &str) -> &'static str {
        match severity.to_lowercase().as_str() {
            "critical" => "C",
            "high" => "H",
            "medium" | "moderate" => "M",
            "low" => "L",
            "info" | "informational" => "I",
            "none" => "-",
            _ => "U",
        }
    }
}

impl Widget for SeverityBadge {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let text = if self.compact {
            format!(" {} ", Self::indicator(&self.severity))
        } else {
            let label = self.severity.to_uppercase();
            if area.width as usize >= label.len() + 2 {
                format!(" {label} ")
            } else {
                format!(" {} ", Self::indicator(&self.severity))
            }
        };

        let style = Self::style_for(&self.severity);
        let x = area.x;
        let y = area.y;

        for (i, ch) in text.chars().enumerate() {
            if i < area.width as usize
                && let Some(cell) = buf.cell_mut((x + i as u16, y))
            {
                cell.set_char(ch).set_style(style);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_indicators() {
        assert_eq!(SeverityBadge::indicator("critical"), "C");
        assert_eq!(SeverityBadge::indicator("HIGH"), "H");
        assert_eq!(SeverityBadge::indicator("medium"), "M");
        assert_eq!(SeverityBadge::indicator("low"), "L");
        assert_eq!(SeverityBadge::indicator("info"), "I");
        assert_eq!(SeverityBadge::indicator("none"), "-");
        assert_eq!(SeverityBadge::indicator("unknown"), "U");
        assert_eq!(SeverityBadge::indicator("other"), "U");
    }

    #[test]
    fn test_severity_colors_use_theme() {
        // Colors should come from the theme, which defaults to dark
        let scheme = colors();
        assert_eq!(SeverityBadge::fg_color("critical"), scheme.critical);
        assert_eq!(SeverityBadge::fg_color("high"), scheme.high);
        assert_eq!(SeverityBadge::fg_color("medium"), scheme.medium);
        assert_eq!(SeverityBadge::fg_color("low"), scheme.low);
    }
}
