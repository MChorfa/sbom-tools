//! Centralized theme and color scheme for TUI.
//!
//! This module provides consistent styling across all TUI views and modes.

use ratatui::prelude::*;
use std::sync::RwLock;

/// Color scheme for the TUI application.
/// Provides semantic colors for different UI elements.
#[derive(Debug, Clone, Copy)]
pub struct ColorScheme {
    // Change status colors
    pub added: Color,
    pub removed: Color,
    pub modified: Color,
    pub unchanged: Color,

    // Severity colors
    pub critical: Color,
    pub high: Color,
    pub medium: Color,
    pub low: Color,
    pub info: Color,

    // License category colors
    pub permissive: Color,
    pub copyleft: Color,
    pub weak_copyleft: Color,
    pub proprietary: Color,
    pub unknown_license: Color,

    // UI element colors
    pub primary: Color,
    pub secondary: Color,
    pub accent: Color,
    pub muted: Color,
    pub border: Color,
    pub border_focused: Color,
    pub background: Color,
    pub background_alt: Color,
    pub text: Color,
    pub text_muted: Color,
    pub selection: Color,
    pub highlight: Color,

    // Status colors
    pub success: Color,
    pub warning: Color,
    pub error: Color,

    // Badge foreground colors (for text on colored backgrounds)
    pub badge_fg_dark: Color, // For badges on bright backgrounds (yellow, cyan)
    pub badge_fg_light: Color, // For badges on dark backgrounds (magenta, red, blue)

    // Side-by-side view colors
    pub selection_bg: Color,        // Background for selected row
    pub search_highlight_bg: Color, // Background for search matches
    pub error_bg: Color,            // Background for removed/error highlights
    pub success_bg: Color,          // Background for added/success highlights

    // Source view scope highlighting
    pub scope_bg: Color, // Subtle background for enclosing bracket scope

    /// True for the NO_COLOR / monochrome scheme: hue-dependent helpers
    /// (severity tints, KEV/dependency badges) must return `Color::Reset`.
    pub monochrome: bool,
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self::dark()
    }
}

impl ColorScheme {
    /// Const dark theme for static initialization
    const fn dark_const() -> Self {
        Self {
            // Change status
            added: Color::Green,
            removed: Color::Red,
            modified: Color::Yellow,
            unchanged: Color::Gray,

            // Severity
            critical: Color::Magenta,
            high: Color::Red,
            medium: Color::Yellow,
            low: Color::Cyan,
            info: Color::Blue,

            // License categories
            permissive: Color::Green,
            copyleft: Color::Yellow,
            weak_copyleft: Color::Cyan,
            proprietary: Color::Red,
            unknown_license: Color::DarkGray,

            // UI elements
            primary: Color::Cyan,
            secondary: Color::Blue,
            accent: Color::Yellow,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            border_focused: Color::Cyan,
            background: Color::Reset,
            background_alt: Color::Rgb(30, 30, 40),
            text: Color::White,
            text_muted: Color::Gray,
            selection: Color::Rgb(50, 50, 70),
            highlight: Color::Yellow,

            // Status
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,

            // Badge foregrounds
            badge_fg_dark: Color::Black,
            badge_fg_light: Color::White,

            // Side-by-side view colors
            selection_bg: Color::Rgb(60, 60, 80),
            search_highlight_bg: Color::Rgb(100, 80, 0),
            error_bg: Color::Rgb(80, 30, 30),
            success_bg: Color::Rgb(30, 80, 30),

            // Source view scope highlighting
            scope_bg: Color::Rgb(35, 35, 50),

            monochrome: false,
        }
    }

    /// Dark theme (default)
    #[must_use]
    pub const fn dark() -> Self {
        Self {
            // Change status
            added: Color::Green,
            removed: Color::Red,
            modified: Color::Yellow,
            unchanged: Color::Gray,

            // Severity
            critical: Color::Magenta,
            high: Color::Red,
            medium: Color::Yellow,
            low: Color::Cyan,
            info: Color::Blue,

            // License categories
            permissive: Color::Green,
            copyleft: Color::Yellow,
            weak_copyleft: Color::Cyan,
            proprietary: Color::Red,
            unknown_license: Color::DarkGray,

            // UI elements
            primary: Color::Cyan,
            secondary: Color::Blue,
            accent: Color::Yellow,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            border_focused: Color::Cyan,
            background: Color::Reset,
            background_alt: Color::Rgb(30, 30, 40),
            text: Color::White,
            text_muted: Color::Gray,
            selection: Color::Rgb(50, 50, 70),
            highlight: Color::Yellow,

            // Status
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,

            // Badge foregrounds
            badge_fg_dark: Color::Black,
            badge_fg_light: Color::White,

            // Side-by-side view colors
            selection_bg: Color::Rgb(60, 60, 80),
            search_highlight_bg: Color::Rgb(100, 80, 0),
            error_bg: Color::Rgb(80, 30, 30),
            success_bg: Color::Rgb(30, 80, 30),

            // Source view scope highlighting
            scope_bg: Color::Rgb(35, 35, 50),

            monochrome: false,
        }
    }

    /// Light theme
    #[must_use]
    pub const fn light() -> Self {
        Self {
            // Change status
            added: Color::Rgb(0, 128, 0),
            removed: Color::Rgb(200, 0, 0),
            modified: Color::Rgb(180, 140, 0),
            unchanged: Color::Rgb(100, 100, 100),

            // Severity
            critical: Color::Rgb(128, 0, 128),
            high: Color::Rgb(200, 0, 0),
            medium: Color::Rgb(180, 140, 0),
            low: Color::Rgb(0, 128, 128),
            info: Color::Rgb(0, 0, 200),

            // License categories
            permissive: Color::Rgb(0, 128, 0),
            copyleft: Color::Rgb(180, 140, 0),
            weak_copyleft: Color::Rgb(0, 128, 128),
            proprietary: Color::Rgb(200, 0, 0),
            unknown_license: Color::Rgb(100, 100, 100),

            // UI elements
            primary: Color::Rgb(0, 100, 150),
            secondary: Color::Rgb(0, 0, 150),
            accent: Color::Rgb(180, 140, 0),
            muted: Color::Rgb(150, 150, 150),
            border: Color::Rgb(180, 180, 180),
            border_focused: Color::Rgb(0, 100, 150),
            background: Color::Rgb(255, 255, 255),
            background_alt: Color::Rgb(240, 240, 245),
            text: Color::Rgb(30, 30, 30),
            text_muted: Color::Rgb(100, 100, 100),
            selection: Color::Rgb(200, 220, 240),
            highlight: Color::Rgb(180, 140, 0),

            // Status
            success: Color::Rgb(0, 128, 0),
            warning: Color::Rgb(180, 140, 0),
            error: Color::Rgb(200, 0, 0),

            // Badge foregrounds (reversed for light theme)
            badge_fg_dark: Color::Rgb(30, 30, 30),
            badge_fg_light: Color::White,

            // Side-by-side view colors (lighter for light theme)
            selection_bg: Color::Rgb(200, 220, 240),
            search_highlight_bg: Color::Rgb(255, 230, 150),
            error_bg: Color::Rgb(255, 200, 200),
            success_bg: Color::Rgb(200, 255, 200),

            // Source view scope highlighting
            scope_bg: Color::Rgb(235, 240, 250),

            monochrome: false,
        }
    }

    /// High contrast theme (accessibility)
    #[must_use]
    pub const fn high_contrast() -> Self {
        Self {
            // Change status
            added: Color::Green,
            removed: Color::LightRed,
            modified: Color::LightYellow,
            unchanged: Color::White,

            // Severity
            critical: Color::LightMagenta,
            high: Color::LightRed,
            medium: Color::LightYellow,
            low: Color::LightCyan,
            info: Color::LightBlue,

            // License categories
            permissive: Color::LightGreen,
            copyleft: Color::LightYellow,
            weak_copyleft: Color::LightCyan,
            proprietary: Color::LightRed,
            unknown_license: Color::Gray,

            // UI elements
            primary: Color::LightCyan,
            secondary: Color::LightBlue,
            accent: Color::LightYellow,
            muted: Color::Gray,
            border: Color::White,
            border_focused: Color::LightCyan,
            background: Color::Black,
            background_alt: Color::Rgb(20, 20, 20),
            text: Color::White,
            text_muted: Color::Gray,
            // `selection` is used as a row *background* (with `.fg(text)`), and text is
            // White here — so a White selection made selected rows invisible. Use a
            // distinct dark blue-grey that stays readable under White text.
            selection: Color::Rgb(80, 80, 120),
            highlight: Color::LightYellow,

            // Status
            success: Color::LightGreen,
            warning: Color::LightYellow,
            error: Color::LightRed,

            // Badge foregrounds
            badge_fg_dark: Color::Black,
            badge_fg_light: Color::White,

            // Side-by-side view colors (high contrast)
            selection_bg: Color::Rgb(50, 50, 80),
            search_highlight_bg: Color::Rgb(120, 100, 0),
            error_bg: Color::Rgb(100, 30, 30),
            success_bg: Color::Rgb(30, 100, 30),

            // Source view scope highlighting
            scope_bg: Color::Rgb(25, 25, 40),

            monochrome: false,
        }
    }

    /// Monochrome theme honoring the `NO_COLOR` convention: grayscale only —
    /// no named hue, no RGB. Structure is carried by weight (bold), glyphs, and
    /// gray levels instead of color.
    #[must_use]
    pub const fn monochrome() -> Self {
        Self {
            // Change status
            added: Color::Reset,
            removed: Color::Reset,
            modified: Color::Reset,
            unchanged: Color::Reset,

            // Severity
            critical: Color::Reset,
            high: Color::Reset,
            medium: Color::Reset,
            low: Color::Reset,
            info: Color::Reset,

            // License categories
            permissive: Color::Reset,
            copyleft: Color::Reset,
            weak_copyleft: Color::Reset,
            proprietary: Color::Reset,
            unknown_license: Color::Reset,

            // UI elements
            primary: Color::Reset,
            secondary: Color::Reset,
            accent: Color::Reset,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            border_focused: Color::White,
            background: Color::Reset,
            background_alt: Color::Reset,
            text: Color::Reset,
            text_muted: Color::Gray,
            // `selection` is a row *background*: DarkGray keeps selected rows
            // visible (≠ text Reset, ≠ background Reset) without introducing hue.
            selection: Color::DarkGray,
            highlight: Color::Reset,

            // Status
            success: Color::Reset,
            warning: Color::Reset,
            error: Color::Reset,

            // Badge foregrounds (badges fall back to bold)
            badge_fg_dark: Color::Reset,
            badge_fg_light: Color::Reset,

            // Side-by-side view colors
            selection_bg: Color::DarkGray,
            search_highlight_bg: Color::Reset,
            error_bg: Color::Reset,
            success_bg: Color::Reset,

            // Source view scope highlighting
            scope_bg: Color::Reset,

            monochrome: true,
        }
    }

    /// Get color for severity level
    #[must_use]
    pub fn severity_color(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" => self.critical,
            "high" => self.high,
            "medium" | "moderate" => self.medium,
            "low" => self.low,
            "info" | "informational" | "none" => self.info,
            _ => self.text_muted,
        }
    }

    /// Get a subtle background tint for severity (used for row highlighting)
    #[must_use]
    /// Subtle row-background tint for a severity, adapted to the active theme.
    ///
    /// Dark themes use dark tints; light themes use pale tints so the dark row text
    /// stays readable (the previous hardcoded dark tints made light-theme rows
    /// unreadable — dark-on-dark).
    pub fn severity_bg_tint(&self, severity: &str) -> Color {
        // Monochrome: no tint at all (the dark-RGB fallback below would otherwise
        // fire, since is_light() is false for a Reset background).
        if self.monochrome {
            return Color::Reset;
        }
        if self.is_light() {
            match severity.to_lowercase().as_str() {
                "critical" => Color::Rgb(250, 228, 250),
                "high" => Color::Rgb(255, 226, 226),
                "medium" => Color::Rgb(255, 247, 214),
                "low" => Color::Rgb(222, 244, 248),
                _ => Color::Reset,
            }
        } else {
            match severity.to_lowercase().as_str() {
                "critical" => Color::Rgb(50, 15, 50),
                "high" => Color::Rgb(50, 15, 15),
                "medium" => Color::Rgb(45, 40, 10),
                "low" => Color::Rgb(15, 35, 40),
                _ => Color::Reset,
            }
        }
    }

    /// Whether the theme has a light background (implying dark text), so tints should
    /// be light rather than dark. Dark themes use `Color::Reset`/`Black` backgrounds
    /// (not matched here); the light theme uses a bright RGB background.
    fn is_light(&self) -> bool {
        matches!(
            self.background,
            Color::Rgb(r, g, b) if u16::from(r) + u16::from(g) + u16::from(b) > 480
        )
    }

    /// Get color for change status
    #[must_use]
    pub fn change_color(&self, status: &str) -> Color {
        match status.to_lowercase().as_str() {
            "added" | "new" | "introduced" => self.added,
            "removed" | "deleted" | "resolved" => self.removed,
            "modified" | "changed" | "updated" => self.modified,
            _ => self.unchanged,
        }
    }

    /// Get appropriate foreground color for severity badges
    /// Returns light fg for dark backgrounds (critical, high, info) and dark fg for bright backgrounds
    #[must_use]
    pub fn severity_badge_fg(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" | "high" | "info" | "informational" => self.badge_fg_light,
            _ => self.badge_fg_dark,
        }
    }

    /// Get KEV (Known Exploited Vulnerabilities) badge color
    /// Returns a bright red/orange color to indicate active exploitation
    #[must_use]
    pub fn kev(&self) -> Color {
        if self.monochrome {
            Color::Reset
        } else {
            Color::Rgb(255, 100, 50) // Bright orange-red for urgency
        }
    }

    /// Get KEV badge foreground color
    #[must_use]
    pub const fn kev_badge_fg(&self) -> Color {
        self.badge_fg_dark
    }

    /// Get direct dependency badge background color (green - easy to fix)
    #[must_use]
    pub fn direct_dep(&self) -> Color {
        if self.monochrome {
            Color::Reset
        } else {
            Color::Rgb(46, 160, 67) // GitHub green
        }
    }

    /// Get transitive dependency badge background color (gray - harder to fix)
    #[must_use]
    pub fn transitive_dep(&self) -> Color {
        if self.monochrome {
            Color::Reset
        } else {
            Color::Rgb(110, 118, 129) // Muted gray
        }
    }

    /// Get appropriate foreground color for change status badges
    /// All change colors (green, red, yellow) work best with dark foreground
    #[must_use]
    pub const fn change_badge_fg(&self) -> Color {
        self.badge_fg_dark
    }

    /// Pick a readable badge foreground for an arbitrary badge background:
    /// bright ANSI colors and high-luminance RGB get the dark foreground,
    /// everything else the light one.
    #[must_use]
    pub fn badge_fg_for(&self, bg: Color) -> Color {
        match bg {
            Color::Yellow
            | Color::LightYellow
            | Color::Cyan
            | Color::LightCyan
            | Color::Green
            | Color::LightGreen
            | Color::White
            | Color::Gray => self.badge_fg_dark,
            Color::Rgb(r, g, b) => {
                // Standard perceived-luminance approximation (ITU-R BT.601).
                let luminance =
                    (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
                if luminance > 128 {
                    self.badge_fg_dark
                } else {
                    self.badge_fg_light
                }
            }
            _ => self.badge_fg_light,
        }
    }

    /// Get appropriate foreground color for license category badges
    #[must_use]
    pub fn license_badge_fg(&self, category: &str) -> Color {
        match category.to_lowercase().as_str() {
            "proprietary" | "commercial" => self.badge_fg_light,
            _ => self.badge_fg_dark,
        }
    }

    /// Chart color palette for visualizations
    #[must_use]
    pub const fn chart_palette(&self) -> [Color; 5] {
        [
            self.primary,
            self.success,
            self.warning,
            self.critical,
            self.secondary,
        ]
    }
}

/// Global theme instance (runtime switchable)
static THEME: RwLock<Theme> = RwLock::new(Theme::dark_const());

/// Theme configuration
#[derive(Debug, Clone)]
pub struct Theme {
    pub colors: ColorScheme,
    pub name: &'static str,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    /// Const dark theme for static initialization
    const fn dark_const() -> Self {
        Self {
            colors: ColorScheme::dark_const(),
            name: "dark",
        }
    }

    #[must_use]
    pub const fn dark() -> Self {
        Self {
            colors: ColorScheme::dark(),
            name: "dark",
        }
    }

    #[must_use]
    pub const fn light() -> Self {
        Self {
            colors: ColorScheme::light(),
            name: "light",
        }
    }

    #[must_use]
    pub const fn high_contrast() -> Self {
        Self {
            colors: ColorScheme::high_contrast(),
            name: "high-contrast",
        }
    }

    #[must_use]
    pub const fn monochrome() -> Self {
        Self {
            colors: ColorScheme::monochrome(),
            name: "monochrome",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "light" => Self::light(),
            "high-contrast" | "highcontrast" | "hc" => Self::high_contrast(),
            "monochrome" | "mono" => Self::monochrome(),
            _ => Self::dark(),
        }
    }

    /// Get the next theme in the rotation. Monochrome is sticky: it is only
    /// entered via `NO_COLOR` (or explicit preference), and the T-toggle must
    /// not reintroduce color for those users.
    #[must_use]
    pub fn next(&self) -> Self {
        match self.name {
            "dark" => Self::light(),
            "light" => Self::high_contrast(),
            "monochrome" => Self::monochrome(),
            _ => Self::dark(),
        }
    }
}

/// Get the current theme name
pub fn current_theme_name() -> &'static str {
    THEME.read().expect("THEME lock not poisoned").name
}

/// Set the current theme
pub fn set_theme(theme: Theme) {
    *THEME.write().expect("THEME lock not poisoned") = theme;
}

/// Resolve the theme to use at TUI startup, honoring the `NO_COLOR` convention that
/// the rest of the CLI respects: when `NO_COLOR` is set in the environment, force the
/// monochrome theme (grayscale only, no hue) regardless of the saved preference.
/// Otherwise use the saved theme name.
#[must_use]
pub fn startup_theme(prefs_name: &str) -> Theme {
    startup_theme_for(std::env::var_os("NO_COLOR").is_some(), prefs_name)
}

fn startup_theme_for(no_color: bool, prefs_name: &str) -> Theme {
    if no_color {
        Theme::monochrome()
    } else {
        Theme::from_name(prefs_name)
    }
}

/// Toggle to the next theme in rotation (dark -> light -> high-contrast -> dark)
pub fn toggle_theme() -> &'static str {
    let mut theme = THEME.write().expect("THEME lock not poisoned");
    *theme = theme.next();
    theme.name
}

/// Convenience function to get current colors
pub fn colors() -> ColorScheme {
    THEME.read().expect("THEME lock not poisoned").colors
}

// ============================================================================
// Style Helpers
// ============================================================================

/// Common style presets for consistent UI elements
pub struct Styles;

impl Styles {
    /// Header title style
    #[must_use]
    pub fn header_title() -> Style {
        Style::default().fg(colors().primary).bold()
    }

    /// Section title style
    #[must_use]
    pub fn section_title() -> Style {
        Style::default().fg(colors().primary).bold()
    }

    /// Subsection title style
    #[must_use]
    pub fn subsection_title() -> Style {
        Style::default().fg(colors().primary)
    }

    /// Normal text style
    #[must_use]
    pub fn text() -> Style {
        Style::default().fg(colors().text)
    }

    /// Muted/secondary text style
    #[must_use]
    pub fn text_muted() -> Style {
        Style::default().fg(colors().text_muted)
    }

    /// Label text style
    #[must_use]
    pub fn label() -> Style {
        Style::default().fg(colors().muted)
    }

    /// Value text style (for data values)
    #[must_use]
    pub fn value() -> Style {
        Style::default().fg(colors().text).bold()
    }

    /// Highlighted/accent style
    #[must_use]
    pub fn highlight() -> Style {
        Style::default().fg(colors().highlight).bold()
    }

    /// Selection style (for selected items)
    #[must_use]
    pub fn selected() -> Style {
        Style::default()
            .bg(colors().selection)
            .fg(colors().text)
            .bold()
    }

    /// Border style (unfocused)
    #[must_use]
    pub fn border() -> Style {
        Style::default().fg(colors().border)
    }

    /// Border style (focused)
    #[must_use]
    pub fn border_focused() -> Style {
        Style::default().fg(colors().border_focused)
    }

    /// Status bar background style
    #[must_use]
    pub fn status_bar() -> Style {
        Style::default().bg(colors().background_alt)
    }

    /// Keyboard shortcut style
    #[must_use]
    pub fn shortcut_key() -> Style {
        Style::default().fg(colors().accent)
    }

    /// Shortcut description style
    #[must_use]
    pub fn shortcut_desc() -> Style {
        Style::default().fg(colors().text_muted)
    }

    /// Success style
    #[must_use]
    pub fn success() -> Style {
        Style::default().fg(colors().success)
    }

    /// Warning style
    #[must_use]
    pub fn warning() -> Style {
        Style::default().fg(colors().warning)
    }

    /// Error style
    #[must_use]
    pub fn error() -> Style {
        Style::default().fg(colors().error)
    }

    /// Added item style
    #[must_use]
    pub fn added() -> Style {
        Style::default().fg(colors().added)
    }

    /// Removed item style
    #[must_use]
    pub fn removed() -> Style {
        Style::default().fg(colors().removed)
    }

    /// Modified item style
    #[must_use]
    pub fn modified() -> Style {
        Style::default().fg(colors().modified)
    }

    /// Critical severity style
    #[must_use]
    pub fn critical() -> Style {
        Style::default().fg(colors().critical).bold()
    }

    /// High severity style
    #[must_use]
    pub fn high() -> Style {
        Style::default().fg(colors().high).bold()
    }

    /// Medium severity style
    #[must_use]
    pub fn medium() -> Style {
        Style::default().fg(colors().medium)
    }

    /// Low severity style
    #[must_use]
    pub fn low() -> Style {
        Style::default().fg(colors().low)
    }
}

// ============================================================================
// Badge Rendering Helpers
// ============================================================================

/// Render a status badge with consistent styling
#[must_use]
pub fn status_badge(status: &str) -> Span<'static> {
    let scheme = colors();
    let (label, color, symbol) = match status.to_lowercase().as_str() {
        "added" | "new" | "introduced" => ("ADDED", scheme.added, "+"),
        "removed" | "deleted" | "resolved" => ("REMOVED", scheme.removed, "-"),
        "modified" | "changed" | "updated" => ("MODIFIED", scheme.modified, "~"),
        _ => ("UNCHANGED", scheme.unchanged, "="),
    };

    Span::styled(
        format!(" {symbol} {label} "),
        Style::default()
            .fg(scheme.change_badge_fg())
            .bg(color)
            .bold(),
    )
}

/// Render a severity badge with consistent styling
#[must_use]
pub fn severity_badge(severity: &str) -> Span<'static> {
    let scheme = colors();
    let (label, bg_color, is_unknown) = match severity.to_lowercase().as_str() {
        "critical" => ("CRITICAL", scheme.critical, false),
        "high" => ("HIGH", scheme.high, false),
        "medium" | "moderate" => ("MEDIUM", scheme.medium, false),
        "low" => ("LOW", scheme.low, false),
        "info" | "informational" => ("INFO", scheme.info, false),
        "none" => ("NONE", scheme.muted, false),
        _ => ("UNKNOWN", scheme.muted, true),
    };
    let fg_color = scheme.severity_badge_fg(severity);

    let style = if is_unknown {
        Style::default().fg(fg_color).bg(bg_color).dim()
    } else {
        Style::default().fg(fg_color).bg(bg_color).bold()
    };

    Span::styled(format!(" {label} "), style)
}

/// Render a compact severity indicator (single char)
#[must_use]
pub fn severity_indicator(severity: &str) -> Span<'static> {
    let scheme = colors();
    let (symbol, bg_color, is_unknown) = match severity.to_lowercase().as_str() {
        "critical" => ("C", scheme.critical, false),
        "high" => ("H", scheme.high, false),
        "medium" | "moderate" => ("M", scheme.medium, false),
        "low" => ("L", scheme.low, false),
        "info" | "informational" => ("I", scheme.info, false),
        "none" => ("-", scheme.muted, false),
        _ => ("U", scheme.muted, true),
    };
    let fg_color = scheme.severity_badge_fg(severity);

    let style = if is_unknown {
        Style::default().fg(fg_color).bg(bg_color).dim()
    } else {
        Style::default().fg(fg_color).bg(bg_color).bold()
    };

    Span::styled(format!(" {symbol} "), style)
}

/// Render a count badge
#[must_use]
pub fn count_badge(count: usize, bg_color: Color) -> Span<'static> {
    let scheme = colors();
    Span::styled(
        format!(" {count} "),
        Style::default()
            .fg(scheme.badge_fg_for(bg_color))
            .bg(bg_color)
            .bold(),
    )
}

/// Render a filter/group badge showing current state
#[must_use]
pub fn filter_badge(label: &str, value: &str) -> Vec<Span<'static>> {
    let scheme = colors();
    vec![
        Span::styled(format!("{label}: "), Style::default().fg(scheme.text_muted)),
        Span::styled(
            format!(" {value} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
    ]
}

// ============================================================================
// Mode Indicator
// ============================================================================

/// Render a mode indicator badge
#[must_use]
pub fn mode_badge(mode: &str) -> Span<'static> {
    let scheme = colors();
    let color = match mode.to_lowercase().as_str() {
        "diff" => scheme.modified,
        "view" => scheme.primary,
        "multi-diff" | "multidiff" => scheme.added,
        "timeline" => scheme.secondary,
        "matrix" => scheme.high,
        _ => scheme.muted,
    };

    Span::styled(
        format!(" {} ", mode.to_uppercase()),
        Style::default().fg(scheme.badge_fg_dark).bg(color).bold(),
    )
}

// ============================================================================
// Footer Hints
// ============================================================================

/// Tab-specific footer hints
pub struct FooterHints;

impl FooterHints {
    /// Hints for the multi-comparison modes. The tail is exactly
    /// `GLOBAL_COUNT` honest globals — the multi modes have no diff tab bar,
    /// help overlay, or export dialog, so the tabbed globals don't apply.
    #[must_use]
    pub fn for_multi_mode(mode: &str) -> Vec<(&'static str, &'static str)> {
        let mut hints: Vec<(&'static str, &'static str)> = match mode {
            "matrix" => vec![
                ("t", "threshold"),
                ("z", "focus"),
                ("H", "highlight"),
                ("C", "clusters"),
                ("Enter", "diff"),
                ("x", "export"),
            ],
            "timeline" => vec![
                ("g", "jump"),
                ("d", "diff"),
                ("t", "stats"),
                ("f", "filter"),
                ("m", "metric"),
            ],
            _ => vec![
                ("f", "filter"),
                ("s", "sort"),
                ("v", "variable"),
                ("h", "heatmap"),
                ("x", "cross-target"),
            ],
        };
        hints.extend([
            ("Tab", "panel"),
            ("/", "search"),
            ("V", "views"),
            ("K", "keys"),
            ("q", "quit"),
        ]);
        hints
    }

    /// Get hints for a specific tab in view mode
    #[must_use]
    pub fn for_view_tab(tab: &str) -> Vec<(&'static str, &'static str)> {
        let mut hints = Self::global();

        match tab.to_lowercase().as_str() {
            "overview" => {
                // 'P' is otherwise undiscoverable, yet it is the only way to
                // reach the CBOM/AI-BOM tab sets on a misdetected document.
                hints.insert(0, ("P", "cycle profile"));
            }
            "tree" | "components" => {
                // g/f/filter already shown in filter bar at top.
                // NOTE: view/ui.rs drops the "1-4" hint unless the detail
                // panel is focused (digits switch app tabs otherwise).
                hints.insert(0, ("p", "panel"));
                hints.insert(1, ("Enter", "select"));
                hints.insert(2, ("1-4", "detail tabs"));
                // '/' here is an inline list filter, not the jump-to search
                // palette the other tabs open — label it honestly.
                if let Some(slash) = hints.iter_mut().find(|(k, _)| *k == "/") {
                    slash.1 = "filter";
                }
            }
            "vulnerabilities" | "vulns" => {
                hints.insert(0, ("f", "filter"));
                hints.insert(1, ("s", "sort"));
                hints.insert(2, ("g", "group"));
                hints.insert(3, ("d", "dedup"));
                hints.insert(4, ("Enter", "component"));
            }
            "licenses" => {
                hints.insert(0, ("g", "group"));
                hints.insert(1, ("Enter", "inspect"));
                hints.insert(2, ("K/J", "scroll"));
            }
            "dependencies" => {
                hints.insert(0, ("Enter", "expand/inspect"));
                hints.insert(1, ("←", "collapse"));
                hints.insert(2, ("x/X", "fold all"));
                hints.insert(3, ("p", "panel"));
                hints.insert(4, ("J/K", "scroll"));
            }
            "quality" => {
                hints.insert(0, ("v", "view"));
            }
            "compliance" => {
                hints.insert(0, ("f", "filter"));
                hints.insert(1, ("←→", "standard"));
                hints.insert(2, ("↑↓", "select"));
            }
            "source" => {
                hints.insert(0, ("v", "tree/raw"));
                hints.insert(1, ("p", "panel"));
                hints.insert(2, ("H/L", "fold all"));
                hints.insert(3, ("Enter", "select"));
            }
            // No ("Enter", "detail") hints here: Enter is a no-op on the
            // four CBOM asset tabs (handle_enter ignores them) and the
            // detail panel is already always visible — advertising a dead
            // key is dishonest. Mirrors what Models/Datasets already do.
            "algorithms" => {
                hints.insert(0, ("s", "sort"));
                hints.insert(1, ("↑↓", "select"));
            }
            "certificates" | "keys" | "protocols" => {
                hints.insert(0, ("↑↓", "select"));
            }
            "pqc-compliance" => {
                hints.insert(0, ("↑↓", "select"));
            }
            "models" | "datasets" => {
                hints.insert(0, ("↑↓", "select"));
                hints.insert(1, ("K/J", "scroll detail"));
            }
            "ai-readiness" => {
                hints.insert(0, ("↑↓", "scroll"));
            }
            _ => {}
        }

        hints
    }

    /// Global hints (always shown)
    #[must_use]
    pub fn global() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Tab", "switch"),
            ("/", "search"),
            ("e", "export"),
            ("?", "help"),
            ("q", "quit"),
        ]
    }

    /// Number of global hints (used to insert separator).
    pub const GLOBAL_COUNT: usize = 5;
}

/// Measured footer width of a hint list as rendered by
/// [`render_footer_hints`]: per hint, a padded key badge (key width + 2),
/// a space, and the description; 1-column gaps between hints; plus the
/// 2-column "│ " section separator while any tab-specific hint remains.
#[must_use]
pub fn footer_hints_width(hints: &[(&str, &str)]) -> u16 {
    use unicode_width::UnicodeWidthStr;
    let mut w: u16 = 0;
    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            w += 1;
        }
        // Badge " {key} " (key + 2) immediately followed by the description.
        w += UnicodeWidthStr::width(*key) as u16 + 2 + UnicodeWidthStr::width(*desc) as u16;
    }
    if hints.len() > FooterHints::GLOBAL_COUNT {
        w += 2; // "│ " separator
    }
    w
}

/// Fit a hint list into `max_width` columns by dropping tab-specific hints
/// from the END of the tab-specific block (the least-important,
/// latest-inserted ones). The trailing `GLOBAL_COUNT` global hints — the
/// always-valid `?`/`q` anchors — are never dropped.
///
/// Returns the kept hints and whether anything was elided (rendered as a
/// leading "… ").
#[must_use]
pub fn fit_footer_hints<'a>(
    hints: &[(&'a str, &'a str)],
    max_width: u16,
) -> (Vec<(&'a str, &'a str)>, bool) {
    let mut kept: Vec<(&str, &str)> = hints.to_vec();
    let mut elided = false;
    // Once anything is elided, the "… " prefix costs 2 more columns.
    while footer_hints_width(&kept) + if elided { 2 } else { 0 } > max_width
        && kept.len() > FooterHints::GLOBAL_COUNT
    {
        let tab_count = kept.len() - FooterHints::GLOBAL_COUNT;
        kept.remove(tab_count - 1);
        elided = true;
    }
    (kept, elided)
}

/// Render footer hints as spans with badge-style keys.
///
/// If the hint list contains more items than `FooterHints::GLOBAL_COUNT`,
/// a `│` separator is inserted between tab-specific and global hints. When
/// `elided` is true (some hints were dropped by [`fit_footer_hints`]), a
/// muted "… " prefix marks the omission.
#[must_use]
pub fn render_footer_hints(hints: &[(&str, &str)], elided: bool) -> Vec<Span<'static>> {
    let scheme = colors();
    let mut spans = Vec::new();
    if elided {
        spans.push(Span::styled("\u{2026} ", Style::default().fg(scheme.muted)));
    }
    let tab_count = hints.len().saturating_sub(FooterHints::GLOBAL_COUNT);

    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        // Insert separator between tab-specific and global hints
        if i == tab_count && tab_count > 0 {
            spans.push(Span::styled("│ ", Style::default().fg(scheme.muted)));
        }
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ));
        spans.push(Span::styled(
            desc.to_string(),
            Style::default().fg(scheme.text_muted),
        ));
    }

    spans
}

#[cfg(test)]
mod a11y_tests {
    use super::{ColorScheme, startup_theme_for};
    use ratatui::style::Color;

    #[test]
    fn severity_tint_unchanged_for_dark_and_high_contrast() {
        // Snapshot-safe: dark/high-contrast tints are the original dark values.
        assert_eq!(
            ColorScheme::dark().severity_bg_tint("critical"),
            Color::Rgb(50, 15, 50)
        );
        assert_eq!(
            ColorScheme::high_contrast().severity_bg_tint("high"),
            Color::Rgb(50, 15, 15)
        );
    }

    #[test]
    fn severity_tint_is_pale_for_light_theme() {
        // Light theme must use pale tints so the dark row text stays readable.
        for sev in ["critical", "high", "medium", "low"] {
            match ColorScheme::light().severity_bg_tint(sev) {
                Color::Rgb(r, g, b) => assert!(
                    u16::from(r) + u16::from(g) + u16::from(b) > 480,
                    "light {sev} tint must be pale, got {r},{g},{b}"
                ),
                other => panic!("expected an RGB tint for {sev}, got {other:?}"),
            }
        }
    }

    #[test]
    fn no_color_forces_monochrome_theme() {
        assert_eq!(startup_theme_for(true, "dark").name, "monochrome");
        assert_eq!(startup_theme_for(true, "light").name, "monochrome");
        assert_eq!(startup_theme_for(false, "light").name, "light");
        assert_eq!(startup_theme_for(false, "dark").name, "dark");
    }

    /// Multi-mode footers must carry exactly GLOBAL_COUNT honest globals so
    /// the separator/fit logic works, with no dead keys ('?' and 'e' render
    /// only in the tabbed layout, unreachable in multi modes).
    #[test]
    fn for_multi_mode_hints_are_honest() {
        for mode in ["matrix", "timeline", "multi"] {
            let hints = super::FooterHints::for_multi_mode(mode);
            assert!(hints.len() > super::FooterHints::GLOBAL_COUNT, "{mode}");
            assert_eq!(hints.last(), Some(&("q", "quit")), "{mode}");
            let tail = &hints[hints.len() - super::FooterHints::GLOBAL_COUNT..];
            // The separator/fit contract depends on exactly this tail.
            assert_eq!(
                tail,
                [
                    ("Tab", "panel"),
                    ("/", "search"),
                    ("V", "views"),
                    ("K", "keys"),
                    ("q", "quit"),
                ],
                "{mode}"
            );
            assert!(
                !hints.contains(&("?", "help")) && !hints.contains(&("e", "export")),
                "{mode}: no dead keys"
            );
        }
        assert!(
            super::FooterHints::for_multi_mode("matrix").contains(&("x", "export")),
            "matrix keeps its real export key"
        );
    }

    /// The two densest diff tabs must lead with their tab-specific power keys
    /// so width fitting sacrifices the memorized globals last. Primary order
    /// in ViewState::shortcuts() IS footer order now.
    #[test]
    fn footer_hints_lead_with_tab_keys() {
        use crate::tui::traits::ViewState;
        let primaries = |v: &dyn ViewState| -> Vec<(String, String)> {
            v.shortcuts()
                .into_iter()
                .filter(|s| s.primary)
                .map(|s| (s.key, s.description))
                .collect()
        };
        let sxs = primaries(&crate::tui::view_states::SideBySideView::new());
        assert_eq!(sxs[0], ("a".to_string(), "align".to_string()));
        assert!(sxs.iter().any(|(k, d)| k == "n/N" && d == "change"));
        let source = primaries(&crate::tui::view_states::SourceView::new());
        assert_eq!(source[0], ("u".to_string(), "collapse".to_string()));
        assert!(source.iter().any(|(k, _)| k == "z") && source.iter().any(|(k, _)| k == "m"));
    }

    #[test]
    fn monochrome_is_sticky_under_theme_toggle() {
        // The T-toggle must not reintroduce color for NO_COLOR users.
        assert_eq!(super::Theme::monochrome().next().name, "monochrome");
        // ...and "mono" resolves as an alias.
        assert_eq!(super::Theme::from_name("mono").name, "monochrome");
    }

    #[test]
    fn monochrome_scheme_is_hue_free() {
        let s = ColorScheme::monochrome();
        let grayscale = |c: Color| {
            matches!(
                c,
                Color::Reset | Color::Gray | Color::DarkGray | Color::White | Color::Black
            )
        };
        for (name, c) in [
            ("added", s.added),
            ("removed", s.removed),
            ("modified", s.modified),
            ("unchanged", s.unchanged),
            ("critical", s.critical),
            ("high", s.high),
            ("medium", s.medium),
            ("low", s.low),
            ("info", s.info),
            ("permissive", s.permissive),
            ("copyleft", s.copyleft),
            ("weak_copyleft", s.weak_copyleft),
            ("proprietary", s.proprietary),
            ("unknown_license", s.unknown_license),
            ("primary", s.primary),
            ("secondary", s.secondary),
            ("accent", s.accent),
            ("muted", s.muted),
            ("border", s.border),
            ("border_focused", s.border_focused),
            ("background", s.background),
            ("background_alt", s.background_alt),
            ("text", s.text),
            ("text_muted", s.text_muted),
            ("selection", s.selection),
            ("highlight", s.highlight),
            ("success", s.success),
            ("warning", s.warning),
            ("error", s.error),
            ("badge_fg_dark", s.badge_fg_dark),
            ("badge_fg_light", s.badge_fg_light),
            ("selection_bg", s.selection_bg),
            ("search_highlight_bg", s.search_highlight_bg),
            ("error_bg", s.error_bg),
            ("success_bg", s.success_bg),
            ("scope_bg", s.scope_bg),
        ] {
            assert!(grayscale(c), "monochrome slot {name} carries hue: {c:?}");
        }
    }

    #[test]
    fn severity_tint_is_reset_in_monochrome() {
        let s = ColorScheme::monochrome();
        for sev in ["critical", "high", "medium", "low", "info"] {
            assert_eq!(s.severity_bg_tint(sev), Color::Reset);
        }
    }

    #[test]
    fn monochrome_kev_and_dep_badges_are_reset() {
        let s = ColorScheme::monochrome();
        assert_eq!(s.kev(), Color::Reset);
        assert_eq!(s.direct_dep(), Color::Reset);
        assert_eq!(s.transitive_dep(), Color::Reset);
        // Colored themes keep their badge hues.
        assert_ne!(ColorScheme::dark().kev(), Color::Reset);
        assert_ne!(ColorScheme::dark().direct_dep(), Color::Reset);
        assert_ne!(ColorScheme::dark().transitive_dep(), Color::Reset);
    }

    #[test]
    fn badge_fg_tracks_bg_luminance() {
        let s = ColorScheme::dark();
        // Bright ANSI backgrounds take the dark foreground.
        assert_eq!(s.badge_fg_for(Color::Yellow), s.badge_fg_dark);
        // Dark RGB backgrounds take the light foreground.
        assert_eq!(s.badge_fg_for(Color::Rgb(200, 0, 0)), s.badge_fg_light);
        // Pale RGB backgrounds (light-theme search highlight) take the dark one.
        assert_eq!(s.badge_fg_for(Color::Rgb(255, 230, 150)), s.badge_fg_dark);
        // Dark ANSI backgrounds take the light foreground.
        assert_eq!(s.badge_fg_for(Color::Red), s.badge_fg_light);
    }

    /// count_badge must pick its foreground through badge_fg_for (bright bg ->
    /// dark fg, dark bg -> light fg); reverting to unconditional badge_fg_dark
    /// reintroduces unreadable dark-on-dark badges with no snapshot noticing.
    #[test]
    fn count_badge_routes_fg_through_badge_fg_for() {
        // count_badge reads the global theme; pin it to dark for determinism.
        super::set_theme(super::Theme::dark());
        let s = ColorScheme::dark();
        let on_bright = super::count_badge(3, Color::Yellow);
        assert_eq!(
            on_bright.style.fg,
            Some(s.badge_fg_dark),
            "a bright badge background must take the dark foreground through count_badge"
        );
        let on_dark = super::count_badge(3, Color::Rgb(120, 0, 0));
        assert_eq!(
            on_dark.style.fg,
            Some(s.badge_fg_light),
            "a dark badge background must take the light foreground — an unconditional badge_fg_dark regression renders unreadable badges"
        );
        assert_eq!(
            on_dark.style.bg,
            Some(Color::Rgb(120, 0, 0)),
            "count_badge must keep the requested badge background"
        );
    }
}

#[cfg(test)]
mod hardcoded_color_guard {
    /// Render-site `Color::` literals bypass the theme and break
    /// light/high-contrast/monochrome rendering. This ratchet walks every
    /// `src/tui/**/*.rs` file (except this one, which defines the palette)
    /// and fails when a file gains a literal that isn't `Color::Reset`.
    ///
    /// Files with legitimate remaining uses (computed gradients, test
    /// assertions about concrete colors) are baselined below with their
    /// current counts; counts may only shrink. Delete an entry once its file
    /// reaches zero so the ratchet locks in.
    const BASELINE: &[(&str, usize)] = &[
        // score-gradient Rgb interpolation + a test's Rgb pattern match
        ("shared/quality.rs", 2),
        // test asserting the selected row bg is themed, not DarkGray
        ("view/ui/render_snapshot_tests.rs", 1),
        // test-only args to highlight_search_matches (2 lines x fg+bg)
        ("views/sidebyside.rs", 4),
    ];

    fn color_literal_lines(src: &str) -> usize {
        // Count occurrences, not lines: `fg(Color::Red).bg(Color::Reset)` on
        // one line must still register the Red literal.
        src.lines()
            .map(|l| l.matches("Color::").count() - l.matches("Color::Reset").count())
            .sum()
    }

    #[test]
    fn no_new_hardcoded_colors_in_tui() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui");
        let mut stack = vec![root.clone()];
        let mut violations = Vec::new();
        let mut seen = 0usize;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir under src/tui") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let rel = path
                    .strip_prefix(&root)
                    .expect("walked from src/tui")
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel == "theme.rs" {
                    continue;
                }
                seen += 1;
                let src = std::fs::read_to_string(&path).expect("read source file");
                let count = color_literal_lines(&src);
                let max = BASELINE
                    .iter()
                    .find(|(p, _)| *p == rel)
                    .map_or(0, |&(_, m)| m);
                if count > max {
                    violations.push(format!(
                        "{rel}: {count} raw Color:: lines (baseline {max}) — \
                         route colors through ColorScheme/theme helpers"
                    ));
                } else if max > 0 && count == 0 {
                    violations.push(format!(
                        "{rel}: now clean — delete its BASELINE entry to lock in the ratchet"
                    ));
                }
            }
        }
        assert!(seen > 50, "walked only {seen} files — wrong root?");
        assert!(violations.is_empty(), "\n{}", violations.join("\n"));
    }
}

#[cfg(test)]
mod selection_contrast_tests {
    use super::ColorScheme;

    /// `selection` is always applied as a row *background* (paired with `.fg(text)`),
    /// so in every theme it must differ from both `text` (else the selected row's text
    /// is invisible) and `background` (else the selection bar itself is invisible).
    /// Regression guard for the high-contrast White-on-White selection bug.
    fn assert_selection_visible(name: &str, s: &ColorScheme) {
        assert_ne!(
            s.selection, s.text,
            "{name}: selection == text — selected rows would be invisible"
        );
        assert_ne!(
            s.selection, s.background,
            "{name}: selection == background — the selection bar would be invisible"
        );
    }

    #[test]
    fn selection_is_visible_in_every_theme() {
        assert_selection_visible("default", &ColorScheme::default());
        assert_selection_visible("dark", &ColorScheme::dark());
        assert_selection_visible("light", &ColorScheme::light());
        assert_selection_visible("high_contrast", &ColorScheme::high_contrast());
        assert_selection_visible("monochrome", &ColorScheme::monochrome());
    }
}

#[cfg(test)]
mod footer_budget_tests {
    use super::{FooterHints, fit_footer_hints, footer_hints_width};

    /// The global ?/q tail must survive any width squeeze; tab-specific
    /// hints drop from the end of their block first.
    #[test]
    fn fit_footer_hints_keeps_global_tail() {
        // Five tab hints ahead of the global tail (the shape every diff tab
        // footer now produces from its ViewState::shortcuts() primaries).
        let mut hints: Vec<(&str, &str)> = vec![
            ("f", "filter"),
            ("t", "transitive"),
            ("h", "highlight"),
            ("Enter", "expand"),
            ("c", "component"),
        ];
        hints.extend(FooterHints::global());
        let (kept, elided) = fit_footer_hints(&hints, 40);
        assert!(elided, "a 40-col budget must drop something");
        assert!(footer_hints_width(&kept) <= 40 || kept.len() == FooterHints::GLOBAL_COUNT);
        let tail: Vec<&str> = kept.iter().rev().take(2).map(|(k, _)| *k).collect();
        assert_eq!(tail, ["q", "?"], "the global tail must survive: {kept:?}");
    }

    /// Nothing is dropped when everything fits.
    #[test]
    fn fit_footer_hints_noop_when_fits() {
        let hints = FooterHints::global();
        let (kept, elided) = fit_footer_hints(&hints, 200);
        assert_eq!(kept.len(), hints.len());
        assert!(!elided);
    }
}
