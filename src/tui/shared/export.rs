//! Shared export dialog widget used by both diff and view TUIs.

use crate::tui::theme::colors;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

/// Format option row data.
struct FormatRow {
    key: &'static str,
    name: &'static str,
    desc: &'static str,
}

/// Data-oriented export formats.
const DATA_FORMATS: &[FormatRow] = &[
    FormatRow {
        key: "j",
        name: "JSON",
        desc: "Structured data for automation",
    },
    FormatRow {
        key: "s",
        name: "SARIF",
        desc: "CI/CD integration (GitHub, etc.)",
    },
    FormatRow {
        key: "c",
        name: "CSV",
        desc: "Spreadsheet import",
    },
];

/// Document-oriented export formats.
const DOC_FORMATS: &[FormatRow] = &[
    FormatRow {
        key: "m",
        name: "Markdown",
        desc: "Documentation & PRs",
    },
    FormatRow {
        key: "h",
        name: "HTML",
        desc: "Stakeholder report",
    },
];

/// Render the export format selection dialog.
///
/// `scope` describes what will be exported (e.g. "Components", "Vulnerabilities",
/// "Report"). It is shown in the title bar.
pub fn render_export_dialog(
    frame: &mut Frame,
    area: Rect,
    scope: &str,
    centered_rect_fn: fn(u16, u16, Rect) -> Rect,
) {
    let scheme = colors();
    // Content: 3 data + 2 doc + 2 section headers + 2 blank + output + cancel + 2 borders = 14
    let mut popup_area = centered_rect_fn(45, 30, area);
    // Percentage sizing clips the fixed 14-row content on small terminals
    // (30% of 24 rows is 7 — the doc formats, output path, and Esc hint all
    // vanished). Grow to the content's absolute minimum, capped by the
    // terminal, and re-center.
    let min_h = 14u16.min(area.height);
    let min_w = 46u16.min(area.width);
    if popup_area.height < min_h {
        popup_area.height = min_h;
        popup_area.y = area.y + (area.height.saturating_sub(min_h)) / 2;
    }
    if popup_area.width < min_w {
        popup_area.width = min_w;
        popup_area.x = area.x + (area.width.saturating_sub(min_w)) / 2;
    }
    frame.render_widget(Clear, popup_area);

    let section_style = Style::default().fg(scheme.text_muted);

    let mut lines = vec![];

    // Data formats section
    lines.push(Line::styled(" Data", section_style));
    for row in DATA_FORMATS {
        lines.push(format_row(row, &scheme));
    }

    // Document formats section
    lines.push(Line::from(""));
    lines.push(Line::styled(" Documents", section_style));
    for row in DOC_FORMATS {
        lines.push(format_row(row, &scheme));
    }

    // Output path preview. Files land in the current working directory —
    // "./<cwd-name>/…" read as a subdirectory that does not exist.
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(" Output: ", Style::default().fg(scheme.muted)),
        Span::styled(
            "./sbom_*.{ext} (current directory)",
            Style::default().fg(scheme.text_muted),
        ),
    ]));

    // Cancel hint with badge-style Esc key
    lines.push(Line::from(""));
    lines.push(
        Line::from(vec![
            Span::styled(
                " Esc ",
                Style::default()
                    .fg(scheme.badge_fg_dark)
                    .bg(scheme.muted)
                    .bold(),
            ),
            Span::styled(" Cancel", Style::default().fg(scheme.text_muted)),
        ])
        .alignment(Alignment::Center),
    );

    let title = format!(" Export {scope} ");
    let export = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .title_style(Style::default().fg(scheme.primary).bold())
                .borders(Borders::ALL)
                .border_style(Style::default().fg(scheme.primary)),
        )
        .alignment(Alignment::Left);

    frame.render_widget(export, popup_area);
}

/// Render a single format row with badge-style key.
fn format_row<'a>(row: &FormatRow, scheme: &crate::tui::theme::ColorScheme) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!(" {} ", row.key),
            Style::default()
                .fg(scheme.badge_fg_dark)
                .bg(scheme.accent)
                .bold(),
        ),
        Span::styled(
            format!(" {:<10}", row.name),
            Style::default().fg(scheme.text).bold(),
        ),
        Span::styled(row.desc.to_string(), Style::default().fg(scheme.text_muted)),
    ])
}
