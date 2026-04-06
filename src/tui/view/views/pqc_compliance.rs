//! PQC compliance view for the CBOM TUI mode.
//!
//! Dedicated CNSA 2.0 + NIST PQC compliance view showing
//! algorithm-by-algorithm assessment.

use crate::model::{ComponentType, CryptoAssetType};
use crate::quality::{ComplianceLevel, ViolationSeverity};
use crate::tui::view::app::ViewApp;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

/// Render the PQC compliance tab (CBOM mode).
pub fn render_pqc_compliance(frame: &mut Frame, area: Rect, app: &mut ViewApp) {
    // Ensure compliance results are cached before borrowing sbom
    app.ensure_compliance_results();

    let algorithms: Vec<_> = app
        .sbom
        .components
        .values()
        .filter(|c| {
            c.component_type == ComponentType::Cryptographic
                && c.crypto_properties
                    .as_ref()
                    .is_some_and(|cp| cp.asset_type == CryptoAssetType::Algorithm)
        })
        .collect();

    if algorithms.is_empty() {
        let msg = Paragraph::new(
            "No algorithms found.\n\nCBOM data with cryptoProperties is required for PQC compliance assessment.",
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" PQC Compliance "),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(msg, area);
        return;
    }
    let Some(results) = app.compliance_results.as_ref() else {
        return;
    };
    let cnsa2_fallback = crate::quality::ComplianceResult::new(ComplianceLevel::Cnsa2, vec![]);
    let pqc_fallback = crate::quality::ComplianceResult::new(ComplianceLevel::NistPqc, vec![]);
    let cnsa2_result = results
        .iter()
        .find(|r| r.level == ComplianceLevel::Cnsa2)
        .unwrap_or(&cnsa2_fallback);
    let pqc_result = results
        .iter()
        .find(|r| r.level == ComplianceLevel::NistPqc)
        .unwrap_or(&pqc_fallback);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    // ── Header: compliance summary ──
    let cnsa2_errors = cnsa2_result.violations.iter().filter(|v| v.severity == ViolationSeverity::Error).count();
    let pqc_errors = pqc_result.violations.iter().filter(|v| v.severity == ViolationSeverity::Error).count();

    let cnsa2_color = if cnsa2_errors == 0 { Color::Green } else { Color::Red };
    let pqc_color = if pqc_errors == 0 { Color::Green } else { Color::Red };

    let header_lines = vec![
        Line::from(vec![
            Span::raw(" CNSA 2.0: "),
            Span::styled(
                if cnsa2_errors == 0 { "COMPLIANT" } else { "NON-COMPLIANT" },
                Style::default().fg(cnsa2_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({cnsa2_errors} errors)")),
            Span::raw("   │   "),
            Span::raw("NIST PQC: "),
            Span::styled(
                if pqc_errors == 0 { "COMPLIANT" } else { "NON-COMPLIANT" },
                Style::default().fg(pqc_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({pqc_errors} errors)")),
        ]),
        Line::raw(""),
        Line::styled(
            " Algorithm-by-Algorithm Assessment",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];

    let header = Paragraph::new(header_lines)
        .block(Block::default().borders(Borders::ALL).title(" PQC Compliance "));
    frame.render_widget(header, chunks[0]);

    // ── Table: per-algorithm compliance status ──
    let header_row = Row::new(vec!["Algorithm", "Family", "Level", "CNSA 2.0", "NIST PQC"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(1);

    let rows: Vec<Row> = algorithms
        .iter()
        .map(|comp| {
            let algo = comp
                .crypto_properties
                .as_ref()
                .and_then(|cp| cp.algorithm_properties.as_ref());

            let family = algo
                .and_then(|a| a.algorithm_family.as_deref())
                .unwrap_or("-");
            let level = algo
                .and_then(|a| a.nist_quantum_security_level)
                .map_or("-".to_string(), |l| l.to_string());

            // Check CNSA 2.0 status for this algorithm
            let cnsa2_status = if cnsa2_result.violations.iter().any(|v| v.element.as_deref() == Some(&comp.name)) {
                Span::styled("FAIL", Style::default().fg(Color::Red))
            } else {
                Span::styled("PASS", Style::default().fg(Color::Green))
            };

            // Check NIST PQC status for this algorithm
            let pqc_status = if pqc_result.violations.iter().any(|v| {
                v.element.as_deref() == Some(&comp.name)
                    && v.severity == ViolationSeverity::Error
            }) {
                Span::styled("FAIL", Style::default().fg(Color::Red))
            } else if pqc_result.violations.iter().any(|v| {
                v.element.as_deref() == Some(&comp.name)
                    && v.severity == ViolationSeverity::Info
            }) {
                Span::styled("OK", Style::default().fg(Color::Green))
            } else {
                Span::styled("PASS", Style::default().fg(Color::Green))
            };

            Row::new(vec![
                ratatui::text::Text::from(comp.name.as_str()),
                ratatui::text::Text::from(family),
                ratatui::text::Text::from(level),
                ratatui::text::Text::from(Line::from(cnsa2_status)),
                ratatui::text::Text::from(Line::from(pqc_status)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(20),
            Constraint::Percentage(10),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
        ],
    )
    .header(header_row)
    .block(Block::default().borders(Borders::ALL));

    frame.render_widget(table, chunks[1]);
}
