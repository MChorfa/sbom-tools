//! Snapshot + key-event tests for the single-SBOM `ViewApp` TUI.
//!
//! Locks render output and event handling of the view-mode app before the
//! planned `App`/`ViewApp` unification. Render tests snapshot a [`TestBackend`]
//! buffer via `insta`; event tests drive the real key handler and assert on
//! `ViewApp` state.
//!
//! [`TestBackend`]: ratatui::backend::TestBackend

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{ViewApp, ViewTab, render};
use crate::tui::test_support::{
    AIBOM_BSI, DEMO_NEW, SIZES, aibom_single, demo_single, pin_theme, render_to_text,
};
use crate::tui::view::events::handle_key_event;

/// Build a `ViewApp` from the demo fixture with a deterministic tab.
///
/// `active_tab` is forced because the constructor restores the last-used tab
/// from on-disk `TuiPreferences`, which would make snapshots environment-dependent.
fn demo_view_app(active_tab: ViewTab) -> ViewApp {
    pin_theme();
    let (sbom, profile) = demo_single();
    let mut app = ViewApp::new(sbom, DEMO_NEW, profile);
    app.active_tab = active_tab;
    app
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Render one view tab at a given size and return the trimmed buffer text.
fn render_tab(active_tab: ViewTab, width: u16, height: u16) -> String {
    let mut app = demo_view_app(active_tab);
    render_to_text(width, height, |frame| {
        render(frame, &mut app);
    })
}

/// The SBOM-profile view tabs (the demo fixture is a plain SBOM).
const VIEW_TABS: [(&str, ViewTab); 8] = [
    ("overview", ViewTab::Overview),
    ("tree", ViewTab::Tree),
    ("vulnerabilities", ViewTab::Vulnerabilities),
    ("licenses", ViewTab::Licenses),
    ("dependencies", ViewTab::Dependencies),
    ("quality", ViewTab::Quality),
    ("compliance", ViewTab::Compliance),
    ("source", ViewTab::Source),
];

#[test]
fn snapshot_all_view_tabs() {
    // The Overview tab renders the document's relative age (e.g. "1 year ago")
    // next to its fixed creation timestamp. The age is derived from `Utc::now()`
    // and drifts over time (and is truncated at narrow widths), so anchor on the
    // ISO timestamp and redact everything after it on that line.
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\([^│\n]*",
        "$1 (AGE)",
    );
    // Lifecycle "Age: 728d" drifts daily; redact the day count.
    settings.add_filter(r"Age: \d+d", "Age: [N]d");
    settings.bind(|| {
        for (name, tab) in VIEW_TABS {
            for (w, h) in SIZES {
                let text = render_tab(tab, w, h);
                insta::assert_snapshot!(format!("view_{name}_{w}x{h}"), text);
            }
        }
    });
}

// ============================================================================
// Key-event behaviour tests (real assertions, not snapshots)
// ============================================================================

#[test]
fn tab_switch_cycles_within_profile() {
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, ViewTab::Tree);

    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, ViewTab::Vulnerabilities);

    handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
    assert_eq!(app.active_tab, ViewTab::Tree);
}

#[test]
fn numeric_keys_jump_to_view_tab() {
    let mut app = demo_view_app(ViewTab::Overview);
    // Position 3 in the SBOM profile is Vulnerabilities.
    handle_key_event(&mut app, key(KeyCode::Char('3')));
    assert_eq!(app.active_tab, ViewTab::Vulnerabilities);
    handle_key_event(&mut app, key(KeyCode::Char('1')));
    assert_eq!(app.active_tab, ViewTab::Overview);
}

#[test]
fn help_overlay_toggles() {
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.show_help);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(!app.show_help);
}

#[test]
fn tree_search_entry_activates_filter() {
    let mut app = demo_view_app(ViewTab::Tree);
    assert!(!app.tree_search_active);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    assert!(
        app.tree_search_active,
        "'/' on the Tree tab starts the inline tree filter"
    );
}

// ============================================================================
// AI-BOM (first-class profile) tests
// ============================================================================

/// Build a `ViewApp` from the BSI AI-BOM fixture with a deterministic tab.
fn aibom_view_app(active_tab: ViewTab) -> ViewApp {
    pin_theme();
    let (sbom, profile) = aibom_single();
    let mut app = ViewApp::new(sbom, AIBOM_BSI, profile);
    app.active_tab = active_tab;
    app
}

#[test]
fn aibom_fixture_detected_as_aibom_profile() {
    let (_sbom, profile) = aibom_single();
    assert_eq!(profile, crate::model::BomProfile::AiBom);
}

#[test]
fn aibom_view_app_uses_ai_readiness_scoring() {
    // The single shared `scoring_profile_for` must route AI-BOMs to the
    // dedicated AI-readiness scoring path (which activates the AI renderer).
    let app = aibom_view_app(ViewTab::AiReadiness);
    assert_eq!(
        app.quality_report.profile,
        crate::quality::ScoringProfile::AiReadiness
    );
}

#[test]
fn aibom_profile_exposes_ai_tab_suite() {
    let tabs = ViewTab::tabs_for_profile(crate::model::BomProfile::AiBom);
    assert!(tabs.contains(&ViewTab::Models));
    assert!(tabs.contains(&ViewTab::Datasets));
    assert!(tabs.contains(&ViewTab::AiReadiness));
}

/// The AI-BOM-profile view tabs (rendered from the BSI AI-BOM fixture).
const AIBOM_TABS: [(&str, ViewTab); 3] = [
    ("models", ViewTab::Models),
    ("datasets", ViewTab::Datasets),
    ("ai_readiness", ViewTab::AiReadiness),
];

#[test]
fn snapshot_aibom_tabs() {
    let mut settings = insta::Settings::clone_current();
    // Lifecycle/age content can drift; redact day counts defensively.
    settings.add_filter(r"Age: \d+d", "Age: [N]d");
    settings.bind(|| {
        for (name, tab) in AIBOM_TABS {
            let mut app = aibom_view_app(tab);
            // Render at the wide size where AI panels have room to breathe.
            let text = render_to_text(120, 40, |frame| {
                render(frame, &mut app);
            });
            insta::assert_snapshot!(format!("aibom_{name}_120x40"), text);
        }
    });
}

// ============================================================================
// View-mode vuln explorer parity (EPSS + KEV filter) and compliance selector
// ============================================================================

use crate::model::{
    CanonicalId, Component, NormalizedSbom, Severity, VulnerabilityRef, VulnerabilitySource,
};

/// Build a `ViewApp` whose single component carries a KEV vuln with a high
/// EPSS score, parked on the Vulnerabilities tab.
fn epss_kev_view_app() -> ViewApp {
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    let mut comp = Component::new("openssl".to_string(), "openssl-ref".to_string())
        .with_version("3.0.0".to_string());
    let mut vuln = VulnerabilityRef::new("CVE-2024-9999".to_string(), VulnerabilitySource::Nvd);
    vuln.severity = Some(Severity::Critical);
    vuln.is_kev = true;
    vuln.epss_score = Some(0.84);
    comp.vulnerabilities.push(vuln);
    sbom.components
        .insert(CanonicalId::from_name_version("openssl", None), comp);

    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = ViewTab::Vulnerabilities;
    app
}

#[test]
fn vuln_explorer_renders_epss_badge() {
    let mut app = epss_kev_view_app();
    let text = render_to_text(120, 40, |frame| {
        render(frame, &mut app);
    });
    // EPSS 84% appears in the detail panel / row badge.
    assert!(
        text.contains("EPSS 84%"),
        "EPSS badge should render in the view-mode vuln explorer:\n{text}"
    );
}

#[test]
fn kev_filter_key_toggles_and_renders_state() {
    let mut app = epss_kev_view_app();
    assert!(!app.vuln_state.filter_kev);
    // 'k' on the Vulnerabilities tab toggles the KEV-only filter.
    handle_key_event(&mut app, key(KeyCode::Char('k')));
    assert!(app.vuln_state.filter_kev, "'k' enables the KEV-only filter");

    let text = render_to_text(120, 40, |frame| {
        render(frame, &mut app);
    });
    // The KEV row survives the filter and the filter bar advertises the toggle.
    assert!(text.contains("CVE-2024-9999"), "KEV vuln survives filter");
    assert!(text.contains("KEV:"), "filter bar shows KEV state");
    assert!(
        text.contains("[k]"),
        "footer hint advertises the [k] toggle"
    );

    handle_key_event(&mut app, key(KeyCode::Char('k')));
    assert!(
        !app.vuln_state.filter_kev,
        "'k' toggles the filter back off"
    );
}

#[test]
fn compliance_selector_exposes_every_standard() {
    use crate::quality::ComplianceLevel;

    // Every standard — including the high-index EU AI Act + BSI SBOM-for-AI
    // tabs that previously overflowed off-screen — must be reachable: the
    // selector scrolls a window so the selected standard is always rendered.
    let levels = ComplianceLevel::all();
    for (idx, level) in levels.iter().enumerate() {
        let mut app = aibom_view_app(ViewTab::Compliance);
        app.ensure_compliance_results();
        app.compliance_state.selected_standard = idx;
        let text = render_to_text(120, 40, |frame| {
            render(frame, &mut app);
        });
        let label = level.short_name();
        assert!(
            text.contains(label),
            "compliance standard `{label}` (index {idx}) must scroll into view:\n{text}"
        );
    }

    // Spot-check the two previously-hidden AI standards by name.
    assert!(levels.iter().any(|l| l.short_name() == "AI-Act"));
    assert!(levels.iter().any(|l| l.short_name() == "BSI-AI"));
}

#[test]
fn crypto_list_scrolls_the_selection_into_view() {
    let (sbom, profile) = crate::tui::test_support::cbom_single();
    let mut app = ViewApp::new(sbom, crate::tui::test_support::CBOM, profile);
    // The Crypto tab lists every cryptographic asset (16 here), which overflows the
    // list panel at the minimum 80x24 terminal size.
    app.active_tab = ViewTab::Crypto;

    app.crypto_list_selected = 0;
    let top = render_to_text(80, 24, |frame| render(frame, &mut app));
    app.crypto_list_selected = usize::MAX; // clamps to the last asset
    let scrolled = render_to_text(80, 24, |frame| render(frame, &mut app));

    // render_to_text strips styling, so any difference must come from the list
    // window scrolling to reveal the selected (last) row — which the previous
    // stateless render_widget never did (it always showed the top of the list).
    assert_ne!(
        top, scrolled,
        "selecting the last algorithm in a short panel must scroll it into view"
    );
}

#[test]
fn pqc_selection_scrolls_into_view() {
    let (sbom, profile) = crate::tui::test_support::cbom_single();
    let mut app = ViewApp::new(sbom, crate::tui::test_support::CBOM, profile);
    app.active_tab = ViewTab::PqcCompliance;

    app.pqc_selected = 0;
    let top = render_to_text(80, 24, |frame| render(frame, &mut app));
    app.go_last();
    assert!(app.pqc_selected > 0, "fixture must have several algorithms");
    let scrolled = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert_ne!(
        top, scrolled,
        "selecting the last algorithm must scroll it into view / update the detail pane"
    );
}

#[test]
fn ai_readiness_scroll_reveals_rows_below_fold() {
    let (sbom, profile) = crate::tui::test_support::aibom_single();
    let mut app = ViewApp::new(sbom, AIBOM_BSI, profile);
    app.active_tab = ViewTab::AiReadiness;

    app.ai_readiness_scroll = 0;
    let top = render_to_text(80, 24, |frame| render(frame, &mut app));
    app.go_last();
    assert!(
        app.ai_readiness_scroll > 0,
        "fixture must overflow the fold"
    );
    let scrolled = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert_ne!(
        top, scrolled,
        "scrolling must reveal checks/recommendations below the fold"
    );
}

#[test]
fn view_list_click_selects_the_item_under_the_cursor() {
    use crate::tui::view::events::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    // (tab, a distinctive item in the LEFT list, its selected index by the demo
    // fixture's rendered order — see the view_{tree,licenses,dependencies} snapshots).
    let cases = [
        (ViewTab::Tree, "axios@1.4.0", 1usize), // "npm (8)" group is flat index 0
        (ViewTab::Licenses, "Apache-2.0", 1usize), // MIT(0), Apache-2.0(1), Unknown(2)
        (ViewTab::Dependencies, "axios@1.4.0", 1usize), // acme-webapp(0), axios(1)
    ];
    for (tab, needle, expected) in cases {
        let mut app = demo_view_app(tab);
        // Render first so the list totals are populated, then find the item's real
        // row from the buffer and click it — a wrong body_start would select a
        // different (or no) item and fail the assertion.
        let text = render_to_text(80, 24, |frame| {
            render(frame, &mut app);
        });
        let row = text
            .lines()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not rendered on {tab:?}")) as u16;
        handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row,
                modifiers: KeyModifiers::empty(),
            },
        );
        let selected = match tab {
            ViewTab::Tree => app.tree_state.selected,
            ViewTab::Licenses => app.license_state.selected,
            ViewTab::Dependencies => app.dependency_state.selected,
            _ => unreachable!(),
        };
        assert_eq!(selected, expected, "click {needle:?} on {tab:?} @row {row}");
    }
}

#[test]
fn aibom_tab_click_selects_a_profile_specific_tab() {
    use crate::tui::view::events::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use unicode_width::UnicodeWidthStr;

    let tabs = ViewTab::tabs_for_profile(crate::model::BomProfile::AiBom);
    let target = *tabs.last().expect("AI-BOM has tabs"); // rightmost: most drift-sensitive
    let first = tabs[0];
    let mut app = aibom_view_app(first);

    let text = render_to_text(240, 40, |frame| {
        render(frame, &mut app);
    });
    let tab_row = text.lines().nth(2).expect("tab bar row").to_string();
    let needle = target.title();
    let byte = tab_row
        .rfind(needle)
        .unwrap_or_else(|| panic!("{needle} not in tab row: {tab_row:?}"));
    let col = UnicodeWidthStr::width(&tab_row[..byte]) as u16;

    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: col,
            row: 2,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(app.active_tab, target, "click on {needle} @col {col}");
}

/// Regression: a GPL-licensed component must count into the copyleft (⚠)
/// bucket of the Licenses risk summary, not "unknown" (the old string match
/// compared against "Strong Copyleft", which the category never stringifies
/// to, so GPL exposure was reported as unknown).
#[test]
fn gpl_risk_summary_renders_as_copyleft() {
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    let mut comp = Component::new("readline".to_string(), "readline-ref".to_string())
        .with_version("8.2".to_string());
    comp.licenses
        .add_declared(crate::model::LicenseExpression::new(
            "GPL-3.0-only".to_string(),
        ));
    sbom.components
        .insert(CanonicalId::from_name_version("readline", None), comp);

    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = ViewTab::Licenses;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("\u{26a0} 1"),
        "GPL must count as copyleft in the risk summary:\n{text}"
    );
    assert!(
        text.contains("? 0"),
        "GPL must not fall into the unknown bucket:\n{text}"
    );
}

/// Esc must never quit the viewer: it backs out one level (right panel ->
/// left, breadcrumb -> back) and otherwise no-ops; only 'q' quits.
#[test]
fn esc_never_quits_view_app() {
    let mut app = demo_view_app(ViewTab::Tree);

    handle_key_event(&mut app, key(KeyCode::Esc));
    assert!(!app.should_quit, "Esc at top level must not quit");

    // Backing out of the right detail panel.
    app.focus_panel = crate::tui::view::app::FocusPanel::Right;
    handle_key_event(&mut app, key(KeyCode::Esc));
    assert!(!app.should_quit);
    assert_eq!(
        app.focus_panel,
        crate::tui::view::app::FocusPanel::Left,
        "Esc backs out of the right panel"
    );

    handle_key_event(&mut app, key(KeyCode::Char('q')));
    assert!(app.should_quit, "'q' still quits");
}

/// A filter with zero matches must render an explanatory empty state, not a
/// silent blank panel. Bookmarked is deterministically empty (the bookmark
/// set starts empty); Critical would NOT be — the demo fixture carries a
/// critical vuln on axios@1.4.0.
#[test]
fn view_tree_filter_empty_state() {
    let mut app = demo_view_app(ViewTab::Tree);
    app.tree_filter = crate::tui::view::app::TreeFilter::Bookmarked;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("No components match filter 'Bookmarked'"),
        "empty tree must explain the active filter:\n{text}"
    );
    assert!(
        text.contains("[f] to change filter"),
        "empty state must offer the recovery hint:\n{text}"
    );
    insta::assert_snapshot!("view_tree_filter_bookmarked_empty_80x24", text);
}

/// Regression: the vuln filter bar previously rendered as one ~185-column
/// line, clipping every hint from "[d] dedupe" onward at 80 cols while its
/// reserved second row sat blank. The hint row must now be fully visible.
#[test]
fn filter_bar_hints_all_visible_at_80_cols() {
    let mut app = epss_kev_view_app();
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("[Tab] next group"),
        "the tail of the hint row must render at 80 cols:\n{text}"
    );
    assert!(
        text.contains("[E/C]"),
        "the expand/collapse hint must render at 80 cols:\n{text}"
    );
}

/// Regression: at the 80x24 minimum the Overview's Vulnerability Severity
/// panel rendered as an empty titled box (the stacked bordered layout needed
/// more height than exists). The compact path must keep the bars visible.
#[test]
fn overview_severity_bars_visible_at_min_size() {
    let mut app = demo_view_app(ViewTab::Overview);
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("Critical"),
        "severity bars must render at 80x24:\n{text}"
    );
    assert!(
        text.contains("Vulnerability Severity"),
        "severity section header must render at 80x24:\n{text}"
    );
}

/// Lock the EOL-enriched compact Overview path (previously untested: the
/// 5-panel stacked layout never fit 80x24 at all).
#[test]
fn view_overview_eol_compact_snapshot() {
    let mut app = demo_view_app(ViewTab::Overview);
    app.stats.eol_enriched = true;
    app.stats.eol_count = 2;
    app.stats.eol_approaching_count = 1;
    app.stats.eol_security_only_count = 1;
    app.stats.eol_supported_count = 8;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("End-of-Life"),
        "EOL section must render in compact mode:\n{text}"
    );
    // Redact the wall-clock-relative document age (same filters as
    // snapshot_all_view_tabs) so the snapshot doesn't rot with time.
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\([^│\n]*",
        "$1 (AGE)",
    );
    settings.bind(|| {
        insta::assert_snapshot!("view_overview_eol_80x24", text);
    });
}

/// Build a `ViewApp` on the CBOM fixture with a deterministic tab.
fn cbom_view_app(active_tab: ViewTab) -> ViewApp {
    pin_theme();
    let (sbom, profile) = crate::tui::test_support::cbom_single();
    let mut app = ViewApp::new(sbom, crate::tui::test_support::CBOM, profile);
    app.active_tab = active_tab;
    app
}

/// Baseline snapshots for all six CBOM tabs at both sizes. The theme-routing
/// PR that introduces these is glyph-neutral (render_to_text strips styles),
/// so they lock a clean baseline for the following data-surfacing PRs.
#[test]
fn snapshot_cbom_tabs() {
    let tabs = [
        ("crypto", ViewTab::Crypto),
        ("algorithms", ViewTab::Algorithms),
        ("certificates", ViewTab::Certificates),
        ("keys", ViewTab::Keys),
        ("protocols", ViewTab::Protocols),
        ("pqc_compliance", ViewTab::PqcCompliance),
    ];
    for (name, tab) in tabs {
        for (w, h) in SIZES {
            let mut app = cbom_view_app(tab);
            let text = render_to_text(w, h, |frame| {
                render(frame, &mut app);
            });
            insta::assert_snapshot!(format!("cbom_{name}_{w}x{h}"), text);
        }
    }
}

/// Regression: selected CBOM list rows must take their background from the
/// theme's selection slot (the hardcoded DarkGray defeated the high-contrast
/// selection fix and lost contrast under the light theme).
#[test]
fn cbom_selected_row_uses_theme_selection_bg() {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let mut app = cbom_view_app(ViewTab::Crypto);
    app.crypto_list_selected = 0;

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| render(frame, &mut app))
        .expect("render");

    let buffer = terminal.backend().buffer();
    let expected = crate::tui::theme::colors().selection;
    let found = (0..24u16).any(|y| {
        (0..80u16).any(|x| {
            buffer
                .cell((x, y))
                .is_some_and(|c| c.style().bg == Some(expected))
        })
    });
    assert!(
        found,
        "some cell must carry the theme selection background {expected:?}"
    );
    let darkgray = (0..24u16).any(|y| {
        (0..80u16).any(|x| {
            buffer
                .cell((x, y))
                .is_some_and(|c| c.style().bg == Some(ratatui::style::Color::DarkGray))
        })
    });
    assert!(
        !darkgray,
        "no cell may use the hardcoded DarkGray selection background"
    );
}

/// Two-severity fixture: full-card path with the triage row underneath.
fn triage_view_app(active_tab: ViewTab) -> ViewApp {
    pin_theme();
    let mut sbom = NormalizedSbom::default();

    let mut kev_comp = Component::new("kev-lib".to_string(), "kev-ref".to_string())
        .with_version("1.0.0".to_string());
    let mut kev_vuln = VulnerabilityRef::new("CVE-2024-0001".to_string(), VulnerabilitySource::Nvd);
    kev_vuln.severity = Some(Severity::Critical);
    kev_vuln.is_kev = true;
    kev_vuln.epss_score = Some(0.73);
    kev_comp.vulnerabilities.push(kev_vuln);
    sbom.components
        .insert(CanonicalId::from_name_version("kev-lib", None), kev_comp);

    let mut fix_comp = Component::new("fix-lib".to_string(), "fix-ref".to_string())
        .with_version("2.0.0".to_string());
    let mut fix_vuln = VulnerabilityRef::new("CVE-2024-0002".to_string(), VulnerabilitySource::Nvd);
    fix_vuln.severity = Some(Severity::High);
    fix_vuln.remediation = Some(crate::model::Remediation {
        remediation_type: crate::model::RemediationType::Upgrade,
        description: None,
        fixed_version: Some("2.1.0".to_string()),
    });
    fix_comp.vulnerabilities.push(fix_vuln);
    sbom.components
        .insert(CanonicalId::from_name_version("fix-lib", None), fix_comp);

    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = active_tab;
    app
}

/// The triage row must render under the full severity cards, answering
/// exploited/fixable/likely-exploited without touching a filter.
#[test]
fn view_vuln_triage_snapshots() {
    for (w, h) in SIZES {
        let mut app = triage_view_app(ViewTab::Vulnerabilities);
        let text = render_to_text(w, h, |frame| {
            render(frame, &mut app);
        });
        assert!(
            text.contains("KEV 1") && text.contains("Fixable 1"),
            "triage row must render at {w}x{h}:\n{text}"
        );
        insta::assert_snapshot!(format!("view_vuln_triage_{w}x{h}"), text);
    }
}

/// Regression for the broadened compact trigger: an all-Critical SBOM must
/// take the compact path instead of rows of empty '0' cards.
#[test]
fn all_critical_sbom_uses_compact_stats() {
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    for i in 0..2 {
        let name = format!("crit-{i}");
        let mut comp =
            Component::new(name.clone(), format!("{name}-ref")).with_version("1.0.0".to_string());
        let mut v = VulnerabilityRef::new(format!("CVE-2024-1{i:03}"), VulnerabilitySource::Nvd);
        v.severity = Some(Severity::Critical);
        comp.vulnerabilities.push(v);
        sbom.components
            .insert(CanonicalId::from_name_version(&name, None), comp);
    }
    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = ViewTab::Vulnerabilities;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        !text.contains(" MEDIUM "),
        "compact path must not render the empty MEDIUM card:\n{text}"
    );
    assert!(
        text.contains("vulnerabilities"),
        "compact summary must render:\n{text}"
    );
}

/// Lock the legend overlay vocabulary (severity letters, license glyphs) to
/// the shared helpers: the legend and the list rows must not drift apart.
/// 80x30 because the popup is 60% of frame height: at 80x24 the last legend
/// rows (including the Proprietary glyph) are clipped and would go unlocked.
#[test]
fn view_legend_overlay_80x30() {
    let mut app = demo_view_app(ViewTab::Licenses);
    app.toggle_legend();
    let text = render_to_text(80, 30, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("\u{2298}"),
        "the full license vocabulary (incl. \u{2298} Proprietary) must be visible:\n{text}"
    );
    insta::assert_snapshot!("view_legend_overlay_80x30", text);
}

/// Compact stats (single-severity SBOM) must show the full triage line —
/// KEV, Fixable, and EPSS — as a full-width row even at 80 cols; embedded in
/// the 35%-wide summary card the EPSS segment was clipped.
#[test]
fn view_vuln_compact_80x24_shows_full_triage_line() {
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    // Distinct vuln counts (3/2/1) keep the top-components bar order
    // deterministic: ties preserve the SBOM map's arbitrary iteration order.
    for i in 0..3 {
        let name = format!("crit-{i}");
        let mut comp =
            Component::new(name.clone(), format!("{name}-ref")).with_version("1.0.0".to_string());
        for j in 0..(3 - i) {
            let mut v =
                VulnerabilityRef::new(format!("CVE-2024-2{i}{j:02}"), VulnerabilitySource::Nvd);
            v.severity = Some(Severity::Critical);
            // Distinct CVSS scores: the table sorts severity -> cvss, and a
            // full tie would surface the dedupe HashMap's random order.
            v.cvss.push(crate::model::CvssScore {
                version: crate::model::CvssVersion::V31,
                base_score: 9.8 - (i as f32).mul_add(0.3, j as f32 * 0.1),
                vector: None,
                exploitability_score: None,
                impact_score: None,
            });
            if i == 0 && j == 0 {
                v.is_kev = true;
                v.epss_score = Some(0.42);
            }
            if i == 1 && j == 0 {
                v.remediation = Some(crate::model::Remediation {
                    remediation_type: crate::model::RemediationType::Upgrade,
                    description: None,
                    fixed_version: Some("1.1.0".to_string()),
                });
            }
            comp.vulnerabilities.push(v);
        }
        sbom.components
            .insert(CanonicalId::from_name_version(&name, None), comp);
    }
    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = ViewTab::Vulnerabilities;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("EPSS\u{2265}10% 1"),
        "the EPSS triage count must survive 80 cols:\n{text}"
    );
    insta::assert_snapshot!("view_vuln_compact_80x24", text);
}

/// Regression: at 80 cols the single-line crypto header clipped its most
/// severe token (Compromised) and never rendered QVuln/WeakKeys/Expiring at
/// all. The two-line danger-first header must surface every non-zero danger
/// metric at the minimum supported width.
#[test]
fn crypto_header_surfaces_danger_counts_at_80_cols() {
    use crate::model::{
        AlgorithmProperties, CertificateProperties, CryptoAssetType, CryptoMaterialState,
        CryptoMaterialType, CryptoPrimitive, CryptoProperties, RelatedCryptoMaterialProperties,
    };
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    let mut add = |name: &str, cp: CryptoProperties| {
        let mut c = Component::new(name.to_string(), format!("{name}-ref"));
        c.component_type = crate::model::ComponentType::Cryptographic;
        c.crypto_properties = Some(cp);
        sbom.components
            .insert(CanonicalId::from_name_version(name, None), c);
    };
    add(
        "MD5",
        CryptoProperties::new(CryptoAssetType::Algorithm)
            .with_algorithm_properties(AlgorithmProperties::new(CryptoPrimitive::Hash)),
    );
    add(
        "RSA-2048",
        CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
            AlgorithmProperties::new(CryptoPrimitive::Pke).with_nist_quantum_security_level(0),
        ),
    );
    add(
        "expired-cert",
        CryptoProperties::new(CryptoAssetType::Certificate).with_certificate_properties(
            CertificateProperties::new()
                .with_not_valid_after(chrono::Utc::now() - chrono::Duration::days(30)),
        ),
    );
    add(
        "expiring-cert",
        CryptoProperties::new(CryptoAssetType::Certificate).with_certificate_properties(
            CertificateProperties::new()
                .with_not_valid_after(chrono::Utc::now() + chrono::Duration::days(30)),
        ),
    );
    add(
        "compromised-key",
        CryptoProperties::new(CryptoAssetType::RelatedCryptoMaterial)
            .with_related_crypto_material_properties(
                RelatedCryptoMaterialProperties::new(CryptoMaterialType::PrivateKey)
                    .with_state(CryptoMaterialState::Compromised),
            ),
    );
    add(
        "small-key",
        CryptoProperties::new(CryptoAssetType::RelatedCryptoMaterial)
            .with_related_crypto_material_properties(
                RelatedCryptoMaterialProperties::new(CryptoMaterialType::PrivateKey)
                    .with_size(1024),
            ),
    );

    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Cbom);
    app.active_tab = ViewTab::Crypto;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    for token in [
        "Compromised:1",
        "Weak:1",
        "QVuln:1",
        "Expired:1",
        "WeakKeys:1",
        "Expiring:1",
    ] {
        assert!(
            text.contains(token),
            "danger header must surface {token}:\n{text}"
        );
    }
}
