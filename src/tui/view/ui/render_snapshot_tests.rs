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
fn compliance_overview_marks_na_standards_muted_not_green() {
    use crate::quality::{
        ComplianceLevel, ComplianceResult, Violation, ViolationCategory, ViolationSeverity,
    };

    // Readiness N/A results keep `is_compliant = true` and warning_count = 0
    // by contract — indistinguishable from a clean pass unless the renderer
    // checks `is_applicable()` first. The cross-standard overview must show
    // them as muted "not applicable", matching the tab strip one panel up.
    fn na_marker(level: ComplianceLevel, rule_id: &'static str) -> ComplianceResult {
        ComplianceResult::new(
            level,
            vec![Violation {
                severity: ViolationSeverity::Info,
                category: ViolationCategory::DocumentMetadata,
                message: "SBOM contains no AI components".to_string(),
                element: None,
                requirement: "Applicability".to_string(),
                rule_id,
                component_id: None,
                counts: None,
                standard_refs: Vec::new(),
            }],
        )
    }

    let mut app = demo_view_app(ViewTab::Compliance);
    // Synthetic per-standard results: everything clean except the two AI
    // readiness profiles, which are N/A. Selecting a clean standard (index 0)
    // makes the violations pane render the Cross-Standard Overview.
    let results: Vec<ComplianceResult> = ComplianceLevel::all()
        .iter()
        .map(|level| match level {
            ComplianceLevel::EuAiAct => na_marker(*level, "SBOM-AIACT-NA"),
            ComplianceLevel::BsiSbomForAi => na_marker(*level, "SBOM-BSIAI-NA"),
            _ => ComplianceResult::new(*level, Vec::new()),
        })
        .collect();
    let ai_idx = ComplianceLevel::all()
        .iter()
        .position(|l| *l == ComplianceLevel::EuAiAct)
        .expect("EU AI Act must be in ComplianceLevel::all()");
    assert!(!results[ai_idx].is_applicable(), "fixture must be N/A");
    app.compliance_results = Some(results);
    app.compliance_state.selected_standard = 0;

    // Tall enough that the overview lists all 16 standards (the panel clips
    // at short heights and the AI profiles sit at the end of the list).
    let text = render_to_text(120, 60, |frame| {
        render(frame, &mut app);
    });

    let ai_line = text
        .lines()
        .find(|l| l.contains("EU AI Act Annex IV Readiness"))
        .unwrap_or_else(|| panic!("overview must list the AI Act standard:\n{text}"))
        .to_string();
    assert!(
        ai_line.contains("\u{2014}") && ai_line.contains("not applicable"),
        "N/A standard must render muted em-dash + 'not applicable': {ai_line}"
    );
    assert!(
        !ai_line.contains('\u{2713}')
            && !ai_line.contains("passed")
            && !ai_line.contains("warnings"),
        "N/A standard must not render as a pass in the overview: {ai_line}"
    );
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

/// Regression: the component-detail scroll was an unbounded saturating_add —
/// over-scrolling emptied the panel. The render-side clamp must write back.
#[test]
fn component_detail_scroll_clamps_to_content() {
    let mut app = demo_view_app(ViewTab::Tree);
    // First render builds the tree cache the key handler navigates over.
    render_to_text(80, 24, |frame| render(frame, &mut app));
    handle_key_event(&mut app, key(KeyCode::Down));
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert!(
        app.get_selected_component().is_some(),
        "Down+Enter must select the first leaf component"
    );
    app.component_detail_scroll = 999;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        app.component_detail_scroll < 999,
        "render must clamp the over-scrolled offset, got {}",
        app.component_detail_scroll
    );
    assert!(
        text.contains("fields"),
        "clamped panel must still show content (the completeness line):
{text}"
    );
}

/// Regression: the Overview tab buried vulns/EOL/staleness below PURL/hash
/// plumbing; risk must render first and the hash lives on the [2] tab only.
#[test]
fn overview_tab_orders_risk_before_identifiers() {
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    let mut comp = Component::new("kev-lib".to_string(), "kev-ref".to_string())
        .with_version("1.0.0".to_string());
    let mut v = VulnerabilityRef::new("CVE-2024-0001".to_string(), VulnerabilitySource::Nvd);
    v.severity = Some(Severity::Critical);
    comp.vulnerabilities.push(v);
    comp.eol = Some(crate::model::EolInfo {
        status: crate::model::EolStatus::EndOfLife,
        product: "kev-lib".to_string(),
        cycle: "1.0".to_string(),
        eol_date: None,
        support_end_date: None,
        is_lts: false,
        latest_in_cycle: None,
        latest_release_date: None,
        days_until_eol: Some(-30),
    });
    comp.staleness = Some(crate::model::StalenessInfo {
        level: crate::model::StalenessLevel::Stale,
        last_published: None,
        is_deprecated: false,
        is_archived: false,
        deprecation_message: None,
        days_since_update: Some(700),
        latest_version: None,
    });
    comp.identifiers.purl = Some("pkg:npm/kev-lib@1.0.0".to_string());
    comp.hashes.push(crate::model::Hash::new(
        crate::model::HashAlgorithm::Sha256,
        "abc123".to_string(),
    ));
    let id = CanonicalId::from_name_version("kev-lib", None);
    sbom.components.insert(id.clone(), comp);

    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = ViewTab::Tree;
    app.selected_component = Some(id.value().to_string());
    app.focus_panel = crate::tui::view::app::FocusPanel::Right;
    // 120x40: the EOL block is tall enough that PURL would fall below the
    // fold at 80x24, making the ordering assertions vacuous.
    let text = render_to_text(120, 40, |frame| {
        render(frame, &mut app);
    });
    // Risk-summary badges under the name: vulns + EOL + staleness.
    assert!(text.contains("1 vulns"), "vuln badge must render:\n{text}");
    assert!(
        text.contains(crate::model::EolStatus::EndOfLife.label()),
        "EOL badge must render:\n{text}"
    );
    assert!(
        text.contains(crate::model::StalenessLevel::Stale.label()),
        "staleness badge must render:\n{text}"
    );
    assert!(
        !text.contains("no known risk signals"),
        "all-clear line must not render alongside risk badges:\n{text}"
    );
    let vulns_at = text.find("Vulns:").expect("Vulns section must render");
    let eol_at = text.find("End-of-Life:").expect("EOL section must render");
    let purl_at = text.find("PURL:").expect("PURL must render");
    assert!(
        vulns_at < purl_at && eol_at < purl_at,
        "risk sections must precede identifier plumbing:\n{text}"
    );
    assert!(
        !text.contains("Hash:"),
        "the hash belongs to the Identifiers tab, not Overview:\n{text}"
    );
}

/// Lock the risk-first component detail panel (badge line, reordered
/// sections, scrollbar) at the minimum supported size.
#[test]
fn view_tree_component_detail_80x24() {
    let mut app = demo_view_app(ViewTab::Tree);
    render_to_text(80, 24, |frame| render(frame, &mut app));
    handle_key_event(&mut app, key(KeyCode::Down));
    handle_key_event(&mut app, key(KeyCode::Enter));
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    insta::assert_snapshot!("view_tree_component_detail_80x24", text);
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
    // The certificate detail's "Remaining: N days" is wall-clock relative
    // (fixture expiry minus today) and would decay the baseline daily.
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(r"Remaining:  \d+ days *", "Remaining:  [N] days   ");
    let _guard = settings.bind_to_scope();

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

/// The single-SBOM License tab previously threw away the engine's pairwise
/// SPDX conflicts; the list header must count them and the detail panel must
/// name the clashing pair.
#[test]
fn license_tab_surfaces_compat_conflicts() {
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    for (name, lic) in [("gpl-lib", "GPL-2.0-only"), ("apache-lib", "Apache-2.0")] {
        let mut comp =
            Component::new(name.to_string(), format!("{name}-ref")).with_version("1.0".to_string());
        comp.licenses
            .add_declared(crate::model::LicenseExpression::new(lic.to_string()));
        sbom.components
            .insert(CanonicalId::from_name_version(name, None), comp);
    }
    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Sbom);
    app.active_tab = ViewTab::Licenses;
    let text = render_to_text(120, 40, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("conflicts"),
        "list header must count conflicts:\n{text}"
    );
    assert!(
        text.contains("Compatibility"),
        "detail panel must render the Compatibility section:\n{text}"
    );
    insta::assert_snapshot!("view_licenses_conflicts_120x40", text);
}

/// All eight CBOM/AI tabs must render the enhanced empty state (icon +
/// centered reason) instead of an unstyled paragraph.
#[test]
fn empty_cbom_and_ai_tabs_use_enhanced_empty_state() {
    pin_theme();
    for (tab, reason) in [
        (ViewTab::Crypto, "CycloneDX 1.6+"),
        (ViewTab::Algorithms, "CycloneDX 1.6+"),
        (ViewTab::Certificates, "CycloneDX 1.6+"),
        (ViewTab::Keys, "CycloneDX 1.6+"),
        (ViewTab::Protocols, "CycloneDX 1.6+"),
        (ViewTab::PqcCompliance, "cryptoProperties"),
        (ViewTab::Models, "machine-learning-model"),
        (ViewTab::Datasets, "data components"),
    ] {
        let profile = if matches!(tab, ViewTab::Models | ViewTab::Datasets) {
            crate::model::BomProfile::AiBom
        } else {
            crate::model::BomProfile::Cbom
        };
        let mut app = ViewApp::new(NormalizedSbom::default(), "", profile);
        app.active_tab = tab;
        let text = render_to_text(80, 24, |frame| {
            render(frame, &mut app);
        });
        assert!(
            text.contains(reason),
            "{tab:?} empty state must explain what data is required:\n{text}"
        );
    }
}

/// Lock one representative enhanced empty state.
#[test]
fn snapshot_cbom_empty_algorithms() {
    pin_theme();
    let mut app = ViewApp::new(
        NormalizedSbom::default(),
        "",
        crate::model::BomProfile::Cbom,
    );
    app.active_tab = ViewTab::Algorithms;
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    insta::assert_snapshot!("cbom_empty_algorithms_80x24", text);
}

/// Regression: regex search was unavailable in view mode. Ctrl+R toggles the
/// mode, the badge + hint render, and invalid patterns surface an error.
#[test]
fn view_global_search_ctrl_r_toggles_regex() {
    pin_theme();
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    handle_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
    );
    assert_eq!(
        app.search_state.mode,
        crate::tui::app_states::SearchMode::Regex
    );
    for c in "ax.*s".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert!(
        app.search_state
            .results
            .iter()
            .any(|r| matches!(r, crate::tui::view::app::SearchResult::Component { name, .. } if name == "axios")),
        "regex 'ax.*s' must match axios: {:?}",
        app.search_state.results.len()
    );

    // Invalid pattern sets the error and empties results.
    for _ in 0..5 {
        handle_key_event(&mut app, key(KeyCode::Backspace));
    }
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    handle_key_event(&mut app, key(KeyCode::Char('(')));
    assert!(app.search_state.search_error.is_some(), "error must be set");
    assert!(app.search_state.results.is_empty());

    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        text.contains("[regex]") && text.contains("invalid pattern"),
        "badge + error must render:\n{text}"
    );
    insta::assert_snapshot!("view_search_overlay_error_80x24", text);
}

/// The view-mode '?' help overlay scrolls: the render measures the ceiling
/// through the shared render_shortcuts_overlay and writes help_max_scroll
/// back (src/tui/view/ui.rs), then j/k and Up/Down step help_scroll clamped
/// to it (src/tui/view/events.rs:225-230); reopening resets the offset.
#[test]
fn view_help_overlay_scrolls_and_clamps() {
    pin_theme();
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.show_help);
    let text = render_to_text(80, 24, |frame| {
        render(frame, &mut app);
    });
    assert!(
        app.help_max_scroll > 0,
        "the View shortcuts content must clip at 80x24 and write a scroll range back:\n{text}"
    );
    assert!(
        text.contains("more"),
        "the clipped overlay must advertise its hidden rows:\n{text}"
    );

    handle_key_event(&mut app, key(KeyCode::Char('j')));
    assert_eq!(
        app.help_scroll, 1,
        "j must scroll the view help overlay down"
    );
    handle_key_event(&mut app, key(KeyCode::Up));
    assert_eq!(app.help_scroll, 0, "Up must scroll back");
    for _ in 0..500 {
        handle_key_event(&mut app, key(KeyCode::Down));
    }
    assert_eq!(
        app.help_scroll, app.help_max_scroll,
        "scrolling must clamp to the measured ceiling, not run away"
    );

    // Close and reopen: toggle_help resets the offset.
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(!app.show_help);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert_eq!(app.help_scroll, 0, "reopening must reset the scroll offset");
}

/// View-mode Ctrl+R (global search, src/tui/view/events.rs handle_search_key)
/// must announce the toggle with the same 'Search mode: ...' status message
/// as every other surface.
#[test]
fn view_ctrl_r_sets_search_mode_status() {
    let mut app = demo_view_app(ViewTab::Overview);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    assert!(app.search_state.active);
    let ctrl_r = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL);
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: regex"),
        "view-mode Ctrl+R must set the status message"
    );
    handle_key_event(&mut app, ctrl_r);
    assert_eq!(
        app.status_message.as_deref(),
        Some("Search mode: substring"),
        "toggling back must announce substring mode"
    );
}

/// The compact/tall threshold counts the license section's true minimum as 3
/// rows (required = 8+8+8+eco_height+3 in render_stats_panel,
/// src/tui/view/views/overview.rs), so an EOL-enriched SBOM at 120x40 keeps
/// the richer stacked bordered panels instead of flapping into compact mode.
#[test]
fn overview_eol_enriched_keeps_stacked_panels_at_120x40() {
    let mut app = demo_view_app(ViewTab::Overview);
    app.stats.eol_enriched = true;
    app.stats.eol_count = 2;
    app.stats.eol_approaching_count = 1;
    app.stats.eol_security_only_count = 1;
    app.stats.eol_supported_count = 8;
    let text = render_to_text(120, 40, |frame| {
        render(frame, &mut app);
    });
    // Stacked layout markers: the bordered EOL panel title carries the
    // at-risk count in parens; the ecosystem panel is a bordered title.
    assert!(
        text.contains(" End-of-Life Status ("),
        "EOL-enriched 120x40 must render the stacked bordered EOL panel:\n{text}"
    );
    assert!(
        text.contains(" Ecosystem Distribution "),
        "EOL-enriched 120x40 must render the stacked Ecosystem panel:\n{text}"
    );
    // Compact-mode idiom: '── <title> ──' section headers inside one panel.
    assert!(
        !text.contains("\u{2500}\u{2500} Vulnerability Severity \u{2500}\u{2500}"),
        "120x40 with EOL data must not flap into the compact section-header layout:\n{text}"
    );
}

/// In VIEW mode, clicking the «/» overflow markers selects the adjacent
/// hidden tab (PrevMarker/NextMarker arms of handle_tab_click in
/// src/tui/view/events.rs, sharing the window geometry stashed by the render).
#[test]
fn view_tab_marker_clicks_select_adjacent_hidden_tabs() {
    use crate::tui::view::events::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use unicode_width::UnicodeWidthStr;

    let click = |app: &mut ViewApp, column: u16| {
        handle_mouse_event(
            app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column,
                row: 2,
                modifiers: KeyModifiers::empty(),
            },
        );
    };

    // « (PrevMarker): a right-side tab at 80 cols clips earlier tabs.
    let mut app = demo_view_app(ViewTab::Compliance);
    let tabs = ViewTab::tabs_for_profile(app.bom_profile);
    let _ = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert!(
        app.tab_window.clipped_left,
        "Compliance at 80 cols must clip earlier tabs: {:?}",
        app.tab_window
    );
    let before = app.tab_window.start;
    click(&mut app, 0); // the « marker cell
    assert_eq!(
        app.active_tab,
        tabs[before - 1],
        "\u{ab} click must select the tab just left of the window"
    );

    // » (NextMarker): Overview at 80 cols clips trailing tabs.
    let mut app = demo_view_app(ViewTab::Overview);
    let _ = render_to_text(80, 24, |frame| render(frame, &mut app));
    let window = app.tab_window;
    assert!(
        window.clipped_right && window.end < tabs.len(),
        "Overview at 80 cols must clip trailing tabs: {window:?}"
    );
    // Mirror tab_bar_hit_windowed's geometry: optional 2-col « marker, the
    // visible labels joined by 3-col dividers, then the 2-col » marker.
    let mut cursor: u16 = if window.clipped_left { 2 } else { 0 };
    for (i, tab) in tabs.iter().enumerate().take(window.end).skip(window.start) {
        let label = format!("[{}] {} ", i + 1, tab.title());
        cursor += UnicodeWidthStr::width(label.as_str()) as u16;
        if i + 1 != window.end {
            cursor += 3;
        }
    }
    click(&mut app, cursor);
    assert_eq!(
        app.active_tab, tabs[window.end],
        "\u{bb} click must select the tab just right of the window"
    );
}

/// Both terminal branches of render_violation_detail
/// (src/tui/view/views/pqc_compliance.rs): an overflowing detail pane must
/// flag hidden lines explicitly, and a violation-free algorithm must render
/// the Compliant line instead of an empty pane.
#[test]
fn pqc_detail_pane_overflow_marker_and_compliant_branch() {
    // X25519 (index 7 -- component order is pinned by the
    // cbom_pqc_compliance snapshots) FAILs both CNSA 2.0 and NIST PQC, so its
    // detail (>= 2 violations x 4 lines each) overflows the pane, whose inner
    // height is squeezed to 4 rows at 80x24.
    let mut app = cbom_view_app(ViewTab::PqcCompliance);
    app.pqc_selected = 7;
    let text = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert!(
        text.contains("\u{250c} X25519 "),
        "detail pane must be titled for the selected algorithm (fixture index drift?):\n{text}"
    );
    assert!(
        text.contains("more lines \u{2014} see the Compliance tab"),
        "overflowing violation detail must render the explicit truncation marker instead of clipping silently:\n{text}"
    );

    // AES-256-GCM (index 5) has ZERO violations of any severity (CNSA emits
    // only Errors and its cell is PASS; NIST emits nothing for a level-1,
    // non-broken, non-PQC-family algorithm).
    let mut app = cbom_view_app(ViewTab::PqcCompliance);
    app.pqc_selected = 5;
    let text = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert!(
        text.contains("\u{250c} AES-256-GCM "),
        "detail pane must be titled for the selected algorithm (fixture index drift?):\n{text}"
    );
    assert!(
        text.contains("Compliant \u{2014} no violations for this algorithm"),
        "violation-free algorithms must render the Compliant branch:\n{text}"
    );
    assert!(
        !text.contains("more lines"),
        "the truncation marker must not render when the detail fits:\n{text}"
    );
}

/// The CNSA 2.0 PASS/FAIL cell keys off Error-severity violations only
/// (src/tui/view/views/pqc_compliance.rs): a Warning naming the algorithm
/// must not flip the cell (or the header verdict) to FAIL.
#[test]
fn pqc_cnsa_cell_ignores_non_error_violations() {
    use crate::quality::{
        ComplianceLevel, ComplianceResult, Violation, ViolationCategory, ViolationSeverity,
    };
    pin_theme();

    let algo_x_app = |severity: ViolationSeverity| -> ViewApp {
        let mut sbom = NormalizedSbom::default();
        let mut comp = Component::new("ALGO-X".to_string(), "algo-x-ref".to_string());
        comp.component_type = crate::model::ComponentType::Cryptographic;
        comp.crypto_properties = Some(crate::model::CryptoProperties::new(
            crate::model::CryptoAssetType::Algorithm,
        ));
        sbom.components
            .insert(CanonicalId::from_name_version("ALGO-X", None), comp);
        let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Cbom);
        app.active_tab = ViewTab::PqcCompliance;
        // Pre-seed the cache: ensure_compliance_results is a no-op when Some,
        // so the render sees exactly one CNSA violation of the given severity.
        // (check_cnsa2 emits only Errors today, so no fixture can drive this.)
        app.compliance_results = Some(vec![
            ComplianceResult::new(
                ComplianceLevel::Cnsa2,
                vec![Violation {
                    severity,
                    category: ViolationCategory::CryptographyInfo,
                    message: "advisory note about parameter choice".to_string(),
                    element: Some("ALGO-X".to_string()),
                    requirement: "advisory requirement".to_string(),
                    rule_id: "TEST-CNSA-PROBE",
                    component_id: None,
                    counts: None,
                    standard_refs: Vec::new(),
                }],
            ),
            ComplianceResult::new(ComplianceLevel::NistPqc, vec![]),
        ]);
        app
    };

    let mut app = algo_x_app(ViolationSeverity::Warning);
    let text = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert!(
        text.contains("ALGO-X"),
        "precondition: the algorithm row must render:\n{text}"
    );
    assert!(
        text.contains("PASS"),
        "the CNSA/NIST cells must show PASS for a Warning-only violation:\n{text}"
    );
    assert!(
        !text.contains("FAIL"),
        "a Warning-severity CNSA violation must not flip the cell to FAIL:\n{text}"
    );
    assert!(
        !text.contains("NON-COMPLIANT"),
        "a Warning must not flip the header verdict:\n{text}"
    );

    let mut app = algo_x_app(ViolationSeverity::Error);
    let text = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert!(
        text.contains("FAIL"),
        "an Error-severity CNSA violation naming the algorithm must flip the cell to FAIL:\n{text}"
    );
}

/// Hard-pins the AI-Readiness clamp bound with a constant instead of the
/// self-oracle: the BSI fixture has 11 checks vs 4 recommendations, so
/// go_last must land on 10 (checks - 1). ai_readiness_navigation_scrolls_
/// and_clamps asserts against ai_readiness_max_scroll() itself, so a
/// regression of that function to recommendations.len()-1 passes it.
#[test]
fn ai_readiness_go_last_scrolls_to_checks_bound() {
    let mut app = aibom_view_app(ViewTab::AiReadiness);
    app.go_last();
    assert_eq!(
        app.ai_readiness_scroll, 10,
        "max scroll must be the LONGER list (11 checks) - 1, not 4 recommendations - 1"
    );
    let text = render_to_text(120, 40, |frame| render(frame, &mut app));
    // Table-only needle: the checks row carries a Weight cell (the raw 0.12
    // is renormalized across all checks before display, so don't pin the
    // number), while the rec-pane line for the same check
    // ('[P2] [Completeness] [AI-011] ..') has no weight column.
    assert!(
        text.lines()
            .any(|l| l.contains("AI-011") && l.contains('%')),
        "at max scroll the checks TABLE must reveal the last check row (AI-011 with its weight cell):\n{text}"
    );
    assert!(
        !text.lines().any(|l| l.contains("AI-001")),
        "at max scroll the first check row must have scrolled off (offset not driving the table?):\n{text}"
    );
}

/// The shared AI-Readiness offset must be clamped PER PANE
/// (src/tui/shared/quality.rs render_ai_readiness_summary): at max scroll
/// (10) the 9-line recommendations paragraph must clamp to its own list
/// (offset 3) instead of scrolling into blank space.
#[test]
fn ai_readiness_rec_pane_clamps_to_its_own_length_at_max_scroll() {
    let mut app = aibom_view_app(ViewTab::AiReadiness);
    app.go_last(); // shared offset 10 for 11 checks; recs pane has only 4 items
    let text = render_to_text(120, 40, |frame| render(frame, &mut app));
    assert!(
        text.contains("Recommendations (4)"),
        "precondition: the recommendations pane must render:\n{text}"
    );
    // Bracketed rec-pane-only format: the checks table renders 'AI-011'
    // without brackets, so this needle cannot be satisfied by the table.
    assert!(
        text.contains("[P2] [Completeness] [AI-011]"),
        "the recommendations pane must still show content at max checks scroll \
         (an unclamped shared offset of 10 blanks the 9-line pane):\n{text}"
    );
}

/// The AI-BOM Quality tab routes to the same AI-readiness summary renderer
/// and must scroll its checks table via quality_state.scroll_offset
/// (src/tui/view/views/quality.rs), not a hardcoded 0.
#[test]
fn aibom_quality_tab_scroll_offset_drives_checks_table() {
    let mut app = aibom_view_app(ViewTab::Quality);
    let top = render_to_text(120, 40, |frame| render(frame, &mut app));
    assert!(
        top.contains("AI Readiness Checks"),
        "AI-BOM Quality tab must route to the AI-readiness renderer:\n{top}"
    );
    // AI-010 passes on the BSI fixture, so it is absent from the 4-item
    // recommendations pane; at offset 0 the table shows AI-001..AI-008 only.
    assert!(
        !top.contains("AI-010"),
        "precondition: AI-010 must sit below the checks-table fold at offset 0:\n{top}"
    );

    app.quality_state.scroll_offset = 8;
    let scrolled = render_to_text(120, 40, |frame| render(frame, &mut app));
    assert_ne!(
        top, scrolled,
        "quality_state.scroll_offset must drive the AI-BOM Quality checks table (hardcoded 0 regression)"
    );
    assert!(
        scrolled.contains("AI-010"),
        "offset 8 must reveal the below-the-fold AI-010 check row:\n{scrolled}"
    );
}

/// When every danger metric is zero the crypto header must render the
/// success 'No crypto risk flags' line instead of an empty first line
/// (src/tui/view/views/crypto.rs render_header danger.is_empty() branch).
#[test]
fn crypto_header_renders_all_clear_when_no_danger_metrics() {
    use crate::model::{AlgorithmProperties, CryptoAssetType, CryptoPrimitive, CryptoProperties};
    pin_theme();
    let mut sbom = NormalizedSbom::default();
    let mut comp = Component::new("ML-KEM-1024".to_string(), "ml-kem-ref".to_string());
    comp.component_type = crate::model::ComponentType::Cryptographic;
    // Level 5 => quantum-safe (not QVuln); name is not weak-by-name; Kem is
    // not the hybrid Combiner primitive; no certs/keys exist — so every
    // CryptographyMetrics danger counter stays 0.
    comp.crypto_properties = Some(
        CryptoProperties::new(CryptoAssetType::Algorithm).with_algorithm_properties(
            AlgorithmProperties::new(CryptoPrimitive::Kem).with_nist_quantum_security_level(5),
        ),
    );
    sbom.components
        .insert(CanonicalId::from_name_version("ML-KEM-1024", None), comp);
    let mut app = ViewApp::new(sbom, "", crate::model::BomProfile::Cbom);
    app.active_tab = ViewTab::Crypto;
    let text = render_to_text(80, 24, |frame| render(frame, &mut app));
    assert!(
        text.contains("No crypto risk flags"),
        "an all-clear CBOM must render the success line, not an empty first header row:\n{text}"
    );
    for token in [
        "Compromised:",
        "Weak:",
        "QVuln:",
        "Expired:",
        "WeakKeys:",
        "Expiring:",
        "HybridPQC:",
    ] {
        assert!(
            !text.contains(token),
            "zero-count danger token {token} must be omitted from the header:\n{text}"
        );
    }
    assert!(
        text.contains("Quantum:"),
        "the neutral counts line must still render under the all-clear line:\n{text}"
    );
}
