//! Snapshot + key-event tests for the diff `App` TUI.
//!
//! These tests lock the render output and event-handling behaviour of the
//! diff-mode `App` before the planned `App`/`ViewApp` unification touches this
//! code. Render tests use `insta` string snapshots of a [`TestBackend`] buffer;
//! event tests drive the real key handlers and assert on `ViewState` accessors.
//!
//! [`TestBackend`]: ratatui::backend::TestBackend
//!
//! Note: the Components table is locked only at 80x24. At 120 wide the version
//! columns hit a ratatui width-distribution tie-break that resolves
//! non-deterministically across processes, so that one size is intentionally
//! skipped rather than asserted on a value that flaps.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{App, TabKind, render};
use crate::tui::events::handle_key_event;
use crate::tui::test_support::{DEMO_NEW, DEMO_OLD, SIZES, demo_diff, pin_theme, render_to_text};

/// Build a diff-mode `App` from the demo fixtures with a deterministic tab.
///
/// `active_tab` is forced rather than read from the constructor default because
/// `App::base` restores the last-used tab from on-disk `TuiPreferences`, which
/// would make snapshots depend on the developer's environment.
fn demo_app(active_tab: TabKind) -> App {
    pin_theme();
    let (diff, old, new) = demo_diff();
    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = active_tab;
    app
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Render one diff tab at a given size and return the trimmed buffer text.
///
/// Encodes the documented call-ordering contract: `prepare_render` MUST run
/// before `render` builds a `RenderContext` from the app.
fn render_tab(active_tab: TabKind, width: u16, height: u16) -> String {
    let mut app = demo_app(active_tab);
    render_to_text(width, height, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    })
}

/// All diff tabs that the tabbed layout renders (multi-comparison modes use
/// dedicated full-screen renders and are not part of this matrix).
const DIFF_TABS: [(&str, TabKind); 10] = [
    ("summary", TabKind::Summary),
    ("components", TabKind::Components),
    ("dependencies", TabKind::Dependencies),
    ("licenses", TabKind::Licenses),
    ("vulnerabilities", TabKind::Vulnerabilities),
    ("quality", TabKind::Quality),
    ("compliance", TabKind::Compliance),
    ("sidebyside", TabKind::SideBySide),
    ("graph", TabKind::GraphChanges),
    ("source", TabKind::Source),
];

#[test]
fn snapshot_all_diff_tabs() {
    // Redact any "N(d|days|months|years) ago" fragments that some views derive
    // from `Utc::now()`. The demo fixture has no dated vulnerabilities today, so
    // this is defensive: it keeps snapshots stable if a fixture later gains them.
    let mut settings = insta::Settings::clone_current();
    settings.add_filter(r"\d+d ago", "Nd ago");
    settings.add_filter(r"Age: \d+d", "Age: [N]d");
    settings.add_filter(
        r"\((?:today|in the future|(?:\d+|1) (?:days?|months?|years?) ago)\)",
        "(AGE)",
    );
    settings.bind(|| {
        for (name, tab) in DIFF_TABS {
            for (w, h) in SIZES {
                // The Components table at 120 wide hits a ratatui column-width
                // tie-break that resolves non-deterministically per process (the
                // version columns gain/lose one space of padding run-to-run). It
                // is locked only at 80x24; see the module-level note. All other
                // tabs are snapshotted at both sizes.
                if tab == TabKind::Components && w >= 120 {
                    continue;
                }
                let text = render_tab(tab, w, h);
                insta::assert_snapshot!(format!("diff_{name}_{w}x{h}"), text);
            }
        }
    });
}

// ============================================================================
// Key-event behaviour tests (real assertions, not snapshots)
// ============================================================================

#[test]
fn tab_switch_advances_and_wraps() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, TabKind::Components);

    handle_key_event(&mut app, key(KeyCode::Tab));
    assert_eq!(app.active_tab, TabKind::Dependencies);

    // Shift+Tab moves back.
    handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
    assert_eq!(app.active_tab, TabKind::Components);
}

#[test]
fn numeric_keys_jump_to_tab() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('5')));
    assert_eq!(app.active_tab, TabKind::Vulnerabilities);
    handle_key_event(&mut app, key(KeyCode::Char('2')));
    assert_eq!(app.active_tab, TabKind::Components);
}

#[test]
fn components_filter_toggle_cycles() {
    let mut app = demo_app(TabKind::Components);
    let initial = app.components_state().filter;
    handle_key_event(&mut app, key(KeyCode::Char('f')));
    assert_ne!(
        app.components_state().filter,
        initial,
        "'f' should advance the component filter"
    );
}

#[test]
fn components_sort_toggle_cycles() {
    let mut app = demo_app(TabKind::Components);
    let initial = app.components_state().sort_by;
    handle_key_event(&mut app, key(KeyCode::Char('s')));
    assert_ne!(
        app.components_state().sort_by,
        initial,
        "'s' should advance the component sort"
    );
}

#[test]
fn search_entry_opens_overlay_and_accepts_input() {
    let mut app = demo_app(TabKind::Components);
    assert!(!app.has_overlay());

    handle_key_event(&mut app, key(KeyCode::Char('/')));
    assert!(app.overlays.search.active, "'/' opens the search overlay");

    for c in ['l', 'o', 'd'] {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    assert_eq!(app.overlays.search.query, "lod");

    handle_key_event(&mut app, key(KeyCode::Backspace));
    assert_eq!(app.overlays.search.query, "lo");

    handle_key_event(&mut app, key(KeyCode::Esc));
    assert!(!app.overlays.search.active, "Esc closes the search overlay");
}

#[test]
fn detail_navigation_moves_component_selection() {
    let mut app = demo_app(TabKind::Components);
    // Totals are computed in prepare_render; needed for selection clamping.
    app.prepare_render();
    assert_eq!(app.components_state().selected, 0);

    handle_key_event(&mut app, key(KeyCode::Down));
    let after_down = app.components_state().selected;
    assert!(
        after_down >= 1 || app.components_state().total <= 1,
        "Down should advance selection when more than one item exists"
    );

    handle_key_event(&mut app, key(KeyCode::Up));
    assert_eq!(
        app.components_state().selected,
        0,
        "Up should return to the first item"
    );
}

/// The diff-mode detail panel must render the RANSOMWARE badge for an
/// introduced ransomware-KEV vulnerability (the flag was previously dropped at
/// the `VulnerabilityDetail` boundary, leaving the badge unreachable in diff
/// mode).
#[test]
fn diff_vuln_detail_shows_ransomware_badge() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let mut vuln = crate::model::VulnerabilityRef::new(
        "CVE-2021-44228".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    vuln.is_kev = true;
    let mut kev = crate::model::KevInfo::new(
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::days(30),
        "patch".to_string(),
    );
    kev.known_ransomware_use = true;
    vuln.kev_info = Some(kev);

    let comp = crate::model::Component::new(
        "log4j-core".to_string(),
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0".to_string(),
    );
    diff.vulnerabilities
        .introduced
        .push(crate::diff::VulnerabilityDetail::from_ref(&vuln, &comp));

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("RANSOMWARE"),
        "diff-mode detail panel must render the RANSOMWARE badge:\n{text}"
    );
}

/// The Graph Changes master table drops its Details column below 60 inner
/// columns (at 80x24 the Min(30) Details column collapsed to zero width and
/// squeezed Component into unreadability).
#[test]
fn graph_details_column_gated_by_width() {
    pin_theme();

    fn render_with_graph_change(width: u16, height: u16) -> String {
        let (mut diff, old, new) = demo_diff();
        diff.graph_changes.push(crate::diff::DependencyGraphChange {
            component_id: crate::model::CanonicalId::from_name_version(
                "acme-webapp",
                Some("2.0.0"),
            ),
            component_name: "acme-webapp".to_string(),
            change: crate::diff::DependencyChangeType::DependencyAdded {
                dependency_id: crate::model::CanonicalId::from_name_version(
                    "left-pad",
                    Some("1.3.0"),
                ),
                dependency_name: "left-pad".to_string(),
            },
            impact: crate::diff::GraphChangeImpact::Medium,
        });
        let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
        app.active_tab = TabKind::GraphChanges;
        render_to_text(width, height, |frame| {
            app.prepare_render();
            render(frame, &mut app);
        })
    }

    // Assert on the table header row (the line containing both Impact and
    // Type) — "Details" also appears in the " Change Details " pane title, so
    // a whole-buffer check would false-positive.
    let header_line = |text: &str| -> String {
        text.lines()
            .find(|l| l.contains("Impact") && l.contains("Type"))
            .expect("graph changes table header must render")
            .to_string()
    };

    let narrow = render_with_graph_change(80, 24);
    assert!(
        !header_line(&narrow).contains("Details"),
        "at 80 cols the Details column must be dropped"
    );
    assert!(
        header_line(&narrow).contains("Component"),
        "Component column must survive at 80 cols"
    );

    let wide = render_with_graph_change(120, 40);
    assert!(
        header_line(&wide).contains("Details"),
        "at 120 cols the Details column must render"
    );
}

#[test]
fn help_overlay_toggles() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(app.overlays.show_help);
    // Any key while help is open with '?' toggles it back off.
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    assert!(!app.overlays.show_help);
}

#[test]
fn sidebyside_aligned_navigation_wired_via_prepare_render() {
    use crate::tui::app_states::AlignmentMode;

    let mut app = demo_app(TabKind::SideBySide);
    app.side_by_side_state_mut().alignment_mode = AlignmentMode::Aligned;
    // prepare_render must build the aligned-row cache AND populate the
    // navigation model (total_rows / change_indices) it drives.
    app.prepare_render();

    {
        let st = app.side_by_side_state();
        assert!(st.total_rows > 0, "aligned mode must populate total_rows");
        assert_eq!(
            st.total_rows,
            st.aligned_rows.len(),
            "total_rows must track the cached row list"
        );
        assert_eq!(
            st.change_indices.len(),
            st.total_rows,
            "every aligned row is a change row"
        );
    }

    app.side_by_side_state_mut().next_change();
    let st = app.side_by_side_state();
    assert_eq!(st.current_change_idx, Some(0));
    assert_eq!(
        st.selected_row, st.change_indices[0],
        "next_change must move the selected row onto the first change"
    );
}

#[test]
fn sidebyside_grouped_scroll_totals_unchanged() {
    use crate::tui::app_states::AlignmentMode;

    // Grouped is no longer the default (Aligned is); force it explicitly.
    let mut app = demo_app(TabKind::SideBySide);
    app.side_by_side_state_mut().alignment_mode = AlignmentMode::Grouped;
    app.prepare_render();

    let (diff, _, _) = demo_diff();
    let expected_left = diff.components.removed.len() + diff.components.modified.len();
    let expected_right = diff.components.added.len() + diff.components.modified.len();

    let st = app.side_by_side_state();
    assert_eq!(st.alignment_mode, AlignmentMode::Grouped);
    assert_eq!(
        st.total_rows, 0,
        "grouped mode uses panel scrolling, not rows"
    );
    assert!(st.change_indices.is_empty());
    assert_eq!(
        st.left_total, expected_left,
        "grouped left panel keeps removed+modified count"
    );
    assert_eq!(
        st.right_total, expected_right,
        "grouped right panel keeps added+modified count"
    );
}

// ============================================================================
// Diff-side alignment regression tests (PR-B): surface metadata changes,
// the CRA sidecar compliance verdict, component license changes, and ML-risk
// styling that the diff TUI previously dropped.
// ============================================================================

mod diff_alignment {
    use super::{App, TabKind, render};
    use crate::diff::{
        ComponentLicenseChange, DiffResult, FieldChange, MetadataChange, MetadataChangeKind,
    };
    use crate::model::{
        Component, ComponentType, CraSidecarMetadata, DatasetRef, MlModelInfo, NormalizedSbom,
    };
    use crate::quality::ComplianceLevel;
    use crate::tui::test_support::{pin_theme, render_to_text};

    /// Build a minimal diff-mode `App` from two empty SBOMs, then let the caller
    /// install a synthetic [`DiffResult`] so each test exercises exactly one
    /// diff signal. Raw source strings are placeholders (the Source tab is not
    /// under test here).
    fn app_with_result(result: DiffResult, tab: TabKind) -> App {
        pin_theme();
        let old = NormalizedSbom::default();
        let new = NormalizedSbom::default();
        let mut app = App::new_diff(result, old, new, "{}", "{}");
        app.active_tab = tab;
        app
    }

    fn render_tab_text(app: &mut App, w: u16, h: u16) -> String {
        render_to_text(w, h, |frame| {
            app.prepare_render();
            render(frame, app);
        })
    }

    #[test]
    fn summary_renders_metadata_changes_section() {
        let mut result = DiffResult::new();
        result.metadata_changes = vec![
            MetadataChange {
                field: "spec_version".to_string(),
                old_value: Some("1.5".to_string()),
                new_value: Some("1.7".to_string()),
                kind: MetadataChangeKind::Modified,
            },
            MetadataChange {
                field: "signature.algorithm".to_string(),
                old_value: None,
                new_value: Some("Ed25519".to_string()),
                kind: MetadataChangeKind::Added,
            },
        ];
        result.calculate_summary();
        // The bug: total_changes counts metadata changes, so the header must not
        // claim changes the body never shows.
        assert_eq!(result.summary.total_changes, 2);

        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);

        assert!(
            text.contains("spec_version"),
            "metadata field must be listed in the diff summary:\n{text}"
        );
        assert!(
            text.contains("META"),
            "metadata changes must carry a META badge:\n{text}"
        );
        assert!(
            text.contains("1.5") && text.contains("1.7"),
            "old -> new metadata values must render:\n{text}"
        );
    }

    fn high_risk_ml_sbom() -> NormalizedSbom {
        let mut sbom = NormalizedSbom::default();
        let mut model = Component::new("model-a".to_string(), "model-a".to_string())
            .with_version("1.0.0".to_string());
        model.component_type = ComponentType::MachineLearningModel;
        // Bare ML metadata: Annex IV documentation gaps are present.
        model.ml_model = Some(MlModelInfo::default());
        sbom.components.insert(model.canonical_id.clone(), model);
        sbom
    }

    #[test]
    fn high_risk_ai_sidecar_marks_ai_act_non_compliant() {
        // Without a high-risk sidecar the bare ML SBOM passes AI-Act (gaps are
        // advisory). The diff App must apply the sidecar so the verdict flips,
        // matching the CLI.
        let new = high_risk_ml_sbom();
        let old = high_risk_ml_sbom();
        let mut app = App::new_diff(DiffResult::new(), old, new, "{}", "{}");
        app = app.with_cra_sidecar(CraSidecarMetadata {
            is_high_risk_ai: true,
            ..Default::default()
        });

        app.ensure_compliance_results();

        let results = app
            .data
            .new_compliance_results
            .as_ref()
            .expect("compliance results computed");
        let ai_act = results
            .iter()
            .find(|r| r.level == ComplianceLevel::EuAiAct)
            .expect("AI-Act standard present");
        assert!(
            !ai_act.is_compliant,
            "high-risk AI SBOM with Annex IV gaps must be NON-COMPLIANT in the diff TUI"
        );
        assert!(ai_act.error_count > 0, "gaps must escalate to errors");
    }

    #[test]
    fn without_sidecar_ai_act_stays_compliant() {
        // Guards the inverse: the escalation must be sidecar-driven, not a
        // blanket failure for any ML SBOM.
        let new = high_risk_ml_sbom();
        let old = high_risk_ml_sbom();
        let mut app = App::new_diff(DiffResult::new(), old, new, "{}", "{}");
        app.ensure_compliance_results();

        let results = app.data.new_compliance_results.as_ref().unwrap();
        let ai_act = results
            .iter()
            .find(|r| r.level == ComplianceLevel::EuAiAct)
            .unwrap();
        assert!(
            ai_act.is_compliant,
            "non-high-risk ML SBOM gaps are advisory, not blocking"
        );
    }

    #[test]
    fn licenses_tab_lists_component_changes_without_aggregates() {
        // Only per-component churn (no net new/removed license across the SBOM):
        // previously the tab early-returned "No license changes detected".
        let mut result = DiffResult::new();
        result.licenses.component_changes = vec![ComponentLicenseChange {
            component_id: "pkg:cargo/libfoo@1.0.0".to_string(),
            component_name: "libfoo".to_string(),
            old_licenses: vec!["MIT".to_string()],
            new_licenses: vec!["GPL-3.0-only".to_string()],
        }];

        let mut app = app_with_result(result, TabKind::Licenses);
        let text = render_tab_text(&mut app, 120, 40);

        assert!(
            !text.contains("No license changes detected"),
            "component license churn must not be reported as no changes:\n{text}"
        );
        assert!(
            text.contains("Component License Changes"),
            "the component license-change panel must render:\n{text}"
        );
        assert!(
            text.contains("libfoo") && text.contains("GPL-3.0-only"),
            "the changed component and its new license must be listed:\n{text}"
        );
    }

    /// Build a modified-component change carrying an `ml_training_dataset`
    /// removal field change (old value present, new absent), as the diff engine
    /// emits for provenance loss.
    fn training_dataset_removal_change() -> DiffResult {
        let mut old = Component::new("model-a".to_string(), "model-a".to_string())
            .with_version("1.0.0".to_string());
        old.component_type = ComponentType::MachineLearningModel;
        old.ml_model = Some(MlModelInfo {
            training_datasets: vec![DatasetRef {
                reference: Some("dataset-1".to_string()),
                name: Some("reviews".to_string()),
                purl: None,
            }],
            ..MlModelInfo::default()
        });

        let mut new = old.clone();
        new.ml_model = Some(MlModelInfo::default());

        let mut change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0);
        change.field_changes = vec![FieldChange {
            field: "ml_training_dataset".to_string(),
            old_value: Some("dataset-1".to_string()),
            new_value: None,
        }];

        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();
        result
    }

    /// Build a modified model-a change with one ml_metric field change.
    fn ml_metric_change(metric: &str, old_v: &str, new_v: &str) -> DiffResult {
        let old = Component::new("model-a".to_string(), "model-a".to_string())
            .with_version("1.0.0".to_string());
        let new = old.clone();
        let mut change = crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0);
        change.field_changes = vec![FieldChange {
            field: format!("ml_metric:{metric}"),
            old_value: Some(old_v.to_string()),
            new_value: Some(new_v.to_string()),
        }];
        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();
        result
    }

    /// The CLI's --fail-on-ml-regression signal must be visible interactively:
    /// the Summary names each regressed metric with its transition.
    #[test]
    fn summary_lists_ml_regressions() {
        let mut result = DiffResult::default();
        result.ml_regressions.push(crate::diff::MlRegression {
            component: "model-a".to_string(),
            metric: "accuracy".to_string(),
            previous_value: 0.9,
            new_value: 0.8,
        });
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("ML REGRESSION"),
            "summary must badge the regression:\n{text}"
        );
        assert!(
            text.contains("model-a accuracy: 0.90 \u{2192} 0.80"),
            "summary must name the component, metric and transition:\n{text}"
        );
    }

    /// Regression for the inverted-color bug: a dropped accuracy previously
    /// painted green (added). Text snapshots drop color, so the direction
    /// arrow is the observable contract.
    #[test]
    fn component_detail_ml_metric_regression_shows_down_arrow() {
        let mut result = ml_metric_change("accuracy", "0.9", "0.8");
        // The CLI populates ml_regressions for regressed components; the
        // detail panel must badge them.
        result.ml_regressions.push(crate::diff::MlRegression {
            component: "model-a".to_string(),
            metric: "accuracy".to_string(),
            previous_value: 0.9,
            new_value: 0.8,
        });
        let mut app = app_with_result(result, TabKind::Components);
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("ML REGRESSION"),
            "detail panel must badge the regressed component:\n{text}"
        );
        assert!(
            text.contains("\u{25bc}"),
            "regressed metric must carry a down arrow:\n{text}"
        );
        assert!(
            !text.contains("\u{25b2}"),
            "regressed metric must not carry an up arrow:\n{text}"
        );

        let mut app = app_with_result(
            ml_metric_change("accuracy", "0.8", "0.9"),
            TabKind::Components,
        );
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("\u{25b2}"),
            "improved metric must carry an up arrow:\n{text}"
        );
    }

    /// A fuzzy match must expose its confidence interval and normalization
    /// audit trail; previously a fuzzy 0.75 rendered identically to a
    /// near-exact 0.75.
    #[test]
    fn match_panel_shows_ci_and_normalizations() {
        let old = Component::new("fuzzy-lib".to_string(), "fuzzy-lib".to_string())
            .with_version("1.0".to_string());
        let new = old.clone();
        let mut mi = crate::diff::MatchInfo::simple(0.75, "Fuzzy", "name similarity");
        mi.normalizations = vec!["lowercase".to_string(), "suffix_stripped".to_string()];
        let change =
            crate::diff::ComponentChange::modified(&old, &new, Vec::new(), 0).with_match_info(mi);
        let mut result = DiffResult::new();
        result.components.modified.push(change);
        result.calculate_summary();

        let mut app = app_with_result(result, TabKind::Components);
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("CI: 0.67\u{2013}0.83 (95%)"),
            "Fuzzy tier margin is 0.08 -> CI 0.67-0.83:\n{text}"
        );
        assert!(
            text.contains("Normalized: lowercase, suffix_stripped"),
            "normalization audit trail must render:\n{text}"
        );
    }

    fn vuln_detail(
        id: &str,
        vex: Option<crate::model::VexState>,
    ) -> crate::diff::VulnerabilityDetail {
        let vref = crate::model::VulnerabilityRef::new(
            id.to_string(),
            crate::model::VulnerabilitySource::Osv,
        );
        let comp =
            crate::model::Component::new("libv".to_string(), "pkg:npm/libv@1.0.0".to_string());
        let mut detail = crate::diff::VulnerabilityDetail::from_ref(&vref, &comp);
        detail.vex_state = vex;
        detail
    }

    /// introduced_without_vex is the security worklist; it is computed but was
    /// never rendered. The card must show gap counts and the by_state tail.
    #[test]
    fn vex_card_lists_gap_counts() {
        let mut result = DiffResult::default();
        result
            .vulnerabilities
            .introduced
            .push(vuln_detail("CVE-2024-0001", None));
        result
            .vulnerabilities
            .introduced
            .push(vuln_detail("CVE-2024-0002", None));
        result
            .vulnerabilities
            .persistent
            .push(vuln_detail("CVE-2024-0003", None));
        result.vulnerabilities.introduced.push(vuln_detail(
            "CVE-2024-0004",
            Some(crate::model::VexState::Affected),
        ));
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        for needle in ["Gaps:", "2 new", "1 ongoing", "AF:1"] {
            assert!(
                text.contains(needle),
                "VEX card must render {needle}:\n{text}"
            );
        }
    }

    /// Regression for the gate relaxation: a diff whose vulns have ZERO VEX
    /// coverage — the pure gap case — previously hid the card entirely.
    #[test]
    fn vex_card_renders_with_zero_coverage() {
        let mut result = DiffResult::default();
        result
            .vulnerabilities
            .introduced
            .push(vuln_detail("CVE-2024-0001", None));
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("VEX: 0%"),
            "zero-coverage card must render with 0%:\n{text}"
        );
        assert!(
            text.contains("Gaps:") && text.contains("1 new"),
            "gap line must render:\n{text}"
        );
    }

    #[test]
    fn component_detail_flags_training_dataset_removal() {
        let mut app = app_with_result(training_dataset_removal_change(), TabKind::Components);
        // Selection clamping + master/detail totals are computed in prepare_render.
        app.prepare_render();
        let text = render_tab_text(&mut app, 120, 40);

        assert!(
            text.contains("ml_training_dataset"),
            "the field key must still render:\n{text}"
        );
        assert!(
            text.contains("PROVENANCE LOSS"),
            "training-dataset removal must carry a provenance-loss risk badge:\n{text}"
        );
    }

    /// App::new_diff must backfill the engine QualityDelta when the pipeline
    /// didn't provide one (TUI-only construction paths previously saw None,
    /// hiding the Quality Impact card and the regression chips).
    #[test]
    fn new_diff_backfills_quality_delta() {
        let app = app_with_result(DiffResult::default(), TabKind::Quality);
        assert!(
            app.data
                .diff_result
                .as_ref()
                .is_some_and(|r| r.quality_delta.is_some()),
            "constructor must backfill quality_delta from the scored reports"
        );
    }

    /// The Quality tab renders the engine's regressed/improved chips, the
    /// violation delta, and ALL category transitions (the previous 4-category
    /// recompute silently omitted Integrity/Provenance regressions).
    #[test]
    fn quality_tab_renders_engine_delta() {
        let mut result = DiffResult::default();
        // overall_score_delta 0.0: both fixture SBOMs are empty, so the tab
        // only trusts the engine delta when it matches the displayed 0-point
        // transition (profile-mismatch guard in render_diff_quality).
        result.quality_delta = Some(crate::diff::QualityDelta {
            overall_score_delta: 0.0,
            old_grade: None,
            new_grade: None,
            category_deltas: vec![
                crate::diff::CategoryDelta {
                    category: "Integrity".to_string(),
                    old_score: 80.0,
                    new_score: 60.0,
                    delta: -20.0,
                },
                crate::diff::CategoryDelta {
                    category: "Licenses".to_string(),
                    old_score: 50.0,
                    new_score: 70.0,
                    delta: 20.0,
                },
            ],
            regressions: vec!["Provenance".to_string(), "Integrity".to_string()],
            improvements: vec!["Licenses".to_string()],
            violation_count_delta: 2,
        });
        let mut app = app_with_result(result, TabKind::Quality);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("Regressed: Provenance, Integrity"),
            "regression chips must render:\n{text}"
        );
        assert!(
            text.contains("Improved: Licenses"),
            "improvement chips must render:\n{text}"
        );
        assert!(
            text.contains("Compliance violations: +2"),
            "violation delta must render:\n{text}"
        );
        assert!(
            text.contains("Integrity: 80% → 60%"),
            "Integrity transition (previously invisible) must render:\n{text}"
        );
    }

    /// The Licenses tab leads with a before→after risk posture header.
    #[test]
    fn licenses_tab_renders_delta_header() {
        let mut result = DiffResult::default();
        result
            .licenses
            .new_licenses
            .push(crate::diff::LicenseChange {
                license: "GPL-3.0-only".to_string(),
                components: vec!["libx".to_string()],
                family: "GPL".to_string(),
            });
        result
            .licenses
            .removed_licenses
            .push(crate::diff::LicenseChange {
                license: "MIT".to_string(),
                components: vec!["liby".to_string()],
                family: "MIT".to_string(),
            });
        let mut app = app_with_result(result, TabKind::Licenses);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("Licenses: +1 new"),
            "header title must render:\n{text}"
        );
        assert!(
            text.contains("High/Critical: 0 \u{2192} 1"),
            "risk transition must render (GPL is High risk):\n{text}"
        );
        assert!(
            text.contains("regressed"),
            "posture label must render:\n{text}"
        );
    }

    /// Compliance selection must be visible without color: the selected row
    /// carries a \u{25b6} marker.
    #[test]
    fn compliance_selection_marker_visible() {
        let mut app = super::demo_app(TabKind::Compliance);
        // Cycle Overview -> NewViolations so a violation table renders.
        crate::tui::events::handle_key_event(
            &mut app,
            super::key(crossterm::event::KeyCode::Char('v')),
        );
        let text = render_to_text(120, 40, |frame| {
            app.prepare_render();
            render(frame, &mut app);
        });
        assert!(
            text.contains("\u{25b6} ERROR")
                || text.contains("\u{25b6} WARN")
                || text.contains("\u{25b6} INFO"),
            "selected violation row must carry the marker:\n{text}"
        );
    }

    /// Multi-ecosystem diffs render grouped +/-/~ bars; single-ecosystem
    /// diffs render a labelled tally row instead of a labelless bar.
    #[test]
    fn ecosystem_chart_is_semantic() {
        fn comp(name: &str, eco: &str) -> crate::diff::ComponentChange {
            let component = Component::new(name.to_string(), format!("pkg:{eco}/{name}@1.0.0"));
            let mut c = crate::diff::ComponentChange::added(&component, 0);
            c.ecosystem = Some(eco.to_string());
            c
        }
        // Two ecosystems -> grouped bars with +/-/~ labels.
        let mut result = DiffResult::default();
        for i in 0..3 {
            result.components.added.push(comp(&format!("np{i}"), "npm"));
        }
        result.components.removed.push(comp("py0", "pypi"));
        result.components.modified.push(comp("py1", "pypi"));
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        assert!(
            text.contains("npm") && text.contains("pypi"),
            "both ecosystem groups must label:\n{text}"
        );
        // The semantic +/-/~ bar-label row is what distinguishes the grouped
        // chart from the old flat per-ecosystem bars.
        assert!(
            text.contains(" +  -  ~"),
            "grouped chart must label its +/-/~ bars:\n{text}"
        );

        // Single ecosystem -> tally row, no bar glyphs in that panel.
        let mut result = DiffResult::default();
        for i in 0..4 {
            result.components.added.push(comp(&format!("np{i}"), "npm"));
        }
        let mut app = app_with_result(result, TabKind::Summary);
        let text = render_tab_text(&mut app, 120, 40);
        // The full labelled tally row — "+4" alone also appears in the All
        // Changes panel title, which would make this assertion vacuous.
        assert!(
            text.contains("npm          +4  -0  ~0"),
            "single ecosystem must render the labelled tally row:\n{text}"
        );
    }
}

#[test]
fn diff_tab_click_selects_the_rendered_tab_including_source() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use unicode_width::UnicodeWidthStr;

    let mut app = demo_app(TabKind::Summary);
    // Wide enough that every tab (incl. the rightmost Source) is on-screen.
    // Tab titles render on row 2 (header Length(2) + Tabs' top row).
    let text = render_to_text(240, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let tab_row = text.lines().nth(2).expect("tab bar row").to_string();

    // Both sit past where the old fixed-13-col estimate placed them; "Source"
    // (rightmost) was entirely unreachable before this fix.
    for (needle, expected) in [
        ("Vulnerabilities", TabKind::Vulnerabilities),
        ("Source", TabKind::Source),
    ] {
        let byte = tab_row
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not in tab row: {tab_row:?}"));
        let col = UnicodeWidthStr::width(&tab_row[..byte]) as u16; // display col, not byte
        app.active_tab = TabKind::Summary;
        handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: col,
                row: 2,
                modifiers: KeyModifiers::empty(),
            },
        );
        assert_eq!(app.active_tab, expected, "click on {needle} @col {col}");
    }
}

/// Shift+Tab arrives from real terminals as `KeyCode::BackTab`; it must
/// reverse-cycle tabs (previously only the synthetic Tab+SHIFT combination
/// was handled, so BackTab was silently dropped).
#[test]
fn backtab_cycles_to_previous_tab_in_diff() {
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::BackTab));
    assert_eq!(app.active_tab, TabKind::Summary);
}

/// End/G, PageUp and PageDown must navigate the Licenses tab (they were
/// documented but dead: the view returned Ignored and the global fallback
/// had no Licenses arm).
#[test]
fn licenses_end_and_paging_keys_navigate() {
    let mut app = demo_app(TabKind::Licenses);
    app.prepare_render();
    // The diff Licenses tab lists CHANGED licenses; the all-MIT demo fixture
    // yields at most one, so seed a synthetic bound — the wiring under test
    // is the global-fallback arms, which read this state directly.
    app.licenses_state_mut().total = 25;
    let total = app.licenses_state().total;

    handle_key_event(&mut app, key(KeyCode::End));
    assert_eq!(
        app.licenses_state().selected,
        total - 1,
        "End jumps to the last license row"
    );

    handle_key_event(&mut app, key(KeyCode::PageUp));
    assert_eq!(
        app.licenses_state().selected,
        (total - 1).saturating_sub(crate::tui::constants::PAGE_SIZE),
        "PageUp moves the selection up by exactly one page"
    );

    handle_key_event(&mut app, key(KeyCode::Home));
    assert_eq!(app.licenses_state().selected, 0, "Home returns to the top");
}

/// K (shortcuts) and D (deep dive) previously set their overlay visible in
/// Diff mode without any render path painting it — an invisible modal that
/// swallowed all input. The overlays must now actually render.
#[test]
fn shortcuts_overlay_renders_in_diff_mode() {
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('K')));
    assert!(
        app.overlays.shortcuts.visible,
        "'K' opens the shortcuts overlay"
    );
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("Keyboard Shortcuts (Diff)"),
        "the shortcuts overlay must be painted in diff mode:\n{text}"
    );
    insta::assert_snapshot!("diff_shortcuts_overlay_80x24", text);
}

#[test]
fn deep_dive_overlay_renders_in_diff_mode() {
    let mut app = demo_app(TabKind::Components);
    app.prepare_render();
    handle_key_event(&mut app, key(KeyCode::Char('D')));
    assert!(
        app.overlays.component_deep_dive.visible,
        "'D' opens the deep-dive overlay for the selected component"
    );
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let expected = app.overlays.component_deep_dive.component_name.clone();
    assert!(
        text.contains(&format!("Component Deep Dive: {expected}")),
        "the deep-dive overlay must be painted with the selected component:\n{text}"
    );
}

/// Lock the Grouped layout (including the Modified-section alignment padding)
/// now that it is opt-in rather than the default.
#[test]
fn snapshot_sidebyside_grouped() {
    use crate::tui::app_states::AlignmentMode;

    let mut app = demo_app(TabKind::SideBySide);
    app.side_by_side_state_mut().alignment_mode = AlignmentMode::Grouped;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    insta::assert_snapshot!("diff_sidebyside_grouped_80x24", text);
}

// ============================================================================
// Multi-comparison modes: baseline snapshots + navigation regression tests
// ============================================================================

/// Baseline snapshots for the three multi-comparison full-screen renders.
/// None existed before (DIFF_TABS deliberately excludes these modes); later
/// multi-mode PRs update these baselines.
#[test]
fn snapshot_multi_modes() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};

    pin_theme();
    let apps: [(&str, App); 3] = [
        ("multidiff", App::new_multi_diff(demo_multi_diff())),
        ("timeline", App::new_timeline(demo_timeline())),
        ("matrix", App::new_matrix(demo_matrix())),
    ];
    for (name, mut app) in apps {
        for (w, h) in SIZES {
            let text = render_to_text(w, h, |frame| {
                app.prepare_render();
                render(frame, &mut app);
            });
            insta::assert_snapshot!(format!("{name}_{w}x{h}"), text);
        }
    }
}

/// Regression for the frozen multi-diff drill-down: total_variable_components
/// was never populated, so the `total > 0` guard kept j/k stuck at index 0.
#[test]
fn multi_diff_drill_down_unfrozen() {
    use crate::tui::test_support::demo_multi_diff;

    pin_theme();
    let mut app = App::new_multi_diff(demo_multi_diff());
    assert!(
        app.tabs.multi_diff.total_variable_components > 0,
        "constructor must populate the variable-component bound"
    );

    handle_key_event(&mut app, key(KeyCode::Char('v')));
    assert!(app.tabs.multi_diff.show_variable_drill_down);
    let total = app.tabs.multi_diff.total_variable_components;
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    assert_eq!(
        app.tabs.multi_diff.selected_variable_component,
        1.min(total - 1),
        "j must advance the drill-down selection when more than one row exists"
    );

    // Guard-level regression independent of fixture size: with the bound set,
    // navigation advances; with the old bound of 0 it froze at index 0.
    app.tabs.multi_diff.total_variable_components = 3;
    app.tabs.multi_diff.selected_variable_component = 0;
    app.tabs.multi_diff.select_next_variable_component();
    app.tabs.multi_diff.select_next_variable_component();
    assert_eq!(app.tabs.multi_diff.selected_variable_component, 2);
}

/// Regression for the frozen Timeline Components panel (total_components
/// never populated).
#[test]
fn timeline_components_panel_navigable() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    assert!(
        app.tabs.timeline.total_components > 0,
        "constructor must populate the component bound"
    );

    handle_key_event(&mut app, key(KeyCode::Tab)); // Versions -> Components
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    assert_eq!(
        app.tabs.timeline.selected_component, 1,
        "j must advance the component selection"
    );
}

/// Regression for the frozen Matrix clustering navigation (total_clusters
/// never populated).
#[test]
fn matrix_cluster_navigation_unfrozen() {
    use crate::tui::test_support::demo_matrix;

    pin_theme();
    let app = App::new_matrix(demo_matrix());
    assert!(
        app.tabs.matrix.total_clusters > 0,
        "constructor must populate the cluster bound (threshold 0.5 clusters the fixtures)"
    );

    let mut app = app;
    app.tabs.matrix.select_next_cluster();
    assert_eq!(
        app.tabs.matrix.selected_cluster,
        1.min(app.tabs.matrix.total_clusters - 1),
        "cluster selection must move once the bound is set"
    );
}

/// Regression for the filtered-list desync: under a component filter, the
/// history modal and the event-side name lookup must resolve the SAME entry
/// the Components panel highlights.
#[test]
fn timeline_selection_resolves_through_filtered_list() {
    use crate::tui::app::TimelineComponentFilter;
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::filtered_evolution_entries;

    pin_theme();
    let result = demo_timeline();

    let removed = filtered_evolution_entries(&result, TimelineComponentFilter::Removed);
    assert!(
        !removed.is_empty(),
        "fixture must have removed components (v2 -> v3 is a near-total replacement)"
    );
    assert!(
        removed.iter().all(|(_, is_removed)| *is_removed),
        "Removed filter must only yield removed components"
    );

    // The first REMOVED component differs from the first UNFILTERED entry
    // (which is an added one) — the old unfiltered lookup returned the wrong
    // component under a filter.
    let unfiltered = filtered_evolution_entries(&result, TimelineComponentFilter::All);
    assert!(
        !unfiltered.is_empty() && !unfiltered[0].1,
        "unfiltered list starts with added components"
    );
    assert_ne!(
        removed[0].0.name, unfiltered[0].0.name,
        "filtered index 0 must not resolve to the unfiltered head"
    );
}

/// Regression for the filter resync: narrowing the filter must clamp the
/// selection and update the navigation bound.
#[test]
fn timeline_filter_resync_clamps_selection() {
    use crate::tui::app::TimelineComponentFilter;
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::filtered_evolution_entries;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    // Park the selection on the last unfiltered component.
    app.tabs.timeline.selected_component = app.tabs.timeline.total_components - 1;

    // Cycle 'f' until a narrower filter than All is active.
    for _ in 0..4 {
        handle_key_event(&mut app, key(KeyCode::Char('f')));
        if app.tabs.timeline.component_filter != TimelineComponentFilter::All {
            break;
        }
    }
    let filter = app.tabs.timeline.component_filter;
    assert_ne!(filter, TimelineComponentFilter::All);

    let visible = filtered_evolution_entries(
        app.data.timeline_result.as_ref().expect("timeline data"),
        filter,
    )
    .len();
    assert_eq!(
        app.tabs.timeline.total_components, visible,
        "'f' must resync the navigation bound to the filtered length"
    );
    assert!(
        app.tabs.timeline.selected_component < visible.max(1),
        "'f' must clamp the selection into the filtered list"
    );
}

/// Regression: the Summary "All Changes" panel silently clipped everything
/// below the fold with a pinned scroll of (0,0) and no key handling — users
/// read the visible handful as the complete change set.
#[test]
fn summary_all_changes_scrolls_below_the_fold() {
    let mut app = demo_app(TabKind::Summary);
    let first = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // '~ lodash' is a patch-level bump, priority-sorted to the very end of
    // the list and below the panel's fold.
    assert!(
        !first.contains("~ lodash"),
        "precondition: the patch entry starts below the fold:\n{first}"
    );

    handle_key_event(&mut app, key(KeyCode::End));
    assert!(
        app.summary_state().scroll_offset > 0,
        "End must move the scroll offset"
    );
    let scrolled = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        scrolled.contains("~ lodash"),
        "scrolling must reveal the entries below the fold:\n{scrolled}"
    );
}

/// all_changes_line_count mirrors render_all_changes' line construction.
#[test]
fn all_changes_line_count_matches_fixture() {
    let (diff, _, _) = demo_diff();
    // Demo fixture: 5 modified + 4 removed + 4 added, 0 introduced
    // Critical/High vulns, 2 metadata changes (+1 section header).
    assert_eq!(crate::tui::views::all_changes_line_count(&diff), 16);

    let empty = crate::diff::DiffResult::default();
    assert_eq!(
        crate::tui::views::all_changes_line_count(&empty),
        1,
        "empty diff renders the single empty-state line"
    );
}

/// The engine's KEV deadline and affected version were discarded before
/// render; the detail panel must now show both.
#[test]
fn diff_vuln_detail_shows_kev_deadline_and_affected_version() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let mut vuln = crate::model::VulnerabilityRef::new(
        "CVE-2024-1234".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    vuln.is_kev = true;
    let comp = crate::model::Component::new("liba".to_string(), "pkg:npm/liba@1.2.3".to_string())
        .with_version("1.2.3".to_string());
    let mut detail = crate::diff::VulnerabilityDetail::from_ref(&vuln, &comp);
    detail.kev_due_date = Some("2026-08-01".to_string());
    detail.days_until_due = Some(-5);
    diff.vulnerabilities.introduced.push(detail);

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("KEV due: 2026-08-01"),
        "detail panel must show the CISA deadline:\n{text}"
    );
    assert!(
        text.contains("5d overdue"),
        "overdue urgency must render:\n{text}"
    );
    assert!(
        text.contains("Affects: 1.2.3"),
        "affected version must render:\n{text}"
    );
}

/// VEX transitions must be summarized in the filter bar and marked on rows.
#[test]
fn diff_vuln_filter_bar_shows_vex_transitions() {
    pin_theme();
    let (mut diff, old, new) = demo_diff();

    let vref = crate::model::VulnerabilityRef::new(
        "CVE-2024-7777".to_string(),
        crate::model::VulnerabilitySource::Osv,
    );
    let comp = crate::model::Component::new("libv".to_string(), "pkg:npm/libv@1.0.0".to_string());
    diff.vulnerabilities
        .persistent
        .push(crate::diff::VulnerabilityDetail::from_ref(&vref, &comp));
    diff.vulnerabilities
        .vex_changes
        .push(crate::diff::VexStatusChange {
            vuln_id: "CVE-2024-7777".to_string(),
            component_name: "libv".to_string(),
            old_state: Some(crate::model::VexState::UnderInvestigation),
            new_state: Some(crate::model::VexState::NotAffected),
        });

    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = TabKind::Vulnerabilities;
    // Flat list mode: a collapsed component group would hide the row.
    app.vulnerabilities_state_mut().group_by_component = false;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        text.contains("VEX \u{394}:") && text.contains("1\u{2192}Not Affected"),
        "filter bar must summarize VEX transitions:\n{text}"
    );
    assert!(
        text.contains("\u{394} CVE-"),
        "the transitioned row must carry the delta marker (ID may truncate):\n{text}"
    );
}

/// Regression: the diff vuln filter bar hard-truncated its View toggle and
/// hints at 80 cols; the second row must carry them now.
#[test]
fn diff_vuln_filter_bar_hints_visible_at_80_cols() {
    let text = render_tab(TabKind::Vulnerabilities, 80, 24);
    assert!(
        text.contains("[f] filter"),
        "hints must be visible at 80 cols:\n{text}"
    );
    assert!(
        text.contains("View:"),
        "View toggle must be visible at 80 cols:\n{text}"
    );
}

/// Lock the Source detail bottom-strip layout ('d' previously squeezed both
/// panels to ~30 cols for a six-line side column).
#[test]
fn snapshot_source_detail_strip() {
    let mut app = demo_app(TabKind::Source);
    handle_key_event(&mut app, key(KeyCode::Char('d')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    insta::assert_snapshot!("diff_source_detail_80x24", text);
}

/// Clicking the tab-bar overflow markers must page hidden tabs into view
/// (they were previously plain truncation with no affordance at all).
#[test]
fn tab_marker_click_selects_adjacent_hidden_tab() {
    use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

    let mut app = demo_app(TabKind::Source);
    // Render at 80 cols so the bar windows around Source (last tab) and the
    // leading « marker appears; the render stashes the window geometry.
    let _ = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    assert!(
        app.tab_window.clipped_left,
        "Source at 80 cols must clip earlier tabs: {:?}",
        app.tab_window
    );
    let before = app.tab_window.start;

    crate::tui::events::handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0, // the « marker cell
            row: 1,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
    );
    let entries = crate::tui::ui::diff_tab_entries(&app);
    assert_eq!(
        app.active_tab,
        entries[before - 1].0,
        "« click must select the tab just left of the window"
    );
}

/// Regression: at 80x24 the Summary previously collapsed every box to ~1
/// line (empty Matching/Security Policy shells, 3 visible changes). The
/// compact strip + tall All Changes list must surface far more.
#[test]
fn compact_summary_shows_many_changes_at_80x24() {
    let text = render_tab(TabKind::Summary, 80, 24);
    assert!(
        text.contains("axios") && text.contains("- jquery"),
        "entries previously below the fold must be visible:\n{text}"
    );
    assert!(
        text.contains("Comp +4 -4 ~5"),
        "the dense stat strip must render:\n{text}"
    );
    assert!(
        !text.contains(" Matching ") && !text.contains("Changes by Ecosystem"),
        "compact mode must not render empty shells:\n{text}"
    );
}

/// Lock the mid-tier degradation (charts dropped, stats+insights kept) so
/// the cascade order cannot regress silently. Height 31 is the smallest that
/// keeps insights (content 24 = demand with insights, without charts); at 30
/// the insights row is dropped too and the tier would go unguarded.
#[test]
fn snapshot_summary_100x31() {
    let text = render_tab(TabKind::Summary, 100, 31);
    assert!(
        text.contains(" Matching ") && !text.contains("Changes by Ecosystem"),
        "100x31 must sit exactly in the charts-dropped, insights-kept tier:\n{text}"
    );
    insta::assert_snapshot!("diff_summary_100x31", text);
}

/// Regression: the Matrix 's' key changed the Sort label but never reordered
/// anything. Sort is a symmetric axis permutation; all consumers of
/// selected_row/col resolve raw indices through it.
#[test]
fn matrix_sort_reorders_axes_symmetrically() {
    use crate::tui::test_support::demo_matrix;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    // Default Name sort under the default Ascending direction: A -> Z.
    {
        let result = app.data.matrix_result.as_ref().unwrap();
        let order = ordered_sbom_indices(result, &app.tabs.matrix);
        let names: Vec<&str> = order
            .iter()
            .map(|&i| result.sboms[i].name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "Name ascending must be A->Z");
        let mut perm = order.clone();
        perm.sort_unstable();
        assert_eq!(perm, (0..result.sboms.len()).collect::<Vec<_>>());
    }

    // Name DESCENDING is a deterministic non-identity permutation
    // (gamma, beta, alpha) — the old inert sort rendered alpha first.
    app.tabs.matrix.sort_by = crate::tui::app::MatrixSortBy::Name;
    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Descending;
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    let gamma_row = text
        .lines()
        .position(|l| l.trim_start().starts_with("│gamma"))
        .expect("gamma must be a row label");
    let alpha_row = text
        .lines()
        .position(|l| l.trim_start().starts_with("│alpha"))
        .expect("alpha must be a row label");
    assert!(
        gamma_row < alpha_row,
        "Name descending must render gamma's row above alpha's:\n{text}"
    );
}

/// Cluster sort must group every cluster's members contiguously (the
/// block-diagonal heatmap property).
#[test]
fn cluster_sort_groups_members_contiguously() {
    use crate::tui::test_support::demo_matrix_large;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    // 8 SBOMs alternating between two identical contents: clustering yields
    // interleaved members ({v1,v3,..} vs {v2,v4,..}), so raw order is NOT
    // contiguous and an identity (no-op) sort fails this test.
    let mut app = App::new_matrix(demo_matrix_large());
    app.tabs.matrix.sort_by = crate::tui::app::MatrixSortBy::Cluster;
    app.tabs.matrix.sort_direction = crate::tui::app::SortDirection::Descending;
    let result = app.data.matrix_result.as_ref().unwrap();
    let order = ordered_sbom_indices(result, &app.tabs.matrix);
    let mut perm = order.clone();
    perm.sort_unstable();
    assert_eq!(perm, (0..result.sboms.len()).collect::<Vec<_>>());
    let clustering = result.clustering.as_ref().expect("fixture clusters");
    let mut multi_member = 0;
    let mut non_trivial = false;
    for cluster in &clustering.clusters {
        let positions: Vec<usize> = cluster
            .members
            .iter()
            .map(|m| order.iter().position(|&x| x == *m).unwrap())
            .collect();
        let (min, max) = (
            *positions.iter().min().unwrap(),
            *positions.iter().max().unwrap(),
        );
        assert_eq!(
            max - min + 1,
            positions.len(),
            "cluster members must occupy a contiguous run of the display order"
        );
        if cluster.members.len() > 1 {
            multi_member += 1;
            // Raw-order contiguity would make this test vacuous.
            let mut sorted_members = cluster.members.clone();
            sorted_members.sort_unstable();
            if sorted_members.windows(2).any(|w| w[1] != w[0] + 1) {
                non_trivial = true;
            }
        }
    }
    assert!(multi_member >= 2, "fixture must produce multiple clusters");
    assert!(
        non_trivial,
        "at least one cluster must be raw-discontiguous or the test can't discriminate"
    );
}

/// Regression: search matches were raw indices; under a sort Enter selected
/// a different SBOM than the one highlighted.
#[test]
fn matrix_search_selects_display_row_under_sort() {
    use crate::tui::test_support::demo_matrix;
    use crate::tui::views::ordered_sbom_indices;

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('s'))); // AvgSimilarity sort
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    for c in "gamma".chars() {
        handle_key_event(&mut app, key(KeyCode::Char(c)));
    }
    handle_key_event(&mut app, key(KeyCode::Enter));
    let result = app.data.matrix_result.as_ref().unwrap();
    let order = ordered_sbom_indices(result, &app.tabs.matrix);
    let raw = order[app.tabs.matrix.selected_row];
    assert!(
        result.sboms[raw].name.contains("gamma"),
        "Enter must select the row whose SBOM matched the query, got {}",
        result.sboms[raw].name
    );
}

/// New snapshots: sorted matrix, column focus dimming, and the 8-SBOM column
/// viewport at 80 cols.
#[test]
fn snapshot_matrix_interactions() {
    use crate::tui::test_support::{demo_matrix, demo_matrix_large};

    pin_theme();
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('s')));
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("matrix_sort_avg_80x24", text);

    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('c'))); // column focus
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("matrix_col_focus_80x24", text);

    let mut app = App::new_matrix(demo_matrix_large());
    for _ in 0..7 {
        handle_key_event(&mut app, key(KeyCode::Right));
    }
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("matrix_viewport_8sboms_80x24", text);
}

/// Regression: comparing v1 against any non-adjacent version reported "no
/// diff available" even though cumulative_from_first holds exactly that data.
#[test]
fn baseline_pair_resolves_cumulative_diff() {
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::resolve_version_diff;

    let result = demo_timeline();
    let diff = resolve_version_diff(&result, 0, 2).expect("baseline pair must resolve");
    let expected = &result.cumulative_from_first[1];
    assert_eq!(
        diff.summary.total_changes, expected.summary.total_changes,
        "0->2 must be the cumulative 0->2 diff"
    );
    // Symmetric: the same diff regardless of endpoint order.
    let rev = resolve_version_diff(&result, 2, 0).expect("reversed pair must resolve");
    assert_eq!(rev.summary.total_changes, expected.summary.total_changes);

    // Adjacent pairs still resolve incrementally.
    let adj = resolve_version_diff(&result, 1, 2).expect("adjacent pair must resolve");
    assert_eq!(
        adj.summary.total_changes,
        result.incremental_diffs[1].summary.total_changes
    );
    // Same version: nothing to diff.
    assert!(resolve_version_diff(&result, 1, 1).is_none());
}

/// The Sort control was inert under Changes/ComponentCount/Name.
#[test]
fn ordered_version_indices_is_truthful() {
    use crate::tui::app::{SortDirection, TimelineSortBy};
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::ordered_version_indices;

    pin_theme();
    let result = demo_timeline();
    let mut app = App::new_timeline(demo_timeline());

    // Chronological = identity.
    assert_eq!(
        ordered_version_indices(&result, &app.tabs.timeline),
        vec![0, 1, 2]
    );

    // Name ascending is A->Z (identity for v1/v2/v3); Descending must be the
    // reverse — the discriminating case an inert sort would fail.
    app.tabs.timeline.sort_by = TimelineSortBy::Name;
    app.tabs.timeline.sort_direction = SortDirection::Ascending;
    let order = ordered_version_indices(&result, &app.tabs.timeline);
    let names: Vec<&str> = order
        .iter()
        .map(|&i| result.sboms[i].name.as_str())
        .collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    assert_eq!(
        ordered_version_indices(&result, &app.tabs.timeline),
        vec![2, 1, 0],
        "Name descending is Z->A"
    );

    // Chronological honors the direction too ('S' was inert).
    app.tabs.timeline.sort_by = TimelineSortBy::Chronological;
    assert_eq!(
        ordered_version_indices(&result, &app.tabs.timeline),
        vec![2, 1, 0],
        "Chronological descending is newest-first"
    );
    app.tabs.timeline.sort_direction = SortDirection::Ascending;

    // Changes descending puts the largest incremental diff first.
    app.tabs.timeline.sort_by = TimelineSortBy::Changes;
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    let order = ordered_version_indices(&result, &app.tabs.timeline);
    let changes = |i: usize| {
        if i == 0 {
            0
        } else {
            result.incremental_diffs[i - 1].summary.total_changes
        }
    };
    assert!(
        changes(order[0]) >= changes(order[1]) && changes(order[1]) >= changes(order[2]),
        "Changes descending must be monotone"
    );
    let mut perm = order.clone();
    perm.sort_unstable();
    assert_eq!(perm, vec![0, 1, 2], "always a permutation");
}

/// Regression: 'g 1 Enter' after a sort selected whatever row sat at display
/// position 0 instead of version 1.
#[test]
fn jump_maps_raw_to_display_under_sort() {
    use crate::tui::app::{SortDirection, TimelineSortBy};
    use crate::tui::test_support::demo_timeline;
    use crate::tui::views::ordered_version_indices;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    // Name DESCENDING: v3,v2,v1 — a non-identity permutation, so an unmapped
    // jump (raw 0 as display 0) would select the WRONG row and fail.
    app.tabs.timeline.sort_by = TimelineSortBy::Name;
    app.tabs.timeline.sort_direction = SortDirection::Descending;
    {
        let result = app.data.timeline_result.as_ref().unwrap();
        let order = ordered_version_indices(result, &app.tabs.timeline);
        assert_ne!(
            order[0], 0,
            "precondition: permutation must be non-identity"
        );
    }

    handle_key_event(&mut app, key(KeyCode::Char('g')));
    handle_key_event(&mut app, key(KeyCode::Char('1')));
    handle_key_event(&mut app, key(KeyCode::Enter));

    let result = app.data.timeline_result.as_ref().unwrap();
    let order = ordered_version_indices(result, &app.tabs.timeline);
    assert_eq!(
        order[app.tabs.timeline.selected_version], 0,
        "the display selection must resolve to raw version 1"
    );

    // A rejected jump (out-of-range) must leave the selection untouched.
    let before = app.tabs.timeline.selected_version;
    handle_key_event(&mut app, key(KeyCode::Char('g')));
    handle_key_event(&mut app, key(KeyCode::Char('9')));
    handle_key_event(&mut app, key(KeyCode::Enter));
    assert_eq!(
        app.tabs.timeline.selected_version, before,
        "rejected jump must not move the selection"
    );
}

/// 'm' cycles the chart metric and falls back to Components when a series is
/// missing.
#[test]
fn chart_metric_cycles_and_falls_back() {
    use crate::tui::app::TimelineChartMetric;
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Components
    );
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Vulnerabilities
    );
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Dependencies
    );
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    assert_eq!(
        app.tabs.timeline.chart_metric,
        TimelineChartMetric::Components
    );

    // Fallback: strip the dependency series and the render must not panic
    // (falls back to component counts).
    let mut app = App::new_timeline(demo_timeline());
    app.data
        .timeline_result
        .as_mut()
        .unwrap()
        .evolution_summary
        .dependency_trend
        .clear();
    app.tabs.timeline.chart_metric = TimelineChartMetric::Dependencies;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("Components Evolution"),
        "missing series must fall back to the Components metric:\n{text}"
    );
}

/// New snapshots: sorted versions table, stats with license churn, and the
/// baseline cumulative diff modal.
#[test]
fn snapshot_timeline_interactions() {
    use crate::tui::test_support::demo_timeline;

    pin_theme();
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('s'))); // -> Changes sort
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    insta::assert_snapshot!("timeline_sort_changes_80x24", text);

    // 120x40: at 80x24 the squeezed Statistics panel clips the second stats
    // line, hiding exactly the License Δ figure this snapshot exists to lock.
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('t'))); // stats panel
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("License \u{394}:"),
        "stats must show the license churn figure:\n{text}"
    );
    insta::assert_snapshot!("timeline_stats_120x40", text);

    // The figure must read the per-step diffs (the old evolution_summary
    // field is never populated): inject one component license change and one
    // conflict and both must surface.
    let mut app = App::new_timeline(demo_timeline());
    {
        let result = app.data.timeline_result.as_mut().unwrap();
        result.incremental_diffs[0].licenses.component_changes.push(
            crate::diff::ComponentLicenseChange {
                component_id: "libx".to_string(),
                component_name: "libx".to_string(),
                old_licenses: vec!["MIT".to_string()],
                new_licenses: vec!["GPL-3.0-only".to_string()],
            },
        );
    }
    handle_key_event(&mut app, key(KeyCode::Char('t')));
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("License \u{394}: 1"),
        "the churn figure must read the per-step diffs:\n{text}"
    );

    // Select v3, open the diff modal, move compare to v1: the baseline
    // cumulative diff must render instead of "No precomputed diff".
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('j')));
    handle_key_event(&mut app, key(KeyCode::Char('j'))); // select v3
    handle_key_event(&mut app, key(KeyCode::Char('d'))); // modal (compare defaults)
    handle_key_event(&mut app, key(KeyCode::Left));
    handle_key_event(&mut app, key(KeyCode::Left)); // compare -> v1
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        !text.contains("No precomputed diff"),
        "v1<->v3 must resolve the cumulative diff:\n{text}"
    );
    insta::assert_snapshot!("timeline_modal_baseline_diff_80x24", text);
}

/// Regression: diff-tab clicks assumed 6 rows of chrome; every tab whose
/// chrome differs (or whose list is scrolled) selected the wrong row. The
/// click must land on the row under the cursor, located from the buffer.
#[test]
fn diff_list_click_selects_the_item_under_the_cursor() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let mut app = demo_app(TabKind::Components);
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let row = text
        .lines()
        .position(|line| line.contains("axios"))
        .expect("axios must render") as u16;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.components_state().selected,
        1,
        "axios is index 1 under the Name sort (click landed at row {row})"
    );
}

/// Same contract for the other mapped tabs: the demo diff has no vulns or
/// dependency changes, so build synthetic results.
#[test]
fn diff_vuln_and_dependency_clicks_select_under_cursor() {
    use crate::diff::DiffResult;
    use crate::model::NormalizedSbom;
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    // Vulnerabilities: three introduced vulns, click the second row.
    let mut result = DiffResult::default();
    for (i, name) in ["libv-a", "libv-b", "libv-c"].iter().enumerate() {
        let vref = crate::model::VulnerabilityRef::new(
            format!("CVE-2024-9{i:02}"),
            crate::model::VulnerabilitySource::Osv,
        );
        let comp =
            crate::model::Component::new((*name).to_string(), format!("pkg:npm/{name}@1.0.0"));
        result
            .vulnerabilities
            .introduced
            .push(crate::diff::VulnerabilityDetail::from_ref(&vref, &comp));
    }
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Vulnerabilities;
    // Flat list: grouped rows have their own geometry.
    app.vulnerabilities_state_mut().group_by_component = false;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let rows: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("+ NEW"))
        .map(|(i, _)| i)
        .collect();
    assert!(rows.len() >= 2, "vuln rows must render:\n{text}");
    let row = rows[1] as u16;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.vulnerabilities_state().selected,
        1,
        "click must select the vuln under the cursor (row {row})"
    );

    // Dependencies: three added edges, click the third row.
    let mut result = DiffResult::default();
    for (i, to) in ["dep-a", "dep-b", "dep-c"].iter().enumerate() {
        result
            .dependencies
            .added
            .push(crate::diff::DependencyChange {
                from: format!("root-{i}"),
                to: (*to).to_string(),
                relationship: "depends_on".to_string(),
                scope: None,
                change_type: crate::diff::ChangeType::Added,
            });
    }
    let mut app = App::new_diff(
        result,
        NormalizedSbom::default(),
        NormalizedSbom::default(),
        "{}",
        "{}",
    );
    app.active_tab = TabKind::Dependencies;
    // Two frames: the first prepare_render builds the graph cache AFTER the
    // visible-node list; the second sees the populated roots (production
    // renders every frame, so this staleness self-corrects immediately).
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // The tree renders roots; its selectable line list starts with the
    // "Changes:" header (0) and a spacer (1), so root-2 is index 4 — the
    // same index the keyboard reaches.
    let row = text
        .lines()
        .position(|line| line.contains("root-2"))
        .unwrap_or_else(|| panic!("third root must render:\n{text}")) as u16;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.dependencies_state().selected,
        4,
        "click must select the line under the cursor (row {row})"
    );
}

/// Timeline clicks select the version row under the cursor, with and without
/// the statistics panel shifting the layout.
#[test]
fn timeline_click_selects_version_under_cursor() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::demo_timeline;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    for stats in [false, true] {
        let mut app = App::new_timeline(demo_timeline());
        if stats {
            handle_key_event(&mut app, key(KeyCode::Char('t')));
        }
        let text = render_to_text(80, 24, |frame| {
            app.prepare_render();
            crate::tui::ui::render(frame, &mut app);
        });
        let row = text
            .lines()
            .position(|line| line.contains("v2"))
            .expect("v2 must render") as u16;
        handle_mouse_event(
            &mut app,
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row,
                modifiers: KeyModifiers::empty(),
            },
        );
        assert_eq!(
            app.tabs.timeline.selected_version, 1,
            "click must select v2 (stats={stats}, row {row})"
        );
    }
}

/// Regression: with the selection scrolled past the viewport, ratatui
/// auto-scrolls the table but the click math ignored it.
#[test]
fn diff_click_accounts_for_scroll() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let mut app = demo_app(TabKind::Components);
    // First render populates the navigation totals select_down clamps on.
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    // Drive the selection past the 11-row viewport at 80x24.
    for _ in 0..12 {
        app.select_down();
    }
    render_to_text(80, 24, |frame| {
        app.prepare_render();
        render(frame, &mut app);
    });
    let visible_rows = 24 - 13;
    let expected_offset = app
        .components_state()
        .selected
        .saturating_sub(visible_rows - 1);
    assert!(expected_offset > 0, "selection must be past the viewport");
    // Click the FIRST visible data row (row 10): must select the offset item,
    // not item 0.
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 10,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.components_state().selected,
        expected_offset,
        "the first visible row is the auto-scroll offset item"
    );
}

/// The wheel must move the selection in all three multi modes (previously a
/// no-op or a mis-route into the diff tab logic).
#[test]
fn multi_mode_wheel_moves_selection() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};

    pin_theme();
    let wheel = |kind| MouseEvent {
        kind,
        column: 10,
        row: 12,
        modifiers: KeyModifiers::empty(),
    };

    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.tabs.multi_diff.selected_target, 1);
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollUp));
    assert_eq!(app.tabs.multi_diff.selected_target, 0);

    let mut app = App::new_timeline(demo_timeline());
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.tabs.timeline.selected_version, 1);

    let mut app = App::new_matrix(demo_matrix());
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.tabs.matrix.selected_row, 1);
    handle_mouse_event(&mut app, wheel(MouseEventKind::ScrollRight));
    assert_eq!(app.tabs.matrix.selected_col, 2);
}

/// Clicks in the Multi-Diff targets list select the row under the cursor;
/// clicks in the top rows must NOT fall through to the diff tab bar.
#[test]
fn multi_diff_click_selects_target() {
    use crate::tui::events::mouse::handle_mouse_event;
    use crate::tui::test_support::demo_multi_diff;
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

    pin_theme();
    let mut app = App::new_multi_diff(demo_multi_diff());
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    // Under the Name sort ai-service is display index 0; webapp is 1. The
    // details-panel title also contains "ai-service", so anchor on webapp.
    let row = text
        .lines()
        .position(|line| line.contains("webapp"))
        .expect("second target must render") as u16;
    let tab_before = app.active_tab;
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.tabs.multi_diff.selected_target, 1,
        "click must select the second target (row {row})"
    );

    // A click at y<=2 previously mis-routed into select_tab.
    handle_mouse_event(
        &mut app,
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 5,
            row: 1,
            modifiers: KeyModifiers::empty(),
        },
    );
    assert_eq!(
        app.active_tab, tab_before,
        "multi-mode clicks must not reach the diff tab bar"
    );
}

/// Multi-mode chrome: status feedback renders (previously silently dropped),
/// shared footer hints, heatmap glyphs, and degenerate-state chrome.
#[test]
fn snapshot_multi_mode_chrome() {
    use crate::tui::test_support::{demo_matrix, demo_multi_diff, demo_timeline};

    pin_theme();
    // Status message replaces the hints for the frame.
    let mut app = App::new_matrix(demo_matrix());
    app.set_status_message("Threshold: >= 90%".to_string());
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("Threshold: >= 90%"),
        "the status message must render:\n{text}"
    );
    insta::assert_snapshot!("matrix_status_message_80x24", text);

    // Heatmap: the magnitude glyphs are text-visible at 120 cols (at 80 the
    // Deviation column truncates them away; the digits keep priority).
    let mut app = App::new_multi_diff(demo_multi_diff());
    app.tabs.multi_diff.heat_map_mode = true;
    // The demo's engine deviations are pathological (10000%); realistic
    // magnitudes keep the glyph inside the Deviation column.
    for v in app
        .data
        .multi_diff_result
        .as_mut()
        .unwrap()
        .summary
        .deviation_scores
        .values_mut()
    {
        *v = 0.35;
    }
    let text = render_to_text(120, 40, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains('\u{2587}')
            || text.contains('\u{2585}')
            || text.contains('\u{2583}')
            || text.contains('\u{2581}'),
        "deviation magnitude glyphs must render at 120 cols:\n{text}"
    );
    insta::assert_snapshot!("multi_dashboard_heatmap_120x40", text);

    // Single-SBOM matrix: enhanced empty state instead of a lone '-' table.
    let mut single = demo_matrix();
    single.sboms.truncate(1);
    single.similarity_scores.clear();
    single.diffs.clear();
    single.clustering = None;
    let mut app = App::new_matrix(single);
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("Need at least 2 SBOMs"),
        "degenerate matrix must explain itself:\n{text}"
    );
    insta::assert_snapshot!("matrix_single_sbom_80x24", text);

    // Zero-match component filter: shared no-results state.
    let mut app = App::new_timeline(demo_timeline());
    // Cycle to a filter with no matches: Stable requires current == first
    // version; if the fixture has stable components, fall back to asserting
    // the no-results copy via an impossible filter by emptying the data.
    app.data
        .timeline_result
        .as_mut()
        .unwrap()
        .evolution_summary
        .components_added
        .clear();
    app.data
        .timeline_result
        .as_mut()
        .unwrap()
        .evolution_summary
        .components_removed
        .clear();
    app.tabs.timeline.total_components = 0;
    let text = render_to_text(80, 24, |frame| {
        app.prepare_render();
        crate::tui::ui::render(frame, &mut app);
    });
    assert!(
        text.contains("No results"),
        "empty component history must use the shared no-results state:\n{text}"
    );
    insta::assert_snapshot!("timeline_filter_no_results_80x24", text);
}
