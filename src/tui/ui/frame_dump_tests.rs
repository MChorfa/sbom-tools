//! Env-gated frame-dump generator for offline UX review of the diff `App` TUI.
//!
//! Does nothing unless `TUI_FRAME_DUMP_DIR` is set. When set, renders every
//! diff tab (for SBOM, CBOM, and AI-BOM diffs), every multi-comparison mode,
//! and the overlay/interaction states to plain-text frames under
//! `$TUI_FRAME_DUMP_DIR/diff/`, with a `MANIFEST.tsv` describing each frame.
//!
//! Run:
//! ```sh
//! TUI_FRAME_DUMP_DIR=/tmp/frames cargo test --lib tui::ui::frame_dump_tests
//! ```

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{App, TabKind, render};
use crate::diff::DiffEngine;
use crate::parsers::parse_sbom_str;
use crate::tui::events::handle_key_event;
use crate::tui::test_support::{
    DEMO_NEW, DEMO_OLD, SIZES, demo_diff, demo_matrix, demo_matrix_large, demo_multi_diff,
    demo_timeline, pin_theme, render_to_text,
};

const CBOM_OLD: &str = include_str!("../../../tests/fixtures/cyclonedx/cbom-1.6.cdx.json");
const CBOM_NEW: &str = include_str!("../../../tests/fixtures/cyclonedx/cbom-1.7.cdx.json");
const AIBOM_OLD: &str = include_str!("../../../tests/fixtures/cyclonedx/aibom-complete.cdx.json");
const AIBOM_NEW: &str =
    include_str!("../../../tests/fixtures/cyclonedx/bsi-aibom-complete.cdx.json");

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

struct Dumper {
    dir: PathBuf,
    manifest: Vec<String>,
}

impl Dumper {
    fn new(sub: &str) -> Option<Self> {
        let root = std::env::var("TUI_FRAME_DUMP_DIR").ok()?;
        let dir = PathBuf::from(root).join(sub);
        fs::create_dir_all(&dir).expect("create dump dir");
        Some(Self {
            dir,
            manifest: Vec::new(),
        })
    }

    fn dump(&mut self, name: &str, desc: &str, text: &str) {
        fs::write(self.dir.join(format!("{name}.txt")), text).expect("write frame");
        self.manifest.push(format!("{name}.txt\t{desc}"));
    }

    fn finish(&self) {
        fs::write(self.dir.join("MANIFEST.tsv"), self.manifest.join("\n")).expect("write manifest");
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn chars(app: &mut App, s: &str) {
    for c in s.chars() {
        handle_key_event(app, key(KeyCode::Char(c)));
    }
}

fn frame(app: &mut App, w: u16, h: u16) -> String {
    render_to_text(w, h, |f| {
        app.prepare_render();
        render(f, app);
    })
}

fn diff_app(old_src: &str, new_src: &str, tab: TabKind) -> App {
    pin_theme();
    let old = parse_sbom_str(old_src).expect("old fixture must parse");
    let new = parse_sbom_str(new_src).expect("new fixture must parse");
    let diff = DiffEngine::new()
        .diff(&old, &new)
        .expect("diff must succeed");
    let mut app = App::new_diff(diff, old, new, old_src, new_src);
    app.active_tab = tab;
    app
}

fn demo_app(tab: TabKind) -> App {
    pin_theme();
    let (diff, old, new) = demo_diff();
    let mut app = App::new_diff(diff, old, new, DEMO_OLD, DEMO_NEW);
    app.active_tab = tab;
    app
}

/// All ten diff tabs, three BOM profiles, both terminal sizes.
#[test]
fn dump_diff_tab_frames() {
    let Some(mut d) = Dumper::new("diff") else {
        return;
    };

    for (name, tab) in DIFF_TABS {
        for (w, h) in SIZES {
            let mut app = demo_app(tab);
            d.dump(
                &format!("sbom_{name}_{w}x{h}"),
                &format!("SBOM demo diff, {name} tab, no interaction, {w}x{h}"),
                &frame(&mut app, w, h),
            );
        }
        // CBOM and AI-BOM diffs: wide frame for content review, narrow for the
        // four most information-dense tabs.
        for (profile, old_src, new_src) in [
            ("cbom", CBOM_OLD, CBOM_NEW),
            ("aibom", AIBOM_OLD, AIBOM_NEW),
        ] {
            let mut app = diff_app(old_src, new_src, tab);
            d.dump(
                &format!("{profile}_{name}_120x40"),
                &format!("{profile} diff ({profile} old vs new fixture), {name} tab, 120x40"),
                &frame(&mut app, 120, 40),
            );
            if matches!(
                tab,
                TabKind::Summary | TabKind::Components | TabKind::Quality | TabKind::Compliance
            ) {
                let mut app = diff_app(old_src, new_src, tab);
                d.dump(
                    &format!("{profile}_{name}_80x24"),
                    &format!("{profile} diff, {name} tab, 80x24"),
                    &frame(&mut app, 80, 24),
                );
            }
        }
    }
    d.finish();
}

/// Overlays and interaction sequences on the demo SBOM diff.
#[test]
fn dump_diff_interaction_frames() {
    let Some(mut d) = Dumper::new("diff_interactions") else {
        return;
    };

    // Shortcuts overlay ('?'), fresh + scrolled.
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    d.dump(
        "overlay_shortcuts_120x40",
        "Summary tab, pressed '?': shortcuts overlay",
        &frame(&mut app, 120, 40),
    );
    d.dump(
        "overlay_shortcuts_80x24",
        "Summary tab, pressed '?': shortcuts overlay at 80x24",
        &frame(&mut app, 80, 24),
    );
    chars(&mut app, "jjj");
    d.dump(
        "overlay_shortcuts_scrolled_80x24",
        "Shortcuts overlay after jjj (scrolled)",
        &frame(&mut app, 80, 24),
    );

    // Shortcuts overlay is tab-contextual: capture it from a second tab.
    let mut app = demo_app(TabKind::Vulnerabilities);
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    d.dump(
        "overlay_shortcuts_vulns_120x40",
        "Vulnerabilities tab, pressed '?': shortcuts overlay (This-Tab section)",
        &frame(&mut app, 120, 40),
    );

    // Export overlay.
    let mut app = demo_app(TabKind::Summary);
    handle_key_event(&mut app, key(KeyCode::Char('e')));
    d.dump(
        "overlay_export_120x40",
        "Summary tab, pressed 'e': export overlay",
        &frame(&mut app, 120, 40),
    );
    d.dump(
        "overlay_export_80x24",
        "Export overlay at 80x24",
        &frame(&mut app, 80, 24),
    );

    // Legend overlay.
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::Char('l')));
    d.dump(
        "overlay_legend_120x40",
        "Components tab, pressed 'l': legend overlay",
        &frame(&mut app, 120, 40),
    );

    // Threshold tuning overlay. No key opens it in Diff mode (the '?'/docs may
    // still claim one — evaluators: cross-check); invoke the toggle directly so
    // the overlay itself is still reviewed.
    let mut app = demo_app(TabKind::Components);
    app.toggle_threshold_tuning();
    d.dump(
        "overlay_threshold_120x40",
        "Components tab, threshold tuning overlay (opened programmatically; no Diff-mode key binds it)",
        &frame(&mut app, 120, 40),
    );

    // Component deep dive.
    let mut app = demo_app(TabKind::Components);
    chars(&mut app, "jj");
    handle_key_event(&mut app, key(KeyCode::Char('D')));
    d.dump(
        "overlay_deep_dive_120x40",
        "Components tab, jj then 'D': component deep-dive overlay",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Tab));
    d.dump(
        "overlay_deep_dive_tab2_120x40",
        "Deep-dive overlay after Tab (second panel)",
        &frame(&mut app, 120, 40),
    );

    // Search: typing state and accepted state.
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    chars(&mut app, "ssl");
    d.dump(
        "search_typing_120x40",
        "Components tab, '/' then typing 'ssl' (search input visible)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Enter));
    d.dump(
        "search_accepted_120x40",
        "Search accepted with Enter: filtered components",
        &frame(&mut app, 120, 40),
    );

    // Selection movement + per-tab detail (Enter) on the list tabs.
    for (name, tab) in [
        ("components", TabKind::Components),
        ("dependencies", TabKind::Dependencies),
        ("licenses", TabKind::Licenses),
        ("vulnerabilities", TabKind::Vulnerabilities),
        ("graph", TabKind::GraphChanges),
    ] {
        let mut app = demo_app(tab);
        chars(&mut app, "jj");
        d.dump(
            &format!("select_{name}_120x40"),
            &format!("{name} tab after jj (selection moved down twice)"),
            &frame(&mut app, 120, 40),
        );
        handle_key_event(&mut app, key(KeyCode::Enter));
        d.dump(
            &format!("enter_{name}_120x40"),
            &format!("{name} tab after jj + Enter (detail/drill state, if any)"),
            &frame(&mut app, 120, 40),
        );
    }

    // Digit tab jumps 7/8/9/0 pressed from Vulnerabilities (digits are
    // global tab-select on every tab; quick filters live behind 'Q').
    let mut app = demo_app(TabKind::Vulnerabilities);
    for k in ['7', '8', '9', '0'] {
        handle_key_event(&mut app, key(KeyCode::Char(k)));
        d.dump(
            &format!("digit_jump_{k}_120x40"),
            &format!("after pressing '{k}' (global digit tab jump)"),
            &frame(&mut app, 120, 40),
        );
    }

    // The 'Q' quick-filter picker on Components: open, toggle filter 1, close.
    let mut app = demo_app(TabKind::Components);
    handle_key_event(&mut app, key(KeyCode::Char('Q')));
    d.dump(
        "quick_filter_picker_120x40",
        "Components tab: 'Q' quick-filter picker modal open",
        &frame(&mut app, 120, 40),
    );
    chars(&mut app, "1");
    d.dump(
        "quick_filter_picker_toggled_120x40",
        "picker: '1' toggled the High Risk quick filter (active marker)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Esc));
    d.dump(
        "quick_filter_active_chip_120x40",
        "picker closed: active-filter chip visible in the toolbar",
        &frame(&mut app, 120, 40),
    );

    // Copy feedback ('y') and back-nav ('b').
    let mut app = demo_app(TabKind::Components);
    chars(&mut app, "j");
    handle_key_event(&mut app, key(KeyCode::Char('y')));
    d.dump(
        "copy_feedback_120x40",
        "Components tab, j then 'y': copy-to-clipboard status feedback",
        &frame(&mut app, 120, 40),
    );

    d.finish();
}

/// Multi-diff, timeline, and matrix modes with their drill-down states.
#[test]
fn dump_multi_mode_frames() {
    let Some(mut d) = Dumper::new("diff_multi") else {
        return;
    };
    pin_theme();

    // ── 1:N multi-diff dashboard ──
    for (w, h) in SIZES {
        let mut app = App::new_multi_diff(demo_multi_diff());
        d.dump(
            &format!("multi_dashboard_{w}x{h}"),
            &format!("Multi-diff dashboard (baseline vs webapp + ai-service), {w}x{h}"),
            &frame(&mut app, w, h),
        );
    }
    let mut app = App::new_multi_diff(demo_multi_diff());
    chars(&mut app, "jj");
    d.dump(
        "multi_dashboard_jj_120x40",
        "Multi-diff dashboard after jj (row selection)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Char('v')));
    d.dump(
        "multi_variable_drilldown_120x40",
        "Multi-diff dashboard after 'v': variable-components drill-down modal",
        &frame(&mut app, 120, 40),
    );
    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    d.dump(
        "multi_shortcuts_120x40",
        "Multi-diff dashboard, pressed '?': shortcuts overlay (MultiDiff context)",
        &frame(&mut app, 120, 40),
    );
    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_key_event(&mut app, key(KeyCode::Char('V')));
    d.dump(
        "multi_view_switcher_120x40",
        "Multi-diff dashboard, pressed 'V': view switcher overlay",
        &frame(&mut app, 120, 40),
    );
    let mut app = App::new_multi_diff(demo_multi_diff());
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    chars(&mut app, "web");
    d.dump(
        "multi_search_120x40",
        "Multi-diff dashboard, '/' + 'web' (search)",
        &frame(&mut app, 120, 40),
    );

    // ── Timeline ──
    for (w, h) in SIZES {
        let mut app = App::new_timeline(demo_timeline());
        d.dump(
            &format!("timeline_{w}x{h}"),
            &format!("Timeline v1->v2->v3, {w}x{h}"),
            &frame(&mut app, w, h),
        );
    }
    let mut app = App::new_timeline(demo_timeline());
    chars(&mut app, "j");
    d.dump(
        "timeline_j_120x40",
        "Timeline after j (version selection moved)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Char('d')));
    d.dump(
        "timeline_d_120x40",
        "Timeline after 'd' (diff details for selected pair)",
        &frame(&mut app, 120, 40),
    );
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Enter));
    d.dump(
        "timeline_component_history_120x40",
        "Timeline after Enter: component version-history modal",
        &frame(&mut app, 120, 40),
    );
    d.dump(
        "timeline_component_history_80x24",
        "Timeline component version-history modal at 80x24",
        &frame(&mut app, 80, 24),
    );
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('m')));
    d.dump(
        "timeline_m_120x40",
        "Timeline after 'm' (metric toggle)",
        &frame(&mut app, 120, 40),
    );
    let mut app = App::new_timeline(demo_timeline());
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    d.dump(
        "timeline_shortcuts_120x40",
        "Timeline, pressed '?': shortcuts overlay (Timeline context)",
        &frame(&mut app, 120, 40),
    );

    // ── Matrix (8 SBOMs so the viewport clips at 80 cols) ──
    for (w, h) in SIZES {
        let mut app = App::new_matrix(demo_matrix_large());
        d.dump(
            &format!("matrix_large_{w}x{h}"),
            &format!("Matrix 8x8, {w}x{h}"),
            &frame(&mut app, w, h),
        );
    }
    let mut app = App::new_matrix(demo_matrix());
    d.dump(
        "matrix_3_120x40",
        "Matrix 3x3 (alpha/beta/gamma with clustering)",
        &frame(&mut app, 120, 40),
    );
    chars(&mut app, "lj");
    d.dump(
        "matrix_3_lj_120x40",
        "Matrix 3x3 after l+j (cell selection moved)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Enter));
    d.dump(
        "matrix_pair_diff_120x40",
        "Matrix 3x3 after Enter: pair-diff drilldown modal",
        &frame(&mut app, 120, 40),
    );
    d.dump(
        "matrix_pair_diff_80x24",
        "Matrix pair-diff drilldown modal at 80x24",
        &frame(&mut app, 80, 24),
    );
    let mut app = App::new_matrix(demo_matrix());
    handle_key_event(&mut app, key(KeyCode::Char('?')));
    d.dump(
        "matrix_shortcuts_120x40",
        "Matrix, pressed '?': shortcuts overlay (Matrix context)",
        &frame(&mut app, 120, 40),
    );

    d.finish();
}
