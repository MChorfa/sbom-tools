//! Env-gated frame-dump generator for offline UX review of the single-SBOM
//! `ViewApp` TUI.
//!
//! Does nothing unless `TUI_FRAME_DUMP_DIR` is set. When set, renders every
//! profile tab set (SBOM / CBOM / AI-BOM) over a spread of fixtures, plus
//! overlay/interaction/edge states, to plain-text frames under
//! `$TUI_FRAME_DUMP_DIR/view/`, with a `MANIFEST.tsv` describing each frame.
//!
//! Run:
//! ```sh
//! TUI_FRAME_DUMP_DIR=/tmp/frames cargo test --lib tui::view::ui::frame_dump_tests
//! ```

use std::fs;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{ViewApp, ViewTab, render};
use crate::model::BomProfile;
use crate::parsers::parse_sbom_str;
use crate::tui::test_support::{AIBOM_BSI, CBOM, DEMO_NEW, SIZES, pin_theme, render_to_text};
use crate::tui::view::events::handle_key_event;

const MINIMAL_SBOM: &str = include_str!("../../../../tests/fixtures/cyclonedx/minimal.cdx.json");
const WITH_VULNS: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/with-vulnerabilities.cdx.json");
const CBOM_WEAK: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/cbom-weak-crypto.cdx.json");
const CBOM_CNSA2_VIOLATIONS: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/cbom-cnsa2-violations.cdx.json");
const CBOM_UNCLASSIFIABLE: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/cbom-unclassifiable-refs.cdx.json");
const HF_DATASET_AIBOM: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/hf-dataset-aibom.cdx.json");
const MINIMAL_MLBOM: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/minimal-mlbom.cdx.json");
const MISTYPED_MLBOM: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/mistyped-mlbom.cdx.json");
const UNTYPED_HF_MODEL: &str =
    include_str!("../../../../tests/fixtures/cyclonedx/untyped-hf-model.cdx.json");
const SPDX3_AI_DATASET: &str =
    include_str!("../../../../tests/fixtures/spdx3/ai-dataset.spdx3.json");

/// Synthetic layout-stress SBOM: overlong names, wide Unicode (CJK/emoji/RTL),
/// deep license expressions, missing versions.
const STRESS_SBOM: &str = r##"{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:00:00Z",
    "component": { "type": "application", "name": "stress-test-app", "version": "1.0.0" }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:maven/com.example/very-long@9.9.9",
      "group": "com.example.organization.division.team.subteam.project",
      "name": "extremely-long-component-name-that-should-be-truncated-gracefully-in-every-view-and-not-break-the-layout-or-overlap-neighboring-columns-0123456789",
      "version": "1.0.0-alpha.1.preview.2+build.9876543210.sha.deadbeefcafe",
      "licenses": [{ "expression": "(Apache-2.0 OR MIT) AND (GPL-3.0-only WITH Classpath-exception-2.0)" }]
    },
    {
      "type": "library",
      "bom-ref": "unicode-lib",
      "name": "网络安全组件-🚀-مكتبة-Ünïcödé-ライブラリ",
      "version": "2.0.0",
      "licenses": [{ "license": { "id": "MIT" } }]
    },
    {
      "type": "library",
      "bom-ref": "bare-lib",
      "name": "bare"
    }
  ],
  "dependencies": [
    { "ref": "pkg:maven/com.example/very-long@9.9.9", "dependsOn": ["unicode-lib", "bare-lib"] }
  ]
}"##;

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

fn chars(app: &mut ViewApp, s: &str) {
    for c in s.chars() {
        handle_key_event(app, key(KeyCode::Char(c)));
    }
}

fn frame(app: &mut ViewApp, w: u16, h: u16) -> String {
    render_to_text(w, h, |f| render(f, app))
}

fn view_app(src: &str, tab: Option<ViewTab>) -> ViewApp {
    pin_theme();
    let sbom = parse_sbom_str(src).expect("fixture must parse");
    let profile = BomProfile::detect(&sbom);
    let mut app = ViewApp::new(sbom, src, profile);
    app.active_tab = tab.unwrap_or(ViewTab::Overview);
    app
}

const fn tab_slug(tab: ViewTab) -> &'static str {
    match tab {
        ViewTab::Overview => "overview",
        ViewTab::Quality => "quality",
        ViewTab::Source => "source",
        ViewTab::Tree => "tree",
        ViewTab::Vulnerabilities => "vulnerabilities",
        ViewTab::Licenses => "licenses",
        ViewTab::Dependencies => "dependencies",
        ViewTab::Compliance => "compliance",
        ViewTab::Algorithms => "algorithms",
        ViewTab::Certificates => "certificates",
        ViewTab::Keys => "keys",
        ViewTab::Protocols => "protocols",
        ViewTab::PqcCompliance => "pqc_compliance",
        ViewTab::Crypto => "crypto",
        ViewTab::Models => "models",
        ViewTab::Datasets => "datasets",
        ViewTab::AiReadiness => "ai_readiness",
    }
}

/// Dump every tab of the detected profile for `src` under `tag_` prefixed names.
fn dump_all_tabs(d: &mut Dumper, tag: &str, src: &str, both_sizes: bool) {
    pin_theme();
    let sbom = parse_sbom_str(src).expect("fixture must parse");
    let profile = BomProfile::detect(&sbom);
    for &tab in ViewTab::tabs_for_profile(profile) {
        let sizes: &[(u16, u16)] = if both_sizes { &SIZES } else { &[(120, 40)] };
        for &(w, h) in sizes {
            let mut app = view_app(src, Some(tab));
            d.dump(
                &format!("{tag}_{}_{w}x{h}", tab_slug(tab)),
                &format!(
                    "{tag} fixture (detected profile: {profile:?}), {} tab, {w}x{h}",
                    tab_slug(tab)
                ),
                &frame(&mut app, w, h),
            );
        }
    }
}

/// Every tab for every fixture/profile combination.
#[test]
fn dump_view_tab_frames() {
    let Some(mut d) = Dumper::new("view") else {
        return;
    };

    // Primary fixture per profile: both terminal sizes.
    dump_all_tabs(&mut d, "sbom_demo", DEMO_NEW, true);
    dump_all_tabs(&mut d, "cbom", CBOM, true);
    dump_all_tabs(&mut d, "aibom_bsi", AIBOM_BSI, true);

    // Content/edge spread: wide frames only.
    dump_all_tabs(&mut d, "sbom_minimal", MINIMAL_SBOM, false);
    dump_all_tabs(&mut d, "sbom_vulns", WITH_VULNS, false);
    dump_all_tabs(&mut d, "cbom_weak", CBOM_WEAK, false);
    dump_all_tabs(
        &mut d,
        "cbom_cnsa2_violations",
        CBOM_CNSA2_VIOLATIONS,
        false,
    );
    dump_all_tabs(&mut d, "cbom_unclassifiable", CBOM_UNCLASSIFIABLE, false);
    dump_all_tabs(&mut d, "aibom_hf_dataset", HF_DATASET_AIBOM, false);
    dump_all_tabs(&mut d, "mlbom_minimal", MINIMAL_MLBOM, false);
    dump_all_tabs(&mut d, "mlbom_mistyped", MISTYPED_MLBOM, false);
    dump_all_tabs(&mut d, "hf_model_untyped", UNTYPED_HF_MODEL, false);
    dump_all_tabs(&mut d, "stress_unicode", STRESS_SBOM, false);
    if parse_sbom_str(SPDX3_AI_DATASET).is_ok() {
        dump_all_tabs(&mut d, "spdx3_ai_dataset", SPDX3_AI_DATASET, false);
    }

    // Layout-stress fixture at the narrow size too (truncation behaviour).
    for &tab in ViewTab::tabs_for_profile(BomProfile::Sbom) {
        let mut app = view_app(STRESS_SBOM, Some(tab));
        d.dump(
            &format!("stress_unicode_{}_80x24", tab_slug(tab)),
            &format!("stress/unicode fixture, {} tab, 80x24", tab_slug(tab)),
            &frame(&mut app, 80, 24),
        );
    }

    // Tiny-terminal degradation.
    for (tag, src) in [("sbom_demo", DEMO_NEW), ("cbom", CBOM)] {
        let mut app = view_app(src, None);
        d.dump(
            &format!("{tag}_overview_60x16"),
            &format!("{tag} overview at a tiny 60x16 terminal"),
            &frame(&mut app, 60, 16),
        );
    }

    d.finish();
}

/// Overlays, drill-downs, search, and profile-cycling states.
#[test]
fn dump_view_interaction_frames() {
    let Some(mut d) = Dumper::new("view_interactions") else {
        return;
    };

    // Help overlay per profile (content is profile/tab-contextual).
    for (tag, src) in [("sbom", DEMO_NEW), ("cbom", CBOM), ("aibom", AIBOM_BSI)] {
        let mut app = view_app(src, None);
        handle_key_event(&mut app, key(KeyCode::Char('?')));
        d.dump(
            &format!("help_{tag}_120x40"),
            &format!("{tag} profile, pressed '?': help overlay"),
            &frame(&mut app, 120, 40),
        );
        d.dump(
            &format!("help_{tag}_80x24"),
            &format!("{tag} profile help overlay at 80x24"),
            &frame(&mut app, 80, 24),
        );
        chars(&mut app, "jjj");
        d.dump(
            &format!("help_{tag}_scrolled_80x24"),
            &format!("{tag} help overlay after jjj (scrolled)"),
            &frame(&mut app, 80, 24),
        );
    }

    // Export + legend overlays.
    let mut app = view_app(DEMO_NEW, None);
    handle_key_event(&mut app, key(KeyCode::Char('e')));
    d.dump(
        "export_sbom_120x40",
        "SBOM overview, pressed 'e': export overlay",
        &frame(&mut app, 120, 40),
    );
    let mut app = view_app(DEMO_NEW, Some(ViewTab::Tree));
    handle_key_event(&mut app, key(KeyCode::Char('l')));
    d.dump(
        "legend_sbom_120x40",
        "SBOM tree, pressed 'l': legend overlay",
        &frame(&mut app, 120, 40),
    );

    // SBOM interactions: tree expand + filter, vuln/license/dep drill-down.
    let mut app = view_app(DEMO_NEW, Some(ViewTab::Tree));
    handle_key_event(&mut app, key(KeyCode::Enter));
    d.dump(
        "tree_enter_120x40",
        "SBOM tree after Enter (expand/collapse or detail)",
        &frame(&mut app, 120, 40),
    );
    let mut app = view_app(DEMO_NEW, Some(ViewTab::Tree));
    handle_key_event(&mut app, key(KeyCode::Char('/')));
    chars(&mut app, "ssl");
    d.dump(
        "tree_filter_typing_120x40",
        "SBOM tree, '/' + 'ssl' typed (inline filter active)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Enter));
    d.dump(
        "tree_filter_accepted_120x40",
        "SBOM tree filter accepted with Enter",
        &frame(&mut app, 120, 40),
    );

    for (name, tab, fixture) in [
        ("vuln", ViewTab::Vulnerabilities, WITH_VULNS),
        ("license", ViewTab::Licenses, DEMO_NEW),
        ("dependency", ViewTab::Dependencies, DEMO_NEW),
        ("compliance", ViewTab::Compliance, DEMO_NEW),
    ] {
        let mut app = view_app(fixture, Some(tab));
        chars(&mut app, "jj");
        d.dump(
            &format!("{name}_jj_120x40"),
            &format!("{name} tab after jj (selection moved)"),
            &frame(&mut app, 120, 40),
        );
        handle_key_event(&mut app, key(KeyCode::Enter));
        d.dump(
            &format!("{name}_enter_120x40"),
            &format!("{name} tab after jj + Enter (detail state, if any)"),
            &frame(&mut app, 120, 40),
        );
    }

    // CBOM interactions.
    for (name, tab) in [
        ("algorithms", ViewTab::Algorithms),
        ("certificates", ViewTab::Certificates),
        ("keys", ViewTab::Keys),
        ("protocols", ViewTab::Protocols),
        ("pqc", ViewTab::PqcCompliance),
    ] {
        let mut app = view_app(CBOM, Some(tab));
        chars(&mut app, "jj");
        handle_key_event(&mut app, key(KeyCode::Enter));
        d.dump(
            &format!("cbom_{name}_enter_120x40"),
            &format!("CBOM {name} tab after jj + Enter"),
            &frame(&mut app, 120, 40),
        );
    }

    // AI-BOM interactions.
    for (name, tab) in [
        ("models", ViewTab::Models),
        ("datasets", ViewTab::Datasets),
        ("ai_readiness", ViewTab::AiReadiness),
    ] {
        let mut app = view_app(AIBOM_BSI, Some(tab));
        chars(&mut app, "jj");
        handle_key_event(&mut app, key(KeyCode::Enter));
        d.dump(
            &format!("aibom_{name}_enter_120x40"),
            &format!("AI-BOM {name} tab after jj + Enter"),
            &frame(&mut app, 120, 40),
        );
    }

    // 'P' profile cycling on a plain SBOM: forces CBOM then AI-BOM tab sets
    // onto data that has no crypto/AI content — exercises honest empty states.
    let mut app = view_app(DEMO_NEW, None);
    handle_key_event(&mut app, key(KeyCode::Char('P')));
    d.dump(
        "profile_cycle_cbom_overview_120x40",
        "Plain SBOM after 'P' (forced CBOM profile): overview",
        &frame(&mut app, 120, 40),
    );
    app.active_tab = ViewTab::Algorithms;
    d.dump(
        "profile_cycle_cbom_algorithms_120x40",
        "Plain SBOM forced to CBOM profile: algorithms tab (empty state)",
        &frame(&mut app, 120, 40),
    );
    handle_key_event(&mut app, key(KeyCode::Char('P')));
    d.dump(
        "profile_cycle_aibom_overview_120x40",
        "Plain SBOM after 'P','P' (forced AI-BOM profile): overview",
        &frame(&mut app, 120, 40),
    );
    app.active_tab = ViewTab::Models;
    d.dump(
        "profile_cycle_aibom_models_120x40",
        "Plain SBOM forced to AI-BOM profile: models tab (empty state)",
        &frame(&mut app, 120, 40),
    );

    // Source viewer scroll + yank feedback.
    let mut app = view_app(DEMO_NEW, Some(ViewTab::Source));
    chars(&mut app, "jjjj");
    d.dump(
        "source_scrolled_120x40",
        "SBOM source tab after jjjj (scrolled)",
        &frame(&mut app, 120, 40),
    );
    let mut app = view_app(DEMO_NEW, Some(ViewTab::Tree));
    chars(&mut app, "jy");
    d.dump(
        "yank_feedback_120x40",
        "SBOM tree, j then 'y': copy feedback in status bar",
        &frame(&mut app, 120, 40),
    );

    d.finish();
}
