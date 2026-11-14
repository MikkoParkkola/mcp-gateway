// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows S1 and N1-N3: the seam rule over the whole source tree, and the
//! certification of a Booted or Defaults config source.

use std::path::Path;

use tokio::time::Instant;

use super::support::{self, Probe};
use super::{ConfigFloor, production_candidates};
use crate::backend::BackendRegistry;
use crate::gateway::restart_floor::{FloorAdapter, FloorFault};
use crate::test_source_text::production_text;

/// The one file that may define a seam, inside its `seams` module.
const SEAMS_HOME: &str = "src/gateway/restart_config_floor.rs";
/// This file lists the seams as literals, so the scans skip it.
const THIS_FILE: &str = "src/gateway/config_floor_source_tests.rs";

/// Every seam definition, as the literal text that defines it.
const DEFINITIONS: &[&str] = &[
    "struct SeamLog<",
    "enum AdmittedPoint {",
    "type AdmittedHook =",
    "type SettleWindow =",
    "struct GateDecision {",
    "enum ReloadSource {",
    "struct ReloadEntry {",
    "enum WatcherPoke {",
    "struct GateSeams {",
    "enum CheckStep {",
    "type CheckHook =",
    "enum LockVerdict {",
    "type LockHook =",
    "type MetaHook =",
    "enum SlotOutcome {",
    "struct SlotEntry {",
    "enum AttemptEvent {",
    "struct AttemptEntry {",
    "struct FloorSeams {",
    "pub(crate) admitted_hook:",
    "pub(crate) settle_window:",
    "pub(crate) decisions: SeamLog<GateDecision>",
    "pub(crate) reloads:",
    "pub(crate) pokes:",
    "pub(crate) check_hook:",
    "pub(crate) lock_hook:",
    "pub(crate) meta_hook:",
    "pub(crate) candidate_override:",
    "pub(crate) slots:",
    "pub(crate) attempts: SeamLog<AttemptEntry>",
    "fn state(&self) -> GateState",
    "fn admissions_in_flight(&self) -> usize",
    "fn decisions(&self) -> Vec<GateDecision>",
    "fn attempt(&self) -> u64",
    "fn reload_lock(&self) -> Arc<tokio::sync::Mutex<()>>",
    "fn set_admitted_hook(&",
    "fn set_settle_window(&",
    "fn call_admitted(&",
    "fn record_reload(&",
    "fn reload_log(&self)",
    "fn record_file_event(&",
    "fn pending_pokes(&",
    "fn consume_poke(&",
    "fn set_check_hook(&",
    "fn set_lock_hook(&",
    "fn set_meta_hook(&",
    "fn override_candidates(&",
    "fn active_candidates(&",
    "fn slot_log(&",
    "fn attempt_log(&",
];

/// Seam names distinctive enough that production text must never mention one.
const NAMES: &[&str] = &[
    "SeamLog",
    "AdmittedPoint",
    "WriterAfterStaging",
    "GateDecision",
    "admissions_in_flight",
    "AdmittedHook",
    "SettleWindow",
    "ReloadSource",
    "ReloadEntry",
    "WatcherPoke",
    "GateSeams",
    "CheckStep",
    "CheckHook",
    "LockVerdict",
    "LockHook",
    "MetaHook",
    "SlotOutcome",
    "SlotEntry",
    "AttemptEvent",
    "AttemptEntry",
    "FloorSeams",
    "set_admitted_hook",
    "set_settle_window",
    "call_admitted",
    "record_reload",
    "reload_log",
    "record_file_event",
    "pending_pokes",
    "consume_poke",
    "set_check_hook",
    "set_lock_hook",
    "set_meta_hook",
    "override_candidates",
    "active_candidates",
    "slot_log",
    "attempt_log",
    "admitted_hook",
    "settle_window",
    "check_hook",
    "lock_hook",
    "meta_hook",
    "candidate_override",
];

/// Line number (1-based) of byte offset `at` in `text`.
fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// Whether `name` occurs in `text` as a whole identifier.
fn names_word(text: &str, name: &str) -> Option<usize> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(name).map(|(at, _)| at).find(|&at| {
        !text[..at].chars().next_back().is_some_and(ident)
            && !text[at + name.len()..].chars().next().is_some_and(ident)
    })
}

/// Seam names a file's production text (test-only items blanked) mentions.
fn leaks(rel: &str, text: &str) -> Vec<String> {
    let production = production_text(text);
    NAMES
        .iter()
        .filter_map(|name| {
            let at = names_word(&production, name)?;
            Some(format!(
                "{rel}:{}: production text names {name}",
                line_of(&production, at)
            ))
        })
        .collect()
}

/// Byte range of the `seams` module inside the home file's text.
fn seams_range(text: &str) -> std::ops::Range<usize> {
    let start = text
        .find("pub(crate) mod seams {")
        .expect("the seams module exists");
    let len = text[start..]
        .find("\n}\n")
        .expect("the seams module closes");
    start..start + len
}

/// Every `.rs` file under `src`: its repo-relative path and its text.
fn source_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    walkdir::WalkDir::new(root.join("src"))
        .into_iter()
        .map(|e| e.expect("src is readable").into_path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| {
            let rel = p.strip_prefix(root).expect("under the root");
            let rel = rel.to_string_lossy().replace('\\', "/");
            (rel, std::fs::read_to_string(&p).expect("readable source"))
        })
        .filter(|(rel, _)| rel != THIS_FILE)
        .collect()
}

/// Each definition literal must occur once in the tree, inside `seams_range`.
fn definition_faults(files: &[(String, String)]) -> Vec<String> {
    let home = &files
        .iter()
        .find(|(rel, _)| rel == SEAMS_HOME)
        .expect("home file")
        .1;
    let range = seams_range(home);
    let mut faults = Vec::new();
    for literal in DEFINITIONS {
        let hits: Vec<(&str, usize, bool)> = files
            .iter()
            .flat_map(|(rel, text)| {
                text.match_indices(literal)
                    .map(move |(at, _)| (rel.as_str(), at, text.len()))
            })
            .map(|(rel, at, _)| (rel, at, rel == SEAMS_HOME && range.contains(&at)))
            .collect();
        if hits.len() != 1 || !hits[0].2 {
            faults.push(format!(
                "{literal:?}: {hits:?} (want one hit inside the seams module)"
            ));
        }
    }
    faults
}

#[test]
fn s1_seams_are_defined_once_and_never_named_in_production() {
    const ROW: &str = "S1";
    let files = source_files();
    let faults = definition_faults(&files);
    assert!(faults.is_empty(), "{ROW} definitions: {faults:#?}");
    let named: Vec<String> = files
        .iter()
        .filter(|(rel, _)| !crate::clock::tests::a_test_file(Path::new(rel)))
        .flat_map(|(rel, text)| leaks(rel, text))
        .collect();
    assert!(
        named.is_empty(),
        "{ROW} production names a seam: {named:#?}"
    );
}

#[test]
fn s1_scan_bites_on_a_seam_read_without_the_attribute() {
    const ROW: &str = "S1 fixture";
    let guarded = "#[cfg(test)]\nmod seams { struct GateSeams; }\n#[cfg(test)]\nfn ok(g: &G) { g.consume_poke(); }\n";
    let leaky =
        "#[cfg(test)]\nmod seams { struct GateSeams; }\nfn bad(g: &G) { g.consume_poke(); }\n";
    assert!(
        leaks("guarded.rs", guarded).is_empty(),
        "{ROW}: a guarded read must pass"
    );
    let found = leaks("leaky.rs", leaky);
    assert_eq!(
        found.len(),
        1,
        "{ROW}: the unguarded read must be found: {found:?}"
    );
    assert!(
        found[0].starts_with("leaky.rs:3:"),
        "{ROW}: names file and line: {found:?}"
    );
}

/// Pause then checkpoint one floor, bounded so a stuck floor fails the row.
async fn certify(row: &str, floor: &mut ConfigFloor) -> Result<(), FloorFault> {
    let deadline = Instant::now() + support::BOUND;
    let run = async {
        floor.pause(deadline).await?;
        floor.checkpoint(deadline).await
    };
    tokio::time::timeout(support::BOUND, run)
        .await
        .unwrap_or_else(|_| panic!("{row}: certify never finished"))
}

/// The certified hash, if the floor certified a file.
fn certified_hash(floor: &ConfigFloor) -> Option<String> {
    floor.certification().map(|c| c.sha256.clone())
}

/// The config-lock probe of each candidate path, in order.
fn probes(paths: &[std::path::PathBuf]) -> Vec<Probe> {
    paths.iter().map(|p| support::config_probe(p)).collect()
}

/// A valid config whose `environment` names `tag`, so each file differs.
fn tagged(tag: &str) -> String {
    format!("{}environment: \"{tag}\"\n", support::BASE)
}

const INVALID: &str = "backends: [\n";

fn defaults(candidates: &support::Candidates) -> ConfigFloor {
    support::defaults_floor(&BackendRegistry::new(), candidates)
}

#[tokio::test]
async fn n1_defaults_with_no_file_is_not_configured() {
    const ROW: &str = "N1 none";
    let candidates = support::Candidates::new();
    let mut floor = defaults(&candidates);
    let free = vec![Probe::Free; 4];
    let result = certify(ROW, &mut floor).await;
    assert_eq!(result, Ok(()), "{ROW}: no file anywhere is not-configured");
    assert_eq!(certified_hash(&floor), None, "{ROW}: nothing is certified");
    assert!(floor.settled(), "{ROW}: not-configured stays settled");
    assert_eq!(
        probes(&candidates.paths),
        free,
        "{ROW}: no lock held at the decision"
    );
    floor.resume();
    assert_eq!(
        probes(&candidates.paths),
        free,
        "{ROW}: no lock held after resume"
    );
}

#[tokio::test]
async fn n1_defaults_certifies_the_one_candidate_that_holds_a_file() {
    const ROW: &str = "N1 one";
    for index in 0..4 {
        let candidates = support::Candidates::new();
        let text = tagged(&format!("only-{index}"));
        candidates.put(index, &text);
        let mut floor = defaults(&candidates);
        let result = certify(ROW, &mut floor).await;
        assert_eq!(result, Ok(()), "{ROW}: position {index} certifies");
        let want = Some(support::sha256_hex(text.as_bytes()));
        assert_eq!(certified_hash(&floor), want, "{ROW}: position {index} hash");
        let mut busy = vec![Probe::Free; 4];
        busy[index] = Probe::Busy;
        assert_eq!(
            probes(&candidates.paths),
            busy,
            "{ROW}: only {index} locked"
        );
        floor.resume();
        assert_eq!(
            probes(&candidates.paths),
            vec![Probe::Free; 4],
            "{ROW}: freed at {index}"
        );
    }
}

#[tokio::test]
async fn n1_defaults_precedence_certifies_position_two_over_four() {
    const ROW: &str = "N1 precedence";
    let candidates = support::Candidates::new();
    let (second, fourth) = (tagged("second"), tagged("fourth"));
    candidates.put(1, &second);
    candidates.put(3, &fourth);
    let mut floor = defaults(&candidates);
    let result = certify(ROW, &mut floor).await;
    assert_eq!(result, Ok(()), "{ROW}: certifies");
    let want = Some(support::sha256_hex(second.as_bytes()));
    assert_eq!(certified_hash(&floor), want, "{ROW}: position 2 wins");
}

#[tokio::test]
async fn n1_defaults_first_candidate_invalid_is_save_failed() {
    const ROW: &str = "N1 invalid";
    let candidates = support::Candidates::new();
    candidates.put(0, INVALID);
    candidates.put(1, &tagged("valid-but-second"));
    let mut floor = defaults(&candidates);
    let result = certify(ROW, &mut floor).await;
    assert_eq!(
        result,
        Err(FloorFault::SaveFailed),
        "{ROW}: the first found file decides"
    );
}

#[test]
fn n1_production_candidates_are_the_four_literal_paths_in_order() {
    const ROW: &str = "N1 production list";
    let home = crate::home_dir::home_dir().expect("a home directory in the test env");
    let want = vec![
        std::path::PathBuf::from("gateway.yaml"),
        std::path::PathBuf::from("config.yaml"),
        home.join(".config/mcp-gateway/gateway.yaml"),
        std::path::PathBuf::from("/etc/mcp-gateway/gateway.yaml"),
    ];
    assert_eq!(
        production_candidates(),
        want,
        "{ROW}: the startup search order"
    );
}

#[tokio::test]
async fn n2_booted_file_deleted_before_certify_is_save_failed() {
    const ROW: &str = "N2 booted";
    let booted = support::Booted::new(support::BASE);
    let mut floor = booted.floor();
    std::fs::remove_file(&booted.cfg.path).expect("delete the booted file");
    let result = certify(ROW, &mut floor).await;
    assert_eq!(
        result,
        Err(FloorFault::SaveFailed),
        "{ROW}: a missing Booted file cancels"
    );
}

#[tokio::test]
async fn n2_defaults_file_deleted_before_certify_is_not_configured() {
    const ROW: &str = "N2 defaults twin";
    let candidates = support::Candidates::new();
    candidates.put(0, support::BASE);
    let mut floor = defaults(&candidates);
    std::fs::remove_file(&candidates.paths[0]).expect("delete the candidate");
    let result = certify(ROW, &mut floor).await;
    assert_eq!(result, Ok(()), "{ROW}: the same deletion on Defaults is Ok");
    assert_eq!(
        certified_hash(&floor),
        None,
        "{ROW}: not-configured certifies nothing"
    );
    assert!(floor.settled(), "{ROW}: not-configured stays settled");
}

/// A Booted floor with no reload context: only a registry and the file.
fn contextless(text: &str) -> (support::ConfigDir, ConfigFloor) {
    let cfg = support::ConfigDir::with(text);
    let floor = support::booted_floor(&BackendRegistry::new(), &cfg.path);
    (cfg, floor)
}

#[tokio::test]
async fn n3_booted_file_without_reload_context_is_certified() {
    const ROW: &str = "N3 certified";
    let (cfg, mut floor) = contextless(support::BASE);
    let result = certify(ROW, &mut floor).await;
    assert_eq!(result, Ok(()), "{ROW}: certifies with reload disabled");
    let want = Some(support::sha256_hex(support::BASE.as_bytes()));
    assert_eq!(certified_hash(&floor), want, "{ROW}: literal hash");
    assert_eq!(
        support::config_probe(&cfg.path),
        Probe::Busy,
        "{ROW}: locked until resume"
    );
    floor.resume();
    assert_eq!(
        support::config_probe(&cfg.path),
        Probe::Free,
        "{ROW}: free after resume"
    );
}

#[tokio::test]
async fn n3_booted_invalid_file_without_reload_context_is_save_failed() {
    const ROW: &str = "N3 invalid";
    let (_cfg, mut floor) = contextless(INVALID);
    let result = certify(ROW, &mut floor).await;
    assert_eq!(
        result,
        Err(FloorFault::SaveFailed),
        "{ROW}: validation still runs"
    );
}
