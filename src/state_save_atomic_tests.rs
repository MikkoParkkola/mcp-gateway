// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The three state saves that used to rewrite their file in place (search
//! ranking usage, transition tracking, tool profiles) go through the shared
//! atomic writer: a save cut midway leaves the previous file loading intact,
//! a symlinked state file stays a link whose target takes the save, and a new
//! file keeps the umask mode (the writer's `Inherit`, not `Private`).
//!
//! A write is cut at a fixed point by re-running the row in a child under
//! `ulimit -f 1` with SIGXFSZ ignored, so the write past the limit fails with
//! EFBIG (os error 27). Every check loads into a fresh instance: transition
//! loading adds to what an instance holds and the ranker's load keeps entries
//! it already has, so a reused instance could pass on stale state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::ranking::SearchRanker;
use crate::tool_profiles::ToolSuggestion;
use crate::tool_profiles::persistence::{PersistedProfiles, PersistedUserProfile};
use crate::transition::TransitionTracker;

/// Set in a child: the path its save goes to.
const CHILD_PATH: &str = "STATE_SAVE_ATOMIC_CHILD_PATH";
/// Set in a child: `large` saves state B, `small` saves state A.
const CHILD_STATE: &str = "STATE_SAVE_ATOMIC_CHILD_STATE";
/// More entries than fit under a one-block file size limit once serialized.
const LARGE: usize = 200;

#[derive(Clone, Copy, Debug)]
enum Class {
    Usage,
    Transitions,
    Profiles,
}

fn profile(user: &str, tool: &str, calls: u64) -> PersistedUserProfile {
    PersistedUserProfile {
        user_id: user.to_owned(),
        created_at: Some(1),
        tools: vec![ToolSuggestion {
            tool_name: tool.to_owned(),
            call_count: calls,
            last_used_secs: Some(5),
        }],
    }
}

impl Class {
    /// State A: one entry of each kind, small.
    fn save_small(self, path: &Path) -> Result<(), String> {
        match self {
            Self::Usage => {
                let ranker = SearchRanker::new();
                for _ in 0..3 {
                    ranker.record_use("srv", "alpha");
                }
                ranker.save(path).map_err(|e| e.to_string())
            }
            Self::Transitions => {
                let tracker = TransitionTracker::new();
                for tool in ["a", "b", "a", "b"] {
                    tracker.record_transition("s", tool);
                }
                tracker.save(path).map_err(|e| e.to_string())
            }
            Self::Profiles => {
                let profiles = PersistedProfiles {
                    saved_at: 7,
                    profiles: HashMap::from([("u1".to_owned(), profile("u1", "alpha", 3))]),
                };
                crate::tool_profiles::persistence::save(path, &profiles).map_err(|e| e.to_string())
            }
        }
    }

    /// State B: `LARGE` entries, larger than the child's file size limit.
    fn save_large(self, path: &Path) -> Result<(), String> {
        match self {
            Self::Usage => {
                let ranker = SearchRanker::new();
                for i in 0..LARGE {
                    ranker.record_use("srv", &format!("t{i}"));
                }
                ranker.save(path).map_err(|e| e.to_string())
            }
            Self::Transitions => {
                let tracker = TransitionTracker::new();
                for i in 0..LARGE {
                    tracker.record_transition("s", &format!("t{i}"));
                }
                tracker.save(path).map_err(|e| e.to_string())
            }
            Self::Profiles => {
                let profiles = PersistedProfiles {
                    saved_at: 8,
                    profiles: (0..LARGE)
                        .map(|i| (format!("u{i}"), profile(&format!("u{i}"), "t", 1)))
                        .collect(),
                };
                crate::tool_profiles::persistence::save(path, &profiles).map_err(|e| e.to_string())
            }
        }
    }

    /// The file loads into a fresh instance and holds exactly state A.
    fn holds_small(self, path: &Path) -> Result<(), String> {
        match self {
            Self::Usage => {
                let ranker = SearchRanker::new();
                ranker.load(path).map_err(|e| format!("load: {e}"))?;
                let got = (
                    ranker.usage_count("srv", "alpha"),
                    ranker.usage_count("srv", "t0"),
                );
                (got == (3, 0))
                    .then_some(())
                    .ok_or(format!("alpha, t0 counts {got:?}, want (3, 0)"))
            }
            Self::Transitions => {
                let tracker = TransitionTracker::new();
                tracker.load(path).map_err(|e| format!("load: {e}"))?;
                let next: Vec<String> = tracker
                    .predict_next("a", 0.0, 1)
                    .into_iter()
                    .map(|p| p.tool)
                    .collect();
                let got = (tracker.total_transitions(), next);
                (got == (3, vec!["b".to_owned()]))
                    .then_some(())
                    .ok_or(format!(
                        "total and successors of a {got:?}, want (3, [\"b\"])"
                    ))
            }
            Self::Profiles => {
                let loaded = crate::tool_profiles::persistence::load(path)
                    .map_err(|e| format!("load: {e}"))?;
                let users: Vec<&String> = loaded.profiles.keys().collect();
                let tools = loaded.profiles.get("u1").map(|p| p.tools.clone());
                let want = vec![ToolSuggestion {
                    tool_name: "alpha".to_owned(),
                    call_count: 3,
                    last_used_secs: Some(5),
                }];
                (users == vec!["u1"] && tools.as_ref() == Some(&want))
                    .then_some(())
                    .ok_or(format!("users {users:?}, u1 tools {tools:?}"))
            }
        }
    }

    /// The file loads into a fresh instance and holds exactly state B.
    fn holds_large(self, path: &Path) -> Result<(), String> {
        let last = format!("t{}", LARGE - 1);
        match self {
            Self::Usage => {
                let ranker = SearchRanker::new();
                ranker.load(path).map_err(|e| format!("load: {e}"))?;
                let got = (
                    ranker.usage_count("srv", "t0"),
                    ranker.usage_count("srv", &last),
                    ranker.usage_count("srv", "alpha"),
                );
                (got == (1, 1, 0))
                    .then_some(())
                    .ok_or(format!("t0, last, alpha counts {got:?}, want (1, 1, 0)"))
            }
            Self::Transitions => {
                let tracker = TransitionTracker::new();
                tracker.load(path).map_err(|e| format!("load: {e}"))?;
                let next: Vec<String> = tracker
                    .predict_next("t0", 0.0, 1)
                    .into_iter()
                    .map(|p| p.tool)
                    .collect();
                let got = (tracker.total_transitions(), next);
                (got == ((LARGE - 1) as u64, vec!["t1".to_owned()]))
                    .then_some(())
                    .ok_or(format!("total and successors of t0 {got:?}"))
            }
            Self::Profiles => {
                let loaded = crate::tool_profiles::persistence::load(path)
                    .map_err(|e| format!("load: {e}"))?;
                let u7 = loaded
                    .profiles
                    .get("u7")
                    .map(|p| p.tools[0].tool_name.clone());
                (loaded.profiles.len() == LARGE && u7.as_deref() == Some("t"))
                    .then_some(())
                    .ok_or(format!("{} users, u7 tool {u7:?}", loaded.profiles.len()))
            }
        }
    }
}

/// In a child (its env names a path): save the requested state there, print
/// `SAVE_OK` or `SAVE_FAILED <error>`, and report true. In the parent: false.
fn child_saves(class: Class) -> bool {
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        return false;
    };
    let path = PathBuf::from(path);
    let saved = match std::env::var(CHILD_STATE).as_deref() {
        Ok("small") => class.save_small(&path),
        _ => class.save_large(&path),
    };
    match saved {
        Ok(()) => println!("SAVE_OK"),
        Err(e) => println!("SAVE_FAILED {e}"),
    }
    true
}

/// Re-run `test_path` in a child shell that runs `setup` first; the child
/// saves `state` to `target`. Returns its exit success and stdout.
fn run_child(test_path: &str, setup: &str, target: &Path, state: &str) -> (bool, String) {
    // The program path from the sanctioned helper; `sh` runs it so the size
    // limit applies before the exec.
    let exe = crate::test_home::test_binary().get_program().to_owned();
    let script = format!("{setup}; exec \"$0\" '{test_path}' --exact --nocapture --test-threads=1");
    // The child's coverage profile goes to a private file: under a size limit
    // it would be written empty and corrupt the measured set.
    let profile_dir = crate::test_dir_keep::kept_tempdir();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg(&exe)
        .envs(crate::test_home::child_env())
        .env(CHILD_PATH, target)
        .env(CHILD_STATE, state)
        .env(
            "LLVM_PROFILE_FILE",
            profile_dir.path().join("child-%p.profraw"),
        )
        .output()
        .expect("child runs");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// A save cut by the size limit: the child exits 0 and reports EFBIG.
const CUT: &str = "ulimit -f 1; trap '' XFSZ";

fn assert_cut(ok: bool, out: &str) {
    assert!(
        ok && out.contains("SAVE_FAILED") && out.contains("(os error 27)"),
        "premise: the size limit cut the save with EFBIG and the child exited 0 (exit ok: {ok}): {out}"
    );
}

/// Every entry in `dir` other than `keep`.
fn others(dir: &Path, keep: &[&str]) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| !keep.contains(&n.as_str()))
        .collect()
}

/// R-torn: a save cut midway leaves the previous file, which loads intact.
fn torn(class: Class, test_path: &str) {
    if child_saves(class) {
        return;
    }
    let dir = tempfile::tempdir().expect("dir");
    let target = dir.path().join("state.json");
    class.save_small(&target).expect("save state A");
    class
        .holds_small(&target)
        .expect("premise: state A saved and loads");
    let (ok, out) = run_child(test_path, CUT, &target, "large");
    assert_cut(ok, &out);
    class
        .holds_small(&target)
        .unwrap_or_else(|e| panic!("previous file not intact after a cut save: {e}"));
    let left = others(dir.path(), &["state.json"]);
    assert!(left.is_empty(), "scratch left after the cut save: {left:?}");
    class.save_large(&target).expect("an uncut save of state B");
    class.holds_large(&target).expect("state B saved and loads");
}

/// R-link: a relative symlink stays a link with the same text, and its target
/// takes the save; a cut save leaves both alone; a dangling link's target is
/// created.
fn link(class: Class, test_path: &str) {
    if child_saves(class) {
        return;
    }
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir(dir.path().join("real")).expect("real dir");
    let real = dir.path().join("real/state.json");
    let path = dir.path().join("state.json");
    let text = Path::new("real/state.json");
    class.save_small(&real).expect("save state A");
    std::os::unix::fs::symlink(text, &path).expect("link");
    class
        .save_large(&path)
        .expect("save state B through the link");
    assert_eq!(
        std::fs::read_link(&path).expect("still a link"),
        text,
        "the link text changed"
    );
    class
        .holds_large(&real)
        .expect("the link's target holds state B");
    let (ok, out) = run_child(test_path, CUT, &path, "large");
    assert_cut(ok, &out);
    assert_eq!(
        std::fs::read_link(&path).expect("still a link"),
        text,
        "a cut save changed the link"
    );
    class
        .holds_large(&real)
        .unwrap_or_else(|e| panic!("the link's target not intact after a cut save: {e}"));
    std::fs::remove_file(&real).expect("make the link dangle");
    class
        .save_large(&path)
        .expect("save through a dangling link");
    assert_eq!(
        std::fs::read_link(&path).expect("still a link"),
        text,
        "the dangling link was replaced"
    );
    class
        .holds_large(&real)
        .expect("the dangling link's target was created with state B");
}

/// R-mode: a new file saved under umask 022 gets 0644 (the umask mode, as
/// `fs::write` gave it), not the owner-only 0600 a `Private` write gives.
fn mode(class: Class, test_path: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    if child_saves(class) {
        return;
    }
    let dir = tempfile::tempdir().expect("dir");
    let target = dir.path().join("state.json");
    let (ok, out) = run_child(test_path, "umask 022", &target, "small");
    assert!(
        ok && out.contains("SAVE_OK"),
        "premise: the child saved (exit ok: {ok}): {out}"
    );
    let got = std::fs::metadata(&target)
        .expect("saved")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        got, 0o644,
        "new file mode {got:o}, want 644 (the umask mode)"
    );
}

#[test]
fn r_torn_usage() {
    torn(Class::Usage, "state_save_atomic_tests::r_torn_usage");
}

#[test]
fn r_torn_transitions() {
    torn(
        Class::Transitions,
        "state_save_atomic_tests::r_torn_transitions",
    );
}

#[test]
fn r_torn_profiles() {
    torn(Class::Profiles, "state_save_atomic_tests::r_torn_profiles");
}

#[test]
fn r_link_usage() {
    link(Class::Usage, "state_save_atomic_tests::r_link_usage");
}

#[test]
fn r_link_transitions() {
    link(
        Class::Transitions,
        "state_save_atomic_tests::r_link_transitions",
    );
}

#[test]
fn r_link_profiles() {
    link(Class::Profiles, "state_save_atomic_tests::r_link_profiles");
}

#[test]
fn r_mode_usage() {
    mode(Class::Usage, "state_save_atomic_tests::r_mode_usage");
}

#[test]
fn r_mode_transitions() {
    mode(
        Class::Transitions,
        "state_save_atomic_tests::r_mode_transitions",
    );
}

#[test]
fn r_mode_profiles() {
    mode(Class::Profiles, "state_save_atomic_tests::r_mode_profiles");
}
