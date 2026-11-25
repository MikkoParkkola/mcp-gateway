// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows that need root. The CI root jobs create group G with users B and C
//! (C in G) and export their ids; every row first asserts that it runs as
//! root, so a run without the job's setup fails instead of passing.

use std::ffi::OsString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{CHILD_MODE, CHILD_TARGET, RESULT};
use crate::config_persistence::{FileMode, Symlink, write_atomic};

/// The file every row saves, inside its fixture directory.
const TARGET: &str = "target.json";

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Saved,
    Refused { kind: String, text: String },
}

/// The ids the root job exports.
struct Ids {
    b: u32,
    c: u32,
    g: u32,
    user_c: String,
}

/// A variable the root job exports; a missing one fails the row.
fn job_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("precondition: the job exports {name}"))
}

fn job_id(name: &str) -> u32 {
    job_env(name)
        .parse()
        .unwrap_or_else(|_| panic!("precondition: the job exports {name} as a number"))
}

/// Asserts root, then reads the job's ids.
fn ids() -> Ids {
    assert!(
        rustix::process::geteuid().is_root(),
        "precondition: the row runs as root (the access-rows root job)"
    );
    Ids {
        b: job_id("ACCESS_ROWS_UID_B"),
        c: job_id("ACCESS_ROWS_UID_C"),
        g: job_id("ACCESS_ROWS_GID_G"),
        user_c: job_env("ACCESS_ROWS_USER_C"),
    }
}

/// A directory owned by `owner`:`group` at `dir_mode`, holding `target.json`
/// ("old") owned by `owner`:`group` at `mode`. The temp root is 0711 under
/// /tmp, so user C can reach the directory whatever the runner's TMPDIR is.
struct Fixture {
    _root: tempfile::TempDir,
    dir: PathBuf,
    target: PathBuf,
}

fn fixture(owner: u32, group: u32, dir_mode: u32, mode: u32) -> Fixture {
    let root = tempfile::tempdir_in("/tmp").expect("temp root");
    set_mode(root.path(), 0o711);
    // Canonical, so a refusal naming the writer's resolved path matches it
    // (/tmp is a link to /private/tmp on macOS).
    let dir = std::fs::canonicalize(root.path())
        .expect("canonical temp root")
        .join("d");
    std::fs::create_dir(&dir).expect("fixture dir");
    std::os::unix::fs::chown(&dir, Some(owner), Some(group)).expect("chown dir");
    set_mode(&dir, dir_mode);
    let target = dir.join(TARGET);
    std::fs::write(&target, b"old").expect("target");
    std::os::unix::fs::chown(&target, Some(owner), Some(group)).expect("chown target");
    set_mode(&target, mode);
    Fixture {
        _root: root,
        dir,
        target,
    }
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Names in the fixture directory besides the target. A save that refused
/// before its scratch existed leaves this empty.
fn stray_files(dir: &Path) -> Vec<OsString> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).expect("list fixture dir") {
        let name = entry.expect("fixture dir entry").file_name();
        if name != TARGET {
            names.push(name);
        }
    }
    names
}

/// `name=value`, one argument for `env`.
fn assign(name: &str, value: impl Into<OsString>) -> OsString {
    let mut arg = OsString::from(format!("{name}="));
    arg.push(value.into());
    arg
}

/// Runs `child::save` as user C (group G) on `target` in `mode`
/// (`inherit` or `private`) and returns what it reported.
fn save_as_c(ids: &Ids, target: &Path, mode: &str) -> Outcome {
    let mut command = if cfg!(target_os = "linux") {
        let mut setpriv = Command::new("setpriv");
        setpriv
            .args(["--reuid", &ids.c.to_string()])
            .args(["--regid", &ids.g.to_string()])
            .arg("--init-groups");
        setpriv
    } else {
        let mut sudo = Command::new("sudo");
        sudo.args(["-u", &ids.user_c]);
        sudo
    };
    // sudo starts the child with a reset environment, so on both systems the
    // variables travel as `env` arguments.
    command.arg("env");
    for (name, value) in crate::test_home::child_env() {
        command.arg(assign(name, value));
    }
    command
        .arg(assign(CHILD_TARGET, target.as_os_str()))
        .arg(assign(CHILD_MODE, mode))
        .arg(crate::test_home::test_binary().get_program())
        .args([
            "--ignored",
            "--exact",
            "config_persistence_access_tests::child::save",
        ])
        .args(["--nocapture", "--test-threads=1"]);
    let run = command.output().expect("start the child as user C");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "the child as user C failed ({}): {stdout}{}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    parse_outcome(&stdout)
}

/// The child's result line: `saved`, or `refused <ErrorKind> <message>`.
fn parse_outcome(stdout: &str) -> Outcome {
    let line = stdout
        .lines()
        // Uncaptured, libtest's own `test .. ...` text can lead the line.
        .find_map(|l| l.split_once(RESULT).map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("the child printed no {RESULT} line: {stdout}"))
        .trim_start();
    if line == "saved" {
        return Outcome::Saved;
    }
    let refused = line
        .strip_prefix("refused ")
        .unwrap_or_else(|| panic!("unreadable result line: {line}"));
    let (kind, text) = refused.split_once(' ').unwrap_or((refused, ""));
    Outcome::Refused {
        kind: kind.to_owned(),
        text: text.to_owned(),
    }
}

/// The save refused with `PermissionDenied` and a message led by `code`.
fn assert_refused(got: &Outcome, code: &str, row: &str) {
    let led_by_code = matches!(got, Outcome::Refused { kind, text }
        if kind == "PermissionDenied" && text.starts_with(&format!("{code}: ")));
    assert!(
        led_by_code,
        "{row}: the save refused PermissionDenied `{code}`; got {got:?}"
    );
}

/// The target still holds "old" with its owner, group and mode, and no
/// scratch was left beside it.
fn assert_untouched(fx: &Fixture, (uid, gid, mode): (u32, u32, u32), row: &str) {
    assert_eq!(
        std::fs::read(&fx.target).expect("read target"),
        b"old",
        "{row}: target bytes"
    );
    let meta = std::fs::metadata(&fx.target).expect("stat target");
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777),
        (uid, gid, mode),
        "{row}: target uid, gid, mode"
    );
    assert!(
        stray_files(&fx.dir).is_empty(),
        "{row}: files left: {:?}",
        stray_files(&fx.dir)
    );
}

/// The target now holds "new" owned by `uid` with `mode`, and nothing else
/// is in the directory.
fn assert_saved_as(fx: &Fixture, uid: u32, mode: u32, row: &str) {
    assert_eq!(
        std::fs::read(&fx.target).expect("read target"),
        b"new",
        "{row}: target bytes"
    );
    let meta = std::fs::metadata(&fx.target).expect("stat target");
    assert_eq!(
        (meta.uid(), meta.mode() & 0o7777),
        (uid, mode),
        "{row}: replacement uid, mode"
    );
    assert!(
        stray_files(&fx.dir).is_empty(),
        "{row}: files left: {:?}",
        stray_files(&fx.dir)
    );
}

/// O-group-writer: C may write B's 0620 file through group G but must not
/// take it over. Linux refuses `foreign-owner`; on macOS C cannot open the
/// target to read its ACL, so it refuses `acl-not-kept` first.
#[test]
#[ignore = "access-rows root job"]
fn o_group_writer_refuses() {
    let ids = ids();
    let code = if cfg!(target_os = "macos") {
        "acl-not-kept"
    } else {
        "foreign-owner"
    };
    for mode in ["inherit", "private"] {
        let row = format!("O-group-writer/{mode}");
        let fx = fixture(ids.b, ids.g, 0o770, 0o620);
        assert_refused(&save_as_c(&ids, &fx.target, mode), code, &row);
        assert_untouched(&fx, (ids.b, ids.g, 0o620), &row);
    }
}

/// O-foreign-readable: the same with B's file readable by G (0640), so the
/// owner rule itself refuses on both systems.
#[test]
#[ignore = "access-rows root job"]
fn o_foreign_readable_refuses() {
    let ids = ids();
    for mode in ["inherit", "private"] {
        let row = format!("O-foreign-readable/{mode}");
        let fx = fixture(ids.b, ids.g, 0o770, 0o640);
        assert_refused(&save_as_c(&ids, &fx.target, mode), "foreign-owner", &row);
        assert_untouched(&fx, (ids.b, ids.g, 0o640), &row);
    }
}

/// O-root-keeps: root saving B's file hands the replacement back to B.
#[test]
#[ignore = "access-rows root job"]
fn o_root_keeps_owner() {
    let ids = ids();
    let fx = fixture(ids.b, ids.g, 0o770, 0o620);
    write_atomic(&fx.target, b"new", FileMode::Inherit, Symlink::Follow).expect("root saves");
    // macOS keeps the owner bits only until the writer reads the target's
    // ACL; reading it widens this to 0620 when neither file holds an entry.
    let kept = if cfg!(target_os = "macos") {
        0o600
    } else {
        0o620
    };
    assert_saved_as(&fx, ids.b, kept, "O-root-keeps/inherit");
    let gid = std::fs::metadata(&fx.target).expect("stat target").gid();
    assert_eq!(gid, ids.g, "O-root-keeps/inherit: replacement gid");

    let fx = fixture(ids.b, ids.g, 0o770, 0o620);
    write_atomic(&fx.target, b"new", FileMode::Private, Symlink::Follow).expect("root saves");
    assert_saved_as(&fx, ids.b, 0o600, "O-root-keeps/private");
}

/// P-copy (b): root backing up B's file makes a backup with B's owner, group
/// and mode, not root's.
#[test]
#[ignore = "access-rows root job"]
fn p_copy_root_keeps_owner() {
    let ids = ids();
    let fx = fixture(ids.b, ids.g, 0o770, 0o640);
    let backup = fx.dir.join("target.json.bak");
    crate::config_persistence::copy_keeping_access(&fx.target, &backup).expect("root copies");
    let meta = std::fs::metadata(&backup).expect("stat backup");
    let kept = if cfg!(target_os = "macos") {
        0o600
    } else {
        0o640
    };
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777),
        (ids.b, ids.g, kept),
        "P-copy(b): backup uid, gid, mode"
    );
    assert_eq!(
        std::fs::read(&backup).expect("read backup"),
        b"old",
        "P-copy(b): bytes"
    );
}

/// O-own-file (control): C saving its own file whose group (0) it cannot
/// take still saves, owner kept, mode narrowed to the owner bits.
#[test]
#[ignore = "access-rows root job"]
fn o_own_file_saves() {
    let ids = ids();
    for mode in ["inherit", "private"] {
        let row = format!("O-own-file/{mode}");
        let fx = fixture(ids.c, 0, 0o700, 0o640);
        assert_eq!(
            save_as_c(&ids, &fx.target, mode),
            Outcome::Saved,
            "{row}: the save"
        );
        assert_saved_as(&fx, ids.c, 0o600, &row);
    }
}

/// O-text: the owner refusal's whole message, spelled out here so a change
/// to the product's wording shows up as a failing row. macOS uses the 0640
/// target, because its 0620 case stops earlier with `acl-not-kept`.
#[test]
#[ignore = "access-rows root job"]
fn o_text_is_exact() {
    let ids = ids();
    let mode = if cfg!(target_os = "macos") {
        0o640
    } else {
        0o620
    };
    let fx = fixture(ids.b, ids.g, 0o770, mode);
    let refused = Outcome::Refused {
        kind: "PermissionDenied".to_owned(),
        text: owner_refusal(&fx.target, ids.b, ids.c),
    };
    assert_eq!(save_as_c(&ids, &fx.target, "inherit"), refused, "O-text");
    assert_untouched(&fx, (ids.b, ids.g, mode), "O-text");
}

/// The owner refusal's message for `path` owned by `owner`, saved as `me`.
fn owner_refusal(path: &Path, owner: u32, me: u32) -> String {
    let path = path.display();
    format!(
        "foreign-owner: refused to replace {path}: the file belongs to uid {owner}, \
         but this gateway runs as uid {me}. Nothing was written. To save it, run the \
         gateway as uid {owner}, or hand the file to uid {me} (chown {me} {path})."
    )
}

/// E-text-owner: the config text writer (CLI edits, client-config export,
/// identity grants) follows the same owner rule, its refusal behind the
/// text writer's own prefix.
#[test]
#[ignore = "access-rows root job"]
fn e_text_owner_refuses() {
    let ids = ids();
    let fx = fixture(ids.b, ids.g, 0o770, 0o640);
    let shown = fx.target.display();
    let refused = Outcome::Refused {
        kind: "Text".to_owned(),
        text: format!(
            "Failed to save config {shown}: {}",
            owner_refusal(&fx.target, ids.b, ids.c)
        ),
    };
    assert_eq!(save_as_c(&ids, &fx.target, "text"), refused, "E-text-owner");
    assert_untouched(&fx, (ids.b, ids.g, 0o640), "E-text-owner");
}

/// E-text-root-keeps: root's text save of B's file (a sudo `setup export`
/// into B's client config) leaves it B's, owner-only.
#[test]
#[ignore = "access-rows root job"]
fn e_text_root_keeps_owner() {
    let ids = ids();
    let fx = fixture(ids.b, ids.g, 0o770, 0o640);
    crate::config_persistence::write_text_atomic(&fx.target, "new").expect("root saves");
    assert_saved_as(&fx, ids.b, 0o600, "E-text-root-keeps");
}
