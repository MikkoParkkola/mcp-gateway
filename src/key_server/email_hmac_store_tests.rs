// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The email-hash key file: created once, reloaded the same, refused when it
//! is unsafe, inconsistent or missing with history behind it.

use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Barrier};

use super::{CREATED_EVENT, FILE, LOCK_WAIT, creation_fields, history_in, resolve, take_lock};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KEY2_HEX: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const KEY_ID: &str = "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd";

#[allow(
    clippy::unnecessary_wraps,
    reason = "the history-scan callback's signature"
)]
fn none() -> Result<bool, String> {
    Ok(false)
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the creation-record callback's signature"
)]
fn recorded(_: &str) -> Result<(), String> {
    Ok(())
}

fn id(dir: &std::path::Path, configured: Option<&str>) -> Result<String, String> {
    resolve(dir, configured, none, recorded).map(|k| k.key_id())
}

fn envelope(dir: &std::path::Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join(FILE)).expect("read")).expect("json")
}

fn write_envelope(dir: &std::path::Path, value: &serde_json::Value) {
    let path = dir.join(FILE);
    std::fs::write(&path, serde_json::to_vec(value).expect("json")).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

#[test]
fn a_first_start_creates_one_private_file_and_a_restart_reloads_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = id(dir.path(), None).expect("first start");
    let mode = std::fs::metadata(dir.path().join(FILE))
        .expect("stat")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
    assert_eq!(id(dir.path(), None).expect("restart"), first);
    let files: Vec<_> = std::fs::read_dir(dir.path())
        .expect("ls")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    assert_eq!(files, [FILE], "no temp or other file is left");
    assert_eq!(envelope(dir.path())["mode"], "generated");
}

#[test]
fn two_installations_get_two_keys() {
    let (a, b) = (
        tempfile::tempdir().expect("a"),
        tempfile::tempdir().expect("b"),
    );
    assert_ne!(
        id(a.path(), None).expect("a"),
        id(b.path(), None).expect("b")
    );
}

#[test]
fn a_configured_key_is_adopted_and_not_copied_into_the_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(id(dir.path(), Some(KEY_HEX)).expect("adopted"), KEY_ID);
    let env = envelope(dir.path());
    assert_eq!(env["mode"], "configured");
    assert!(env.get("key_hex").is_none(), "{env}");
    assert_eq!(env["key_id"], KEY_ID);
}

#[test]
fn a_readable_by_others_file_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    id(dir.path(), None).expect("first start");
    for mode in [0o640, 0o644] {
        std::fs::set_permissions(dir.path().join(FILE), std::fs::Permissions::from_mode(mode))
            .expect("chmod");
        let err = id(dir.path(), None).expect_err("refused");
        assert!(err.contains(FILE), "{mode:o}: {err}");
    }
}

#[test]
fn a_missing_file_with_retained_history_is_refused_even_with_a_configured_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    for configured in [None, Some(KEY_HEX)] {
        let err = resolve(dir.path(), configured, || Ok(true), recorded).expect_err("refused");
        assert!(err.contains("restore") && err.contains(FILE), "{err}");
        assert!(!dir.path().join(FILE).exists(), "no key was created");
    }
    let err = resolve(
        dir.path(),
        None,
        || Err("segment 3 unreadable".into()),
        recorded,
    )
    .expect_err("refused");
    assert!(err.contains("segment 3 unreadable"), "{err}");
}

#[test]
fn a_damaged_or_inconsistent_file_is_refused_without_printing_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    id(dir.path(), Some(KEY_HEX)).expect("adopted");
    let good = serde_json::json!({"version": 1, "mode": "generated", "key_id": KEY_ID, "key_hex": KEY_HEX});
    let cases = [
        serde_json::json!({"version": 2, "mode": "generated", "key_id": KEY_ID, "key_hex": KEY_HEX}),
        serde_json::json!({"version": 1, "mode": "generated", "key_id": KEY_ID, "key_hex": &KEY_HEX[..62]}),
        serde_json::json!({"version": 1, "mode": "generated", "key_id": KEY_ID}),
        // The key changed while the id it names stayed.
        serde_json::json!({"version": 1, "mode": "generated", "key_id": KEY_ID, "key_hex": KEY2_HEX}),
    ];
    for case in cases {
        write_envelope(dir.path(), &case);
        let err = id(dir.path(), None).expect_err("refused");
        assert!(!err.contains(KEY_HEX) && !err.contains(KEY2_HEX), "{err}");
    }
    write_envelope(dir.path(), &good);
    assert_eq!(id(dir.path(), None).expect("restored"), KEY_ID);
    std::fs::write(dir.path().join(FILE), b"{not json").expect("write");
    assert!(id(dir.path(), None).is_err());
}

#[test]
fn the_same_key_moves_to_a_configured_reference_and_another_key_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_envelope(
        dir.path(),
        &serde_json::json!({"version": 1, "mode": "generated", "key_id": KEY_ID, "key_hex": KEY_HEX, "previous_key_ids": ["old"]}),
    );
    let err = id(dir.path(), Some(KEY2_HEX)).expect_err("another key");
    assert!(err.contains("reset"), "{err}");
    assert_eq!(id(dir.path(), Some(KEY_HEX)).expect("same key"), KEY_ID);
    let env = envelope(dir.path());
    assert_eq!(env["mode"], "configured");
    assert!(env.get("key_hex").is_none(), "{env}");
    assert_eq!(env["previous_key_ids"], serde_json::json!(["old"]));
}

/// The publish step itself, raced: every writer waits at a barrier just
/// before its no-replace link; exactly one wins and the file holds its bytes.
#[test]
fn raced_publishes_leave_exactly_one_winner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join(FILE);
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8u8)
        .map(|n| {
            let (target, barrier) = (target.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                crate::config::publish_new_file(&target, &[b'0' + n], |from, to| {
                    barrier.wait();
                    std::fs::hard_link(from, to)
                })
                .expect("a lost race is success");
            })
        })
        .collect();
    for h in handles {
        h.join().expect("writer");
    }
    let content = std::fs::read(&target).expect("read");
    assert_eq!(content.len(), 1, "one writer's bytes, whole");
    let left = std::fs::read_dir(dir.path()).expect("ls").count();
    assert_eq!(left, 1, "no temp is left");
}

#[test]
fn a_file_that_appears_first_keeps_its_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join(FILE);
    crate::config::publish_new_file(&target, b"new", |from, to| {
        std::fs::write(to, b"first")?;
        std::fs::hard_link(from, to)
    })
    .expect("lost race");
    assert_eq!(std::fs::read(&target).expect("read"), b"first");
}

/// Full startup, raced: every start converges on one key id.
#[test]
fn concurrent_first_starts_converge_on_one_key() {
    let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
    let barrier = Arc::new(Barrier::new(8));
    let ids: Vec<String> = (0..8)
        .map(|_| {
            let (dir, barrier) = (Arc::clone(&dir), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                id(dir.path(), None).expect("start")
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|h| h.join().expect("start"))
        .collect();
    assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
}

/// The first start records the new key once; a restart records nothing.
#[test]
fn the_first_start_records_the_key_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let calls = std::cell::RefCell::new(Vec::new());
    let record = |id: &str| {
        calls.borrow_mut().push(id.to_owned());
        Ok(())
    };
    let first = resolve(dir.path(), None, none, record)
        .expect("first")
        .key_id();
    resolve(dir.path(), None, none, |_| {
        panic!("a restart records nothing")
    })
    .expect("restart");
    assert_eq!(*calls.borrow(), [first]);
    assert_eq!(envelope(dir.path())["creation_recorded"], true);
}

/// A failed record refuses the start and leaves the flag false, so the next
/// start records it: a crash between publishing and recording heals.
#[test]
fn a_failed_record_refuses_and_the_next_start_records_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = resolve(dir.path(), None, none, |_| Err("log full".into())).expect_err("refused");
    assert!(err.contains("log full"), "{err}");
    assert_eq!(envelope(dir.path())["creation_recorded"], false);
    let seen = std::cell::Cell::new(false);
    resolve(dir.path(), None, none, |_| {
        seen.set(true);
        Ok(())
    })
    .expect("healed");
    assert!(seen.get(), "the next start recorded the key");
    assert_eq!(envelope(dir.path())["creation_recorded"], true);
}

/// The creation record names the key id and nothing else of the key.
#[test]
fn the_creation_record_carries_only_the_key_id() {
    let fields = creation_fields(KEY_ID);
    assert_eq!(fields.len(), 2, "{fields:?}");
    assert_eq!(fields["event"], CREATED_EVENT);
    assert_eq!(fields["email_hash_key_id"], KEY_ID);
}

/// The scan finds a creation record or any hashed record in the log, and
/// reports an empty log as no history.
#[test]
fn the_history_scan_finds_a_record_or_a_hash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("audit.jsonl");
    std::fs::write(&log, "{\"event\":\"tool.invoked\"}\n").expect("write");
    assert_eq!(history_in(&log), Ok(false));
    for line in [
        format!("{{\"event\":\"{CREATED_EVENT}\",\"email_hash_key_id\":\"{KEY_ID}\"}}"),
        "{\"event\":\"token.issued\",\"email_hash\":\"ab\"}".to_owned(),
    ] {
        std::fs::write(&log, format!("{{\"event\":\"tool.invoked\"}}\n{line}\n")).expect("write");
        assert_eq!(history_in(&log), Ok(true), "{line}");
    }
}

/// An unreadable log is an error, never "no history".
#[test]
fn an_unreadable_log_is_not_no_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("audit.jsonl");
    std::fs::write(&log, "{}\n").expect("write");
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let read = history_in(&log);
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).expect("chmod back");
    // Root reads a mode-0 file; the row is meaningful only for a normal user.
    if rustix::process::geteuid().as_raw() != 0 {
        assert!(read.is_err(), "{read:?}");
    }
}

/// Fail closed: one garbled line anywhere refuses, never "no history".
#[test]
fn a_garbled_line_refuses_instead_of_being_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("audit.jsonl");
    std::fs::write(
        &log,
        "{\"event\":\"tool.invoked\"}\n{\"event\":\"token.iss\n",
    )
    .expect("write");
    let err = history_in(&log).expect_err("a garbled line is not \"no history\"");
    assert!(err.contains("line 2"), "{err}");
    let refused = resolve(dir.path(), None, || history_in(&log), recorded).expect_err("refused");
    assert!(refused.contains("line 2"), "{refused}");
    assert!(!dir.path().join(FILE).exists(), "no key was created");
}

/// A hash nested inside a record (the audit identity's shape) is history.
#[test]
fn a_hash_nested_under_identity_is_history() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("audit.jsonl");
    for nested in [
        "{\"event\":\"token.issued\",\"identity\":{\"subject\":\"s\",\"email_hash\":\"ab\"}}",
        "{\"event\":\"x\",\"items\":[{\"identity\":{\"email_hash_key_id\":\"cd\"}}]}",
    ] {
        std::fs::write(&log, format!("{nested}\n")).expect("write");
        assert_eq!(history_in(&log), Ok(true), "{nested}");
        let refused =
            resolve(dir.path(), None, || history_in(&log), recorded).expect_err("refused");
        assert!(refused.contains("restore"), "{refused}");
        assert!(!dir.path().join(FILE).exists(), "no key was created");
    }
}

/// A malformed field holding the key never puts the key in the refusal.
#[test]
fn a_malformed_envelope_never_quotes_the_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    for bad in [
        format!("{{\"version\":1,\"mode\":\"{KEY_HEX}\",\"key_id\":\"x\"}}"),
        format!("{{\"version\":\"{KEY_HEX}\",\"mode\":\"generated\",\"key_id\":\"x\"}}"),
        format!("{{\"version\":1,\"mode\":\"generated\",\"key_id\":\"x\",\"{KEY_HEX}\":1}}"),
    ] {
        write_envelope(dir.path(), &serde_json::Value::Null);
        std::fs::write(dir.path().join(FILE), &bad).expect("write");
        let err = id(dir.path(), None).expect_err("refused");
        assert!(!err.contains(KEY_HEX), "{err}");
        assert!(err.contains("line 1"), "{err}");
    }
}

/// A start waits the vault's 30 seconds for another holding the lock.
#[test]
fn a_start_waits_thirty_seconds_for_the_lock() {
    assert_eq!(LOCK_WAIT, std::time::Duration::from_secs(30));
}

/// A held lock past the wait refuses, naming the envelope and the lock file.
#[test]
fn a_held_lock_past_the_wait_refuses_naming_the_envelope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lock = dir.path().join(".key-server-email-hmac.lock");
    let _held = take_lock(&lock, std::time::Duration::ZERO).expect("first holder");
    let Err(err) = take_lock(&lock, std::time::Duration::ZERO) else {
        panic!("a second holder took a held lock");
    };
    assert!(
        err.contains("the key-server email HMAC envelope")
            && err.contains(&lock.display().to_string()),
        "{err}"
    );
}

/// A publish that fails before its link (a crash, an unsupported link)
/// leaves no key file and no temp, and the next start makes a fresh key.
#[test]
fn a_failed_publish_serves_no_key_and_leaves_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join(FILE);
    let failed = crate::config::publish_new_file(&target, b"{}", |_, _| {
        Err(std::io::Error::other("power lost before the link"))
    });
    assert!(failed.is_err());
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("ls").count(),
        0,
        "nothing left behind"
    );
    assert!(
        id(dir.path(), None).is_ok(),
        "the next start creates the key"
    );
}
