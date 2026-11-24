// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An update never turns a slot that holds a secret reference into plain
//! text: a long enough new value is stored whatever the slot's name, a
//! shorter one is refused before anything is stored or written (rows K1-K6
//! of the design; through the real route, gateway.yaml on disk).

use super::*;

/// The short-value bound the route compares, in bytes.
const BOUND: usize = crate::security::needles::SHORT_VALUE_BYTES;

/// A file a reference points at, owner-only, in its own folder.
struct Held {
    _folder: tempfile::TempDir,
    reference: String,
}

fn held_file() -> Held {
    let folder = tempfile::tempdir().expect("a folder for the held secret");
    let file = folder.path().join("db-host");
    write_owner_only(&file, "db.internal.example").expect("the held secret");
    let reference = format!("file:{}", file.display());
    Held {
        _folder: folder,
        reference,
    }
}

/// gateway.yaml with backend `a` whose env `key` holds `reference` (single
/// quotes: a Windows path's backslashes stay as written) and whose
/// `LOG_LEVEL` is plain.
fn holding(key: &str, reference: &str) -> String {
    format!(
        "secrets:\n  store: files\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    env:\n      {key}: '{reference}'\n      LOG_LEVEL: info\n"
    )
}

/// A value of exactly `bytes` bytes, ASCII.
fn ascii(bytes: usize) -> String {
    "q".repeat(bytes)
}

/// The race seam: after the route's read, another writer puts `text` on disk.
fn lands(panel: &Panel, text: &str) -> BackendStoreForTest {
    let config = panel.path();
    let text = text.to_owned();
    BackendStoreForTest {
        store: None,
        after_precheck: Some(Arc::new(move || {
            write_owner_only(&config, &text).expect("the other writer");
        })),
    }
}

/// K1 (KEEP.1): a long value over a held reference is stored even though
/// `DATABASE_HOST` does not name a credential; gateway.yaml holds the store's
/// reference.
#[tokio::test]
async fn k1_a_long_value_over_a_held_reference_is_stored_whatever_the_name() {
    let held = held_file();
    let panel = Panel::with(&holding("DATABASE_HOST", &held.reference), Reloads::Accept).await;
    let value = ascii(BOUND + 8);
    let (status, body) = panel
        .update("a", json!({"env": {"DATABASE_HOST": value}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stored = body["secrets_stored"].as_array().expect("secrets_stored");
    assert_eq!(
        (stored.len(), stored[0]["field"].as_str()),
        (1, Some("env.DATABASE_HOST")),
        "{body}"
    );
    assert_eq!(
        panel
            .written("a")
            .env
            .get("DATABASE_HOST")
            .map(String::as_str),
        stored[0]["reference"].as_str(),
        "the slot does not hold the store's reference"
    );
    assert_eq!(panel.entries().len(), 1, "{:?}", panel.entries());
    assert!(
        !panel.text().contains(&value),
        "the value reached gateway.yaml"
    );
    no_value(&body, &value);
}

/// K2 (KEEP.2): a short value over a held reference is refused before any
/// store call or byte; the plain member of the same request is not applied.
#[tokio::test]
async fn k2_a_short_value_over_a_held_reference_is_refused_before_anything() {
    let held = held_file();
    let panel = Panel::with(&holding("DATABASE_HOST", &held.reference), Reloads::Accept).await;
    let before = panel.text();
    let counted = Arc::new(Limited::new(&panel.dir.path().join("secrets")));
    let seam = BackendStoreForTest {
        store: Some(Arc::clone(&counted) as Arc<dyn SecretStore + Send + Sync>),
        after_precheck: None,
    };
    let (status, body) = panel
        .update_seamed(
            "a",
            json!({"env": {"DATABASE_HOST": "abc", "LOG_LEVEL": "debug"}}),
            Some(seam),
        )
        .await;
    assert_eq!(
        (status, body.clone()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({
                "error": "secret_too_short",
                "field": "env.DATABASE_HOST",
                "message": format!(
                    "env.DATABASE_HOST holds a secret reference today; a new value shorter than {BOUND} bytes cannot be kept as a secret, so nothing was changed"
                ),
            })
        )
    );
    assert_eq!(panel.text(), before, "gateway.yaml changed");
    assert_eq!(counted.calls(), 0, "the store was opened");
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());
}

/// K2b (KEEP.2): the bound is in bytes, on both sides, ASCII and multibyte.
#[tokio::test]
async fn k2b_the_bound_is_counted_in_bytes_on_both_sides() {
    // One byte short is refused; "ééé" is 6 bytes in 3 characters.
    for short in [ascii(BOUND - 1), "é".repeat((BOUND - 2) / 2)] {
        let held = held_file();
        let panel = Panel::with(&holding("DATABASE_HOST", &held.reference), Reloads::Accept).await;
        let before = panel.text();
        let (status, body) = panel
            .update("a", json!({"env": {"DATABASE_HOST": short}}))
            .await;
        assert_eq!(
            (status, body["error"].clone()),
            (StatusCode::UNPROCESSABLE_ENTITY, json!("secret_too_short")),
            "{short:?}: {body}"
        );
        assert_eq!(panel.text(), before, "{short:?}");
    }
    // Exactly the bound is stored; "éééé" is 8 bytes in 4 characters, so a
    // count of characters would refuse it.
    for exact in [ascii(BOUND), "é".repeat(BOUND / 2)] {
        let held = held_file();
        let panel = Panel::with(&holding("DATABASE_HOST", &held.reference), Reloads::Accept).await;
        let (status, body) = panel
            .update("a", json!({"env": {"DATABASE_HOST": exact}}))
            .await;
        assert_eq!(
            (status, body["secrets_stored"][0]["field"].clone()),
            (StatusCode::OK, json!("env.DATABASE_HOST")),
            "{exact:?}: {body}"
        );
        assert!(
            !panel.text().contains(&exact),
            "{exact:?} reached gateway.yaml"
        );
    }
}

/// K3 (KEEP.3): a slot holding no reference keeps today's rule: a long plain
/// value under a name that is not a credential is written as typed, and a
/// long value under a credential name is stored.
#[tokio::test]
async fn k3_a_plain_slot_keeps_todays_rule() {
    let panel = Panel::new().await;
    let typed = "a-plain-value-longer-than-the-bound";
    let (status, body) = panel.update("a", json!({"env": {"PLAIN": typed}})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (
            panel.written("a").env.get("PLAIN").cloned(),
            body["secrets_stored"].clone(),
            panel.entries().len()
        ),
        (Some(typed.to_owned()), json!([]), 0)
    );
    let (status, body) = panel
        .update("a", json!({"env": {"SERVICE_TOKEN": TOKEN}}))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["secrets_stored"][0]["field"], "env.SERVICE_TOKEN",
        "{body}"
    );
}

/// K4 (KEEP.4): for an accepted and a refused update, neither answer, nor
/// gateway.yaml, nor the admin audit log, nor a log line on the test's own
/// thread shows the value or any 8-byte run of it. Lines a blocking-pool
/// thread logs fall outside this capture.
#[test]
fn k4_no_answer_file_audit_or_log_carries_the_value() {
    let value = "zq-keep-canary-5521-xy";
    let short = "zq5";
    let (seen, logs) = crate::test_log_capture::capture_at(tracing::Level::TRACE, || {
        current_thread().block_on(async {
            let held = held_file();
            let mut panel =
                Panel::with(&holding("DATABASE_HOST", &held.reference), Reloads::Accept).await;
            let journal = audited(&mut panel);
            let (status, accepted) = panel
                .update("a", json!({"env": {"DATABASE_HOST": value}}))
                .await;
            assert_eq!(status, StatusCode::OK, "{accepted}");
            let (status, refused) = panel
                .update("a", json!({"env": {"DATABASE_HOST": short}}))
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
            let audit = std::fs::read_to_string(&journal).unwrap_or_default();
            assert!(!audit.is_empty(), "the audited write left no record");
            [
                ("accepted answer", accepted.to_string()),
                ("refused answer", refused.to_string()),
                ("gateway.yaml", panel.text()),
                ("audit log", audit),
            ]
        })
    });
    // The accepted update's reload logs this on the capture's thread every
    // time: without it the capture saw nothing and the checks below prove
    // nothing.
    assert!(logs.contains(RELOADED), "the log capture is dead: {logs:?}");
    for (what, text) in seen
        .iter()
        .map(|(w, t)| (*w, t.as_str()))
        .chain([("log lines", logs.as_str())])
    {
        assert!(!text.contains(short), "{what} shows the short value");
        no_run(what, text, value);
    }
}

/// The line a reload logs for every backend it updates, on the thread that
/// applies it: a capture holding it is live.
const RELOADED: &str = "Config reload: backend updated backend=a";

/// A current-thread runtime, so an async body inside a log capture logs on
/// the capture's own thread.
fn current_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

/// Hands the panel an admin audit log whose folder is registered and owned
/// by the log, so it outlives the log and goes at exit; returns the log path.
fn audited(panel: &mut Panel) -> std::path::PathBuf {
    let folder = crate::test_dir_keep::kept_tempdir();
    let journal = folder.path().join("audit.jsonl");
    let config = crate::security::transparency_log::TransparencyLogConfig {
        enabled: true,
        path: journal.to_string_lossy().into_owned(),
        key_id: "keep-rows".to_string(),
        ..Default::default()
    };
    let logger = crate::security::TransparencyLogger::open(Arc::new(config)).expect("an audit log");
    logger.keep_test_dir(folder);
    Arc::get_mut(&mut panel.state)
        .expect("the panel's state is not shared yet")
        .transparency_log = Some(Arc::new(logger));
    journal
}

/// No slice of `secret` as long as the short-value bound appears in `text`.
#[track_caller]
fn no_run(what: &str, text: &str, secret: &str) {
    for window in secret.as_bytes().windows(BOUND) {
        let run = std::str::from_utf8(window).expect("ascii");
        assert!(!text.contains(run), "{what} shows {run:?}");
    }
}

/// K5 (D4): the slot is plain when the route reads it and a reference when
/// the writer does: 409, the other writer's bytes kept, nothing stored for
/// either slot, no value in the answer.
#[tokio::test]
async fn k5_a_slot_that_became_a_reference_meanwhile_is_not_overwritten() {
    let held = held_file();
    let panel = Panel::new().await;
    let raced = holding("PLAIN", &held.reference);
    let value = "a-plain-value-longer-than-the-bound";
    let (status, body) = panel
        .update_seamed(
            "a",
            json!({"env": {"PLAIN": value, "SERVICE_TOKEN": TOKEN}}),
            Some(lands(&panel, &raced)),
        )
        .await;
    assert_eq!(
        (status, body.clone()),
        (
            StatusCode::CONFLICT,
            json!({"error": "env.PLAIN now holds a secret reference; nothing was changed; reload the server and try again"})
        )
    );
    assert_eq!(panel.text(), raced, "the other writer's reference was lost");
    assert!(panel.entries().is_empty(), "{:?}", panel.entries());
    no_value(&body, value);
    no_value(&body, TOKEN);
}

/// K5b (D4, with K4's checks): on that same race, neither submitted value nor
/// any bound-length slice of it shows in the refusal, the admin audit log or a
/// log line on the test's own thread.
#[test]
fn k5b_the_race_refusal_leaves_no_value_in_the_audit_log_or_logs() {
    let value = "a-plain-value-longer-than-the-bound";
    let ((status, body, audit), logs) =
        crate::test_log_capture::capture_at(tracing::Level::TRACE, || {
            current_thread().block_on(async {
                let held = held_file();
                let mut panel = Panel::new().await;
                let journal = audited(&mut panel);
                let raced = holding("PLAIN", &held.reference);
                let sent = json!({"env": {"PLAIN": value, "SERVICE_TOKEN": TOKEN}});
                let (status, body) = panel
                    .update_seamed("a", sent, Some(lands(&panel, &raced)))
                    .await;
                // No file means the refusal wrote no record; any other read
                // error fails the row rather than passing it unread.
                let audit = match std::fs::read_to_string(&journal) {
                    Ok(text) => text,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(e) => panic!("the audit log does not read: {e}"),
                };
                // The refusal itself logs nothing on this thread; an accepted
                // update in the same capture shows the capture was live.
                let (later, answer) = panel.update("a", json!({"env": {"AFTER": "1"}})).await;
                assert_eq!(later, StatusCode::OK, "{answer}");
                (status, body, audit)
            })
        });
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(logs.contains(RELOADED), "the log capture is dead: {logs:?}");
    for (what, text) in [
        ("the refusal", body.to_string()),
        ("audit log", audit),
        ("log lines", logs),
    ] {
        no_run(what, &text, value);
        no_run(what, &text, TOKEN);
    }
}

/// K6 (D2, with D4's seam for M9): a held reference set to another
/// reference, to empty or to a template is written as given, nothing stored,
/// nothing refused; and the same when the slot became a reference meanwhile.
#[tokio::test]
async fn k6_a_kept_value_over_a_held_reference_is_written_as_given() {
    let other = held_file();
    // The template names a variable every test host sets: the writer
    // refuses a template it cannot resolve.
    for kept in [other.reference.as_str(), "", "${PATH}"] {
        let held = held_file();
        let panel = Panel::with(&holding("DATABASE_HOST", &held.reference), Reloads::Accept).await;
        let (status, body) = panel
            .update("a", json!({"env": {"DATABASE_HOST": kept}}))
            .await;
        assert_eq!(status, StatusCode::OK, "{kept:?}: {body}");
        assert_eq!(
            (
                panel.written("a").env.get("DATABASE_HOST").cloned(),
                panel.entries().len()
            ),
            (Some(kept.to_owned()), 0),
            "{kept:?}"
        );

        let panel = Panel::new().await;
        let raced = holding("PLAIN", &held.reference);
        let (status, body) = panel
            .update_seamed(
                "a",
                json!({"env": {"PLAIN": kept}}),
                Some(lands(&panel, &raced)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "raced {kept:?}: {body}");
        assert_eq!(
            (
                panel.written("a").env.get("PLAIN").cloned(),
                panel.entries().len()
            ),
            (Some(kept.to_owned()), 0),
            "raced {kept:?}"
        );
    }
}
