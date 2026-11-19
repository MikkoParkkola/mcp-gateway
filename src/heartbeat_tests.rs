// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the daily heartbeat (the heartbeat test plan). Every row drives the
//! awaited core or `decide` with explicit inputs; none relies on the
//! development-build skip, and every "nothing is sent" row carries its own
//! positive control.

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::NaiveDate;

use super::fixtures::*;
use super::*;

/// P1. The request is exactly a POST of the five fields, with a header set
/// inside the allowlist. Control: the same check's first send exists.
#[tokio::test]
async fn request_is_exactly_the_five_fields() {
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    let out = heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await;
    assert_eq!(out, Outcome::Sent);
    let seen = rx.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    let r = &seen[0];
    assert_eq!(
        (r.method.as_str(), r.path.as_str(), r.query.as_deref()),
        ("POST", "/v1/heartbeat", None)
    );
    let allowed: BTreeSet<&str> = [
        "content-type",
        "accept",
        "accept-encoding",
        "host",
        "content-length",
    ]
    .into();
    assert!(
        r.headers.keys().all(|h| allowed.contains(h.as_str())),
        "{:?}",
        r.headers
    );
    // Values too (tp-r1): none may carry anything about the machine or user.
    assert_eq!(
        r.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    let host = r.headers.get("host").expect("a host header");
    assert!(host.starts_with("127.0.0.1:"), "{host}");
    if let Some(accept) = r.headers.get("accept") {
        assert_eq!(accept, "*/*");
    }
    if let Some(encodings) = r.headers.get("accept-encoding") {
        assert!(
            encodings
                .split(',')
                .map(|e| e.split(';').next().unwrap_or("").trim())
                .all(|e| ["gzip", "deflate", "br", "zstd", "identity"].contains(&e)),
            "accept-encoding: {encodings}"
        );
    }
    let length: usize = r
        .headers
        .get("content-length")
        .expect("a length")
        .parse()
        .expect("a number");
    assert_eq!(length, r.body.len());
    let body: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&r.body).expect("a JSON object");
    let keys: BTreeSet<&str> = body.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["event", "install_id", "project", "runtime", "version"].into()
    );
    assert_eq!(body["project"], "mcp-gateway");
    assert_eq!(body["event"], "heartbeat");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["runtime"], expected_runtime());
    let id = body["install_id"].as_str().expect("a string id");
    assert!(is_install_id(id), "{id}");
    assert_eq!(id, read_id(dir.path()));
}

/// P2. The production URL and constants are the literals the disclosure states.
#[test]
fn production_url_is_the_literal() {
    assert_eq!(URL, "https://telemetry.revaluator.ai/v1/heartbeat");
    assert_eq!(PROJECT, "mcp-gateway");
    assert_eq!(EVENT, "heartbeat");
}

/// N1. A clock that reads before the epoch gives no date: nothing is
/// claimed or sent; a readable clock sends (control).
#[tokio::test]
async fn a_clock_before_the_epoch_sends_nothing() {
    fn before_epoch() -> Option<NaiveDate> {
        None
    }
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    let out = heartbeat_once(
        &release(),
        dir.path(),
        &test_client(),
        &rx.url(),
        before_epoch,
    )
    .await;
    assert_eq!(out, Outcome::NoDate);
    assert_eq!(rx.connections(), 0);
    let claims = std::fs::read_dir(dir.path().join("heartbeat")).map_or(0, |d| {
        d.flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("day-"))
            .count()
    });
    assert_eq!(claims, 0, "a day was claimed without a date");
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// D0. The control every decision row shares: a release snapshot with
/// nothing set sends.
#[test]
fn a_release_snapshot_with_nothing_set_sends() {
    assert_eq!(decide(&release()), Ok(()));
}

/// D1. Each opt-out variable with a true value skips; the same snapshot
/// without it sends.
#[test]
fn each_opt_out_value_skips() {
    for name in ["DO_NOT_TRACK", "NO_TELEMETRY"] {
        for value in ["1", "true", "yes"] {
            assert_eq!(
                decide(&with(name, value)),
                Err(Skip::OptOut),
                "{name}={value}"
            );
        }
    }
    assert_eq!(decide(&release()), Ok(()), "control");
}

/// D2. Each CI variable skips (literal list of 18).
#[test]
fn each_ci_variable_skips() {
    for name in CI_NAMES {
        assert_eq!(decide(&with(name, "true")), Err(Skip::Ci), "{name}");
    }
    assert_eq!(
        CI.len(),
        CI_NAMES.len(),
        "the code's list and the written list differ in size"
    );
    assert_eq!(decide(&release()), Ok(()), "control");
}

/// D3. Each proxy variable with a value skips.
#[test]
fn each_proxy_variable_skips() {
    for name in PROXY_NAMES {
        assert_eq!(
            decide(&with(name, "http://proxy.invalid:3128")),
            Err(Skip::Proxy),
            "{name}"
        );
    }
    assert_eq!(decide(&release()), Ok(()), "control");
}

/// D4. A hardened posture skips; the standard one sends.
#[test]
fn hardened_skips() {
    let mut s = release();
    s.posture = SecurityPosture::Hardened;
    assert_eq!(decide(&s), Err(Skip::Hardened));
    assert_eq!(decide(&release()), Ok(()), "control");
}

/// D5. A development build skips; a release build sends.
#[test]
fn a_debug_build_skips() {
    let mut s = release();
    s.build = Build::Dev;
    assert_eq!(decide(&s), Err(Skip::DevBuild));
    assert_eq!(decide(&release()), Ok(()), "control");
}

/// D6. Empty, `0` and `false` do not opt out or mark CI.
#[test]
fn truthiness_empty_zero_false_do_not_opt_out() {
    for name in ["DO_NOT_TRACK", "NO_TELEMETRY", "CI", "GITHUB_ACTIONS"] {
        for value in ["", "0", "false"] {
            assert_eq!(decide(&with(name, value)), Ok(()), "{name}={value:?}");
        }
        assert!(decide(&with(name, "1")).is_err(), "control {name}=1");
    }
    // Whitespace is a value, not empty (code review 1).
    assert_eq!(decide(&with("DO_NOT_TRACK", " ")), Err(Skip::OptOut));
    assert_eq!(decide(&with("CI", " ")), Err(Skip::Ci));
}

/// D7. A proxy variable that is present but empty does not skip.
#[test]
fn an_empty_proxy_variable_does_not_skip() {
    for name in PROXY_NAMES {
        assert_eq!(decide(&with(name, "")), Ok(()), "{name} empty");
        assert_eq!(
            decide(&with(name, "http://p.invalid:1")),
            Err(Skip::Proxy),
            "control {name}"
        );
    }
    // Whitespace is a value, not empty (code review 1).
    assert_eq!(decide(&with("HTTPS_PROXY", " ")), Err(Skip::Proxy));
}

/// D9. A test build's own reader yields a development build.
#[test]
fn a_test_build_reader_is_dev() {
    assert_eq!(Build::current(), Build::Dev);
    assert_eq!(
        Snapshot::from_process(SecurityPosture::Standard).build,
        Build::Dev
    );
}

/// A skipped check opens no connection and creates nothing; the same
/// fixture with the release snapshot sends once (the in-row control).
async fn skipped_sends_nothing(snapshot: Snapshot, why: Skip) {
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    let out = heartbeat_once(&snapshot, dir.path(), &test_client(), &rx.url(), nov19).await;
    assert_eq!(out, Outcome::Skipped(why));
    assert_eq!(rx.connections(), 0);
    assert!(
        !dir.path().join("heartbeat").exists(),
        "a skipped check created state"
    );
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
    assert_eq!(rx.requests().len(), 1, "control");
}

/// D1-D5 through the core: each skip reason opens no connection.
#[tokio::test]
async fn each_skip_opens_no_connection() {
    skipped_sends_nothing(with("DO_NOT_TRACK", "1"), Skip::OptOut).await;
    skipped_sends_nothing(with("CI", "true"), Skip::Ci).await;
    skipped_sends_nothing(with("HTTPS_PROXY", "http://p.invalid:1"), Skip::Proxy).await;
    let mut hardened = release();
    hardened.posture = SecurityPosture::Hardened;
    skipped_sends_nothing(hardened, Skip::Hardened).await;
    let mut dev = release();
    dev.build = Build::Dev;
    skipped_sends_nothing(dev, Skip::DevBuild).await;
}

/// O2. N threads behind one barrier on one dir: exactly one connection, and
/// every thread read the same id.
#[test]
fn threads_share_one_send_per_day() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("rt");
    let rx = rt.block_on(Listener::start(Answer::NoContent));
    let dir = tempfile::tempdir().expect("dir");
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let url = rx.url();
    let outcomes: Vec<(Outcome, String)> = std::thread::scope(|s| {
        let joins: Vec<_> = (0..4)
            .map(|_| {
                let (barrier, url, path, handle) = (
                    Arc::clone(&barrier),
                    url.clone(),
                    dir.path(),
                    rt.handle().clone(),
                );
                s.spawn(move || {
                    barrier.wait();
                    let out = handle.block_on(heartbeat_once(
                        &release(),
                        path,
                        &test_client(),
                        &url,
                        nov19,
                    ));
                    // Read without panicking, so a missing id reaches the
                    // row's own assertions below.
                    let id = std::fs::read_to_string(path.join("heartbeat").join("install-id"))
                        .unwrap_or_default();
                    (out, id)
                })
            })
            .collect();
        joins
            .into_iter()
            .map(|j| j.join().expect("thread"))
            .collect()
    });
    let sent = outcomes.iter().filter(|(o, _)| *o == Outcome::Sent).count();
    assert_eq!(sent, 1, "{outcomes:?}");
    assert!(
        outcomes
            .iter()
            .all(|(o, _)| matches!(o, Outcome::Sent | Outcome::NoClaim)),
        "a loser did something other than NoClaim: {outcomes:?}"
    );
    assert_eq!(rx.requests().len(), 1);
    let id = read_id(dir.path());
    assert!(is_install_id(&id));
    assert!(
        outcomes.iter().all(|(_, seen)| *seen == id),
        "threads read different ids: {outcomes:?}"
    );
}

/// O3. The next UTC day sends again, with the same id.
#[tokio::test]
async fn next_day_sends_again_with_the_same_id() {
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    let c = test_client();
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov19).await,
        Outcome::Sent
    );
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov19).await,
        Outcome::NoClaim
    );
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov20).await,
        Outcome::Sent
    );
    let ids: Vec<String> = rx
        .requests()
        .iter()
        .map(|r| {
            let v: serde_json::Value = serde_json::from_str(&r.body).expect("json");
            v["install_id"].as_str().expect("id").to_owned()
        })
        .collect();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1], "the id changed between days");
    let other = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), other.path(), &c, &rx.url(), nov19).await,
        Outcome::Sent
    );
    assert_ne!(
        read_id(other.path()),
        ids[0],
        "two clean data dirs got the same id"
    );
}

/// O4. A clock moved back to a day already claimed sends nothing; the next
/// new day still sends (control).
#[tokio::test]
async fn a_clock_moved_back_never_resends() {
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    let c = test_client();
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov18).await,
        Outcome::Sent
    );
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov20).await,
        Outcome::Sent
    );
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov18).await,
        Outcome::NoClaim
    );
    assert_eq!(rx.requests().len(), 2);
}

/// O5. `heartbeat` is a regular file (fails even as root): nothing is sent
/// and no id appears; a clean dir sends (control).
#[tokio::test]
async fn a_blocked_heartbeat_dir_sends_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("heartbeat"), b"not a dir").expect("plant");
    let rx = Listener::start(Answer::NoContent).await;
    let out = heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await;
    assert_eq!(out, Outcome::NoId);
    assert_eq!(rx.connections(), 0);
    let clean = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), clean.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
    assert_eq!(rx.requests().len(), 1, "control");
}

/// O6. A valid id, but today's claim path is a directory: nothing is sent;
/// with the path free the same dir sends (control).
#[tokio::test]
async fn a_valid_id_with_a_blocked_claim_sends_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    let c = test_client();
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov18).await,
        Outcome::Sent
    );
    std::fs::create_dir(dir.path().join("heartbeat").join("day-2026-11-19")).expect("plant");
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov19).await,
        Outcome::NoClaim
    );
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &c, &rx.url(), nov20).await,
        Outcome::Sent
    );
    assert_eq!(rx.requests().len(), 2);
}

/// O7. An empty, short or non-hex `install-id` is never replaced and sends
/// nothing; a clean dir sends (control).
#[tokio::test]
async fn a_malformed_id_is_never_replaced() {
    let rx = Listener::start(Answer::NoContent).await;
    for planted in [
        "",
        "abc123",
        "0123456789abcdef0123456789abcdeg",
        "0123456789abcdef0123456789abcdef\n",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789ABCDEF0123456789ABCDEF",
    ] {
        // The code creates its own owner-only dir and a valid id first (so no
        // other rule decides, on any OS), then the id is replaced (tp-r2).
        let dir = tempfile::tempdir().expect("dir");
        assert_eq!(
            heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov18).await,
            Outcome::Sent
        );
        std::fs::write(dir.path().join("heartbeat").join("install-id"), planted).expect("plant");
        let before = rx.requests().len();
        let out = heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await;
        assert_eq!(
            rx.requests().len(),
            before,
            "a malformed id was sent: {planted:?}"
        );
        assert_eq!(out, Outcome::NoId, "{planted:?}");
        assert_eq!(read_id(dir.path()), planted, "the planted id was replaced");
    }
    let clean = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), clean.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// O8's data dir, so its clock can watch the claim.
static PAST_MIDNIGHT_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
/// The 19th until the 19th's claim exists in O8's dir, then the 20th: the
/// date moves between the claim and the send however often the code reads it.
fn past_midnight() -> Option<NaiveDate> {
    let claimed = PAST_MIDNIGHT_DIR
        .get()
        .is_some_and(|d| d.join("heartbeat").join("day-2026-11-19").exists());
    if claimed { nov20() } else { nov19() }
}

/// O8. The date moves between the claim and the send: nothing is sent; a
/// steady clock sends (control).
#[tokio::test]
async fn a_claim_past_midnight_sends_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let rx = Listener::start(Answer::NoContent).await;
    PAST_MIDNIGHT_DIR
        .set(dir.path().to_path_buf())
        .expect("set once");
    let out = heartbeat_once(
        &release(),
        dir.path(),
        &test_client(),
        &rx.url(),
        past_midnight,
    )
    .await;
    assert_eq!(out, Outcome::DateMoved);
    assert_eq!(rx.connections(), 0);
    let steady = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), steady.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// O9. A pre-existing `heartbeat/` that others can read or write stops the
/// check and is left as it is; an owner-only one sends (control).
#[cfg(unix)]
#[tokio::test]
async fn a_wide_existing_dir_stops_the_check() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("dir");
    let hb = dir.path().join("heartbeat");
    std::fs::create_dir(&hb).expect("dir");
    std::fs::set_permissions(&hb, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let rx = Listener::start(Answer::NoContent).await;
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::NoId
    );
    assert_eq!(
        std::fs::metadata(&hb).expect("meta").permissions().mode() & 0o777,
        0o755,
        "the mode was changed"
    );
    std::fs::set_permissions(&hb, std::fs::Permissions::from_mode(0o700)).expect("mode");
    assert_eq!(
        heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
    assert_eq!(rx.connections(), 1);
}
