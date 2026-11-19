// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the daily heartbeat (the heartbeat test plan). Every row drives the
//! awaited core or `decide` with explicit inputs; none relies on the
//! development-build skip, and every "nothing is sent" row carries its own
//! positive control.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::NaiveDate;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;

/// One request as the listener saw it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: Option<String>,
    /// Header name (lowercase) to value.
    headers: BTreeMap<String, String>,
    body: String,
}

/// How the listener answers.
#[derive(Clone)]
pub(super) enum Answer {
    NoContent,
    Error500,
    RedirectTo(String),
    Never,
}

/// A loopback HTTP listener that records every connection and request.
pub(super) struct Listener {
    base: String,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Listener {
    pub(super) async fn start(answer: Answer) -> Self {
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", socket.local_addr().expect("addr"));
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (count, log) = (Arc::clone(&connections), Arc::clone(&seen));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = socket.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let (log, answer) = (Arc::clone(&log), answer.clone());
                tokio::spawn(async move {
                    let Some(request) = read_request(&mut stream).await else {
                        return;
                    };
                    log.lock().expect("log").push(request);
                    let reply = match answer {
                        Answer::NoContent => "HTTP/1.1 204 No Content\r\n\r\n".to_owned(),
                        Answer::Error500 => {
                            "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n"
                                .to_owned()
                        }
                        Answer::RedirectTo(to) => format!(
                            "HTTP/1.1 302 Found\r\nlocation: {to}\r\ncontent-length: 0\r\n\r\n"
                        ),
                        Answer::Never => {
                            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                            return;
                        }
                    };
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        Self {
            base,
            connections,
            seen,
        }
    }

    pub(super) fn url(&self) -> String {
        format!("{}/v1/heartbeat", self.base)
    }

    pub(super) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("log").clone()
    }
}

/// Read one HTTP/1.1 request: head, then a content-length body.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (target, None),
    };
    let mut headers = BTreeMap::new();
    let mut length = 0_usize;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_ascii_lowercase();
        if name == "content-length" {
            length = value.trim().parse().ok()?;
        }
        headers.insert(name, value.trim().to_owned());
    }
    while buf.len() < head_end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    Some(Seen {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn day(d: u32) -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(2026, 11, d)
}
pub(super) fn nov19() -> Option<NaiveDate> {
    day(19)
}
pub(super) fn nov20() -> Option<NaiveDate> {
    day(20)
}
fn nov18() -> Option<NaiveDate> {
    day(18)
}

/// A release snapshot with nothing set: the one that sends.
pub(super) fn release() -> Snapshot {
    Snapshot {
        build: Build::Release,
        posture: SecurityPosture::Standard,
        env: BTreeMap::new(),
    }
}

/// `release()` with one variable set.
fn with(name: &str, value: &str) -> Snapshot {
    let mut s = release();
    s.env.insert(name.to_owned(), value.to_owned());
    s
}

pub(super) fn test_client() -> reqwest::Client {
    base_builder().build().expect("a test client")
}

/// The runtime string for this host, written out (not built from the code's
/// expression).
fn expected_runtime() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux/x86_64",
        ("linux", "aarch64") => "linux/aarch64",
        ("macos", "aarch64") => "macos/aarch64",
        ("macos", "x86_64") => "macos/x86_64",
        ("windows", "x86_64") => "windows/x86_64",
        ("windows", "aarch64") => "windows/aarch64",
        other => panic!("no expected runtime written for {other:?}"),
    }
}

pub(super) fn is_install_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Create `path` owner-only (0700 on Unix), so the wide-dir rule is never
/// what decides a row about something else.
pub(super) fn owner_only_dir(path: &Path) {
    std::fs::create_dir(path).expect("dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
    }
}

pub(super) fn read_id(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("heartbeat").join("install-id")).expect("an install id")
}

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
    for (name, value) in &r.headers {
        assert!(
            ["content-type", "host", "content-length"].contains(&name.as_str()) || value.len() < 64,
            "{name}: {value}"
        );
    }
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
    let claims = std::fs::read_dir(dir.path().join("heartbeat"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("day-"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(claims, 0, "a day was claimed without a date");
    let control = tempfile::tempdir().expect("dir");
    assert_eq!(
        heartbeat_once(&release(), control.path(), &test_client(), &rx.url(), nov19).await,
        Outcome::Sent
    );
}

/// The CI names, written out here rather than taken from `CI` (A7).
pub(super) const CI_NAMES: [&str; 18] = [
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "BUILDKITE",
    "DRONE",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
    "BITBUCKET_BUILD_NUMBER",
    "APPVEYOR",
    "CODEBUILD_BUILD_ID",
    "TF_BUILD",
    "CIRRUS_CI",
    "SEMAPHORE",
    "BITRISE_IO",
    "BUDDY",
];
/// The proxy names, written out.
pub(super) const PROXY_NAMES: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

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
                    (out, read_id(path))
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
        let dir = tempfile::tempdir().expect("dir");
        owner_only_dir(&dir.path().join("heartbeat"));
        std::fs::write(dir.path().join("heartbeat").join("install-id"), planted).expect("plant");
        let out = heartbeat_once(&release(), dir.path(), &test_client(), &rx.url(), nov19).await;
        assert_eq!(out, Outcome::NoId, "{planted:?}");
        assert_eq!(read_id(dir.path()), planted, "the planted id was replaced");
    }
    assert_eq!(rx.connections(), 0);
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
