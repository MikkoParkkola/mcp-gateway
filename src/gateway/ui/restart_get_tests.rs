// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart slice 7c-GET rows: the restart GET mints a confirmation only on
//! `?confirm=1`, for the full admin view, when restart is ready (mik-9447 test
//! plan r3, 7c GET rows). Where a plan row also posts the token, these rows
//! judge it through the registry on the state instead; the route POST is
//! slice 7c-POST's.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::restart_confirm::{
    InvocationSource, Platform, Presented, Readiness, Refusal, RestartConfirm, SampleSource,
    ScriptedInvocation,
};
use crate::config::AuthConfig;
use crate::gateway::recent_writes::WriteSample;
use crate::gateway::router::tests::audience_state;
use crate::gateway::router::{AppState, ProcessFacts, ProcessStart, create_router};
use crate::restart::invocation::{FileId, InvocationDigest};
use crate::security::{TransparencyLogConfig, TransparencyLogger};

const URI: &str = "/ui/api/gateway/restart";
const ADMIN: &str = "restart-admin";
/// An admin scoped to one backend: not the full admin view.
const SCOPED: &str = "restart-scoped";

/// Which gateway a row runs against.
#[derive(Clone, Copy)]
enum Gateway {
    /// Auth on, an unscoped admin key, and a transparency log.
    KeysWithLog,
    /// Auth on, the admin keys, and no transparency log: a state config
    /// validation refuses (auth on requires the log), built only so the
    /// readiness check for a missing log stays covered.
    KeysWithoutLog,
    /// Auth off and no transparency log, the only config that allows it.
    /// Every caller is anonymous there, so the admin-only restart routes
    /// refuse each request.
    AuthOff,
}

struct Fixture {
    router: Router,
    state: Arc<AppState>,
    /// Requests carry the admin key (auth on).
    admin: bool,
    _audit: Arc<tempfile::TempDir>,
    _store: crate::gateway::router::tests::FixtureDir,
}

fn file_id() -> FileId {
    FileId {
        dev: 1,
        ino: 2,
        size: 3,
        ctime_sec: 4,
        ctime_nsec: 5,
    }
}

fn sample(count: u64, writes_total: u64) -> WriteSample {
    WriteSample {
        count,
        complete_secs: 60,
        taken_at_mono: Instant::now(),
        writes_total,
    }
}

/// A scripted invocation: digest and target as given, reads counted.
fn invocation(
    digest: Option<InvocationDigest>,
    target: Option<Result<FileId, std::io::ErrorKind>>,
) -> Arc<ScriptedInvocation> {
    Arc::new(ScriptedInvocation {
        digest,
        target,
        reads: AtomicUsize::new(0),
    })
}

fn ready_invocation() -> Arc<ScriptedInvocation> {
    invocation(
        Some(InvocationDigest::for_test([9; 32])),
        Some(Ok(file_id())),
    )
}

/// Samples handed out in order, one per GET.
fn samples(list: &[Option<WriteSample>]) -> Arc<Mutex<VecDeque<Option<WriteSample>>>> {
    Arc::new(Mutex::new(list.iter().copied().collect()))
}

/// A registry that is on, with fresh random bytes per mint, on Unix.
fn confirm(
    inv: &Arc<ScriptedInvocation>,
    script: &Arc<Mutex<VecDeque<Option<WriteSample>>>>,
) -> RestartConfirm {
    let counter = Arc::new(Mutex::new(0u8));
    let fill: super::restart_confirm::Fill = Arc::new(move |bytes: &mut [u8]| {
        let mut n = counter.lock().unwrap();
        *n = n.wrapping_add(1);
        bytes.fill(*n);
        Ok(())
    });
    RestartConfirm::for_test(Arc::new(Instant::now), fill)
        .with_samples(SampleSource::Scripted(Arc::clone(script)))
        .with_invocation(InvocationSource::Scripted(Arc::clone(inv)))
        .with_platform(Platform::Unix)
}

async fn fixture(gateway: Gateway, registry: Option<RestartConfirm>) -> Fixture {
    let auth: AuthConfig = match gateway {
        Gateway::KeysWithLog | Gateway::KeysWithoutLog => {
            serde_json::from_value(json!({"enabled": true, "api_keys": [{
                "key_sha256": crate::config::api_key_digest_spec(ADMIN.as_bytes()),
                "name": ADMIN, "admin": true, "backends": ["*"]
            }, {
                "key_sha256": crate::config::api_key_digest_spec(SCOPED.as_bytes()),
                "name": SCOPED, "admin": true, "backends": ["alpha"]
            }]}))
            .unwrap()
        }
        Gateway::AuthOff => AuthConfig::default(),
    };
    let audit = crate::test_dir_keep::kept_tempdir();
    let (mut state, store) = audience_state(&auth, (None, None), |meta| meta).await;
    let unique = Arc::get_mut(&mut state).expect("unique state");
    if let Gateway::KeysWithLog = gateway {
        let config = TransparencyLogConfig {
            enabled: true,
            path: audit.path().join("audit.jsonl").display().to_string(),
            ..Default::default()
        };
        let log = Arc::new(TransparencyLogger::open(Arc::new(config)).expect("audit log"));
        log.keep_test_dir(Arc::clone(&audit));
        unique.transparency_log = Some(log);
    } else {
        unique.transparency_log = None;
    }
    if let Some(registry) = registry {
        unique.process =
            Arc::new(ProcessFacts::new(ProcessStart::now(), None).with_restart_confirm(registry));
    }
    Fixture {
        router: create_router(Arc::clone(&state)),
        state,
        admin: !matches!(gateway, Gateway::AuthOff),
        _audit: audit,
        _store: store,
    }
}

/// GET `query` (appended to the route), as the admin when auth is on.
async fn get(fx: &Fixture, query: &str) -> (Value, HeaderMap) {
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("{URI}{query}"));
    if fx.admin {
        req = req.header("authorization", format!("Bearer {ADMIN}"));
    }
    let req = req.body(Body::empty()).expect("request");
    tokio::time::timeout(Duration::from_secs(10), async {
        let response = fx.router.clone().oneshot(req).await.expect("response");
        assert_eq!(response.status().as_u16(), 200, "GET {query}");
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (serde_json::from_slice(&bytes).expect("JSON"), headers)
    })
    .await
    .expect("router responds within 10 seconds")
}

/// What the POST would present when nothing changed since the GET that
/// showed `shown`: the admin key's per-session principal and the same values.
fn presented(fx: &Fixture, shown: WriteSample) -> Presented {
    let client = fx
        .state
        .live_config
        .generation()
        .auth()
        .validate_token(ADMIN);
    Presented {
        principal: super::principal::cursor_principal(client.as_ref(), &HeaderMap::new()),
        boot: fx.state.dashboard_bootstrap.stream_hub().boot(),
        invocation: Some(InvocationDigest::for_test([9; 32])),
        target: Some(Ok(file_id())),
        sample: Some(shown),
    }
}

fn registry(fx: &Fixture) -> &RestartConfirm {
    fx.state.process.restart_confirm()
}

fn token(body: &Value) -> Option<&str> {
    body.get("confirm").and_then(Value::as_str)
}

// T-DEFAULT-OFF-ROUTE (pin: nothing turns restart on yet): the production
// registry, no override: a `?confirm=1` GET mints nothing.
#[tokio::test]
async fn the_production_gateway_mints_no_confirmation() {
    let fx = fixture(Gateway::KeysWithLog, None).await;
    let (body, _) = get(&fx, "?confirm=1").await;
    assert_eq!(token(&body), None, "{body}");
    assert_eq!(body["available"], false, "{body}");
}

// T-OFF-READY: invocation and target ready, the registry switched off.
#[tokio::test]
async fn restart_switched_off_mints_nothing_even_when_ready() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(0, 10))]);
    let fx = fixture(
        Gateway::KeysWithLog,
        Some(confirm(&inv, &script).switched_off()),
    )
    .await;
    let (body, _) = get(&fx, "?confirm=1").await;
    assert_eq!(token(&body), None, "{body}");
    assert_eq!(body["reason"], "restart_not_available", "{body}");
}

// T-NOLOG-GET (lead), readiness half: no transparency log, everything else
// ready: `audit_log_required` is the only reason left. Shown on an auth-on
// state with no log, which config refuses; the real auth-off gateway is the
// next row.
#[tokio::test]
async fn no_transparency_log_answers_audit_log_required() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(0, 10))]);
    let fx = fixture(Gateway::KeysWithoutLog, Some(confirm(&inv, &script))).await;
    let (body, _) = get(&fx, "?confirm=1").await;
    assert_eq!(body["available"], false, "{body}");
    assert_eq!(body["reason"], "audit_log_required", "{body}");
    assert!(
        body["recovery"]
            .as_str()
            .is_some_and(|r| r.contains("transparency log")),
        "{body}"
    );
    assert_eq!(token(&body), None, "{body}");
}

// T-GET-OPTIN (ui): only `?confirm=1` mints, and the response is no-store.
#[tokio::test]
async fn only_confirm_1_mints_and_its_answer_is_not_stored() {
    let inv = ready_invocation();
    let shown = sample(2, 10);
    // One sample per GET; this row makes sixteen.
    let script = samples(&[Some(shown); 16]);
    let fx = fixture(Gateway::KeysWithLog, Some(confirm(&inv, &script))).await;
    let (plain, plain_headers) = get(&fx, "").await;
    assert_eq!(token(&plain), None, "a plain GET never mints: {plain}");
    assert_eq!(plain["available"], true, "{plain}");
    assert!(
        plain_headers
            .get("cache-control")
            .is_none_or(|v| v != "no-store")
    );
    for query in [
        "?confirm=0",
        "?confirm=yes",
        "?confirm",
        "?confirm=1&confirm=1",
        "?confirm=1=1",
        "?confirm=1&bad=%ZZ",
        "?confirm=1&=x",
        "?confirm=1&",
        "?confirm=1&a=%4",
        "?%63onfirm=1",
        "?confirm=%31",
        "?confirm=1&confirm=0",
    ] {
        let (body, _) = get(&fx, query).await;
        assert_eq!(body, plain, "{query} answers exactly like a plain GET");
    }
    assert_eq!(registry(&fx).entry_count(), 0, "nothing minted so far");
    let (body, headers) = get(&fx, "?confirm=1").await;
    let first = token(&body)
        .expect("?confirm=1 mints for the full admin view")
        .to_owned();
    assert_eq!(
        headers.get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store")
    );
    // Polling after the dialog opened leaves its token valid.
    let (after, _) = get(&fx, "").await;
    assert_eq!(token(&after), None);
    assert_eq!(
        registry(&fx).entry_count(),
        1,
        "the plain GET minted nothing"
    );
    // A second `?confirm=1` replaces the first.
    let (again, _) = get(&fx, "?confirm=1").await;
    let second = token(&again).expect("second mint").to_owned();
    assert_ne!(first, second);
    assert_eq!(
        registry(&fx).consume(&first, &presented(&fx, shown)).err(),
        Some(Refusal::Invalid)
    );
    assert!(
        registry(&fx)
            .consume(&second, &presented(&fx, shown))
            .is_ok(),
        "the newest token holds"
    );
}

// T-GET-PRECOND (table): `?confirm=1` with one precondition missing answers
// the normal preview, with no `confirm` and no registry entry.
#[tokio::test]
async fn a_missing_precondition_answers_the_preview_without_a_token() {
    // name, invocation, the sample shown, platform, whether the random source works
    type Case = (
        &'static str,
        Arc<ScriptedInvocation>,
        Option<WriteSample>,
        Platform,
        bool,
    );
    let digest = Some(InvocationDigest::for_test([9; 32]));
    let cases: Vec<Case> = vec![
        (
            "invocation unavailable",
            invocation(None, None),
            Some(sample(0, 1)),
            Platform::Unix,
            true,
        ),
        (
            "target None",
            invocation(digest, None),
            Some(sample(0, 1)),
            Platform::Unix,
            true,
        ),
        (
            "target Err",
            invocation(digest, Some(Err(std::io::ErrorKind::NotFound))),
            Some(sample(0, 1)),
            Platform::Unix,
            true,
        ),
        (
            "sample None",
            ready_invocation(),
            None,
            Platform::Unix,
            true,
        ),
        (
            "platform unavailable",
            ready_invocation(),
            Some(sample(0, 1)),
            Platform::Windows,
            true,
        ),
        (
            "random source fails",
            ready_invocation(),
            Some(sample(0, 1)),
            Platform::Unix,
            false,
        ),
    ];
    for (name, inv, shown, platform, fill_ok) in cases {
        let script = samples(&[shown, shown]);
        let mut rc = confirm(&inv, &script).with_platform(platform);
        if !fill_ok {
            rc = RestartConfirm::for_test(Arc::new(Instant::now), Arc::new(|_: &mut [u8]| Err(())))
                .with_samples(SampleSource::Scripted(Arc::clone(&script)))
                .with_invocation(InvocationSource::Scripted(Arc::clone(&inv)))
                .with_platform(platform);
        }
        let fx = fixture(Gateway::KeysWithLog, Some(rc)).await;
        let (plain, _) = get(&fx, "").await;
        let (body, headers) = get(&fx, "?confirm=1").await;
        assert_eq!(body, plain, "{name}: the normal preview");
        assert_eq!(token(&body), None, "{name}");
        assert!(
            headers.get("cache-control").is_none_or(|v| v != "no-store"),
            "{name}"
        );
        assert_eq!(registry(&fx).entry_count(), 0, "{name}: no entry");
    }
}

// Readiness order (r2): the platform reason comes before audit_log_required.
#[tokio::test]
async fn the_platform_reason_comes_before_the_missing_log() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(0, 1))]);
    let rc = confirm(&inv, &script).with_platform(Platform::Windows);
    let fx = fixture(Gateway::KeysWithoutLog, Some(rc)).await;
    let (body, _) = get(&fx, "").await;
    assert_eq!(body["reason"], "windows_manual_restart", "{body}");
    // Restart off, or no restart target, also comes before the missing log.
    for (name, inv, off) in [
        ("switched off", ready_invocation(), true),
        (
            "no target",
            invocation(Some(InvocationDigest::for_test([9; 32])), None),
            false,
        ),
    ] {
        let script = samples(&[Some(sample(0, 1))]);
        let mut rc = confirm(&inv, &script);
        if off {
            rc = rc.switched_off();
        }
        let fx = fixture(Gateway::KeysWithoutLog, Some(rc)).await;
        let (body, _) = get(&fx, "").await;
        assert_eq!(body["reason"], "restart_not_available", "{name}: {body}");
    }
}

// T-GET-PRECOND, the half HTTP cannot reach: a caller with no per-session
// principal mints nothing. (The view leg is the scoped-admin row below.)
#[test]
fn no_principal_or_a_partial_view_mints_nothing() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(0, 1)); 4]);
    let rc = confirm(&inv, &script);
    let ready = rc.readiness(true);
    assert!(
        matches!(ready, Readiness::Ready { .. }),
        "premise: ready, {ready:?}"
    );
    let shown = Some(sample(0, 1));
    assert_eq!(
        rc.confirmation(ready, shown, None, &HeaderMap::new(), 1),
        None,
        "no principal"
    );
    assert_eq!(
        rc.confirmation(ready, None, None, &HeaderMap::new(), 1),
        None,
        "no sample"
    );
    assert_eq!(rc.entry_count(), 0);
}

// T-GET-VALUES: one GET reads each source once, and the token binds the
// sample that GET displayed.
#[tokio::test]
async fn one_get_reads_each_source_once_and_binds_what_it_shows() {
    let inv = ready_invocation();
    let shown = sample(5, 70);
    let script = samples(&[Some(shown), Some(sample(9, 99))]);
    let fx = fixture(Gateway::KeysWithLog, Some(confirm(&inv, &script))).await;
    let (body, _) = get(&fx, "?confirm=1").await;
    let token = token(&body).expect("mint").to_owned();
    assert_eq!(body["recent_writes"]["count"], 5, "{body}");
    assert_eq!(
        inv.reads.load(Ordering::SeqCst),
        1,
        "the invocation source is read once"
    );
    assert_eq!(
        script.lock().unwrap().len(),
        1,
        "the sample source is read once"
    );
    assert!(
        registry(&fx)
            .consume(&token, &presented(&fx, shown))
            .is_ok(),
        "the token binds the sample the GET showed"
    );
}

// D3 (lead): every override seam on the registry is compiled only into test
// builds. The registry's source with test-only items blanked holds none of
// them, while the raw source does, so the scan cannot pass on an empty read.
#[test]
fn the_registry_override_seams_exist_only_in_test_builds() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gateway/ui/restart_confirm.rs"
    );
    let raw = std::fs::read_to_string(path).expect("read restart_confirm.rs");
    let shipped = crate::test_source_text::production_text(&raw);
    for seam in [
        "fn for_test(",
        "fn with_samples(",
        "fn with_invocation(",
        "fn with_platform(",
        "fn switched_off(",
        "fn plant(",
        "Scripted(",
        "struct ScriptedInvocation",
    ] {
        assert!(raw.contains(seam), "premise: {seam} is in the source");
        assert!(
            !shipped.contains(seam),
            "{seam} is compiled into a release build"
        );
    }
    // The hook that swaps a registry into the process facts is a seam too.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gateway/router/process_facts.rs"
    );
    let raw = std::fs::read_to_string(path).expect("read process_facts.rs");
    let shipped = crate::test_source_text::production_text(&raw);
    assert!(
        raw.contains("fn with_restart_confirm("),
        "premise: the hook is in the source"
    );
    assert!(
        !shipped.contains("fn with_restart_confirm("),
        "with_restart_confirm is compiled into a release build"
    );
}

// T-NOLOG-LINE, its GET leg (GET.1): a minting GET writes the token to no log
// line at any level. The POST legs are slice 7c-POST's.
#[test]
fn a_minting_get_logs_no_token() {
    let (body, logs) = crate::test_log_capture::capture_at(tracing::Level::TRACE, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let inv = ready_invocation();
            let script = samples(&[Some(sample(1, 5))]);
            let fx = fixture(Gateway::KeysWithLog, Some(confirm(&inv, &script))).await;
            tracing::info!("restart-get-log-probe");
            get(&fx, "?confirm=1").await.0
        })
    });
    let token = token(&body).expect("the GET minted");
    assert!(
        logs.contains("restart-get-log-probe"),
        "premise: the capture is live"
    );
    assert!(!logs.contains(token), "the token reached a log line");
}

// T-GET-PRECOND, the view leg: an admin scoped to one backend does not get
// the full admin view; its `?confirm=1` is refused 403 and mints nothing.
#[tokio::test]
async fn a_scoped_admins_confirm_request_is_refused_and_mints_nothing() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(0, 1)); 2]);
    let fx = fixture(Gateway::KeysWithLog, Some(confirm(&inv, &script))).await;
    let req = Request::builder()
        .method("GET")
        .uri(format!("{URI}?confirm=1"))
        .header("authorization", format!("Bearer {SCOPED}"))
        .body(Body::empty())
        .expect("request");
    let response = fx.router.clone().oneshot(req).await.expect("response");
    assert_eq!(response.status().as_u16(), 403);
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    assert!(
        !String::from_utf8_lossy(&bytes).contains("confirm"),
        "no token in a refusal"
    );
    assert_eq!(registry(&fx).entry_count(), 0, "no entry");
}

// ui's condition on D2: the route adds `confirm` next to the availability
// body. A minting full-view GET carries exactly the three members the dialog
// reads; a GET that does not mint carries no `confirm`.
#[tokio::test]
async fn a_minting_get_carries_exactly_available_recent_writes_and_confirm() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(3, 30)); 2]);
    let fx = fixture(Gateway::KeysWithLog, Some(confirm(&inv, &script))).await;
    let (minted, _) = get(&fx, "?confirm=1").await;
    let mut keys: Vec<&str> = minted
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["available", "confirm", "recent_writes"], "{minted}");
    assert_eq!(minted["available"], true, "{minted}");
    assert_eq!(
        minted["recent_writes"],
        json!({"count": 3, "complete_secs": 60}),
        "{minted}"
    );
    assert!(
        minted["confirm"]
            .as_str()
            .is_some_and(|t| t.starts_with("rc1.")),
        "{minted}"
    );
    let (plain, _) = get(&fx, "").await;
    assert!(
        plain.get("confirm").is_none(),
        "a GET that does not mint: {plain}"
    );
    let mut rest = minted.clone();
    rest.as_object_mut().expect("an object").remove("confirm");
    assert_eq!(rest, plain, "confirm is the only member the mint adds");
}

// T-NOLOG-GET (lead), route half: the real gateway with no transparency log
// is an auth-off one, where every caller is anonymous; the admin-only restart
// GET refuses each request, so no confirmation the POST would refuse is ever
// offered.
#[tokio::test]
async fn an_auth_off_gateway_refuses_every_restart_get() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(0, 1)); 2]);
    let fx = fixture(Gateway::AuthOff, Some(confirm(&inv, &script))).await;
    let req = Request::builder()
        .method("GET")
        .uri(format!("{URI}?confirm=1"))
        .body(Body::empty())
        .expect("request");
    let response = fx.router.clone().oneshot(req).await.expect("response");
    assert_eq!(response.status().as_u16(), 403);
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    assert!(
        !String::from_utf8_lossy(&bytes).contains("confirm"),
        "no token in a refusal"
    );
    assert_eq!(registry(&fx).entry_count(), 0, "no entry");
}

// D2 (ui's B6 rows depend on it): while restart is not ready, the body is
// byte for byte the one shipped before 7c-GET, as an exact string (keys in
// serde_json's sorted order), with and without the full view's sample.
#[test]
fn the_not_ready_body_is_byte_identical_to_the_shipped_one() {
    use super::restart::availability_body;
    use super::restart_confirm::Reason;
    use super::status::StatusView;
    #[cfg(not(windows))]
    let reason = "restart_not_available";
    #[cfg(windows)]
    let reason = "windows_manual_restart";
    // Read, not restated: the Unix line was reworded, and restart_advice_tests.rs
    // (A8b) allows each guidance sentence one copy under src/.
    let recovery = Reason::PLATFORM.recovery();
    let off = Readiness::Unavailable(Reason::PLATFORM);
    let shown = WriteSample {
        count: 7,
        complete_secs: 42,
        taken_at_mono: Instant::now(),
        writes_total: 99,
    };
    assert_eq!(
        serde_json::to_string(&availability_body(StatusView::Full, Some(shown), off)).unwrap(),
        format!(
            r#"{{"available":false,"reason":"{reason}","recent_writes":{{"complete_secs":42,"count":7}},"recovery":"{recovery}"}}"#
        )
    );
    assert_eq!(
        serde_json::to_string(&availability_body(StatusView::CountsOnly, None, off)).unwrap(),
        format!(r#"{{"available":false,"reason":"{reason}","recovery":"{recovery}"}}"#)
    );
}

// T-GET-OPTIN: other well-formed pairs beside exactly one confirm=1 still mint.
#[tokio::test]
async fn other_well_formed_pairs_beside_confirm_1_still_mint() {
    let inv = ready_invocation();
    let script = samples(&[Some(sample(1, 5)); 2]);
    let fx = fixture(Gateway::KeysWithLog, Some(confirm(&inv, &script))).await;
    let (body, _) = get(&fx, "?tab=actions&confirm=1&lang=en%2Dgb").await;
    assert!(token(&body).is_some(), "{body}");
}
