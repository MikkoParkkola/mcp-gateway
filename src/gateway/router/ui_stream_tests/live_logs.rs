// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live stream's activity and config kinds, through the real router,
//! over real transparency loggers in a temporary directory.

use super::*;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

const SCOPED_ADMIN: &str = "u3-scoped-admin-key";

fn logger(dir: &tempfile::TempDir, name: &str) -> Arc<TransparencyLogger> {
    let config = TransparencyLogConfig {
        enabled: true,
        path: dir.path().join(name).to_string_lossy().into_owned(),
        ..TransparencyLogConfig::default()
    };
    Arc::new(TransparencyLogger::open(Arc::new(config)).expect("the logger opens"))
}

fn scoped_admin(backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(SCOPED_ADMIN.as_bytes())),
        name: SCOPED_ADMIN.to_string(),
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        admin: true,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// A gateway writing both logs (`governance` false: no governance log), with
/// the bearer, the standard key and a scoped admin key over `a` and `b`.
async fn logged(governance: bool) -> (Arc<AppState>, impl Sized, Arc<TransparencyLogger>) {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let inv = logger(&dir, "invocation.jsonl");
    let gov = governance.then(|| logger(&dir, "governance.jsonl"));
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![standard_key(), scoped_admin(&["a", "b"])],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (state, fixture_dir) = super::super::tests::meta_fixture::test_router_app_state_with_logs(
        &auth,
        Some(Arc::clone(&inv)),
        gov,
    )
    .await;
    (state, (fixture_dir, dir), inv)
}

fn call(log: &TransparencyLogger, server: &str, n: usize) {
    log.log_invocation(
        "s",
        "c",
        server,
        &format!("tool_{n}"),
        "sha256:aa",
        "sha256:bb",
    )
    .expect("the call is logged");
}

#[tokio::test]
async fn s1a_an_admin_activity_stream_gets_a_call_made_after_it_opened() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let hello = s.until("hello").await;
    assert_eq!(
        hello.json()["kinds"],
        serde_json::json!(["status", "reload", "activity", "config"])
    );
    call(&inv, "srv", 1);
    let event = s.until("activity").await;
    assert!(event.json().is_object(), "the row: {}", event.data);
    assert!(event.part('i').is_some(), "the id carries the log position");
}

#[tokio::test]
async fn s1c_a_reconnect_with_its_id_resumes_with_no_gap_and_no_repeat() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    s.until("hello").await;
    for n in 1..=3 {
        call(&inv, "srv", n);
    }
    s.until("activity").await;
    let second = s.until("activity").await;
    drop(s);
    let id = second.id.expect("an activity frame carries an id");
    call(&inv, "srv", 4);
    let mut again = open(&state, request(STREAM, Who::Bearer(BEARER), Some(&id))).await;
    again.until("hello").await;
    let counter = |f: &Frame| {
        f.part('i')
            .and_then(|p| p.split('-').next()?.parse::<u64>().ok())
    };
    let before = counter(&Frame {
        id: Some(id.clone()),
        ..parse("")
    })
    .unwrap();
    let next = counter(&again.until("activity").await).unwrap();
    let last = counter(&again.until("activity").await).unwrap();
    assert_eq!(
        (next, last),
        (before + 1, before + 2),
        "the third and fourth calls, once each"
    );
}

#[tokio::test]
async fn s3_a_scoped_admin_gets_activity_and_never_config() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    let hello = s.until("hello").await;
    assert_eq!(
        hello.json()["kinds"],
        serde_json::json!(["status", "reload", "activity"])
    );
    state
        .governance_log
        .as_ref()
        .unwrap()
        .append_event(
            serde_json::json!({"kind": "config", "change": 1})
                .as_object()
                .cloned()
                .unwrap(),
            &crate::security::audit::AuditEnvelope::gateway(),
        )
        .unwrap();
    call(&inv, "a", 1);
    loop {
        let f = s.next().await.expect("the stream is still open");
        assert_ne!(f.event, "config", "a scoped key never gets a config row");
        if f.event == "activity" {
            break;
        }
    }
}

#[tokio::test]
async fn a1d_a_narrowed_backend_list_ends_the_stream_with_its_kinds_unchanged() {
    let (state, _dirs, _inv) = logged(true).await;
    tokio::time::pause();
    let mut s = open(&state, request(STREAM, Who::Bearer(SCOPED_ADMIN), None)).await;
    s.until("hello").await;
    state.live_config.edit(|c| {
        for key in &mut c.auth.api_keys {
            if key.name == SCOPED_ADMIN {
                key.backends = vec!["a".to_string()];
            }
        }
    });
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "the narrowed access ended the stream"
    );
}

#[tokio::test]
async fn a1f_a_status_only_caller_keeps_its_stream_across_rechecks() {
    let (state, _dirs, _inv) = logged(true).await;
    tokio::time::pause();
    let mut s = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    assert_eq!(
        s.until("hello").await.json()["kinds"],
        serde_json::json!(["status"])
    );
    // Past several one-second rechecks, to the first keep-alive.
    let comment = s.until("comment").await;
    assert_eq!(comment.event, "comment", "the stream is still open");
}

#[tokio::test]
async fn f13_no_frame_or_id_carries_a_search_segment_or_offset() {
    let (state, _dirs, inv) = logged(true).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let hello = s.until("hello").await;
    call(&inv, "srv", 1);
    let event = s.until("activity").await;
    for text in [
        hello.data.as_str(),
        event.data.as_str(),
        event.id.as_deref().unwrap_or(""),
    ] {
        for word in ["segment", "offset", "\"at\"", "restarts"] {
            assert!(!text.contains(word), "{word} in {text}");
        }
    }
}

#[tokio::test]
async fn startup_attaches_each_reader_once_per_process() {
    let (state, _dirs, _inv) = logged(true).await;
    // The fixture attached both, as server start does; a second call attaches
    // nothing, so a record is never announced twice.
    assert_eq!(
        state.dashboard_bootstrap.stream_hub().attach_logs(
            state.transparency_log.as_deref(),
            state.governance_log.as_deref(),
        ),
        0
    );
}

#[tokio::test]
async fn a_gateway_with_no_governance_log_serves_activity_without_config() {
    let (state, _dirs, inv) = logged(false).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    assert_eq!(
        s.until("hello").await.json()["kinds"],
        serde_json::json!(["status", "reload", "activity"])
    );
    call(&inv, "srv", 1);
    assert!(s.until("activity").await.json().is_object());
}
