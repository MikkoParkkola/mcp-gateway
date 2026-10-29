// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the frames carry, and how a reconnect resumes.

use super::*;

fn gen_of(f: &Frame, tag: char) -> u64 {
    f.part(tag)
        .and_then(|v| v.parse().ok())
        .expect("a generation")
}

#[tokio::test]
async fn a_status_change_arrives_with_a_higher_generation_and_the_full_composite() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let first = s.until("status").await;
    assert!(first.part('b').is_some(), "the boot part leads: {first:?}");
    let before = gen_of(&first, 's');
    let _ = state
        .backends
        .register(http_backend_at("docs", "http://127.0.0.1:9/mcp"));
    let next = s.until("status").await;
    assert!(gen_of(&next, 's') > before);
    assert_eq!(next.json()["server_count"], 1);
}

#[tokio::test]
async fn a_reconnect_gets_the_snapshot_first_and_the_boot_part_round_trips() {
    let (state, _dir) = fixture().await;
    let mut a = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let seen = a.until("status").await;
    let id = seen.id.clone().expect("id");
    let mut b = open(&state, request(STREAM, Who::Bearer(BEARER), Some(&id))).await;
    let again = b.until("status").await;
    assert_eq!(again.part('b'), seen.part('b'));
    assert!(gen_of(&again, 's') >= gen_of(&seen, 's'));
}

#[tokio::test]
async fn the_query_form_works_and_the_header_wins() {
    let (state, _dir) = fixture().await;
    let mut a = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let id = a.until("status").await.id.expect("id");
    let uri = format!("{STREAM}?last_event_id={id}");
    let mut q = open(&state, request(&uri, Who::Bearer(BEARER), None)).await;
    assert_eq!(q.status, StatusCode::OK);
    q.until("status").await;
    let mut both = open(&state, request(&uri, Who::Bearer(BEARER), Some("garbage"))).await;
    assert_eq!(both.status, StatusCode::OK);
    both.until("status").await;
}

#[tokio::test]
async fn a_malformed_or_foreign_boot_id_is_a_fresh_connect() {
    let (state, _dir) = fixture().await;
    for bad in ["not-an-id", "bffffffffffffffff.s999999.r999999"] {
        let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), Some(bad))).await;
        assert_eq!(s.status, StatusCode::OK, "{bad}");
        let f = s.until("status").await;
        assert_ne!(f.part('b').as_deref(), Some("ffffffffffffffff"));
    }
}

#[tokio::test]
async fn an_applied_reload_sends_reload_with_the_generation_within_a_tick() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let first = s.until("reload").await;
    let before = first.json()["generation"].as_u64().expect("generation");
    state
        .live_config
        .edit(|c| c.security.sanitize_input = !c.security.sanitize_input);
    let next = s.until("reload").await;
    assert!(next.json()["generation"].as_u64().unwrap() > before);
    assert!(gen_of(&next, 'r') > gen_of(&first, 'r'));
}

#[tokio::test]
async fn a_snapshot_frame_never_advances_a_log_part() {
    let (state, _dir) = fixture().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let f = s.until("status").await;
    assert!(f.part('i').is_none() && f.part('g').is_none(), "{f:?}");
}

#[tokio::test]
async fn a_counts_only_stream_is_silent_for_admin_fields_and_speaks_for_counts() {
    let (state, _dir) = fixture().await;
    let _ = state
        .backends
        .register(http_backend_at("docs", "http://127.0.0.1:9/mcp"));
    let mut admin = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let mut counts = open(&state, request(STREAM, Who::Bearer(KEY), None)).await;
    admin.until("status").await;
    assert_eq!(counts.until("status").await.json()["server_count"], 1);
    // An admin-only field moves: the success counter on the server's row.
    let docs = state.backends.get("docs").expect("registered");
    docs.shared_entry_for_test()
        .failsafe
        .record_success(Duration::from_millis(5));
    let seen = admin.until("status").await.json();
    assert_eq!(
        seen["servers"][0]["success_count"], 1,
        "admin sees it: {seen}"
    );
    // A counts-only field moves: a second server. The counts stream's very next
    // status frame is that one, so nothing was sent for the success counter.
    let _ = state
        .backends
        .register(http_backend_at("wiki", "http://127.0.0.1:9/mcp"));
    assert_eq!(counts.until("status").await.json()["server_count"], 2);
}

#[tokio::test]
async fn hello_carries_a_jittered_retry_hint() {
    let (state, _dir) = fixture().await;
    let mut seen = Vec::new();
    let mut held = Vec::new();
    for _ in 0..8 {
        let cookie = issue(&state);
        let mut s = open(&state, request(STREAM, Who::Cookie(&cookie), None)).await;
        seen.push(s.until("hello").await.retry.expect("a retry line"));
        held.push(s);
    }
    assert!(seen.iter().all(|r| (3000..=5000).contains(r)), "{seen:?}");
    assert!(seen.iter().any(|r| *r != seen[0]), "all equal: {seen:?}");
}
