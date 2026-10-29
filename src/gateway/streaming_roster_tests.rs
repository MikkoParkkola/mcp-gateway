// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The client listing: names are display text, provisional sessions are not
//! clients, the order and the cap are fixed, and no id reaches the output.

use std::sync::Arc;

use chrono::{TimeZone, Utc};

use super::{MAX_NAMED_CLIENTS, NotificationMultiplexer};
use crate::config::StreamingConfig;
use crate::gateway::session_id::SessionOwner;
use crate::gateway::streaming::MintKind;

fn mux() -> NotificationMultiplexer {
    NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        StreamingConfig::default(),
    )
}

fn owner(name: &str) -> SessionOwner {
    SessionOwner::Credential(name.to_owned())
}

/// Open an ordinary session for `who` and report `name` for it; returns the id.
fn client(m: &NotificationMultiplexer, who: &str, name: Option<&str>) -> String {
    let id = m
        .get_or_create_session_id_scoped(None, &owner(who), None)
        .expose_secret()
        .to_owned();
    if let Some(name) = name {
        m.record_reported_name(&id, &owner(who), name);
    }
    id
}

fn set_seen(m: &NotificationMultiplexer, id: &str, secs: i64) {
    let session = m.sessions.read().get(id).cloned().expect("session");
    *session.last_seen.write() = Utc.timestamp_opt(secs, 0).single();
}

#[test]
fn a_named_client_is_listed_with_last_seen_and_no_session_id() {
    let m = mux();
    let id = client(&m, "alice", Some("Claude Desktop"));
    let roster = m.client_roster();
    assert_eq!(roster.named.len(), 1);
    assert_eq!(roster.named[0].reported_name, "Claude Desktop");
    assert!(roster.named[0].last_seen.is_some());
    let json = serde_json::to_string(&roster).expect("serializes");
    assert!(!json.contains(&id), "{json}");
    assert!(!json.contains("gw-"), "{json}");
}

#[test]
fn markup_in_a_name_is_kept_as_the_same_string() {
    let m = mux();
    client(&m, "alice", Some("<script>alert(1)</script>"));
    assert_eq!(
        m.client_roster().named[0].reported_name,
        "<script>alert(1)</script>"
    );
}

#[test]
fn control_and_format_characters_are_stripped() {
    let m = mux();
    client(&m, "alice", Some("\u{202e}Evil\u{0000}\nName\u{200b}"));
    assert_eq!(m.client_roster().named[0].reported_name, "EvilName");
}

#[test]
fn a_long_name_is_capped_at_64_characters() {
    let m = mux();
    client(&m, "alice", Some(&"x".repeat(200)));
    assert_eq!(m.client_roster().named[0].reported_name.chars().count(), 64);
}

#[test]
fn a_session_without_a_usable_name_counts_as_unnamed() {
    let m = mux();
    client(&m, "alice", None);
    client(&m, "bob", Some("\u{200b}\u{200b}"));
    client(&m, "carol", Some("Cursor"));
    let roster = m.client_roster();
    assert_eq!((roster.named_total, roster.unnamed), (1, 2));
}

#[test]
fn provisional_sessions_are_in_neither_count() {
    let m = mux();
    let _held = m
        .open_request_session_scoped(None, &owner("alice"), None, MintKind::Provisional)
        .expect("below the cap");
    let roster = m.client_roster();
    assert_eq!((roster.named_total, roster.unnamed), (0, 0));
}

#[test]
fn clients_are_ordered_by_last_seen_descending_then_name() {
    let m = mux();
    let b = client(&m, "u1", Some("Bravo"));
    let a = client(&m, "u2", Some("Alpha"));
    let z = client(&m, "u3", Some("Zulu"));
    set_seen(&m, &b, 100);
    set_seen(&m, &a, 100);
    set_seen(&m, &z, 200);
    let names: Vec<_> = m
        .client_roster()
        .named
        .into_iter()
        .map(|c| c.reported_name)
        .collect();
    assert_eq!(names, ["Zulu", "Alpha", "Bravo"]);
}

#[test]
fn the_listing_stops_at_100_and_says_so() {
    let m = mux();
    for i in 0..=MAX_NAMED_CLIENTS {
        client(&m, &format!("user-{i}"), Some(&format!("client-{i:03}")));
    }
    let roster = m.client_roster();
    assert_eq!(roster.named.len(), MAX_NAMED_CLIENTS);
    assert_eq!(roster.named_total, MAX_NAMED_CLIENTS + 1);
    assert!(roster.truncated);
}

#[test]
fn another_owner_cannot_set_a_sessions_name() {
    let m = mux();
    let id = client(&m, "alice", None);
    m.record_reported_name(&id, &owner("mallory"), "Admin Console");
    assert_eq!(m.client_roster().unnamed, 1);
}

#[test]
fn a_later_initialize_replaces_the_name() {
    let m = mux();
    let id = client(&m, "alice", Some("First"));
    m.record_reported_name(&id, &owner("alice"), "Second");
    assert_eq!(m.client_roster().named[0].reported_name, "Second");
}

#[test]
fn a_touch_moves_last_seen_forward() {
    let m = mux();
    let id = client(&m, "alice", Some("Cursor"));
    set_seen(&m, &id, 100);
    m.sessions.read().get(id.as_str()).expect("session").touch();
    let seen = m.client_roster().named[0].last_seen.expect("seen");
    assert!(seen.timestamp() > 100);
}
