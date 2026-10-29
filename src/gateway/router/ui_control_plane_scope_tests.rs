// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who reads which identity grants and audit events in the control-plane
//! snapshot. Each grant names who may use which server and tool, so a caller
//! whose role does not read every principal's rows sees only its own: grants
//! under its own grant subject, and audit events it performed.

use super::*;
use crate::control_plane::{ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};

/// An issuer no caller signs in with: its `dev-1` is not the fixture's.
const FOREIGN_ISSUER: &str = "https://issuer-foreign";

fn subject(issuer: &str, subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.test"),
        name: None,
        groups: vec![],
        issuer: issuer.to_string(),
    }
}

/// Every seeded grant: (grant id, authority, subject, label).
const GRANTS: &[(&str, &str, &str, Option<&str>)] = &[
    ("grant-dev", ISSUER, DEV, None),
    // The same identity under another label: still the developer's.
    ("grant-dev-relabelled", ISSUER, DEV, Some("another label")),
    // The developer's subject under another issuer: nobody's here.
    ("grant-dev-foreign-issuer", FOREIGN_ISSUER, DEV, None),
    ("grant-unmapped", ISSUER, "nobody-1", None),
    ("grant-key", "api_key", STANDARD_KEY, None),
    ("grant-other", ISSUER, OTHER_DEV, None),
];

/// Every seeded audit event: (event id, actor id, target id).
fn events() -> Vec<(&'static str, String, &'static str)> {
    let actor = |issuer: &str, sub: &str| subject(issuer, sub).stable_actor_id();
    vec![
        ("event-dev", actor(ISSUER, DEV), "matrix-target"),
        (
            "event-dev-foreign",
            actor(FOREIGN_ISSUER, DEV),
            "matrix-target",
        ),
        ("event-unmapped", actor(ISSUER, "nobody-1"), "matrix-target"),
        (
            "event-key",
            format!("gateway-client:{STANDARD_KEY}"),
            "matrix-target",
        ),
        ("event-other", actor(ISSUER, OTHER_DEV), "matrix-target"),
        // By another user, about the developer's grant: an earlier owner of
        // that grant id could have been anyone, so it is not the developer's.
        (
            "event-about-dev-grant",
            actor(ISSUER, OTHER_DEV),
            "grant-dev",
        ),
    ]
}

fn seed(state: &AppState) {
    state
        .meta_mcp
        .set_identity_grants(LocalIdentityGrantStore::from_grants(GRANTS.iter().map(
            |(grant_id, authority, sub, label)| IdentityGrant {
                grant_id: (*grant_id).to_string(),
                subject: GrantSubject::new(*authority, *sub, label.map(str::to_string)),
                agent: GrantAgent::Any,
                capability: "matrix-capability".to_string(),
                tool: None,
                scope: GrantScope::Execute,
                owner: None,
                expires_at: None,
                revoked_at: None,
                provenance: "local-file".to_string(),
                reason: "matrix".to_string(),
            },
        )));
    let store = state.control_plane_store.as_ref().expect("a store");
    for (event_id, actor_id, target_id) in events() {
        store
            .append_audit(&ControlPlaneAuditEvent {
                grant_change: None,
                event_id: event_id.to_string(),
                actor_id,
                action: ControlPlaneAction::MutateGrant,
                target_id: target_id.to_string(),
                reason: "matrix seed".to_string(),
                rollback: ControlPlaneRollbackPlan {
                    summary: "revert".to_string(),
                    step: "none".to_string(),
                },
            })
            .expect("the event is stored");
    }
}

/// The snapshot `caller` reads with everything seeded, as raw text and parsed.
async fn snapshot_as(caller: Caller) -> (String, Value) {
    let fx = fixture(caller.gateway(), true).await;
    seed(&fx.state);
    let router = create_router(Arc::clone(&fx.state));
    let cookie = session(&fx.state);
    let req = ("GET", routes::UI_CONTROL_PLANE, "plain");
    let (status, body) = send(&router, request(caller, req, &fx, Some(&cookie))).await;
    let text = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(status, StatusCode::OK, "{caller:?}: {text}");
    let parsed = serde_json::from_str(&text).expect("the snapshot is JSON");
    (text, parsed)
}

fn ids<'a>(value: &'a Value, list: &str, field: &str) -> Vec<&'a str> {
    let mut ids: Vec<&str> = value["view"][list]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| row[field].as_str())
        .collect();
    ids.sort_unstable();
    ids
}

/// Each restricted caller sees exactly its own grants and events: in the
/// parsed view, in the counts, and nowhere else in the body.
#[tokio::test]
async fn a_restricted_caller_reads_only_its_own_grants_and_events() {
    let cases: [(Caller, &[&str], &[&str]); 4] = [
        (
            Caller::OidcDeveloper,
            &["grant-dev", "grant-dev-relabelled"],
            &["event-dev"],
        ),
        (
            Caller::OidcUnmapped,
            &["grant-unmapped"],
            &["event-unmapped"],
        ),
        (
            Caller::AdminKeyUnmapped,
            &["grant-unmapped"],
            &["event-unmapped"],
        ),
        (Caller::StandardKey, &["grant-key"], &["event-key"]),
    ];
    for (caller, grants, events_seen) in cases {
        let (text, parsed) = snapshot_as(caller).await;
        assert_eq!(ids(&parsed, "grants", "grant_id"), grants, "{caller:?}");
        assert_eq!(
            ids(&parsed, "audit_events", "event_id"),
            events_seen,
            "{caller:?}"
        );
        assert_eq!(
            parsed["inventory_counts"]["audit_events"],
            events_seen.len(),
            "{caller:?}"
        );
        for (grant_id, ..) in GRANTS.iter().filter(|(id, ..)| !grants.contains(id)) {
            assert!(!text.contains(grant_id), "{caller:?} reads {grant_id}");
        }
        for (event_id, ..) in events().iter().filter(|(id, ..)| !events_seen.contains(id)) {
            assert!(!text.contains(event_id), "{caller:?} reads {event_id}");
        }
    }
}

/// The control: callers whose role reads every principal's rows keep the
/// full lists.
#[tokio::test]
async fn an_admin_auditor_or_reviewer_reads_every_grant_and_event() {
    let mut all_grants: Vec<&str> = GRANTS.iter().map(|(id, ..)| *id).collect();
    all_grants.sort_unstable();
    let mut all_events: Vec<&str> = events().iter().map(|(id, ..)| *id).collect();
    all_events.sort_unstable();
    for caller in [
        Caller::AdminKey,
        Caller::OidcAdmin,
        Caller::OidcAuditor,
        Caller::OidcReviewer,
    ] {
        let (_, parsed) = snapshot_as(caller).await;
        assert_eq!(ids(&parsed, "grants", "grant_id"), all_grants, "{caller:?}");
        assert_eq!(
            ids(&parsed, "audit_events", "event_id"),
            all_events,
            "{caller:?}"
        );
    }
}

/// An identity whose grant subject names nobody (no subject, or no issuer)
/// owns no grants of its own. Like dispatch, the subject then falls back to
/// the API key the caller presented (here the standard key), and to nothing
/// else.
#[tokio::test]
async fn an_identity_that_names_nobody_falls_back_to_its_key() {
    for caller in [
        Caller::OidcDeveloperNoSubject,
        Caller::OidcDeveloperNoIssuer,
    ] {
        let (_, parsed) = snapshot_as(caller).await;
        assert_eq!(
            ids(&parsed, "grants", "grant_id"),
            ["grant-key"],
            "{caller:?}"
        );
    }
}
