// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A call a grant allowed names that grant: its invocation record says
//! `grant`, the matched row's keyed id and its grant id, read under the
//! same borrow as the match. Unsigned calls through the dispatch tail, where
//! the grant check runs inside the call's own notes.
//!
//! The refusal side is pinned by `rule_ids::a_grant_refusal_records_no_rule_or_grant_id`
//! (no ids on any refusal reason).

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use serde_json::{Value, json};

use super::super::grant_audit_fixture::{
    CAPS, Endpoint, PERSONAL, capability_backend_exposed, grant, grants, invocations,
};
use super::{api_key, call, context, gateway, invoke_args, only};
use crate::gateway::authz::Emit;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::Outbound;
use crate::gateway::meta_mcp::invoke::audit::{preload_allow_for_test, with_dispatch_scope};
use crate::gateway::meta_mcp::visible::memo::with_visibility_memo;
use crate::identity_grants::{IdentityGrant, LocalIdentityGrantStore};
use crate::security::audit::AuditFailurePolicy;
use crate::security::decision_record::{Allow, AllowRank, Noted};
use crate::security::rule_id::{RuleId, RuleKey};

const ALICE: (&str, &str) = ("api_key", "alice");

/// The key the rows' grant stores are keyed under.
fn key() -> RuleKey {
    RuleKey::from_derived([9; 32])
}

/// A gateway serving alice's personal capability, with `rows` as its keyed
/// grants and a log in `dir`. The endpoint lives as long as the gateway.
struct Granted {
    meta: MetaMcp,
    dir: Arc<tempfile::TempDir>,
    endpoint: Endpoint,
}

async fn granted(rows: Vec<IdentityGrant>) -> Granted {
    let endpoint = Endpoint::start(false).await;
    let dir = crate::test_dir_keep::kept_tempdir();
    let meta = gateway(
        &endpoint,
        vec![],
        Some(&dir),
        AuditFailurePolicy::BestEffort,
    );
    meta.set_identity_grants(grants(rows).with_rule_ids(&key()));
    Granted {
        meta,
        dir,
        endpoint,
    }
}

/// The keyed id the published store holds for `grant_id`, asserted present
/// so an unkeyed store cannot pass for a stub.
fn held_id(meta: &MetaMcp, grant_id: &str) -> RuleId {
    let (live, _) = meta.identity_grant_sink();
    let id = live.read().rule_id(grant_id).cloned();
    id.unwrap_or_else(|| panic!("premise: the store holds an id for {grant_id}"))
}

/// alice's one `gateway_invoke` of her capability, asserted delivered with
/// one upstream arrival; returns its one invocation record's decision.
async fn granted_call(g: &Granted, arrivals: usize) -> Value {
    let answer = call(&g.meta, &api_key("alice"), "gateway_invoke", invoke_args()).await;
    assert!(
        answer.get("error").is_none(),
        "premise, delivered: {answer}"
    );
    assert_eq!(
        g.endpoint.arrivals(),
        arrivals,
        "premise: the granted call reached the capability"
    );
    let records = invocations(&g.dir);
    records
        .last()
        .unwrap_or_else(|| panic!("an invocation record: {records:?}"))["decision"]
        .clone()
}

/// The decision's `(kind, rule_id, grant_id)`.
fn named(decision: &Value) -> (Value, Value, Value) {
    (
        decision["kind"].clone(),
        decision.get("rule_id").cloned().unwrap_or(Value::Null),
        decision.get("grant_id").cloned().unwrap_or(Value::Null),
    )
}

fn as_grant(id: &RuleId, grant_id: &str) -> (Value, Value, Value) {
    (json!("grant"), json!(id.as_str()), json!(grant_id))
}

/// R2 (ATTR.1). Three rows, g-a (another capability), g-m (the match) and
/// g-z (expired), only g-m matching: the record names g-m's keyed id and
/// grant id, not the first row's. Kills M15 (the first row's id).
#[tokio::test]
async fn grant_id_and_keyed_id_name_the_matched_row() {
    let mut other = grant("g-a", ALICE, ALICE);
    other.capability = "another-capability".to_owned();
    let mut expired = grant("g-z", ALICE, ALICE);
    expired.expires_at = chrono::DateTime::from_timestamp(1_000_000_000, 0);
    let g = granted(vec![other, grant("g-m", ALICE, ALICE), expired]).await;
    let expected = held_id(&g.meta, "g-m");
    assert_ne!(
        held_id(&g.meta, "g-a"),
        expected,
        "premise: the rows hold distinct ids"
    );
    let decision = granted_call(&g, 1).await;
    assert_eq!(named(&decision), as_grant(&expected, "g-m"), "{decision}");
}

/// R18 (ATTR.1). An unsigned call (no signing context): the grant check runs
/// inside the call's notes at dispatch, and its record names the grant.
/// Kills M14 (in-notes notes dropped).
#[tokio::test]
async fn an_unsigned_call_names_its_grant() {
    let g = granted(vec![grant("g-m", ALICE, ALICE)]).await;
    let expected = held_id(&g.meta, "g-m");
    let decision = granted_call(&g, 1).await;
    assert_eq!(named(&decision), as_grant(&expected, "g-m"), "{decision}");
    assert_eq!(
        only(invocations(&g.dir), "invocation record")["decision"],
        decision,
        "one record for the call"
    );
}

/// R24 (ATTR.3). Public and shared capabilities read no grant row: the
/// record is `default_allow` with no rule or grant id, and the answer is
/// delivered. Pins M17 (public or shared noting a grant).
#[tokio::test]
async fn public_and_shared_capabilities_name_no_grant() {
    for exposure in ["public", "shared"] {
        let g = granted(vec![grant("g-m", ALICE, ALICE)]).await;
        g.meta
            .set_capabilities(capability_backend_exposed(g.endpoint.port, ALICE, exposure));
        held_id(&g.meta, "g-m");
        let decision = granted_call(&g, 1).await;
        assert_eq!(
            named(&decision),
            (json!("default_allow"), Value::Null, Value::Null),
            "{exposure}: {decision}"
        );
    }
}

/// Publish `next` just before a matched grant is noted inside a call's
/// notes; a note outside them (admission) re-arms the hook untouched.
fn swap_inside_dispatch(
    store: Arc<parking_lot::RwLock<LocalIdentityGrantStore>>,
    next: LocalIdentityGrantStore,
    fired: Rc<Cell<bool>>,
) {
    super::super::visibility::before_grant_note::set(move || {
        if crate::gateway::meta_mcp::invoke::audit::in_dispatch_scope_for_test() {
            *store.write() = next;
            fired.set(true);
        } else {
            swap_inside_dispatch(store, next, fired);
        }
    });
}

/// R31 (ATTR.1). A reload replaces g-m's row the moment the dispatch's
/// evaluation matched it, before the grant is settled: the call names the
/// id of the row it matched (the old one), and the next call the new one.
/// Kills M16 (the id read after the store's borrow is released).
#[tokio::test]
async fn the_grant_id_is_read_under_the_match_borrow() {
    let mut old = grant("g-m", ALICE, ALICE);
    old.reason = "the row the call matched".to_owned();
    let mut new = grant("g-m", ALICE, ALICE);
    new.reason = "the row a reload published".to_owned();
    let g = granted(vec![old]).await;
    let old_id = held_id(&g.meta, "g-m");
    let replacement = grants(vec![new]).with_rule_ids(&key());
    let new_id = replacement
        .rule_id("g-m")
        .cloned()
        .expect("premise: the replacement is keyed");
    assert_ne!(old_id, new_id, "premise: the rows hold distinct ids");
    let fired = Rc::new(Cell::new(false));
    let (live, _) = g.meta.identity_grant_sink();
    swap_inside_dispatch(live, replacement, Rc::clone(&fired));
    let first = granted_call(&g, 1).await;
    assert!(
        fired.get(),
        "premise: the reload landed inside the dispatch"
    );
    assert_eq!(named(&first), as_grant(&old_id, "g-m"), "{first}");
    let second = granted_call(&g, 2).await;
    assert_eq!(named(&second), as_grant(&new_id, "g-m"), "{second}");
}

/// What an open dispatch scope holding a weaker allow notes once `check` has
/// run inside it, and what it notes holding the preload alone. A grant
/// outranks the preload, so any grant `check` noted would show.
async fn notes_around(check: impl FnOnce()) -> (Noted, Noted) {
    let weaker = || {
        Allow::by(
            AllowRank::FirewallAllow,
            Some(RuleId::of("firewall", &key(), b"another check")),
        )
    };
    let ((), alone) = with_dispatch_scope(async { preload_allow_for_test(weaker()) }).await;
    let ((), after) = with_dispatch_scope(with_visibility_memo(async {
        preload_allow_for_test(weaker());
        check();
    }))
    .await;
    (
        after.decision_for_test().clone(),
        alone.decision_for_test().clone(),
    )
}

/// R27 (ATTR.1), the listing site. The check every catalogue listing runs per
/// tool (`may_invoke`, its grant evaluated silently) admits alice's granted
/// capability and notes nothing. Kills M10 at the listing.
#[tokio::test]
async fn a_listing_of_a_granted_capability_notes_nothing() {
    let g = granted(vec![grant("g-m", ALICE, ALICE)]).await;
    let who = api_key("alice");
    let caller = context(&who);
    let (after, alone) = notes_around(|| {
        let listed = g.meta.may_invoke(CAPS, PERSONAL, caller.scope(), None);
        assert!(listed.is_ok(), "premise: alice may invoke it: {listed:?}");
    })
    .await;
    assert_eq!(after, alone);
}

/// R27 (ATTR.1), the send-recheck site. The chokepoint's recheck before a
/// send (silent) passes alice's granted capability and notes nothing.
/// Kills M10 at the send recheck.
#[tokio::test]
async fn the_send_recheck_of_a_granted_capability_notes_nothing() {
    let g = granted(vec![grant("g-m", ALICE, ALICE)]).await;
    let who = api_key("alice");
    let caller = context(&who);
    let (after, alone) = notes_around(|| {
        let arguments = json!({});
        let outbound = Outbound {
            arguments: &arguments,
            answers: None,
            backend: None,
        };
        let permit = g
            .meta
            .direct_send_permit(caller.scope(), None, (CAPS, PERSONAL), &outbound);
        assert!(permit.is_ok(), "premise: the recheck passes");
    })
    .await;
    assert_eq!(after, alone);
}

/// R27 control (ATTR.1). The same grant check audited, inside a grant
/// decision slot as a dispatch opens one, does note the grant over the
/// preload, so the silent rows can fail.
#[tokio::test]
async fn an_audited_grant_check_notes_its_grant() {
    let g = granted(vec![grant("g-m", ALICE, ALICE)]).await;
    let who = api_key("alice");
    let caller = context(&who);
    let weaker = || {
        Allow::by(
            AllowRank::FirewallAllow,
            Some(RuleId::of("firewall", &key(), b"another check")),
        )
    };
    let ((), alone) = with_dispatch_scope(async { preload_allow_for_test(weaker()) }).await;
    let ((checked, written, _), after) = with_dispatch_scope(with_visibility_memo(
        super::super::grant_audit::with_grant_slot(g.meta.transparency_logger.as_ref(), async {
            preload_allow_for_test(weaker());
            g.meta
                .identity_grant_rule(CAPS, PERSONAL, caller.scope(), Emit::Audit)
        }),
    ))
    .await;
    assert!(
        checked.is_ok(),
        "premise: the grant admits alice: {checked:?}"
    );
    assert!(written.is_ok(), "premise: the slot's notes were written");
    assert_ne!(
        after.decision_for_test(),
        alone.decision_for_test(),
        "the audited grant was not noted"
    );
}
