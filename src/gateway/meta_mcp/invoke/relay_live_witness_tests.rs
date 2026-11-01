// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-timing rows (T2, T3, T4) for the meta, meta-catalogue and stdio
//! witness sites. They need the request's pinned generation, which the
//! caller context does not carry until the generation accessor lands, so
//! each is ignored and its body states what it will do. Every ignored row
//! must be unskipped, and shown red then green, before this change merges.
//!
//! Shape of every row, as the direct route's (`collusion_direct_tests::live`):
//! alice is delivered `PROSE` from `alpha:read` under `block`; bob relays it.
//!  - (a) admitted under `block`; the witness hook publishes `off`. Pinned
//!    code refuses with -32002; code that reads the live config after the
//!    hook sends.
//!  - (b) admitted under `off`; the hook publishes `block`. Pinned code
//!    sends; code that reads the live config after the hook refuses.
//!
//! Each asserts the hook ran and that its reload was the only publish since
//! admission.

use super::live::{LiveMeta, live_meta};
use crate::security::firewall::CollusionAction::{Block, Off};
use crate::security::firewall::collusion_live_rig::{PROSE, plain};
use crate::security::firewall::relay_witness_hook;

/// The pinned generation reaches the witness through PR1's accessor on the
/// caller context; until it exists a row cannot pin one.
fn pin_through_the_accessor() -> ! {
    unimplemented!("waits on PR1's meta/stdio generation accessor")
}

/// Arm the witness hook to publish `action` over the live config.
fn arm_publish(lm: &super::live::LiveMeta, action: crate::security::firewall::CollusionAction) {
    let live = std::sync::Arc::clone(lm.live());
    relay_witness_hook::arm(move || {
        let mut config = (*live.get()).clone();
        config.security.firewall.collusion.action = action;
        live.set(config);
    });
}

macro_rules! witness_row {
    ($name:ident, $doc:literal, $admitted:expr, $hook:expr) => {
        #[doc = $doc]
        ///
        /// Unskip when PR1 lands.
        #[test]
        #[ignore = "waits on PR1's meta/stdio generation accessor"]
        fn $name() {
            let lm = live_meta(Block, 600);
            if $admitted == Off {
                lm.publish(Off);
            }
            arm_publish(&lm, $hook);
            pin_through_the_accessor();
        }
    };
}

witness_row!(
    t3a_meta_catalogue_admitted_under_block_a_later_off_still_refuses,
    "T3a: meta `catalogue_refusal`, admitted under `block`, `off` published at the seam: refused (403, -32002).",
    Block,
    Off
);
witness_row!(
    t3b_meta_catalogue_admitted_under_off_a_later_block_still_sends,
    "T3b: meta `catalogue_refusal`, admitted under `off`, `block` published at the seam: forwarded. RED on base.",
    Off,
    Block
);
witness_row!(
    t4a_stdio_admitted_under_block_a_later_off_still_refuses,
    "T4a: a stdio line held at the dispatch pause while `off` is published: the frame carries -32002.",
    Block,
    Off
);
witness_row!(
    t4b_stdio_admitted_under_off_a_later_block_still_sends,
    "T4b: a stdio line held at the dispatch pause while `block` is published: dispatched. RED on base.",
    Off,
    Block
);

/// The publish count either side of the hook's reload.
#[derive(Default)]
struct Seen {
    visits: std::cell::Cell<u32>,
    before: std::cell::Cell<u64>,
    after: std::cell::Cell<u64>,
}

/// Arm the witness hook to publish `action`, noting the publish count either
/// side of it.
fn arm_noting(
    lm: &LiveMeta,
    action: crate::security::firewall::CollusionAction,
) -> std::rc::Rc<Seen> {
    let seen = std::rc::Rc::new(Seen::default());
    seen.visits.set(relay_witness_hook::reached());
    let (live, probe) = (std::sync::Arc::clone(lm.live()), std::rc::Rc::clone(&seen));
    relay_witness_hook::arm(move || {
        probe.before.set(live.seq());
        let mut config = (*live.get()).clone();
        config.security.firewall.collusion.action = action;
        live.set(config);
        probe.after.set(live.seq());
    });
    seen
}

/// Bob calls `alpha:send` with the text alice was delivered, as a request
/// pinned to the generation published now, with `hook` published at the
/// witness seam. Returns the invocation and what the backend received.
async fn bob_sends(
    lm: &LiveMeta,
    hook: crate::security::firewall::CollusionAction,
) -> (
    crate::Result<serde_json::Value>,
    usize,
    std::rc::Rc<Seen>,
    u64,
) {
    let pinned = lm.live().generation();
    let admitted = lm.live().seq();
    let seen = arm_noting(lm, hook);
    let policy = crate::security::ToolPolicy::default();
    let authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
        tool_policy: &policy,
        generation: Some(&pinned),
    };
    let bob = crate::gateway::meta_mcp::MetaMcpCallerContext {
        caller_key: Some("bob"),
        ..crate::gateway::meta_mcp::authz_tests::ctx(&authorizer)
    };
    let call = serde_json::json!({"server": "alpha", "tool": "send", "arguments": {"text": PROSE}});
    let result = lm.meta.invoke_tool(&call, None, &bob).await;
    (result, lm.seen.lock().len(), seen, admitted)
}

fn assert_ordered(seen: &Seen, admitted: u64) {
    assert!(
        relay_witness_hook::reached() > seen.visits.get(),
        "the witness hook never ran"
    );
    assert_eq!(seen.before.get(), admitted, "a reload preceded the hook");
    assert_eq!(
        seen.after.get(),
        admitted + 1,
        "the hook's reload did not publish"
    );
}

/// Alice is delivered the sensitive read under `block`.
fn alice_delivered(lm: &LiveMeta) {
    let generation = lm.live().generation();
    lm.rig
        .deliver("alice", ("alpha", "read"), &plain(PROSE), &generation);
}

/// T2a: meta `relay_refusal`, admitted under `block`, `off` published at the
/// seam: refused with -32002, nothing sent. GREEN pin on base.
#[tokio::test]
async fn t2a_meta_admitted_under_block_a_later_off_still_refuses() {
    let lm = live_meta(Block, 600);
    alice_delivered(&lm);
    let (result, sent, seen, admitted) = bob_sends(&lm, Off).await;
    assert!(
        matches!(&result, Err(crate::Error::Forbidden { code: -32002, .. })),
        "T2a: not refused: {result:?}"
    );
    assert_eq!(sent, 0, "the backend was called");
    assert_ordered(&seen, admitted);
}

/// T2b: meta `relay_refusal`, admitted under `off`, `block` published at the
/// seam: forwarded. RED on base: the startup `block` refuses it.
#[tokio::test]
async fn t2b_meta_admitted_under_off_a_later_block_still_sends() {
    let lm = live_meta(Block, 600);
    alice_delivered(&lm);
    lm.publish(Off);
    let (result, sent, seen, admitted) = bob_sends(&lm, Block).await;
    assert!(result.is_ok(), "T2b: refused: {result:?}");
    assert_eq!(sent, 1, "the backend was not called");
    assert_ordered(&seen, admitted);
}
