// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Config-timing rows (T4) for the stdio witness: the relay check on a
//! stdio line judges under the generation that line was read under, never
//! the one published when it is checked.
//!
//! The existing stdio collusion fixtures dispatch a line directly with the
//! line's generation in hand (`dispatch_single`), so the row pins a
//! generation as the line's and the witness hook publishes the reload at the
//! seam, before the witness evaluates the generation it judges under. (The
//! dispatch pause sits in the read loop these fixtures bypass.)
//!
//! The HTTP caller was delivered `PROSE` from `alpha:read` under `block`; the
//! stdio operator then sends it through `alpha:send`.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::{Alpha, PROSE, text_result};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::config_reload::Generation;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::firewall::CollusionAction::{self, Block, Off};
use crate::security::firewall::collusion_live_rig::{config, seed_meta};
use crate::security::firewall::{Firewall, RelayCaller, relay_witness_hook};

/// A stdio gateway over `alpha` under `block`, its live config seeded from
/// the firewall's own, and the count of `send` calls the backend served.
fn live_stdio() -> (Arc<MetaMcp>, Arc<Firewall>, Arc<AtomicUsize>) {
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let sends = Arc::new(AtomicUsize::new(0));
    backend.set_transport_for_test(Arc::new(Alpha {
        sends: Arc::clone(&sends),
        read: Arc::new(parking_lot::Mutex::new(PROSE.to_string())),
    }));
    assert!(registry.register(backend));
    let firewall_config = config(Block, &["alpha:read"], vec![]).security.firewall;
    let firewall = Arc::new(Firewall::from_config(firewall_config, None).keyed_for_test());
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.share_keyring_with_for_test(&firewall);
    seed_meta(&meta, &firewall);
    (Arc::new(meta), firewall, sends)
}

/// The publish count either side of the hook's reload.
#[derive(Default)]
struct Seen {
    visits: Cell<u32>,
    before: Cell<u64>,
    after: Cell<u64>,
}

/// The stdio operator sends `PROSE` through `alpha:send` on a line read
/// under `line`, with `hook` published at the witness seam.
async fn operator_sends(
    meta: &Arc<MetaMcp>,
    line: &Arc<Generation>,
    hook: CollusionAction,
) -> (Value, Rc<Seen>, u64) {
    let live = meta.live_config().expect("the fixture seeds a live config");
    let admitted = live.seq();
    let seen = Rc::new(Seen::default());
    seen.visits.set(relay_witness_hook::reached());
    let (published, probe) = (Arc::clone(&live), Rc::clone(&seen));
    relay_witness_hook::arm(move || {
        probe.before.set(published.seq());
        let mut next = (*published.get()).clone();
        next.security.firewall.collusion.action = hook;
        published.set(next);
        probe.after.set(published.seq());
    });
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let params = json!({"name": "gateway_invoke",
                        "arguments": {"server": "alpha", "tool": "send",
                                      "arguments": {"text": PROSE}}});
    let request = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params});
    let answer =
        super::super::super::Gateway::dispatch_single(meta, line, &mtls, &request, "stdio-live")
            .await
            .expect("a request is answered");
    (answer, seen, admitted)
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

/// The HTTP caller was delivered `PROSE` from `alpha:read`.
fn http_delivered(firewall: &Firewall) {
    let http = RelayCaller::Keyed("http-caller");
    firewall.record_delivery(http, "alpha", "read", &text_result(PROSE));
}

/// T4a: a line read under `block`, `off` published at the seam: the frame
/// still carries -32002 and the backend is not called. GREEN pin on base.
#[tokio::test]
async fn t4a_stdio_read_under_block_a_later_off_still_refuses() {
    let (meta, firewall, sends) = live_stdio();
    http_delivered(&firewall);
    let live = meta.live_config().expect("seeded");
    let line = live.generation();
    let (answer, seen, admitted) = operator_sends(&meta, &line, Off).await;
    assert_eq!(
        answer["error"]["code"], -32002,
        "T4a: not refused: {answer}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0, "the backend was called");
    assert_ordered(&seen, admitted);
}

/// T4b: a line read under `off`, `block` published at the seam: dispatched,
/// the backend is called once. RED on base: refused under the startup
/// `block`.
#[tokio::test]
async fn t4b_stdio_read_under_off_a_later_block_still_sends() {
    let (meta, firewall, sends) = live_stdio();
    http_delivered(&firewall);
    let live = meta.live_config().expect("seeded");
    let mut off = (*live.get()).clone();
    off.security.firewall.collusion.action = Off;
    live.set(off);
    let line = live.generation();
    let (answer, seen, admitted) = operator_sends(&meta, &line, Block).await;
    assert!(answer.get("error").is_none(), "T4b: refused: {answer}");
    assert_eq!(
        sends.load(Ordering::SeqCst),
        1,
        "the backend was not called"
    );
    assert_ordered(&seen, admitted);
}
