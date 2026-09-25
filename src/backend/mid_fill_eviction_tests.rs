// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7548 — a grant revocation that lands while a caller's catalogue fill is
//! still on the wire.
//!
//! `evict_identity_slots` removes the pool entry UNCONDITIONALLY, even with a
//! request in flight, so a fill already on the wire writes into the orphaned
//! entry's cache, which nobody can reach, and the next read recreates an empty
//! slot. The sibling `tests::revocation_during_a_fill_is_not_served_afterwards`
//! races the SHARED slot's generation guard, and T-S9 evicts only after both
//! fills have landed, so neither pins this race on a per-identity slot.
//!
//! THE FILL IS HELD, NOT SLEPT ON. [`Gated`] parks the fetch inside the
//! transport until the cell releases it; `Notify` stores a permit, so neither
//! signal can be lost to ordering.
//!
//! BOTH ASSERTIONS ARE ABSENCES. They also hold on a backend that caches
//! nothing, which is why the unrevoked control exists.

use super::{ALPHA_TOOL, PerIdentityTools, backend_in, bind, minted, prefix};
use crate::backend::{Backend, PoolKey};
use crate::identity_propagation::SessionMode;
use crate::protocol::JsonRpcResponse;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// A wire that signals `entered` once a fetch reaches it, then holds that
/// fetch until `release`, then delegates.
struct Gated {
    inner: Arc<PerIdentityTools>,
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl crate::transport::Transport for Gated {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Permitted,
        )
        .await
    }

    /// OVERRIDDEN for the same reason as the inner wire's: the trait default
    /// drops the minted headers, and the inner wire answers per credential.
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner
            .request_with_headers(method, params, extra_headers, identity_key, resend)
            .await
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Upper bound on any single wait, so a mis-wired gate fails the cell rather
/// than hanging the suite.
const WAIT: Duration = Duration::from_secs(5);

/// Alpha fills on a `session_mode` backend through a held wire; `revoke`
/// decides whether alpha's grant is revoked while the fill is on the wire.
/// Returns the backend and the eviction count (0 when not revoked).
async fn race(session_mode: SessionMode, revoke: bool) -> (Arc<Backend>, usize) {
    let backend = backend_in(session_mode);
    let gate = Arc::new(Gated {
        inner: PerIdentityTools::new(),
        entered: Notify::new(),
        release: Notify::new(),
    });
    backend.set_transport_for_test(Arc::clone(&gate.inner) as Arc<dyn crate::transport::Transport>);
    backend.set_pooled_transport_for_test(
        &PoolKey::PerUser {
            binding: bind("alpha"),
        },
        Arc::clone(&gate) as Arc<dyn crate::transport::Transport>,
    );

    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move {
            backend
                .get_tools_for_binding(Some(&bind("alpha")), &minted("alpha"))
                .await
        }
    });

    // THE PREMISE: the fill is on the wire before anything else happens. The
    // inner wire records only after release, so this is the one observable.
    tokio::time::timeout(WAIT, gate.entered.notified())
        .await
        .expect("alpha's fill never reached the wire");

    let evicted = if revoke {
        backend.evict_identity_slots(&prefix("alpha")).await
    } else {
        0
    };

    gate.release.notify_one();
    tokio::time::timeout(WAIT, fill)
        .await
        .expect("alpha's fill never finished")
        .expect("fill task panicked")
        .expect("alpha's fill succeeds on the connection it already held");

    (backend, evicted)
}

/// Asserts the revoked identity's catalogue is served by neither read path.
fn assert_not_served(backend: &Backend, evicted: usize) {
    let names = backend.get_cached_tool_names_for(Some(&bind("alpha")));
    assert!(
        !names.iter().any(|n| n == ALPHA_TOOL),
        "the fill that was on the wire when alpha was revoked landed in a \
         slot alpha can still read: {names:?}"
    );
    assert!(
        backend
            .get_cached_tool_for(Some(&bind("alpha")), ALPHA_TOOL)
            .is_none(),
        "alpha's revoked tool is still resolvable from the cache"
    );
    // Corroboration only: seeding the wire creates the slot, so a count of 1
    // holds whether or not the fill reached it.
    assert_eq!(evicted, 1, "the revocation prefix matched no slot");
}

/// GIVEN a `stateless` backend whose fill for alpha is held on the wire
/// WHEN alpha's grant is revoked, and only then is the fill released
/// THEN alpha's catalogue is not served afterwards, by name or by lookup.
#[tokio::test]
async fn revocation_during_a_stateless_fill_is_not_served_afterwards() {
    let (backend, evicted) = race(SessionMode::Stateless, true).await;
    assert_not_served(&backend, evicted);
}

/// The same race on `per_user`: the first cell that races a real per-identity
/// fill against eviction in that mode, since the older sibling races the
/// shared slot.
#[tokio::test]
async fn revocation_during_a_per_user_fill_is_not_served_afterwards() {
    let (backend, evicted) = race(SessionMode::PerUser, true).await;
    assert_not_served(&backend, evicted);
}

/// POSITIVE CONTROL: the same held fill with no revocation IS served. Without
/// it, both absences above would hold on a backend that caches nothing.
#[tokio::test]
async fn an_unrevoked_stateless_fill_is_served_afterwards() {
    let (backend, _) = race(SessionMode::Stateless, false).await;
    assert!(
        backend
            .get_cached_tool_names_for(Some(&bind("alpha")))
            .iter()
            .any(|n| n == ALPHA_TOOL),
        "the control's fill cached nothing, so the revocation cells prove nothing"
    );
    assert!(
        backend
            .get_cached_tool_for(Some(&bind("alpha")), ALPHA_TOOL)
            .is_some(),
        "the control's tool is not resolvable from the cache"
    );
}
