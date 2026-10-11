// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), group 3, index lifecycle rows I4, I5 and I8:
//! an index entry is published and removed against the `PooledEntry`
//! identity, never the binding string. Every test name starts with `g3_`.
//! These are mutant-red rows (seam created by the fix): I4/I5 by M09, I8 by
//! M16.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Notify;

use super::Backend;
use super::pool::PooledEntry;
use super::slot_eviction_tests::{fill_slot, per_user_backend, slot};
use crate::protocol::{JsonRpcResponse, RequestId, Tool, ToolsListResult};
use crate::transport::{ResendPermission, Transport};
use crate::{Error, Result};

const WAIT: Duration = Duration::from_secs(10);
const ALPHA: &str = "alpha";

fn entry_of(backend: &Backend, binding: &str) -> Arc<PooledEntry> {
    Arc::clone(backend.pool.get(&slot(binding)).expect("the slot").value())
}

/// I4: alpha rotates from binding B1 to B2, then B1's entry is evicted. The
/// entry still points at B2.
#[tokio::test]
async fn g3_i4_rotation_old_eviction_keeps_new_entry() {
    let backend = per_user_backend("g3-i4");
    fill_slot(&backend, "g3:b1").await;
    backend.record_caller_slot(ALPHA, "g3:b1");
    assert_eq!(
        backend.caller_slot_binding(ALPHA).as_deref(),
        Some("g3:b1"),
        "premise: alpha is indexed at B1"
    );
    fill_slot(&backend, "g3:b2").await;
    backend.record_caller_slot(ALPHA, "g3:b2");
    assert_eq!(
        backend.caller_slot_binding(ALPHA).as_deref(),
        Some("g3:b2"),
        "premise: the rotation moved alpha's entry to B2"
    );

    assert_eq!(backend.evict_identity_slots("g3:b1"), 1, "B1 left the pool");

    assert_eq!(
        backend.caller_slot_binding(ALPHA).as_deref(),
        Some("g3:b2"),
        "I4: evicting the old B1 slot took alpha's B2 entry with it"
    );
}

/// I5: B1 is evicted and readmitted as a new `PooledEntry`; the evicted
/// entry's cleanup then runs late. The readmitted slot's entry survives.
#[tokio::test]
async fn g3_i5_readmitted_same_binding_survives_late_cleanup() {
    let backend = per_user_backend("g3-i5");
    fill_slot(&backend, "g3:b1").await;
    backend.record_caller_slot(ALPHA, "g3:b1");
    let old = entry_of(&backend, "g3:b1");

    assert_eq!(backend.evict_identity_slots("g3:b1"), 1, "B1 left the pool");
    assert_eq!(
        backend.caller_slot_binding(ALPHA),
        None,
        "premise: evicting B1 forgot alpha's entry"
    );
    fill_slot(&backend, "g3:b1").await;
    backend.record_caller_slot(ALPHA, "g3:b1");
    assert!(
        !Arc::ptr_eq(&old, &entry_of(&backend, "g3:b1")),
        "premise: B1 was readmitted as a new entry"
    );
    assert_eq!(
        backend.caller_slot_binding(ALPHA).as_deref(),
        Some("g3:b1"),
        "premise: alpha is indexed at the readmitted B1"
    );

    backend.forget_caller_slot(&old);

    assert_eq!(
        backend.caller_slot_binding(ALPHA).as_deref(),
        Some("g3:b1"),
        "I5: the late cleanup of the evicted entry removed the readmitted entry"
    );
}

fn tool(name: &str) -> Tool {
    serde_json::from_value(serde_json::json!({
        "name": name, "description": "A ledger tool.",
        "inputSchema": {"type": "object"}
    }))
    .expect("a tool")
}

/// An upstream whose `tools/list` can be held mid-flight: it signals
/// `reached`, then waits for `release`.
struct Gated {
    hold: Option<(Arc<Notify>, Arc<Notify>)>,
}

#[async_trait]
impl Transport for Gated {
    async fn request(&self, _method: &str, _params: Option<Value>) -> Result<JsonRpcResponse> {
        Err(Error::BackendUnavailable(
            "a per-identity fill must not reach the identity-less path".to_string(),
        ))
    }

    async fn request_with_headers(
        &self,
        _method: &str,
        _params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: ResendPermission,
    ) -> Result<JsonRpcResponse> {
        if let Some((reached, release)) = &self.hold {
            reached.notify_one();
            release.notified().await;
        }
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            ToolsListResult {
                tools: vec![tool("read")],
                next_cursor: None,
            },
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// I8: a fill held before it publishes loses its slot to an eviction and a
/// replacement. Released, it publishes nothing: no index entry, and the old
/// catalogue does not land in the replacement. The replacement's own fill then
/// stands.
#[tokio::test]
async fn g3_i8_retired_fill_cannot_publish() {
    let backend = per_user_backend("g3-i8");
    let (reached, release) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    backend.set_pooled_transport_for_test(
        &slot("g3:b1"),
        Arc::new(Gated {
            hold: Some((Arc::clone(&reached), Arc::clone(&release))),
        }),
    );
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move {
            let filled = backend.get_tools_for_binding(Some("g3:b1"), &[]).await;
            // What a fill's caller does next: publish the slot to the index.
            backend.record_caller_slot(ALPHA, "g3:b1");
            filled.is_ok()
        }
    });
    tokio::time::timeout(WAIT, reached.notified())
        .await
        .expect("the fill reached the upstream");

    assert_eq!(
        backend.evict_identity_slots("g3:b1"),
        1,
        "the held fill's slot was retired"
    );
    backend.set_pooled_transport_for_test(&slot("g3:b1"), Arc::new(Gated { hold: None }));
    release.notify_one();
    let filled = tokio::time::timeout(WAIT, fill)
        .await
        .expect("the released fill finished")
        .expect("the fill task");
    assert!(filled, "premise: the released fill completed");

    assert_eq!(
        backend.caller_slot_binding(ALPHA),
        None,
        "I8: a fill whose slot was retired published an index entry"
    );
    assert!(
        backend.populated_per_user_bindings_for_test().is_empty(),
        "I8: the retired fill's catalogue landed in the replacement slot"
    );

    backend
        .get_tools_for_binding(Some("g3:b1"), &[])
        .await
        .expect("the replacement fills");
    backend.record_caller_slot(ALPHA, "g3:b1");
    assert_eq!(
        backend.caller_slot_binding(ALPHA).as_deref(),
        Some("g3:b1"),
        "I8: the replacement's own entry does not stand"
    );
}
