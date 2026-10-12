// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8393 R8b: a page that is never stored can still revoke cache admission,
//! and a fill already in flight cannot put it back.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::backend::{Backend, Listing};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

/// Upper bound on any wait in a race leg, so a mis-wired gate fails the row
/// rather than hanging the suite; a passing row never comes near it.
const WAIT: Duration = Duration::from_secs(30);

fn backend() -> Arc<Backend> {
    Arc::new(Backend::new(
        "edits",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

fn tool(name: &str, read_only: bool) -> Value {
    json!({"name": name, "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": read_only, "idempotentHint": true}})
}

/// A truncated page relisting an admitted tool as a write revokes it.
#[tokio::test]
async fn a_truncated_page_relisting_a_tool_as_a_write_revokes_it() {
    let backend = backend();
    backend.set_read_only_declared_for_test(&["t"]);
    let _ = backend.remember_listed_tools_as(None, false, &[tool("t", false)], Listing::Truncated);
    assert!(
        !backend.is_read_only_for(None, "t"),
        "a partial page that relisted the tool as a write left it admitted"
    );
}

/// A page fetched under a caller's own credential is not stored in the shared
/// slot, and it still revokes there.
#[tokio::test]
async fn a_credentialed_page_relisting_a_tool_as_a_write_revokes_it() {
    let backend = backend();
    backend.set_read_only_declared_for_test(&["t"]);
    let _ = backend.remember_listed_tools_as(None, true, &[tool("t", false)], Listing::Complete);
    assert!(!backend.is_read_only_for(None, "t"));
}

/// A page that revokes nothing changes nothing; one that cannot be read
/// declares nothing, so it revokes nothing either.
#[tokio::test]
async fn a_page_that_revokes_nothing_leaves_admission_alone() {
    let backend = backend();
    backend.set_read_only_declared_for_test(&["t", "u"]);
    let malformed = json!({"name": "u", "annotations": "not an object"});
    let _ = backend.remember_listed_tools_as(
        None,
        false,
        &[tool("t", true), malformed],
        Listing::Truncated,
    );
    assert!(backend.is_read_only_for(None, "t"));
    assert!(
        backend.is_read_only_for(None, "u"),
        "an unreadable entry revoked admission"
    );
}

/// Answers `tools/list` with `t` declared read-only, held until `release`.
struct Held {
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl crate::transport::Transport for Held {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list");
        self.entered.notify_one();
        self.release.notified().await;
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({ "tools": [tool("t", true)] }),
        ))
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

/// The race: a fill that read `t` as read-only is on the wire when a partial
/// page revokes `t`. Narrowing alone would let the fill land afterwards and
/// re-admit it (mutant c13); the revocation invalidates, so the fill's store
/// is refused.
#[tokio::test]
async fn a_fill_in_flight_cannot_undo_a_revocation() {
    let backend = backend();
    let wire = Arc::new(Held {
        entered: Notify::new(),
        release: Notify::new(),
    });
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    backend.set_read_only_declared_for_test(&["t"]);
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.get_tools_shared().await }
    });
    tokio::time::timeout(WAIT, wire.entered.notified())
        .await
        .expect("the fill reached the wire");
    let _ = backend.remember_listed_tools_as(None, false, &[tool("t", false)], Listing::Truncated);
    wire.release.notify_one();
    let _ = tokio::time::timeout(WAIT, fill)
        .await
        .expect("the fill finished");
    assert!(
        !backend.is_read_only_for(None, "t"),
        "a fill that started before the revocation re-admitted the tool"
    );
}

/// The cold race (r6): no admission yet, a fill on the wire that will declare
/// `t` read-only, and a page that declares `t` a write. Revoking only what is
/// admitted would let the fill land and admit `t` (mutant c14).
#[tokio::test]
async fn a_cold_fill_in_flight_cannot_admit_a_tool_a_page_declared_a_write() {
    let backend = backend();
    let wire = Arc::new(Held {
        entered: Notify::new(),
        release: Notify::new(),
    });
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.get_tools_shared().await }
    });
    tokio::time::timeout(WAIT, wire.entered.notified())
        .await
        .expect("the fill reached the wire");
    let _ = backend.remember_listed_tools_as(None, false, &[tool("t", false)], Listing::Truncated);
    wire.release.notify_one();
    let _ = tokio::time::timeout(WAIT, fill)
        .await
        .expect("the fill finished");
    assert!(
        !backend.is_read_only_for(None, "t"),
        "a cold fill that started before the page admitted a tool the page declared a write"
    );
}

/// The control (r7): a revocation clears the whole set, and a fill that
/// starts AFTER it reads a newer list, so what that list declares read-only
/// is admitted again. `u` stays out: the new list does not declare it.
#[tokio::test]
async fn a_fill_after_a_revocation_admits_what_it_declares() {
    let backend = backend();
    let wire = Arc::new(Held {
        entered: Notify::new(),
        release: Notify::new(),
    });
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    backend.set_read_only_declared_for_test(&["t", "u"]);
    let _ = backend.remember_listed_tools_as(None, false, &[tool("t", false)], Listing::Truncated);
    assert!(!backend.is_read_only_for(None, "t"));
    assert!(
        !backend.is_read_only_for(None, "u"),
        "a revocation clears the slot's whole admission set"
    );
    wire.release.notify_one();
    backend.get_tools_shared().await.expect("a later fill");
    assert!(
        backend.is_read_only_for(None, "t"),
        "a fill after the revocation must admit what it declares"
    );
    assert!(!backend.is_read_only_for(None, "u"));
}
