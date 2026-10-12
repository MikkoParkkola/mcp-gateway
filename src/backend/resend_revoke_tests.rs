// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8399: a listing the gateway does not store must still revoke resend
//! permission, or a write the backend now lists as unsafe can be resent and
//! run twice.
//!
//! Every revocation row seeds `t` RESEND-ONLY (permitted, not cache-admitted):
//! a page that relists a cache-admitted tool already revokes both sets through
//! #3851's read-only leg, so a seed in both sets would pass without the fix.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::Backend;
use crate::backend::Listing;
use crate::config::{BackendConfig, FailsafeConfig};

fn backend() -> Arc<Backend> {
    Arc::new(Backend::new(
        "ledger",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// A listed tool. `hints` is its `annotations` object, or `None` for none.
fn tool(name: &str, hints: Option<Value>) -> Value {
    let mut t = json!({"name": name, "inputSchema": {"type": "object"}});
    if let Some(hints) = hints {
        t["annotations"] = hints;
    }
    t
}

fn write(name: &str) -> Value {
    tool(
        name,
        Some(json!({"readOnlyHint": false, "idempotentHint": false})),
    )
}

fn idempotent(name: &str) -> Value {
    tool(
        name,
        Some(json!({"readOnlyHint": false, "idempotentHint": true})),
    )
}

fn read_only(name: &str) -> Value {
    tool(name, Some(json!({"readOnlyHint": true})))
}

fn seed_resend_only(backend: &Backend, names: &[&str]) {
    *backend.shared_entry_for_test().resend_permitted.write() =
        names.iter().map(|n| (*n).to_owned()).collect();
}

fn permitted(backend: &Backend) -> HashSet<String> {
    backend.resend_permitted_snapshot()
}

/// S1: a truncated page relisting resend-permitted `t` as a write revokes it.
#[tokio::test]
async fn s1_a_truncated_page_relisting_a_write_revokes_its_resend() {
    let backend = backend();
    seed_resend_only(&backend, &["t"]);
    let _ = backend.remember_listed_tools_as(None, false, &[write("t")], Listing::Truncated);
    assert!(
        !permitted(&backend).contains("t"),
        "a partial page declared `t` a write and it can still be resent"
    );
}

/// S2: the same through a credentialed page landing on the shared slot.
#[tokio::test]
async fn s2_a_credentialed_page_relisting_a_write_revokes_its_resend() {
    let backend = backend();
    seed_resend_only(&backend, &["t"]);
    let _ = backend.remember_listed_tools_as(None, true, &[write("t")], Listing::Complete);
    assert!(!permitted(&backend).contains("t"));
}

/// S3, the split: idempotent but not read-only keeps its resend permission
/// and loses only its cache admission, even when it held both.
#[tokio::test]
async fn s3_an_idempotent_relist_keeps_resend_and_loses_cache_admission() {
    let backend = backend();
    seed_resend_only(&backend, &["t"]);
    backend.set_read_only_declared_for_test(&["t"]);
    let _ = backend.remember_listed_tools_as(None, false, &[idempotent("t")], Listing::Truncated);
    assert!(
        permitted(&backend).contains("t"),
        "an idempotent tool may still be retried"
    );
    assert!(
        !backend.is_read_only_for(None, "t"),
        "but it is no longer a declared read"
    );
}

/// `write(name)` whose schema breaks an `x-mcp-header` constraint, so
/// `prepare_tool_metadata` drops it before the safety sets are read.
fn header_invalid_write(name: &str) -> Value {
    let mut t = write(name);
    t["inputSchema"] = json!({"type": "object", "properties": {
        "ratio": {"type": "number", "x-mcp-header": "Ratio"}
    }});
    t
}

/// S6a: a write dropped by the header check still revokes its resend.
#[tokio::test]
async fn s6a_a_header_invalid_write_still_revokes_its_resend() {
    let backend = backend();
    seed_resend_only(&backend, &["t"]);
    let _ = backend.remember_listed_tools_as(
        None,
        false,
        &[header_invalid_write("t")],
        Listing::Truncated,
    );
    assert!(!permitted(&backend).contains("t"));
}

/// S6b, #3851's leg: the same page also revokes cache admission.
#[tokio::test]
async fn s6b_a_header_invalid_write_still_revokes_its_cache_admission() {
    let backend = backend();
    backend.set_read_only_declared_for_test(&["t"]);
    let _ = backend.remember_listed_tools_as(
        None,
        false,
        &[header_invalid_write("t")],
        Listing::Truncated,
    );
    assert!(!backend.is_read_only_for(None, "t"));
}

/// S10: an entry that cannot be read declares nothing, so it revokes nothing.
#[tokio::test]
async fn s10_an_unreadable_entry_revokes_no_resend() {
    let backend = backend();
    seed_resend_only(&backend, &["t"]);
    let malformed = json!({"name": "t", "annotations": "not an object"});
    let _ = backend.remember_listed_tools_as(None, false, &[malformed], Listing::Truncated);
    assert!(permitted(&backend).contains("t"));
}

/// S12: one unsafe occurrence keeps a name out of a set, in either order,
/// on a complete listing as on a partial one.
#[tokio::test]
async fn s12_one_unsafe_occurrence_keeps_a_name_out() {
    for (pages, listing) in [
        (vec![idempotent("t"), write("t")], Listing::Complete),
        (vec![write("t"), idempotent("t")], Listing::Complete),
        (vec![idempotent("t"), write("t")], Listing::Truncated),
        (
            vec![idempotent("t"), header_invalid_write("t")],
            Listing::Complete,
        ),
    ] {
        let backend = backend();
        seed_resend_only(&backend, &["t"]);
        let _ = backend.remember_listed_tools_as(None, false, &pages, listing);
        assert!(
            !permitted(&backend).contains("t"),
            "a conflicting duplicate kept resend permission: {pages:?}"
        );
    }
}

/// S12, per set: read-only on one occurrence and idempotent on the other is
/// resend-safe twice but read-only once, so it keeps resend and is not a read.
#[tokio::test]
async fn s12_the_two_sets_judge_duplicates_independently() {
    let backend = backend();
    seed_resend_only(&backend, &["t"]);
    backend.set_read_only_declared_for_test(&["t"]);
    let _ = backend.remember_listed_tools_as(
        None,
        false,
        &[read_only("t"), idempotent("t")],
        Listing::Complete,
    );
    assert!(permitted(&backend).contains("t"));
    assert!(!backend.is_read_only_for(None, "t"));
}

/// What one `tools/list` page answers.
#[derive(Clone)]
enum Page {
    /// These tools, and a next cursor when `true`.
    Tools(Vec<Value>, bool),
    /// A JSON-RPC error frame.
    ErrorFrame,
    /// A transport failure.
    Lost,
    /// Wait until released, then answer these tools as the last page.
    Held(Vec<Value>),
    /// The transport panics.
    Panic,
}

/// Answers `tools/list` page by page (page `n` is asked with cursor `cN`),
/// and fails the first `tools/call` with a retryable transport error.
struct Wire {
    pages: parking_lot::Mutex<Vec<Page>>,
    calls: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl Wire {
    fn new(pages: Vec<Page>) -> Arc<Self> {
        Arc::new(Self {
            pages: parking_lot::Mutex::new(pages),
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        })
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let id = crate::protocol::RequestId::Number(1);
        if method == "tools/call" {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(crate::Error::Transport("stream reset".into()));
            }
            return Ok(crate::protocol::JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "done"}], "isError": false}),
            ));
        }
        assert_eq!(method, "tools/list");
        let n: usize = params
            .as_ref()
            .and_then(|p| p.get("cursor")?.as_str()?.strip_prefix('c')?.parse().ok())
            .unwrap_or(0);
        let page = self.pages.lock().get(n).cloned().expect("a scripted page");
        let (tools, more) = match page {
            Page::Tools(tools, more) => (tools, more),
            Page::ErrorFrame => {
                return Ok(crate::protocol::JsonRpcResponse::error(
                    Some(id),
                    -32603,
                    "upstream failed",
                ));
            }
            Page::Lost => return Err(crate::Error::Transport("stream reset".into())),
            Page::Held(tools) => {
                self.entered.notify_one();
                self.release.notified().await;
                (tools, false)
            }
            Page::Panic => panic!("the transport fell over mid-drain"),
        };
        let mut result = json!({ "tools": tools });
        if more {
            result["nextCursor"] = json!(format!("c{}", n + 1));
        }
        Ok(crate::protocol::JsonRpcResponse::success(id, result))
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

/// A backend whose retries back off for 1 ms, so S4 does not wait.
fn fast_retry_backend(wire: &Arc<Wire>) -> Arc<Backend> {
    let mut failsafe = FailsafeConfig::default();
    failsafe.retry.initial_backoff = Duration::from_millis(1);
    failsafe.retry.max_backoff = Duration::from_millis(1);
    // Enforcement off: nothing lists the slot ahead of the call, so the
    // seeded permission is what the retry decision reads.
    let config = BackendConfig {
        input_schema_enforcement: crate::config::InputSchemaEnforcement::Off,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "ledger",
        config,
        &failsafe,
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::clone(wire) as Arc<dyn crate::transport::Transport>);
    backend
}

async fn call_t(backend: &Backend) -> crate::Result<crate::protocol::JsonRpcResponse> {
    backend
        .request_with_headers("tools/call", Some(json!({"name": "t"})), &[], None)
        .await
}

/// S4, the fail-fast check. The first `tools/call` is lost. While `t` may be
/// resent it is retried (two frames); once a partial page declares it a
/// write, the loss reaches the caller after one frame.
#[tokio::test]
async fn s4_a_revoked_write_is_not_resent_after_a_lost_call() {
    let control = Wire::new(Vec::new());
    let backend = fast_retry_backend(&control);
    seed_resend_only(&backend, &["t"]);
    call_t(&backend).await.expect("the retry succeeds");
    assert_eq!(
        control.calls.load(Ordering::SeqCst),
        2,
        "premise: `t` is resent"
    );

    let wire = Wire::new(Vec::new());
    let backend = fast_retry_backend(&wire);
    seed_resend_only(&backend, &["t"]);
    let _ = backend.remember_listed_tools_as(None, false, &[write("t")], Listing::Truncated);
    assert!(call_t(&backend).await.is_err(), "the lost call is reported");
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "a write the backend now declares unsafe was sent twice"
    );
}

/// A backend whose catalogue is always stale (TTL zero), so every read
/// refills: the fill under test is a refresh over a stored catalogue.
fn refreshing_backend(wire: &Arc<Wire>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::ZERO,
    ));
    backend.set_transport_for_test(Arc::clone(wire) as Arc<dyn crate::transport::Transport>);
    backend
}

/// A first, complete fill that declares `t` idempotent, so it is resend-permitted
/// and a catalogue is stored. Then the wire serves `next`.
async fn primed(next: Vec<Page>) -> (Arc<Backend>, Arc<Wire>) {
    let wire = Wire::new(vec![Page::Tools(vec![idempotent("t")], false)]);
    let backend = refreshing_backend(&wire);
    backend.get_tools_shared().await.expect("the first fill");
    assert!(
        permitted(&backend).contains("t"),
        "premise: the fill permits `t`"
    );
    *wire.pages.lock() = next;
    (backend, wire)
}

fn catalogue_len(backend: &Backend) -> usize {
    backend.cached_tools_snapshot_and_truncated().0.len()
}

/// S13: a refresh whose page 1 declares `t` a write and whose page 2 fails
/// keeps the last complete catalogue, and no longer permits resending `t`.
#[tokio::test]
async fn s13_an_abandoned_refresh_narrows_from_what_it_read() {
    let (backend, _wire) =
        primed(vec![Page::Tools(vec![write("t")], true), Page::ErrorFrame]).await;
    let _ = backend.get_tools_shared().await;
    assert!(
        !permitted(&backend).contains("t"),
        "a refresh read `t` declared a write, failed, and kept it resend-permitted"
    );
    assert_eq!(
        catalogue_len(&backend),
        1,
        "the last complete catalogue is still served"
    );
}

/// S15: the same refresh, cancelled while page 2 is on the wire.
#[tokio::test]
async fn s15_a_cancelled_refresh_narrows_from_what_it_read() {
    let (backend, wire) = primed(vec![
        Page::Tools(vec![write("t")], true),
        Page::Held(Vec::new()),
    ])
    .await;
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.get_tools_shared().await }
    });
    tokio::time::timeout(WAIT, wire.entered.notified())
        .await
        .expect("page 2 reached the wire");
    fill.abort();
    let _ = fill.await;
    assert!(
        !permitted(&backend).contains("t"),
        "a cancelled refresh read `t` declared a write and kept it resend-permitted"
    );
    assert_eq!(catalogue_len(&backend), 1);
}

/// Upper bound on any wait, so a mis-wired gate fails the row rather than
/// hanging the suite.
const WAIT: Duration = Duration::from_secs(30);

/// S8, the cold race: a fill on the wire that will declare `t` idempotent,
/// and a partial page declaring `t` a write before it lands. The fill must
/// not grant what the page revoked.
#[tokio::test]
async fn s8_a_fill_in_flight_cannot_grant_what_a_page_revoked() {
    let wire = Wire::new(vec![Page::Held(vec![idempotent("t")])]);
    let backend = refreshing_backend(&wire);
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.get_tools_shared().await }
    });
    tokio::time::timeout(WAIT, wire.entered.notified())
        .await
        .expect("the fill reached the wire");
    let _ = backend.remember_listed_tools_as(None, false, &[write("t")], Listing::Truncated);
    wire.release.notify_one();
    tokio::time::timeout(WAIT, fill)
        .await
        .expect("the fill finished")
        .expect("the fill task")
        .expect("the fill answers its own caller");
    assert!(!permitted(&backend).contains("t"));
}

/// S9, the control: a fill after the revocation reads a newer list and
/// grants what it declares.
#[tokio::test]
async fn s9_a_fill_after_a_revocation_grants_what_it_declares() {
    let wire = Wire::new(vec![Page::Tools(vec![idempotent("t")], false)]);
    let backend = refreshing_backend(&wire);
    seed_resend_only(&backend, &["t"]);
    let _ = backend.remember_listed_tools_as(None, false, &[write("t")], Listing::Truncated);
    backend.get_tools_shared().await.expect("a later fill");
    assert!(permitted(&backend).contains("t"));
}

/// S17, the fill half: an abandoned refresh read only a prefix, so a name it
/// never reached (`u`) keeps its permission; the write it read (`t`) loses it.
#[tokio::test]
async fn s17_an_abandoned_refresh_keeps_names_it_never_read() {
    let wire = Wire::new(vec![Page::Tools(
        vec![idempotent("t"), idempotent("u")],
        false,
    )]);
    let backend = refreshing_backend(&wire);
    backend.get_tools_shared().await.expect("the first fill");
    *wire.pages.lock() = vec![Page::Tools(vec![write("t")], true), Page::ErrorFrame];
    let _ = backend.get_tools_shared().await;
    let set = permitted(&backend);
    assert!(!set.contains("t"));
    assert!(
        set.contains("u"),
        "a name the refresh never reached lost its permission"
    );
}

/// S18: a complete direct listing replaces the slot while a refresh is on the
/// wire; the refresh is then cancelled. The replacement is newer, so the
/// abandoned refresh must not narrow it.
#[tokio::test]
async fn s18_an_abandoned_refresh_leaves_a_newer_replacement_alone() {
    let (backend, wire) = primed(vec![
        Page::Tools(vec![write("t")], true),
        Page::Held(Vec::new()),
    ])
    .await;
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.get_tools_shared().await }
    });
    tokio::time::timeout(WAIT, wire.entered.notified())
        .await
        .expect("page 2 reached the wire");
    let _ = backend.remember_listed_tools_as(None, false, &[idempotent("t")], Listing::Complete);
    fill.abort();
    let _ = fill.await;
    assert!(
        permitted(&backend).contains("t"),
        "an abandoned refresh narrowed the newer complete listing"
    );
}

/// Unwind: a transport that panics on page 2. The hook narrows during the
/// unwind, and the panic stays inside the fill's task.
#[tokio::test]
async fn an_unwinding_refresh_still_narrows_from_what_it_read() {
    let (backend, _wire) = primed(vec![Page::Tools(vec![write("t")], true), Page::Panic]).await;
    let fill = tokio::spawn({
        let backend = Arc::clone(&backend);
        async move { backend.get_tools_shared().await }
    });
    assert!(
        fill.await.is_err_and(|e| e.is_panic()),
        "premise: the fill panicked"
    );
    assert!(!permitted(&backend).contains("t"));
}

/// S11: a caller's partial page revokes in that caller's slot only. Another
/// identity's slot keeps the permission its own listing gave it (mutant m7,
/// a revocation that always reads the shared slot).
#[tokio::test]
async fn s11_a_callers_page_revokes_in_that_callers_slot_only() {
    use crate::backend::PoolKey;
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let slot = |who: &str| PoolKey::PerUser {
        binding: who.to_string(),
    };
    for who in ["alpha", "beta"] {
        backend.set_pooled_transport_for_test(
            &slot(who),
            Wire::new(Vec::new()) as Arc<dyn crate::transport::Transport>,
        );
        *backend
            .pooled_entry(&slot(who))
            .expect("the slot exists")
            .resend_permitted
            .write() = std::iter::once("t".to_owned()).collect();
    }
    let _ =
        backend.remember_listed_tools_as(Some("alpha"), false, &[write("t")], Listing::Truncated);
    let holds = |who: &str| {
        backend
            .pooled_entry(&slot(who))
            .expect("the slot exists")
            .resend_permitted
            .read()
            .contains("t")
    };
    assert!(
        !holds("alpha"),
        "alpha's own page did not revoke in alpha's slot"
    );
    assert!(holds("beta"), "alpha's page revoked beta's permission");
}

/// S13b: the abandoned refresh narrows cache admission too (mutant m15,
/// narrowing resend only).
#[tokio::test]
async fn s13b_an_abandoned_refresh_narrows_cache_admission_too() {
    let wire = Wire::new(vec![Page::Tools(vec![read_only("t")], false)]);
    let backend = refreshing_backend(&wire);
    backend.get_tools_shared().await.expect("the first fill");
    assert!(
        backend.is_read_only_for(None, "t"),
        "premise: `t` is admitted"
    );
    *wire.pages.lock() = vec![Page::Tools(vec![write("t")], true), Page::ErrorFrame];
    let _ = backend.get_tools_shared().await;
    assert!(!backend.is_read_only_for(None, "t"));
}
