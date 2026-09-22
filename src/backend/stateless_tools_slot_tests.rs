// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7543 — the tools catalogue on a `stateless` backend's shared slot.
//!
//! THE FAMILY THAT ACTUALLY LEAKED. The disclosure was live on `tools/list`,
//! and the `stateless` cells that landed with the fix cover resources, resource
//! templates and prompts only. They cannot be extended to a fourth family:
//! `catalogue_families_per_caller_tests::listed_for` has exactly three match
//! arms and panics on anything else, because tools is covered at this layer.
//!
//! So the pin belongs beside `tests::per_user_metadata_fetch_is_identity_free\
//! _and_shared`, the control for the identity-free path. Own file because
//! `tests.rs` is over the 800-line ceiling and may not grow; declared from
//! `backend::mod` so the module is compiled rather than orphaned.

use super::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::protocol::{JsonRpcResponse, RequestId, Tool};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The catalogue the upstream serves when no minted credential arrives.
const STATIC_TOOL: &str = "gateway_static_ledger";
const ALPHA_TOOL: &str = "alpha_private_ledger";
const BETA_TOOL: &str = "beta_private_ledger";

/// One recorded upstream fetch: the headers it carried, and the slot it ran on.
type Fetch = (Vec<(String, String)>, Option<String>);

/// A `tools/list` upstream that answers a different catalogue per credential.
///
/// The fixture's whole point: the upstream really does discriminate, so "beta
/// was not served alpha's tools" can only hold because the fill carried no
/// identity — never because one answer was all the upstream ever had.
struct PerIdentityTools {
    shared: String,
    per_identity: HashMap<String, String>,
    seen: parking_lot::Mutex<Vec<Fetch>>,
}

impl PerIdentityTools {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            shared: STATIC_TOOL.to_string(),
            per_identity: HashMap::from([
                ("alpha".to_string(), ALPHA_TOOL.to_string()),
                ("beta".to_string(), BETA_TOOL.to_string()),
            ]),
            seen: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// The header list every fetch carried, in order.
    ///
    /// RAW — no sort, no dedup, nothing dropped. An empty list is a real entry
    /// and is the evidence under test: it says the fill that populated the
    /// shared slot went upstream with no calling identity attached. Normalising
    /// a transcript is how an earlier cell here was found vacuous.
    fn headers(&self) -> Vec<Vec<(String, String)>> {
        self.seen.lock().iter().map(|(h, _)| h.clone()).collect()
    }

    /// The slot every fetch ran on, in order. Raw, for the same reason.
    fn slots(&self) -> Vec<Option<String>> {
        self.seen.lock().iter().map(|(_, k)| k.clone()).collect()
    }
}

#[async_trait]
impl crate::transport::Transport for PerIdentityTools {
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

    /// OVERRIDDEN, NOT INHERITED. The trait's default forwards to `request` and
    /// discards both `extra_headers` and `identity_key`, so a fixture that took
    /// it would record an empty header list for every fetch and the assertion
    /// below would hold against any implementation at all.
    async fn request_with_headers(
        &self,
        method: &str,
        _params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        assert_eq!(method, "tools/list", "fixture serves only tools/list");
        self.seen
            .lock()
            .push((extra_headers.to_vec(), identity_key.map(str::to_string)));

        let tool = extra_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer minted-for-"))
            .and_then(|s| self.per_identity.get(s).cloned())
            .unwrap_or_else(|| self.shared.clone());

        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({ "tools": [{ "name": tool, "inputSchema": { "type": "object" } }] }),
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

/// A backend with identity propagation configured and `session_mode =
/// stateless` — the shape the fixtures this suite already had could not reach.
///
/// CHECK THE CONFIGURATION, NOT THE NAME. The original defect survived a
/// complete mutation table because every fixture was `per_user`, and no
/// mutation could reach the arm that was broken. `stateless` is the arm.
fn stateless_backend() -> Arc<Backend> {
    Arc::new(Backend::new(
        "stateless_tools",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "ledger".to_string(),
                required: false,
                session_mode: SessionMode::Stateless,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..Default::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// The credential the resolver mints for `subject`, shaped as the meta route
/// hands it to `get_tools_for_binding`.
fn minted(subject: &str) -> Vec<(String, String)> {
    vec![(
        "Authorization".to_string(),
        format!("Bearer minted-for-{subject}"),
    )]
}

fn names(tools: &[Tool]) -> Vec<String> {
    tools.iter().map(|t| t.name.clone()).collect()
}

/// GIVEN a `stateless` backend with identity propagation configured, whose
/// upstream serves a different tool catalogue per credential
/// WHEN caller A fills the tools catalogue and caller B then reads it
/// THEN the one fetch that populated the shared slot carried NO identity
/// headers, so B is served the static-credential catalogue and not A's.
///
/// THE FAMILY THAT LEAKED, PINNED. `pool_key_for` hands a `stateless` backend
/// `PoolKey::Shared` however well its caller identifies itself, while the
/// resolver still mints that caller a credential — `cache_binding` is derived
/// from subject and audience and never consults the session mode. Carry those
/// minted headers into the fill and A's private catalogue is what every caller
/// reads until TTL. Both callers pass a binding here, exactly as the meta route
/// does, so the collapse to one slot is the production path and not a shortcut.
///
/// THE HEADER TRANSCRIPT IS THE ASSERTION AND IT IS FIRST. Items can coincide;
/// a minted `Authorization` recorded on the fill that populated a slot every
/// caller reads cannot. An items assertion placed ahead of it would fail first
/// and the header check would never run.
///
/// This pins the documented `stateless` gap (IDP.5), NOT a per-caller
/// `stateless` catalogue: serving one needs an uncached path or a per-identity
/// slot, and both are changes to `pool_key_for`.
#[tokio::test]
async fn a_stateless_tools_fill_carries_no_identity_onto_the_shared_slot() {
    let wire = PerIdentityTools::new();
    let backend = stateless_backend();
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);

    let seen_by_a = backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("caller A fills the tools catalogue");
    let seen_by_b = backend
        .get_tools_for_binding(Some("beta@ledger"), &minted("beta"))
        .await
        .expect("caller B reads it");

    // THE DISCRIMINATOR, FIRST. One fill, and it went upstream with no headers.
    assert_eq!(
        wire.headers(),
        vec![Vec::<(String, String)>::new()],
        "the fill that populated the SHARED slot of a `stateless` backend \
         carried the calling identity's minted credential upstream, so what \
         every caller now reads is private to one of them"
    );
    // PROVENANCE: it really was the shared slot, not a private one.
    assert_eq!(
        wire.slots(),
        vec![None],
        "a `stateless` backend must fill its one shared slot once, unkeyed"
    );

    // THE DISCLOSURE. B reads the slot A filled.
    assert!(
        !names(&seen_by_b).contains(&ALPHA_TOOL.to_string()),
        "caller B was served caller A's private tool catalogue out of the \
         shared slot of a `stateless` backend: {:?}",
        names(&seen_by_b)
    );

    // ANTI-VACUITY. Both callers ARE served the static-credential catalogue —
    // what a `stateless` backend served before this branch existed. Without it
    // the absence above holds against a backend that answered nobody at all.
    assert_eq!(
        names(&seen_by_a),
        vec![STATIC_TOOL.to_string()],
        "caller A was not served the static-credential catalogue"
    );
    assert_eq!(
        names(&seen_by_b),
        vec![STATIC_TOOL.to_string()],
        "caller B was served nothing, so the absence check above measures an \
         empty answer rather than isolation"
    );
    assert!(
        !names(&seen_by_a).contains(&BETA_TOOL.to_string())
            && !names(&seen_by_b).contains(&BETA_TOOL.to_string()),
        "the upstream stopped discriminating on the credential, so the fixture \
         can no longer tell an identified fill from an unidentified one"
    );
}
