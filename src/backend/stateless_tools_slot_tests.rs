// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7334.CATALOGUE.1 — the tools catalogue on a `stateless` backend's slot.
//!
//! THE FAMILY THAT ACTUALLY LEAKED. The disclosure was live on `tools/list`,
//! and the `stateless` cells in `catalogue_families_per_caller_tests` cover
//! resources, resource templates and prompts only. They cannot be extended to a
//! fourth family: `catalogue_families_per_caller_tests::listed_for` has exactly
//! three match arms and panics on anything else, because tools is covered here.
//!
//! So the pin belongs beside `tests::per_user_metadata_fetch_is_identity_free\
//! _and_shared`, the control for the identity-free path. Own file because
//! `tests.rs` is over the 800-line ceiling and may not grow; declared from
//! `backend::mod` so the module is compiled rather than orphaned.
//!
//! THESE CELLS WERE INVERTED, NOT WRITTEN FRESH. Until `pool_key_for` granted a
//! private slot to `(Some(_), Some(binding))`, this file asserted that a
//! `stateless` fill carried NO identity and landed on the shared slot, and said
//! so in its own doc comment. That was the documented gap; it is now the
//! delivered mode, so the assertions flip. Each flip is the arm being widened
//! and not a test made to pass — the identity-free rows below are kept for
//! exactly that reason (IDP.5).

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

        // `readOnlyHint: true` on every answer, so the resend set this fill
        // derives is non-empty whichever catalogue came back. An annotation
        // present on only one identity's tools would let T-S8 pass because the
        // OTHER identity had nothing to inherit, rather than because the set
        // landed on the right slot.
        Ok(JsonRpcResponse::success(
            RequestId::Number(1),
            json!({ "tools": [{
                "name": tool,
                "inputSchema": { "type": "object" },
                "annotations": { "readOnlyHint": true },
            }] }),
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

/// The same backend with `wire` pre-opened on the shared slot AND on each
/// identity's own slot.
///
/// ONE WIRE FOR EVERY SLOT, deliberately. It discriminates on the credential it
/// is handed, so a catalogue that came back per-identity did so because the
/// fill carried that identity — never because the fixture seeded each slot a
/// different answer. Production opens these from config in
/// `ensure_entry_started`; there is no real upstream here.
fn wired(wire: &Arc<PerIdentityTools>) -> Arc<Backend> {
    let backend = stateless_backend();
    let clone = || Arc::clone(wire) as Arc<dyn crate::transport::Transport>;
    backend.set_transport_for_test(clone());
    for binding in ["alpha@ledger", "beta@ledger"] {
        backend.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: binding.to_string(),
            },
            clone(),
        );
    }
    backend
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
/// WHEN alpha fills, beta fills, and an identity-free caller reads
/// THEN each fill ran on ITS OWN slot carrying ITS OWN minted credential, and
/// the identity-free read still runs unkeyed on the shared slot.
///
/// THE FAMILY THAT LEAKED, PINNED — T-S1 for tools. `pool_key_for` grants a
/// private slot to `(Some(_), Some(binding))`, so a `stateless` backend's
/// identified caller now selects its own slot, and `get_cached_list_for` derives
/// `identity_key` from that same `match` — which is what carries the minted
/// headers past the #727 gate. Slot and credential move together or not at all.
///
/// THE TRANSCRIPT IS THE ASSERTION AND IT IS FIRST. Items can coincide; a
/// header list recorded against the slot the fill ran on cannot. An items
/// assertion placed ahead of it would fail first and the transcript check would
/// never run. Raw throughout — no sort, no dedup, no dropping of `None` —
/// because count and multiplicity are exactly what a vacuous cell erases.
///
/// ROW 3 IS NOT OPTIONAL. Without an identity-free read that still lands
/// unkeyed on the shared slot, rows 1 and 2 pass against an implementation that
/// bought isolation by blanking the single-tenant path (IDP.5).
#[tokio::test]
async fn each_identity_fills_its_own_stateless_tools_slot() {
    let wire = PerIdentityTools::new();
    let backend = wired(&wire);

    let seen_by_a = backend
        .get_tools_for_binding(Some("alpha@ledger"), &minted("alpha"))
        .await
        .expect("alpha fills its own tools catalogue");
    let seen_by_b = backend
        .get_tools_for_binding(Some("beta@ledger"), &minted("beta"))
        .await
        .expect("beta fills its own tools catalogue");
    let seen_by_none = backend
        .get_tools_for_binding(None, &[])
        .await
        .expect("the identity-free caller still reads the shared slot");

    // THE DISCRIMINATOR, FIRST. Three reads, three fills, each carrying the
    // credential of the caller whose slot it ran on.
    assert_eq!(
        wire.headers(),
        vec![minted("alpha"), minted("beta"), Vec::new()],
        "a `stateless` fill did not carry its own caller's minted credential \
         upstream, so the catalogue it cached is not that caller's"
    );
    // PROVENANCE: the slot each fill ran on, in order.
    assert_eq!(
        wire.slots(),
        vec![
            Some("alpha@ledger".to_string()),
            Some("beta@ledger".to_string()),
            None,
        ],
        "a `stateless` backend must fill each identified caller's OWN slot and \
         keep the identity-free read on the shared one"
    );

    // ROW 1 — the mode being built.
    assert_eq!(
        names(&seen_by_a),
        vec![ALPHA_TOOL.to_string()],
        "alpha was not served its own tool catalogue"
    );
    assert_eq!(
        names(&seen_by_b),
        vec![BETA_TOOL.to_string()],
        "beta was not served its own tool catalogue"
    );

    // ROW 2 — isolation, meaningful only because row 1 showed each caller was
    // served something of its own.
    assert!(
        !names(&seen_by_a).contains(&BETA_TOOL.to_string())
            && !names(&seen_by_b).contains(&ALPHA_TOOL.to_string()),
        "one `stateless` caller was served another's private tool catalogue: \
         alpha={:?} beta={:?}",
        names(&seen_by_a),
        names(&seen_by_b)
    );
    assert!(
        !names(&seen_by_a).contains(&STATIC_TOOL.to_string())
            && !names(&seen_by_b).contains(&STATIC_TOOL.to_string()),
        "an identified caller was served the gateway's static-credential \
         catalogue under its own identity: alpha={:?} beta={:?}",
        names(&seen_by_a),
        names(&seen_by_b)
    );

    // ROW 3 — IDP.5, and the anti-vacuity guard. The identity-free caller keeps
    // the static-credential catalogue it had before this arm widened.
    assert_eq!(
        names(&seen_by_none),
        vec![STATIC_TOOL.to_string()],
        "the identity-free caller lost the static-credential catalogue, so \
         isolation was bought by blanking the shared path"
    );
}

/// GIVEN the same `stateless` backend
/// WHEN a caller passes minted headers with NO binding
/// THEN the fill records an EMPTY header list on the shared slot.
///
/// T-S10 — #727's header gate keeps a test that can fail it. Widening
/// `pool_key_for` removes the last PRODUCTION path that reaches the gate:
/// `PropagatedCredential::cache_binding` is a `String`, not an `Option`, and
/// both places a `None` binding arises return empty headers with it. So the
/// gate becomes defence-in-depth, and without this cell a mutant that deletes
/// it passes every other cell in this file — the same fixture blind spot that
/// let the original defect through a complete mutation table.
#[tokio::test]
async fn a_stateless_fill_without_a_binding_drops_minted_headers() {
    let wire = PerIdentityTools::new();
    let backend = wired(&wire);

    let seen = backend
        .get_tools_for_binding(None, &minted("alpha"))
        .await
        .expect("the unbound fill answers");

    assert_eq!(
        wire.headers(),
        vec![Vec::<(String, String)>::new()],
        "a fill with no binding carried a minted credential onto the SHARED \
         slot, so one caller's catalogue is what every caller now reads"
    );
    assert_eq!(
        wire.slots(),
        vec![None],
        "a fill with no binding must run on the shared slot"
    );
    assert_eq!(
        names(&seen),
        vec![STATIC_TOOL.to_string()],
        "the unbound fill was answered under a caller's credential rather than \
         the gateway's own"
    );
}

/// The cells that pin what ELSE follows from the widened arm: the cache the
/// slot now holds, the retry set derived from it, the revocation that must
/// reach it, and the schema mirror that must read it. Own file so this one
/// stays under the 800-line ceiling; declared here rather than from
/// `backend::mod` so `super::` reaches this file's fixture.
#[path = "stateless_slot_lifecycle_tests.rs"]
mod stateless_slot_lifecycle_tests;
