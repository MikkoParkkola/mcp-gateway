// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Drivers for the response-stage matrix (MIK-8689): one real `/mcp` or
//! `/mcp/alpha` call on the router fixture, with the HMAC receipt and the
//! public seal both installed. Each returns the delivered JSON-RPC body; the
//! matrix (`route_check_matrix_tests::response`) owns every assertion.

use serde_json::{Value, json};

use super::super::direct_guards_fixture::{self as fixture, Answer, post_direct, post_meta_invoke};
use super::{modern_call, surfacing};
use crate::attestation::{BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::meta::Era;
use crate::trust::provenance_public::{ProvenancePublicSigner, TrustSet};

/// The backend answers the rows choose from.
pub(crate) use super::super::direct_guards_fixture::Answer as BackendAnswer;

/// The public seal's test seed and key id (as `provenance_delivery_tests`).
const SEED: [u8; 32] = [7u8; 32];
const KID: &str = "prov-test-1";

/// Both provenance signers on `meta`, `alpha`'s `read` surfaced by name so an
/// `/mcp` call delivers the backend's own envelope (Native) as the result.
fn dual_signed(meta: MetaMcp) -> MetaMcp {
    let mut meta = surfacing(meta);
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    meta.enable_public_provenance(ProvenancePublicSigner::from_seed_for_test(SEED, KID));
    meta
}

/// The trust set holding the seal's public key.
pub(crate) fn trust_set() -> TrustSet {
    let signer = ProvenancePublicSigner::from_seed_for_test(SEED, KID);
    let jwk = serde_json::to_string(&signer.public_jwk()).expect("the jwk serializes");
    TrustSet::from_json(&jwk).expect("the trust set loads")
}

/// The route an HTTP response row drives.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HttpRoute {
    /// `tools/call read` on `/mcp` (the surfaced name).
    Mcp,
    /// `tools/call read` on `/mcp/alpha`.
    Direct,
}

impl HttpRoute {
    fn uri(self) -> &'static str {
        match self {
            Self::Mcp => "/mcp",
            Self::Direct => "/mcp/alpha",
        }
    }
}

/// `tools/call read` on `route` as a caller of `era` declares it.
async fn call_read(fx: &fixture::Fx, route: HttpRoute, era: Era) -> Value {
    match era {
        Era::Modern => modern_call(fx, route.uri(), ("read", json!({})), &json!({})).await,
        Era::Legacy => {
            let params = json!({ "name": "read", "arguments": {} });
            fixture::send(fx, route.uri(), "k-std", "tools/call", params, None)
                .await
                .1
        }
    }
}

/// One `read` call on `route` in `era`, the backend answering `answer`.
pub(crate) async fn signed_call(route: HttpRoute, era: Era, answer: Answer) -> Value {
    let fx = fixture::fixture_built(answer, dual_signed).await;
    call_read(&fx, route, era).await
}

/// One legacy keyed call (`r1`) on `route`. Mcp goes through
/// `gateway_invoke`, the route a key is honoured on.
async fn keyed_call(fx: &fixture::Fx, route: HttpRoute) -> Value {
    match route {
        HttpRoute::Mcp => {
            post_meta_invoke(fx, "k-std", "alpha", "read", json!({}), Some("r1"), None)
                .await
                .1
        }
        HttpRoute::Direct => {
            post_direct(fx, "alpha", "k-std", "read", json!({}), Some("r1"), None)
                .await
                .1
        }
    }
}

/// Two keyed calls on one fixture: the first runs, the second is the replay.
/// Returns (first, replay, backend `tools/call` count).
pub(crate) async fn signed_replay(route: HttpRoute, answer: Answer) -> (Value, Value, usize) {
    let fx = fixture::fixture_built(answer, dual_signed).await;
    let first = keyed_call(&fx, route).await;
    let replay = keyed_call(&fx, route).await;
    (
        first,
        replay,
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
    )
}

/// The egress matrix's planted credential, which a Warn rule on `read`
/// redacts in a delivered answer (MIK-8155).
pub(crate) fn planted_credential() -> &'static str {
    // Leaked once per test that asks: `Answer::Text` holds a `'static` text.
    Box::leak(crate::gateway::egress_fixture::secret().into_boxed_str())
}

/// One `read` call on `route` in `era` whose backend answers `text`, under a
/// Warn rule on `read`: the egress firewall redacts a credential and still
/// delivers the answer.
pub(crate) async fn signed_redacted_call(route: HttpRoute, era: Era, text: &'static str) -> Value {
    let fx = fixture::fixture_firewalled_with_built(
        Answer::Text(text),
        Some(crate::security::firewall::FirewallAction::Warn),
        dual_signed,
    )
    .await;
    call_read(&fx, route, era).await
}
