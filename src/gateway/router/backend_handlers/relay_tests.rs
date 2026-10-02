// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7697: relay check and delivery recording key on the same principal as
//! the other per-caller controls, for a grant subject and a certificate.
//!
//! Every caller here presents the SAME API key, so a computation that falls
//! back to the credential (ignoring the subject or the certificate) sees one
//! principal and the cross-principal refusal below never happens.

use std::sync::Arc;

use serde_json::{Value, json};

use super::super::{AppState, BackendAuthContext};
use super::{direct_control_identity, record_direct_delivery, relay_refusal};
use crate::config::AuthConfig;
use crate::gateway::auth::{AuthenticatedClient, anonymous_client, principal_of};
use crate::identity_grants::GrantSubject;
use crate::mtls::CertIdentity;
use crate::protocol::RequestId;
use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost.";

fn shared_key() -> AuthenticatedClient {
    AuthenticatedClient {
        name: "shared".to_string(),
        principal: principal_of("one key for everyone"),
        authenticated: true,
        ..anonymous_client()
    }
}

fn cert(san_uri: &str) -> CertIdentity {
    CertIdentity {
        san_uris: vec![san_uri.to_string()],
        display_name: "agent".to_string(),
        ..Default::default()
    }
}

/// One identity carrier per caller: a grant subject, or a certificate with
/// the `mtls` subject the route resolves from it (`caller_grant_subject`).
enum Who {
    Subject(GrantSubject),
    Cert(CertIdentity, GrantSubject),
}

impl Who {
    fn auth<'a>(&'a self, client: &'a AuthenticatedClient) -> BackendAuthContext<'a> {
        let (grant_subject, cert_identity) = match self {
            Self::Subject(s) => (Some(s), None),
            Self::Cert(c, s) => (Some(s), Some(c)),
        };
        BackendAuthContext {
            client: Some(client),
            oauth_agent_identity: None,
            cert_identity,
            grant_subject,
        }
    }
}

async fn blocking_state() -> (Arc<AppState>, tempfile::TempDir) {
    let (mut state, store) =
        crate::gateway::router::tests::test_router_app_state_with_auth(&AuthConfig::default())
            .await;
    let config = FirewallConfig {
        collusion: CollusionConfig {
            action: CollusionAction::Block,
            sources: vec!["alpha:read".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    Arc::get_mut(&mut state).expect("state is unique").firewall =
        Some(Arc::new(Firewall::from_config(config, None)));
    (state, store)
}

fn send_params() -> Value {
    json!({"name": "send", "arguments": {"text": PROSE}})
}

fn refused(state: &AppState, auth: BackendAuthContext<'_>) -> bool {
    let fw = state.firewall.as_ref().expect("firewall");
    let audit = ("direct:alpha", "shared");
    relay_refusal(
        fw,
        auth,
        &RequestId::Number(1),
        ("alpha", "send"),
        &send_params(),
        audit,
    )
    .is_some()
}

/// A is delivered sensitive text; B (another principal behind the same key)
/// is refused for sending it; A itself and A' (same principal, other key) are
/// excused. The control identity agrees with the relay key throughout.
async fn parity(a: &Who, a_other_key: &Who, b: &Who) {
    let (state, _store) = blocking_state().await;
    let key = shared_key();
    let other_key = AuthenticatedClient {
        principal: principal_of("a second key"),
        ..shared_key()
    };
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    record_direct_delivery(&state, a.auth(&key), "alpha", "read", Some(&delivered));

    assert!(
        refused(&state, b.auth(&key)),
        "another principal behind the same key must be refused"
    );
    assert!(
        !refused(&state, a.auth(&key)),
        "the receiver is not relaying"
    );
    assert!(
        !refused(&state, a_other_key.auth(&other_key)),
        "the same principal on another key is the receiver"
    );

    let control = |who: &Who, client: &AuthenticatedClient| {
        direct_control_identity(&state, who.auth(client), "x")
    };
    assert_eq!(control(a, &key), control(a_other_key, &other_key));
    assert_ne!(control(a, &key), control(b, &key));
}

#[tokio::test]
async fn grant_subject_keys_relay_and_recording() {
    let subject = |id: &str| Who::Subject(GrantSubject::new("oidc:https://idp", id, None));
    parity(&subject("alice"), &subject("alice"), &subject("bob")).await;
}

#[tokio::test]
async fn certificate_keys_relay_and_recording() {
    let cert = |uri: &str| {
        let subject = GrantSubject::new("mtls", uri, Some("agent".to_string()));
        Who::Cert(cert(uri), subject)
    };
    parity(
        &cert("spiffe://corp/agent-a"),
        &cert("spiffe://corp/agent-a"),
        &cert("spiffe://corp/agent-b"),
    )
    .await;
}

/// A signing failure replaces the result with a refusal: the caller is
/// delivered nothing, so nothing is recorded and B sending the text is no
/// relay.
#[tokio::test]
async fn a_signing_refusal_records_nothing() {
    use crate::protocol::JsonRpcResponse;
    use crate::security::message_signing::MessageSigner;

    let (mut state, _store) = blocking_state().await;
    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&state.backends));
    let signer = MessageSigner::new(
        b"relay-signing-key-sentinel-0123456789abcdef".to_vec(),
        None,
        "component-current".into(),
    );
    meta.enable_message_signing(signer, std::time::Duration::from_secs(300), false);
    Arc::get_mut(&mut state).expect("state is unique").meta_mcp = Arc::new(meta);
    let key = shared_key();
    let subject = |id: &str| Who::Subject(GrantSubject::new("oidc:https://idp", id, None));
    let (a, b) = (subject("alice"), subject("bob"));
    let delivered = json!({"content": [{"type": "text", "text": PROSE}]});
    let mut response = JsonRpcResponse::success(RequestId::Number(1), delivered);
    // An empty nonce is one the signer refuses.
    let target = ("alpha", "read");
    super::super::sign_and_record(&state, a.auth(&key), target, &mut response, Some(Some("")));
    assert!(
        response.result.is_none(),
        "signing did not refuse: {response:?}"
    );
    assert!(
        !refused(&state, b.auth(&key)),
        "a result the caller never received was recorded"
    );
}
