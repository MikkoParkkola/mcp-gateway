// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Site 5 (`invoke/relay.rs`, the egress relay check): a call on a provider
//! hidden from the caller is checked as a call on an unregistered name is,
//! on everything it would forward, `_meta` included, never on its arguments
//! alone as a capability's call is.

use std::collections::HashMap;

use super::*;
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};

/// A name no backend or provider registers.
const UNREGISTERED: &str = "gamma";

/// The certificate the holder of bearer `who` presents: each caller its own,
/// so a certificate subject never makes the two callers one principal.
fn cert_of(who: &str) -> crate::mtls::CertIdentity {
    let name = format!("agent-{who}");
    crate::mtls::CertIdentity {
        common_name: Some(name.clone()),
        display_name: name,
        ..Default::default()
    }
}

/// The relay fixture (detection blocking, `alpha:read` its source) with two
/// unscoped keys, `a` (alice) and `b` (bob), and the provider `caps`
/// (`cap_open`) under a default profile that leaves it out, for certificates
/// whose rules admit everything: `caps` is hidden from either caller
/// presenting it, and nothing refuses it before the route stage.
async fn hidden_provider_fixture() -> Fixture {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    let unscoped = |secret: &[u8], name: &str| ApiKeyConfig {
        backends: vec!["*".to_string()],
        ..key(secret, name)
    };
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![unscoped(b"a", "alice"), unscoped(b"b", "bob")],
        ..AuthConfig::default()
    };
    let (mut state, store) =
        crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await;
    let (reads, sends) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let catalogue = Arc::new(AtomicUsize::new(0));
    let catalogue_params = Arc::new(Mutex::new(Vec::new()));
    let read = Arc::new(Mutex::new(Read::Text(PROSE.to_string())));
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    let alpha = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    alpha.set_transport_for_test(Arc::new(Alpha {
        read: Arc::clone(&read),
        reads: Arc::clone(&reads),
        sends: Arc::clone(&sends),
        catalogue: Arc::clone(&catalogue),
        catalogue_params: Arc::clone(&catalogue_params),
    }));
    assert!(state_mut.backends.register(alpha));
    let window = Duration::from_secs(600);
    // The suite fixture's firewall: a wildcard `allow`, which must not soften
    // a relay block.
    let config = FirewallConfig {
        rules: crate::yaml::from_str("[{match: \"*\", action: allow}]").expect("rules"),
        collusion: CollusionConfig {
            action: CollusionAction::Block,
            window_secs: window.as_secs(),
            sources: vec!["alpha:read".to_string()],
            ..CollusionConfig::default()
        },
        ..FirewallConfig::default()
    };
    // The firewall and the Meta-MCP share one keyring, as the suite's own
    // fixture and the gateway pair them.
    let first = MetaMcp::new(Arc::clone(&state_mut.backends));
    let firewall =
        Arc::new(Firewall::from_config(config, None).with_continuations(first.continuation()));
    let mut meta =
        MetaMcp::with_features(Arc::clone(&state_mut.backends), None, None, None, window);
    meta.share_keyring_with_for_test(&firewall);
    meta.set_firewall(Some(Arc::clone(&firewall)));
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    let profiles = HashMap::from([(
        "nocaps".to_string(),
        RoutingProfileConfig {
            deny_backends: Some(vec!["caps".to_string()]),
            ..Default::default()
        },
    )]);
    let meta = meta.with_profile_registry(ProfileRegistry::from_config(&profiles, "nocaps"));
    let caps = Arc::new(crate::capability::CapabilityBackend::new(
        "caps",
        Arc::new(crate::capability::CapabilityExecutor::new()),
    ));
    let definition = crate::capability::parse_capability(
        "name: cap_open\n\
         description: Open\n\
         providers:\n\
         \x20 primary:\n\
         \x20   service: rest\n\
         \x20   config:\n\
         \x20     base_url: https://example.invalid\n\
         \x20     path: /open\n",
    )
    .expect("the capability parses");
    caps.register_capability(definition)
        .expect("the capability registers");
    meta.set_capabilities(caps);
    state_mut.firewall = Some(firewall);
    state_mut.meta_mcp = Arc::new(meta);
    let admit_all = |who: &str| PolicyRuleConfig {
        match_criteria: CertMatchConfig {
            cn: cert_of(who).common_name,
            ..Default::default()
        },
        allow: ToolScopeConfig {
            backends: vec!["*".to_string()],
            tools: vec!["*".to_string()],
        },
        deny: ToolScopeConfig {
            backends: Vec::new(),
            tools: Vec::new(),
        },
    };
    state_mut.mtls_policy = Arc::new(crate::mtls::MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![admit_all("a"), admit_all("b")],
        ..Default::default()
    }));
    Fixture {
        state,
        read,
        reads,
        sends,
        catalogue,
        catalogue_params,
        window,
        _store: store,
    }
}

/// One modern `gateway_invoke` of `server:tool` with `arguments`, as bearer
/// `who` presenting its own certificate ([`cert_of`]), `extra` merged into `_meta`.
async fn invoke_as_agent(
    fx: &Fixture,
    who: &str,
    (server, tool, arguments): (&str, &str, Value),
    extra: &Value,
) -> (u16, String) {
    let params = json!({"name": "gateway_invoke",
        "arguments": {"server": server, "tool": tool, "arguments": arguments},
        "_meta": meta_of(extra)});
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .header("authorization", format!("Bearer {who}"))
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    request.extensions_mut().insert(cert_of(who));
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .expect("answers");
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Bob relays alice's read in `_meta.progressToken`, his arguments clean, to
/// the hidden provider's tool and to the same tool on an unregistered name:
/// both are refused by the relay check alike (trace ids masked, the name read
/// as the hidden one), and the hidden capability never runs.
#[tokio::test]
async fn a_relay_in_meta_to_a_hidden_provider_is_refused_as_for_an_unregistered_name() {
    let fx = hidden_provider_fixture().await;
    let (status, read) = invoke_as_agent(&fx, "a", ("alpha", "read", json!({})), &json!({})).await;
    assert!(
        status == 200 && read.contains("orchard ledger"),
        "base: alice's read is delivered: {read}"
    );
    let relay = json!({"progressToken": PROSE});
    // Control: the same relay to a visible backend is refused, so the
    // detector holds alice's read and checks `_meta`.
    let visible = invoke_as_agent(
        &fx,
        "b",
        ("alpha", "send", json!({"text": "hello"})),
        &relay,
    )
    .await;
    assert_eq!(
        envelope(&visible.1)["error"]["code"],
        -32002,
        "control: a relay in `_meta` to a visible backend was not refused: {}",
        visible.1
    );
    let call = |server| (server, "cap_open", json!({"text": "hello"}));
    let before = crate::capability::CapabilityBackend::executed_for_test();
    let hidden = invoke_as_agent(&fx, "b", call("caps"), &relay).await;
    let unregistered = invoke_as_agent(&fx, "b", call(UNREGISTERED), &relay).await;
    assert_eq!(
        crate::capability::CapabilityBackend::executed_for_test(),
        before,
        "the hidden capability ran: {}",
        hidden.1
    );
    let trace = regex::Regex::new(r"gw-[0-9a-f-]{36}").expect("pattern");
    let mask = |body: &str| trace.replace_all(body, "gw-ID").into_owned();
    assert_eq!(
        (hidden.0, mask(&hidden.1)),
        (
            unregistered.0,
            mask(&unregistered.1).replace(UNREGISTERED, "caps")
        ),
        "a relay to the hidden provider answers unlike one to an unregistered name"
    );
    assert_eq!(
        envelope(&hidden.1)["error"]["code"],
        -32002,
        "the relay was not refused: {}",
        hidden.1
    );
}
