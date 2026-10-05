// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::network_bind_refusal;
use crate::config::Config;

fn config(host: &str, auth: bool, override_set: bool) -> Config {
    let mut c = Config::default();
    c.server.host = host.to_string();
    c.auth.enabled = auth;
    c.server.allow_unauthenticated_network_bind = override_set;
    c
}

/// The deployment templates this repository ships must start.
///
/// Every one of them binds `0.0.0.0`, because a container or a pod that
/// binds loopback receives nothing. That is half the refusal condition, so
/// each template has to answer the other half — and until this case existed,
/// three of them did not: the Helm chart and the Kubernetes base carried no
/// `auth` section at all, which is `enabled: false`, which is refused. An
/// unmodified `helm install` produced a pod that exited.
///
/// The shapes below are the ones those files now hold. Reading the files
/// themselves from a unit test would tie this crate to the repository
/// layout, so they are mirrored here and named, which is the trade this
/// makes deliberately: it catches a REGRESSION in what the refusal accepts,
/// not an edit to the templates.
#[test]
fn the_shipped_deployment_shapes_are_allowed_to_serve() {
    // Helm values.yaml and the Kubernetes base ConfigMap: a credential is
    // required, and only /health is open so probes work without one.
    let mut cluster = config("0.0.0.0", true, false);
    cluster.auth.bearer_token = Some("env:MCP_GATEWAY_TOKEN".to_string());
    cluster.auth.public_paths = vec!["/health".to_string()];
    assert!(
        network_bind_refusal(&cluster).is_none(),
        "the shipped cluster templates would not start"
    );

    // docker-compose.yaml: binds 0.0.0.0 inside the container and keeps the
    // init config's public /mcp, so it sets the escape hatch — the host
    // publish is 127.0.0.1 only, and the gateway cannot see that.
    let mut compose = config("0.0.0.0", true, true);
    compose.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];
    assert!(
        network_bind_refusal(&compose).is_none(),
        "the shipped compose template would not start"
    );

    // And the same compose shape WITHOUT the hatch is refused, so the line
    // is load-bearing rather than decorative.
    let mut without = compose.clone();
    without.server.allow_unauthenticated_network_bind = false;
    assert!(
        network_bind_refusal(&without).is_some(),
        "the compose template's escape hatch is not what makes it start"
    );
}

/// Every native credential gate counts, not only `auth`.
///
/// Each of these rejects a caller that presents nothing, so a gateway
/// carrying one does not have tools "reachable without a credential" — the
/// question this refusal actually asks. Refusing them stops the most
/// carefully secured deployments from starting, which is a denial of
/// service dressed as a security control.
///
/// Enumerated one gate per case rather than asserted in a lump, because the
/// failure this guards against is a gate being FORGOTTEN: mTLS and
/// `agent_auth` both were.
#[test]
fn a_native_credential_gate_means_the_tools_are_not_open() {
    // mTLS that requires a client certificate: rejected during the TLS
    // handshake, before any HTTP exists.
    let mut mtls = config("0.0.0.0", false, false);
    mtls.mtls.enabled = true;
    mtls.mtls.require_client_cert = true;
    assert!(
        network_bind_refusal(&mtls).is_none(),
        "an mTLS gateway requiring client certificates was refused"
    );

    // ...but mTLS WITHOUT that requirement and with no policy is
    // encryption, not authentication, and its own doc comment says so. It
    // must still refuse.
    let mut encryption_only = mtls.clone();
    encryption_only.mtls.require_client_cert = false;
    encryption_only.mtls.policies = Vec::new();
    assert!(
        network_bind_refusal(&encryption_only).is_some(),
        "TLS without client certificates authenticates nobody"
    );

    // Optional certificates PLUS a policy does gate: the policy denies
    // every call that arrives without a verified identity.
    let mut policy_gated = encryption_only.clone();
    policy_gated.mtls.policies = vec![crate::mtls::config::PolicyRuleConfig::default()];
    assert!(
        network_bind_refusal(&policy_gated).is_none(),
        "an mTLS policy denies uncredentialed calls, so the tools are not open"
    );

    // Agent JWT auth: the middleware wraps every route and answers 401 to a
    // request with no valid token. `enabled` is sufficient here because
    // `Config::validate` refuses a config whose agent keys could not reject
    // anybody, so this state cannot reach a running gateway — see
    // `config::Config::validate_agent_key_material` and its tests.
    let mut agent = config("0.0.0.0", false, false);
    agent.agent_auth.enabled = true;
    assert!(
        network_bind_refusal(&agent).is_none(),
        "a gateway requiring an agent JWT was refused"
    );

    // And with none of them, the same bind is still refused, so the cases
    // above pass on the gate rather than on the fixture.
    assert!(
        network_bind_refusal(&config("0.0.0.0", false, false)).is_some(),
        "the control case must refuse, or these prove nothing"
    );
}

#[test]
fn a_public_path_counts_when_it_covers_the_tool_surface() {
    // Whether a configured prefix opens the tools is DERIVED here, not
    // asserted: it opens them exactly when some real tool request path
    // starts with it, which is what `ResolvedAuthConfig::is_public_path`
    // computes at request time. Writing the column by hand is how the
    // earlier spellings of this rule stayed green while being wrong.
    let real_tool_paths = ["/mcp", "/mcp/github"];
    let cases = [
        // Reach a tool route.
        "",
        "/",
        "/m",
        "/mc",
        "/mcp",
        "/mcp/",
        "/mcp/github",
        // Do NOT, and each of these once refused the gateway at startup:
        // the check asked whether an entry BEGAN with `/mcp` rather than
        // whether it reached a tool route, so an operator's own health
        // endpoint stopped the process from starting.
        "/mcp-status",
        "/mcpx",
        "/mcp.json",
        "/mcp%2Ffoo",
        "/mcp\u{FF0F}foo",
        "/health",
        "/metrics",
        "/MCP",
        "/.well-known/oauth-protected-resource",
    ];
    for path in cases {
        let opens_tools = real_tool_paths.iter().any(|real| real.starts_with(path));
        let mut c = config("0.0.0.0", true, false);
        c.auth.public_paths = vec!["/health".to_string(), path.to_string()];
        assert_eq!(
            network_bind_refusal(&c).is_some(),
            opens_tools,
            "public path {path:?} was judged wrongly: refusing a legitimate \
             config stops a gateway starting, and missing one serves every \
             backend without a credential"
        );
    }
}

#[test]
fn a_blank_public_path_is_the_most_public_path_there_is() {
    // Public paths are matched by PREFIX (`ResolvedAuthConfig::is_public_path`,
    // `path.starts_with(p)`), so a blank entry is a prefix of every path and
    // opens the whole gateway — the MCP endpoint included. A YAML list with
    // a stray dash produces one.
    //
    // This case exists because the check used to skip empty entries, so the
    // single entry that opens everything was the single entry that did not
    // count: the config below read as secured and served every backend.
    let mut c = config("0.0.0.0", true, false);
    c.auth.public_paths = vec!["/health".to_string(), String::new()];
    assert!(
        network_bind_refusal(&c).is_some(),
        "a blank public path opens every route and must be refused"
    );
}

#[test]
fn auth_enabled_is_not_enough_when_tools_are_public() {
    // Two changes that are each right and together are not: the starter
    // config enables auth AND lists /mcp as a public path so tools stay
    // open. `auth.enabled` alone then reads as safe, while every backend
    // stays reachable without a credential — on a network address.
    let mut c = config("0.0.0.0", true, false);
    c.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];
    let refusal = network_bind_refusal(&c);
    assert!(
        refusal.is_some(),
        "tools open to the network with no credential must be refused"
    );
    let msg = refusal.unwrap();
    assert!(
        msg.contains("public_paths"),
        "the message must name the condition that fired, not a stale one: {msg}"
    );

    // Health alone is fine: it carries no authority.
    let mut probe_only = config("0.0.0.0", true, false);
    probe_only.auth.public_paths = vec!["/health".to_string()];
    assert!(network_bind_refusal(&probe_only).is_none());
}

#[test]
fn a_published_loopback_gateway_still_refuses_open_tools() {
    // The interaction the three changes create together, which none of them
    // has alone. The bind is loopback, so the bind-address check passes.
    // `public_url` is declared, so the origin gate deliberately admits that
    // hostname — that is what it is for. The starter config leaves /mcp
    // public so the local client keeps working. Put together, a proxy or
    // tunnel in front reaches every backend with no credential, while the
    // operator's config says `auth.enabled: true` and reads as protected.
    let mut c = config("127.0.0.1", true, false);
    c.server.public_url = Some("https://gw.example.com".to_string());
    c.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];

    let refusal = network_bind_refusal(&c);
    assert!(
        refusal.is_some(),
        "a gateway published by name must not leave tools open"
    );
    let msg = refusal.unwrap();
    assert!(
        msg.contains("gw.example.com"),
        "and must name the declared host as the exposure, since narrowing \
         the bind would not fix it: {msg}"
    );

    // A loopback public_url is not a publication, so nothing changes.
    let mut local = config("127.0.0.1", true, false);
    local.server.public_url = Some("http://127.0.0.1:39400".to_string());
    local.auth.public_paths = vec!["/health".to_string(), "/mcp".to_string()];
    assert!(
        network_bind_refusal(&local).is_none(),
        "the ordinary local install must still start"
    );

    // And health-only stays fine even when published.
    let mut published_probe = config("127.0.0.1", true, false);
    published_probe.server.public_url = Some("https://gw.example.com".to_string());
    published_probe.auth.public_paths = vec!["/health".to_string()];
    assert!(network_bind_refusal(&published_probe).is_none());
}

#[test]
fn an_unauthenticated_network_bind_is_refused() {
    for host in ["0.0.0.0", "192.168.1.5", "::"] {
        let refusal = network_bind_refusal(&config(host, false, false));
        assert!(refusal.is_some(), "{host} with auth off must be refused");
        let msg = refusal.unwrap();
        assert!(msg.contains("auth.enabled"), "must name the remedy: {msg}");
        assert!(
            msg.contains("authentication is disabled"),
            "must name the condition that fired: {msg}"
        );
        assert!(
            msg.contains("127.0.0.1"),
            "must name the other remedy: {msg}"
        );
    }
}

#[test]
fn a_loopback_bind_serves_without_authentication() {
    for host in ["127.0.0.1", "localhost", "::1"] {
        assert!(
            network_bind_refusal(&config(host, false, false)).is_none(),
            "{host} is the documented default and must keep working"
        );
    }
}

#[test]
fn authentication_or_the_override_permits_a_network_bind() {
    assert!(network_bind_refusal(&config("0.0.0.0", true, false)).is_none());
    assert!(network_bind_refusal(&config("0.0.0.0", false, true)).is_none());
}
