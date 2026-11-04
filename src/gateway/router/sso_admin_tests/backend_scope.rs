// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential scoped to some backends has no gateway-wide admin standing on
//! the MCP surface, whatever role it maps to. An admin API key with
//! `backends: [alpha]` and a role-admin key-server token whose policy scopes
//! it to `alpha` are both refused the admin meta-tools. Unscoped admins (the
//! static bearer, an admin key holding `*`, an admin key with no backends, a
//! role-admin token scoped to every backend) keep them.

use super::*;

const SCOPED_ADMIN_KEY: &str = "e1-scoped-admin-key";
const EMPTY_ADMIN_KEY: &str = "e1-empty-admin-key";

fn key_on(key: &str, admin: bool, backends: &[&str]) -> ApiKeyConfig {
    ApiKeyConfig {
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        ..api_key(key, admin)
    }
}

/// Issuer A's staff policy limited to `alpha`; issuer B's stays unscoped.
fn scoped_policy(issuer: &str) -> KeyServerPolicyConfig {
    let mut policy = staff_policy(issuer);
    policy.scopes.backends = vec!["alpha".to_string()];
    policy
}

/// [`gateway`], with issuer A's tokens scoped to `alpha` and two more admin
/// keys: one scoped to `alpha`, one with no backends.
async fn scoped_gateway(rules: &[&str]) -> Gateway {
    let (a, b) = (Idp::start(ISS_A).await, Idp::start(ISS_B).await);
    let config = KeyServerConfig {
        enabled: true,
        delegated_bearer: true,
        oidc: vec![a.provider(), b.provider()],
        policies: vec![scoped_policy(ISS_A), staff_policy(ISS_B)],
        max_oidc_token_age_secs: 300,
        ..KeyServerConfig::default()
    };
    let key_server = crate::key_server::KeyServer {
        store: Arc::new(crate::key_server::InMemoryTokenStore::new()),
        oidc: Arc::new(OidcVerifier::with_http_client(
            config.oidc.clone(),
            reqwest::Client::new(),
        )),
        policy: Arc::new(crate::key_server::policy::PolicyEngine::new(
            config.policies.clone(),
        )),
        config,
    };
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![
            api_key(STANDARD_KEY, false),
            api_key(ADMIN_KEY, true),
            key_on(SCOPED_ADMIN_KEY, true, &["alpha"]),
            key_on(EMPTY_ADMIN_KEY, true, &[]),
        ],
        ..AuthConfig::default()
    };
    let (state, store) =
        test_router_app_state_with_auth_and_key_server(&auth, Some(Arc::new(key_server))).await;
    set_rules(&state, rules);
    Gateway {
        state,
        _store: store,
        a,
        b,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_scoped_admin_has_no_admin_standing_on_the_mcp_surface() {
    let gw = scoped_gateway(&[
        ADMIN_GROUP_RULE,
        "{ issuer: \"https://idp-b.example\", group: ops-admins, role: admin }",
    ])
    .await;
    let scoped_token = gw.a.token("admin-a", &["ops-admins"], &json!({}));
    let unscoped_token = gw.b.token("admin-b", &["ops-admins"], &json!({}));
    let cells = [
        ("static bearer", BEARER.to_string(), Standing::Admin),
        ("admin key, *", ADMIN_KEY.to_string(), Standing::Admin),
        (
            "admin key, []",
            EMPTY_ADMIN_KEY.to_string(),
            Standing::Admin,
        ),
        ("role-admin token, *", unscoped_token, Standing::Admin),
        ("standard key", STANDARD_KEY.to_string(), Standing::Standard),
        (
            "admin key, [alpha]",
            SCOPED_ADMIN_KEY.to_string(),
            Standing::Standard,
        ),
        (
            "role-admin token, [alpha]",
            scoped_token,
            Standing::Standard,
        ),
    ];
    let mut wrong = Vec::new();
    for (who, bearer, want) in cells {
        let got = standing(&gw.state, &bearer).await;
        if got != want {
            wrong.push(format!("{who}: got {got:?}, want {want:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
