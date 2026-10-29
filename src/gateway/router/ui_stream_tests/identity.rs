// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A stream follows its credential's standing, not the standing it opened with:
//! a role mapping that stops granting admin, and a key-server token revoked.

use super::*;

const ISSUER: &str = "https://issuer.test";
const ADMIN_RULE: &str =
    "rules: [{ issuer: \"https://issuer.test\", group: ops-admins, role: admin }]";

/// A key-server temporary token for a member of `ops-admins`.
fn token(groups: &[&str]) -> crate::key_server::TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    let now = crate::clock::unix_secs().expect("the test clock reads");
    crate::key_server::TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: crate::key_server::oidc::VerifiedIdentity {
            subject: "sub".to_owned(),
            email: "user@issuer.test".to_owned(),
            name: None,
            groups: groups.iter().map(ToString::to_string).collect(),
            issuer: ISSUER.to_owned(),
        },
        scopes: crate::key_server::store::TokenScopes {
            backends: vec!["*".to_owned()],
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

/// Publish `yaml` as `control_plane.role_mapping`, as a reload would.
fn set_mapping(state: &AppState, yaml: &str) {
    let mut config = (*state.live_config.get()).clone();
    config.control_plane.role_mapping = crate::yaml::from_str(yaml).expect("rules parse");
    state.live_config.set(config);
}

/// A gateway whose key server holds `token`, and the role mapping that makes
/// its holder an admin. Time is paused only after the store is built.
async fn gateway(
    token: crate::key_server::TemporaryToken,
) -> (Arc<AppState>, Arc<crate::key_server::KeyServer>, impl Sized) {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
    ));
    key_server.store.insert(token).await;
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_owned()),
        public_paths: vec!["/health".to_owned()],
        ..AuthConfig::default()
    };
    let (state, dir) =
        test_router_app_state_with_auth_and_key_server(&auth, Some(Arc::clone(&key_server))).await;
    set_mapping(&state, ADMIN_RULE);
    tokio::time::pause();
    (state, key_server, dir)
}

#[tokio::test]
async fn a_role_mapping_that_stops_granting_admin_ends_an_admin_stream() {
    let t = token(&["ops-admins"]);
    let bearer = t.token.clone();
    let (state, _ks, _dir) = gateway(t).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
    let hello = s.until("hello").await;
    assert_eq!(
        hello.json()["kinds"],
        serde_json::json!(["status", "reload"])
    );
    s.until("status").await;
    set_mapping(&state, "rules: []");
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "the demoted caller's stream ended"
    );
    // The reconnect derives its kinds afresh: counts only, no `reload`.
    let mut again = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
    assert_eq!(
        again.until("hello").await.json()["kinds"],
        serde_json::json!(["status"])
    );
}

#[tokio::test]
async fn a_revoked_key_server_token_ends_its_stream_within_a_recheck() {
    let t = token(&["ops-admins"]);
    let (bearer, jti) = (t.token.clone(), t.jti.clone());
    let (state, key_server, _dir) = gateway(t).await;
    let mut s = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
    s.until("status").await;
    assert!(key_server.store.revoke_by_jti(&jti).await);
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "the revoked token's stream ended"
    );
    let refused = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}
