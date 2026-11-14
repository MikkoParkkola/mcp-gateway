// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The status stream within a caller's backend scope: counts of its own
//! backends only, ids that out-of-scope change does not move, and a close
//! when a reload changes the scope. Gateway backends are `alpha` and `beta`;
//! scoped callers reach `[alpha, late]`, so registering `late` is in-scope
//! change and registering `other` is not.

use super::*;

const PLAIN: &str = "u3-scoped-plain-key";
const SADMIN: &str = "u3-scoped-admin-key";
const EMPTY_PLAIN: &str = "u3-empty-plain-key";
const EMPTY_ADMIN: &str = "u3-empty-admin-key";
const GATEWAY_ADMIN: &str = "u3-gateway-admin-key";
const SCOPE: [&str; 2] = ["alpha", "late"];

fn key(secret: &str, backends: &[&str], admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        name: secret.to_string(),
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        admin,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn register(state: &AppState, name: &str) {
    let _ = state
        .backends
        .register(http_backend_at(name, "http://127.0.0.1:9/mcp"));
}

/// The bearer and the four keys, the plain and scoped-admin keys over the
/// lists given.
fn auth(plain: &[&str], admin: &[&str]) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_owned()),
        api_keys: vec![
            key(PLAIN, plain, false),
            key(SADMIN, admin, true),
            key(EMPTY_PLAIN, &[], false),
            key(EMPTY_ADMIN, &[], true),
            key(GATEWAY_ADMIN, &["*"], true),
        ],
        public_paths: vec!["/health".to_owned()],
        ..AuthConfig::default()
    }
}

const ISSUER: &str = "https://issuer.test";
/// One group per control-plane role an identity can hold.
const ROLE_RULES: &str = "rules: [\
    { issuer: \"https://issuer.test\", group: g-admin, role: admin },\
    { issuer: \"https://issuer.test\", group: g-auditor, role: auditor },\
    { issuer: \"https://issuer.test\", group: g-developer, role: developer }]";

/// A key-server token in `group`, scoped to [`SCOPE`].
fn token(group: &str) -> crate::key_server::TemporaryToken {
    use crate::key_server::InMemoryTokenStore;
    let now = crate::clock::unix_secs().expect("the test clock reads");
    crate::key_server::TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: crate::key_server::oidc::VerifiedIdentity::for_test(
            format!("sub-{group}"),
            format!("{group}@issuer.test"),
            None,
            vec![group.to_owned()],
            ISSUER.to_owned(),
        ),
        scopes: crate::key_server::store::TokenScopes {
            backends: SCOPE.iter().map(ToString::to_string).collect(),
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

/// The gateway with `alpha` and `beta`, the four keys, a token per role, and
/// time paused once real I/O is done. Returns the tokens' bearers by group.
async fn gateway() -> (Arc<AppState>, Vec<(&'static str, String)>, impl Sized) {
    let key_server = Arc::new(crate::key_server::KeyServer::new(
        crate::config::KeyServerConfig::default(),
        crate::key_server::email_hash::EmailHashKey::for_test(),
    ));
    let mut bearers = Vec::new();
    for group in ["g-admin", "g-auditor", "g-developer"] {
        let t = token(group);
        bearers.push((group, t.token.clone()));
        crate::key_server::store::activate_for_test(
            key_server.store.as_ref(),
            key_server.config.token_ttl_secs,
            t,
        );
    }
    let auth = auth(&SCOPE, &SCOPE);
    let (state, dir) =
        test_router_app_state_with_auth_and_key_server(&auth, Some(key_server)).await;
    let mut config = (*state.live_config.get()).clone();
    config.control_plane.role_mapping = crate::yaml::from_str(ROLE_RULES).expect("rules parse");
    state.live_config.set(config);
    register(&state, "alpha");
    register(&state, "beta");
    tokio::time::pause();
    (state, bearers, dir)
}

/// Every scoped caller kind: two keys, and an identity per role.
fn scoped_callers(bearers: &[(&'static str, String)]) -> Vec<(String, String)> {
    let mut out = vec![
        ("plain key".to_owned(), PLAIN.to_owned()),
        ("scoped admin key".to_owned(), SADMIN.to_owned()),
    ];
    out.extend(
        bearers
            .iter()
            .map(|(g, b)| (format!("identity {g}"), b.clone())),
    );
    out
}

fn part(frame: &Frame, tag: char) -> u64 {
    frame
        .part(tag)
        .and_then(|p| p.parse().ok())
        .expect("an id part")
}

fn head_part(hello: &Frame, tag: char) -> u64 {
    let head = hello.json()["head"].as_str().unwrap_or_default().to_owned();
    head.split('.')
        .find_map(|p| p.strip_prefix(tag))
        .and_then(|n| n.parse().ok())
        .expect("the head names that part")
}

/// Wait until the watcher has published at least twice since `before`, so a
/// change made before the call is in the snapshot every stream has seen.
async fn watcher_observed(state: &AppState, before: usize) {
    let probe = state.dashboard_bootstrap.stream_hub().probe();
    for _ in 0..200 {
        if probe.observe_calls() >= before + 2 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the watcher did not observe the change");
}

fn observed(state: &AppState) -> usize {
    state
        .dashboard_bootstrap
        .stream_hub()
        .probe()
        .observe_calls()
}

#[tokio::test]
async fn a_scoped_stream_counts_its_own_backends_and_ids_ignore_the_rest() {
    let (state, bearers, _dir) = gateway().await;
    let mut streams = Vec::new();
    for (who, bearer) in scoped_callers(&bearers) {
        let mut s = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
        assert_eq!(s.status, StatusCode::OK, "{who} opens");
        let hello = s.until("hello").await;
        assert_eq!(
            head_part(&hello, 's'),
            0,
            "{who}: hello starts its own count"
        );
        let first = s.until("status").await;
        let body = first.json();
        assert_eq!(body["server_count"], 1, "{who} counts alpha only: {body}");
        assert!(
            body.get("servers").is_none(),
            "{who} gets counts, never the full view"
        );
        assert_eq!(part(&first, 's'), 1, "{who}: its first status frame");
        streams.push((who, s, part(&first, 's')));
    }
    let before = observed(&state);
    register(&state, "other");
    watcher_observed(&state, before).await;
    register(&state, "late");
    for (who, s, prev) in &mut streams {
        let next = s.until("status").await;
        assert_eq!(
            next.json()["server_count"],
            2,
            "{who}: the next status is the in-scope change, none for `other`"
        );
        assert_eq!(part(&next, 's'), *prev + 1, "{who}: one frame, one step");
    }
}

#[tokio::test]
async fn empty_lists_and_unscoped_admins_keep_their_views() {
    let (state, _bearers, _dir) = gateway().await;
    let mut empty = open(&state, request(STREAM, Who::Bearer(EMPTY_PLAIN), None)).await;
    let body = empty.until("status").await.json();
    assert_eq!(
        body["server_count"], 0,
        "an empty list reaches nothing: {body}"
    );
    assert!(body.get("servers").is_none());
    for who in [EMPTY_ADMIN, BEARER] {
        let mut s = open(&state, request(STREAM, Who::Bearer(who), None)).await;
        let body = s.until("status").await.json();
        assert!(
            body.get("servers").is_some(),
            "{who} is a UI-wide admin: {body}"
        );
    }
}

/// Give the key `name` the list `backends`, as a reload of the file would: a
/// whole new auth section, so the generation builds a new key table. The
/// premise is checked, so a setup that changes nothing fails here.
fn set_backends(state: &AppState, name: &str, backends: &[&str]) {
    let (plain, admin) = if name == PLAIN {
        (backends, &SCOPE[..])
    } else {
        (&SCOPE[..], backends)
    };
    state.live_config.edit(|c| c.auth = auth(plain, admin));
    let published = state.live_config.get();
    let key = published
        .auth
        .api_keys
        .iter()
        .find(|k| k.name == name)
        .expect("the reload publishes the key");
    let want: Vec<String> = backends.iter().map(|b| (*b).to_string()).collect();
    assert_eq!(key.backends, want, "the reload set {name}'s list");
}

async fn narrowing_ends_the_stream_and_a_reorder_does_not(who: &str) {
    let (state, _bearers, _dir) = gateway().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(who), None)).await;
    assert_eq!(s.until("status").await.json()["server_count"], 1);
    // The same scope reordered and repeated is no change. `Conn::send` runs
    // `require_entitled` under the current generation before and after it
    // reserves room for a frame, so a status frame delivered after the
    // reorder is the stream judged under it and kept open; no time window is
    // needed.
    set_backends(&state, who, &["late", "alpha", "alpha"]);
    register(&state, "late");
    assert_eq!(
        s.until("status").await.json()["server_count"],
        2,
        "{who}: still open after a reorder"
    );
    set_backends(&state, who, &["alpha"]);
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "{who}: the narrowed scope ended it"
    );
    let mut again = open(&state, request(STREAM, Who::Bearer(who), None)).await;
    let body = again.until("status").await.json();
    assert_eq!(
        body["server_count"], 1,
        "{who} reconnects under the new scope: {body}"
    );
}

#[tokio::test]
async fn a_reload_that_narrows_a_plain_keys_scope_ends_its_stream() {
    narrowing_ends_the_stream_and_a_reorder_does_not(PLAIN).await;
}

#[tokio::test]
async fn a_reload_that_narrows_a_scoped_admin_keys_scope_ends_its_stream() {
    narrowing_ends_the_stream_and_a_reorder_does_not(SADMIN).await;
}

/// A backend removed from the gateway leaves every open scoped count, an
/// identity's included: its token still names the backend, but the count is
/// of registered backends the grant reaches.
#[tokio::test]
async fn a_removed_backend_leaves_an_identity_callers_open_stream() {
    let (state, bearers, _dir) = gateway().await;
    let mut streams = Vec::new();
    for (group, bearer) in &bearers {
        let mut s = open(&state, request(STREAM, Who::Bearer(bearer), None)).await;
        assert_eq!(s.until("status").await.json()["server_count"], 1, "{group}");
        streams.push((group, s));
    }
    assert!(state.backends.remove("alpha"), "alpha was registered");
    for (group, s) in &mut streams {
        let next = s.until("status").await.json();
        assert_eq!(
            next["server_count"], 0,
            "{group}: the open stream dropped alpha"
        );
    }
}

/// Give the gateway-wide admin key `backends` and `admin`, as a reload of the
/// file would, and check the reload published them.
fn set_gateway_admin(state: &AppState, backends: &[&str], admin: bool) {
    state.live_config.edit(|c| {
        c.auth = auth(&SCOPE, &SCOPE);
        let k = c
            .auth
            .api_keys
            .iter_mut()
            .find(|k| k.name == GATEWAY_ADMIN)
            .expect("the fixture configures the key");
        k.backends = backends.iter().map(|b| (*b).to_string()).collect();
        k.admin = admin;
    });
    let published = state.live_config.get();
    let key = published
        .auth
        .api_keys
        .iter()
        .find(|k| k.name == GATEWAY_ADMIN)
        .expect("the reload publishes the key");
    let want: Vec<String> = backends.iter().map(|b| (*b).to_string()).collect();
    assert_eq!(
        (key.backends.clone(), key.admin),
        (want, admin),
        "the reload set the key"
    );
}

/// A gateway-wide admin's stream, opened with the full view, ends when a
/// reload demotes the key: to an admin over one backend, or to no admin at
/// all with every backend kept.
async fn a_demotion_ends_a_gateway_admins_stream(backends: &[&str], admin: bool) {
    let (state, _bearers, _dir) = gateway().await;
    let mut s = open(&state, request(STREAM, Who::Bearer(GATEWAY_ADMIN), None)).await;
    let first = s.until("status").await.json();
    assert!(
        first.get("servers").is_some(),
        "opened with the full view: {first}"
    );
    set_gateway_admin(&state, backends, admin);
    assert!(
        s.ended_within(REVOKED_WITHIN).await,
        "the demoted key's stream ended"
    );
}

#[tokio::test]
async fn narrowing_a_gateway_admin_to_one_backend_ends_its_stream() {
    a_demotion_ends_a_gateway_admins_stream(&["alpha"], true).await;
}

#[tokio::test]
async fn taking_admin_from_a_gateway_admin_ends_its_stream() {
    a_demotion_ends_a_gateway_admins_stream(&["*"], false).await;
}

/// S2: a restart record change reaches the unscoped admin as one status frame
/// carrying it; no scoped caller gets a frame for it (its next status frame is
/// the in-scope change, one step on) or ever carries the member.
#[tokio::test]
async fn s2_a_restart_change_reaches_only_the_full_view() {
    let (state, bearers, _dir) = gateway().await;
    let mut admin = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let first = admin.until("status").await;
    let none = serde_json::Value::Null;
    assert_eq!(first.json().get("restart"), Some(&none), "{}", first.json());
    let mut scoped = Vec::new();
    for (who, bearer) in scoped_callers(&bearers) {
        let mut s = open(&state, request(STREAM, Who::Bearer(&bearer), None)).await;
        let status = s.until("status").await;
        assert!(status.json().get("restart").is_none(), "{who}");
        scoped.push((who, s, part(&status, 's')));
    }
    let before = observed(&state);
    state.meta_mcp.restart_board().accept(1_000);
    let next = admin.until("status").await;
    assert_eq!(
        next.json()["restart"]["phase"],
        "accepted",
        "{}",
        next.json()
    );
    assert_eq!(part(&next, 's'), part(&first, 's') + 1, "one frame");
    watcher_observed(&state, before).await;
    register(&state, "late");
    for (who, s, prev) in &mut scoped {
        let next = s.until("status").await;
        assert_eq!(next.json()["server_count"], 2, "{who}: the in-scope change");
        assert!(next.json().get("restart").is_none(), "{who}");
        assert_eq!(
            part(&next, 's'),
            *prev + 1,
            "{who}: no frame for the restart"
        );
    }
}

/// S3: a commit that changes only the deadline sends the admin one status
/// frame with the new deadline, and no tick-only frames follow: the next
/// status frame is the next real change.
#[tokio::test]
async fn s3_a_deadline_only_commit_sends_the_admin_one_frame() {
    let (state, _bearers, _dir) = gateway().await;
    let board = state.meta_mcp.restart_board();
    board.accept(1_000);
    board.checkpoint();
    let mut admin = open(&state, request(STREAM, Who::Bearer(BEARER), None)).await;
    let first = admin.until("status").await;
    assert_eq!(
        first.json()["restart"]["deadline"],
        1_000,
        "{}",
        first.json()
    );
    board.commit(2_000);
    let next = admin.until("status").await;
    let body = next.json();
    let restart = &body["restart"];
    assert_eq!(
        (&restart["deadline"], &restart["phase"]),
        (&serde_json::json!(2_000), &serde_json::json!("checkpoint")),
        "{restart}"
    );
    assert_eq!(part(&next, 's'), part(&first, 's') + 1, "one frame");
    register(&state, "late");
    let after = admin.until("status").await;
    assert_eq!(after.json()["server_count"], 3, "{}", after.json());
    assert_eq!(
        part(&after, 's'),
        part(&next, 's') + 1,
        "no tick-only frame"
    );
}
