// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/signin` at its boundary: the origin rule decides before the body
//! is read, no URL or header carries a key, and the router's own answers
//! (stream error, wrong method, over-limit body, wrong content type) are
//! `no-store` and cookie-free. Fixture and helpers are the parent's.

use super::super::e5_dashboard_session_tests::{redeem, send_to};
use super::super::tests::test_router_app_state_with_auth_and_config;
use super::*;
#[cfg(feature = "metrics")]
use std::collections::VecDeque;
#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicUsize, Ordering};

/// The origin guard's own 403. It sets no `Cache-Control`.
fn assert_origin_guard(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
    assert_eq!(
        reply.json()["error"]["message"].as_str(),
        Some("Origin not allowed"),
        "{}",
        reply.body
    );
    assert_no_cookie(reply);
}

fn url_has_no_secret_query(url: &str) {
    let query = url
        .split_once('?')
        .map_or("", |(_, query)| query.split('#').next().unwrap_or(query));
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        assert!(
            !matches!(name, "bootstrap" | "code" | "key"),
            "{url} carries {name}"
        );
    }
}

#[cfg(feature = "metrics")]
struct Counted {
    polls: Arc<AtomicUsize>,
    items: VecDeque<Result<bytes::Bytes, std::io::Error>>,
}

/// `Body::from_stream` reads by polling (`poll_frame` calls `try_poll_next`).
/// `size_hint` does not poll, so an unread body stays at zero.
#[cfg(feature = "metrics")]
impl futures::Stream for Counted {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        std::task::Poll::Ready(this.items.pop_front())
    }
}

#[cfg(feature = "metrics")]
fn counted(body: &str) -> (Body, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let mut items = VecDeque::new();
    items.push_back(Ok(bytes::Bytes::from(body.to_owned())));
    let stream = Counted {
        polls: Arc::clone(&polls),
        items,
    };
    (Body::from_stream(stream), polls)
}

#[cfg(feature = "metrics")]
fn erroring(body: &str) -> Body {
    let mut items = VecDeque::new();
    items.push_back(Ok(bytes::Bytes::from(body.to_owned())));
    items.push_back(Err(std::io::Error::other("body read failed")));
    Body::from_stream(Counted {
        polls: Arc::new(AtomicUsize::new(0)),
        items,
    })
}

/// A foreign Origin is refused by the origin guard: 403, no cookie, the key
/// not checked. The same POST with this gateway's own Origin reaches the route
/// and mints.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n5_foreign_origin_is_refused_before_the_key_is_checked() {
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    let origin = http_origin(&state, "127.0.0.1");
    let body = format!("key={ADMIN_SECRET}");
    recorded!(read, {
        let (foreign_body, foreign_polls) = counted(&body);
        let before = read();
        let refused = send(
            &state,
            form_post(
                SIGNIN,
                Some("https://evil.example"),
                foreign_body,
                FORM,
                None,
                true,
            ),
        )
        .await;
        let after_refusal = read();
        assert_origin_guard(&refused);
        assert_eq!(foreign_polls.load(Ordering::SeqCst), 0, "the body was read");
        assert_delta(&before, &after_refusal, "invalid_credential", 0.0);
        assert!(
            signin_records(&log).is_empty(),
            "a foreign Origin wrote {:?}",
            signin_records(&log)
        );

        let (own_body, own_polls) = counted(&body);
        let before_mint = read();
        let minted = send(
            &state,
            form_post(SIGNIN, Some(&origin), own_body, FORM, None, true),
        )
        .await;
        let after_mint = read();
        assert_mint(&minted);
        assert!(
            own_polls.load(Ordering::SeqCst) >= 1,
            "the permitted body was not read"
        );
        assert_delta(&before_mint, &after_mint, "invalid_credential", 0.0);
        assert_eq!(signin_records(&log).len(), 1, "{:?}", signin_records(&log));
    });
}

/// `Origin: null` is the guard's 403. An absent Origin is admitted by the
/// guard and refused by the route before the body is read. The permitted
/// Origin beside them mints. Null is not asserted to be 401.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n6_null_origin_and_absent_origin_are_refused_before_the_key_is_checked() {
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    let origin = http_origin(&state, "127.0.0.1");
    let body = format!("key={ADMIN_SECRET}");
    recorded!(read, {
        let (null_body, null_polls) = counted(&body);
        let before_null = read();
        let null_origin = send(
            &state,
            form_post(SIGNIN, Some("null"), null_body, FORM, None, true),
        )
        .await;
        let after_null = read();
        assert_origin_guard(&null_origin);
        assert_eq!(null_polls.load(Ordering::SeqCst), 0, "the body was read");
        assert_delta(&before_null, &after_null, "invalid_credential", 0.0);
        assert!(
            signin_records(&log).is_empty(),
            "{:?}",
            signin_records(&log)
        );

        let (absent_body, absent_polls) = counted(&body);
        let before_absent = read();
        let absent = send(
            &state,
            form_post(SIGNIN, None, absent_body, FORM, None, true),
        )
        .await;
        let after_absent = read();
        assert_route_origin_refusal(&absent);
        assert_eq!(absent_polls.load(Ordering::SeqCst), 0, "the body was read");
        assert_delta(&before_absent, &after_absent, "invalid_credential", 0.0);
        assert!(
            signin_records(&log).is_empty(),
            "{:?}",
            signin_records(&log)
        );

        let (own_body, own_polls) = counted(&body);
        let before_mint = read();
        let minted = send(
            &state,
            form_post(SIGNIN, Some(&origin), own_body, FORM, None, true),
        )
        .await;
        let after_mint = read();
        assert_mint(&minted);
        assert!(own_polls.load(Ordering::SeqCst) >= 1);
        assert_delta(&before_mint, &after_mint, "invalid_credential", 0.0);
        assert_eq!(signin_records(&log).len(), 1, "{:?}", signin_records(&log));
    });
}

/// With `public_url` set, the loopback Origin is admitted by the guard and
/// refused by the route. `https://gw.example` mints, with `Secure`.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n6b_loopback_origin_is_refused_when_a_public_url_is_set() {
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    reload(&state, |config| {
        config.server.public_url = Some("https://gw.example".to_string());
    });
    let loopback = http_origin(&state, "127.0.0.1");
    let body = format!("key={ADMIN_SECRET}");
    recorded!(read, {
        let (refused_body, refused_polls) = counted(&body);
        let before = read();
        let refused = send(
            &state,
            form_post(SIGNIN, Some(&loopback), refused_body, FORM, None, true),
        )
        .await;
        let after_refusal = read();
        assert_route_origin_refusal(&refused);
        assert_eq!(refused_polls.load(Ordering::SeqCst), 0, "the body was read");
        assert_delta(&before, &after_refusal, "invalid_credential", 0.0);
        assert!(
            signin_records(&log).is_empty(),
            "{:?}",
            signin_records(&log)
        );

        let (mint_body, mint_polls) = counted(&body);
        let before_mint = read();
        let minted = send(
            &state,
            form_post(
                SIGNIN,
                Some("https://gw.example"),
                mint_body,
                FORM,
                None,
                true,
            ),
        )
        .await;
        let after_mint = read();
        assert_mint(&minted);
        assert_cookie_flags(&minted.set_cookie(), true);
        assert!(mint_polls.load(Ordering::SeqCst) >= 1);
        assert_delta(&before_mint, &after_mint, "invalid_credential", 0.0);
        assert_eq!(signin_records(&log).len(), 1, "{:?}", signin_records(&log));
    });
}

/// An unparseable `public_url` names no origin, so the route admits none. The
/// guard reads such a value as unset and still admits a loopback Origin, so
/// the refusal is the route's own (401, not the guard's 403) and the body is
/// never read. With no `public_url` the same Origin mints (N6c).
#[cfg(feature = "metrics")]
#[tokio::test]
async fn n6d_an_unparseable_public_url_admits_no_signin_origin() {
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    reload(&state, |config| {
        config.server.public_url = Some("not a url".to_string());
    });
    let loopback = http_origin(&state, "127.0.0.1");
    let (body, polls) = counted(&format!("key={ADMIN_SECRET}"));
    let refused = send(
        &state,
        form_post(SIGNIN, Some(&loopback), body, FORM, None, true),
    )
    .await;
    assert_route_origin_refusal(&refused);
    assert_eq!(polls.load(Ordering::SeqCst), 0, "the body was read");
    assert!(
        signin_records(&log).is_empty(),
        "{:?}",
        signin_records(&log)
    );
}

/// On a network bind with no `public_url`, the guard admits a numeric Origin
/// that names the request's own address (the page this gateway served there).
/// The route admits only the public origin or a loopback origin, so it refuses
/// that one with its own 401 (not the guard's 403) and never reads the body.
#[cfg(feature = "metrics")]
#[tokio::test]
async fn n6e_a_numeric_self_origin_on_a_network_bind_is_refused() {
    let mut config = crate::config::Config::default();
    // TEST-NET-1: a network address, neither loopback nor a wildcard.
    config.server.host = "192.0.2.10".to_string();
    let (mut state, _dir) =
        test_router_app_state_with_auth_and_config(&auth_with(fixture_keys()), config).await;
    assert_eq!(
        state.live_config.running().server.host,
        "192.0.2.10",
        "premise: the running bind"
    );
    let (log, _audit_dir) = with_audit(&mut state);
    let authority = format!("192.0.2.10:{}", listener_port(&state));
    let origin = format!("http://{authority}");
    let (body, polls) = counted(&format!("key={ADMIN_SECRET}"));
    let mut request = form_post(SIGNIN, Some(&origin), body, FORM, None, true);
    request.headers_mut().insert(
        header::HOST,
        authority.parse().expect("a host header value"),
    );
    let refused = send(&state, request).await;
    assert_route_origin_refusal(&refused);
    assert_eq!(polls.load(Ordering::SeqCst), 0, "the body was read");
    assert!(
        signin_records(&log).is_empty(),
        "{:?}",
        signin_records(&log)
    );
}

/// A wildcard bind serves loopback too. With no `public_url`, the gateway's
/// own loopback page posts with its numeric loopback Origin, which the guard
/// admits on a non-loopback bind; the route admits it and mints, on `0.0.0.0`,
/// on `::` and on an empty host (every interface).
#[tokio::test]
async fn n6f_a_wildcard_bind_admits_its_own_loopback_page() {
    for bind in ["0.0.0.0", "::", ""] {
        let mut config = crate::config::Config::default();
        config.server.host = bind.to_string();
        let (mut state, _dir) =
            test_router_app_state_with_auth_and_config(&auth_with(fixture_keys()), config).await;
        assert_eq!(
            state.live_config.running().server.host,
            bind,
            "premise: the running bind"
        );
        let (log, _audit_dir) = with_audit(&mut state);
        let authority = format!("127.0.0.1:{}", listener_port(&state));
        let mut request = form_post(
            SIGNIN,
            Some(&format!("http://{authority}")),
            Body::from(format!("key={ADMIN_SECRET}")),
            FORM,
            None,
            true,
        );
        request.headers_mut().insert(
            header::HOST,
            authority.parse().expect("a host header value"),
        );
        let minted = send(&state, request).await;
        assert_eq!(
            minted.status,
            StatusCode::SEE_OTHER,
            "{bind}: {}",
            minted.body
        );
        assert_mint(&minted);
        assert_eq!(
            signin_records(&log).len(),
            1,
            "{bind}: {:?}",
            signin_records(&log)
        );
    }
}

/// Host, port and TLS are restart-only. A reload that changes one leaves the
/// listener as it was, and the page it serves posts from the running origin.
/// Through a router built before the reload, as in production, that origin
/// still mints, for each of the three changed alone: the port, the host (to a
/// network address, which would admit no loopback origin) and TLS (which would
/// expect `https`).
#[tokio::test]
async fn n6g_a_reloaded_listener_setting_does_not_refuse_the_running_origin() {
    type Edit = fn(&mut crate::config::Config);
    let cases: [(&str, Edit); 3] = [
        ("port", |config| config.server.port += 1),
        ("host", |config| {
            config.server.host = "192.0.2.10".to_string();
        }),
        ("tls", |config| config.mtls.enabled = true),
    ];
    for (name, edit) in cases {
        let (mut state, _dir) = fixture().await;
        let (log, _audit_dir) = with_audit(&mut state);
        let running = format!("http://127.0.0.1:{}", listener_port(&state));
        let router = super::super::create_router(Arc::clone(&state));
        let before = state.live_config.running().clone();
        reload(&state, edit);
        let after = state.live_config.running();
        assert_eq!(
            (&after.server.host, after.server.port, after.mtls.enabled),
            (&before.server.host, before.server.port, before.mtls.enabled),
            "{name}: premise: the listener keeps its settings until a restart"
        );
        let minted = send_to(
            router,
            form_post(
                SIGNIN,
                Some(&running),
                Body::from(format!("key={ADMIN_SECRET}")),
                FORM,
                None,
                true,
            ),
        )
        .await;
        assert_eq!(
            minted.status,
            StatusCode::SEE_OTHER,
            "{name}: {}",
            minted.body
        );
        assert_mint(&minted);
        assert_eq!(
            signin_records(&log).len(),
            1,
            "{name}: {:?}",
            signin_records(&log)
        );
    }
}

/// `public_url` is read live. Through a router built before a reload that
/// sets it, the loopback origin the route admitted is now the route's refusal
/// (401) and the public origin mints.
#[tokio::test]
async fn n6h_a_reloaded_public_url_applies_at_once() {
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    let loopback = http_origin(&state, "127.0.0.1");
    let router = super::super::create_router(Arc::clone(&state));
    reload(&state, |config| {
        config.server.public_url = Some("https://gw.example".to_string());
    });
    let post = |origin: &str| {
        form_post(
            SIGNIN,
            Some(origin),
            Body::from(format!("key={ADMIN_SECRET}")),
            FORM,
            None,
            true,
        )
    };
    let refused = send_to(router.clone(), post(&loopback)).await;
    assert_route_origin_refusal(&refused);
    assert!(
        signin_records(&log).is_empty(),
        "{:?}",
        signin_records(&log)
    );
    let minted = send_to(router, post("https://gw.example")).await;
    assert_mint(&minted);
    assert_eq!(signin_records(&log).len(), 1, "{:?}", signin_records(&log));
}

/// `http://127.0.0.2` and `https://gw.example:8443` are the guard's 403s.
/// The loopback spellings the guard admits mint on a gateway
/// with no public URL, and `https://gw.example` mints when `public_url`
/// spells port 443.
#[tokio::test]
async fn n6c_loopback_spellings_and_the_default_port() {
    let (plain, _plain_dir) = fixture().await;
    let other = send(
        &plain,
        post_signin(
            Some(&http_origin(&plain, "127.0.0.2")),
            &format!("key={ADMIN_SECRET}"),
            None,
            true,
        ),
    )
    .await;
    assert_origin_guard(&other);

    let (published, _published_dir) = fixture().await;
    reload(&published, |config| {
        config.server.public_url = Some("https://gw.example:443".to_string());
    });
    let wrong_port = send(
        &published,
        post_signin(
            Some("https://gw.example:8443"),
            &format!("key={ADMIN_SECRET}"),
            None,
            true,
        ),
    )
    .await;
    assert_origin_guard(&wrong_port);

    let localhost = send(
        &plain,
        post_signin(
            Some(&http_origin(&plain, "localhost")),
            &format!("key={ADMIN_SECRET}"),
            None,
            true,
        ),
    )
    .await;
    assert_mint(&localhost);
    assert_cookie_flags(&localhost.set_cookie(), false);

    let v4 = send(
        &plain,
        post_signin(
            Some(&http_origin(&plain, "127.0.0.1")),
            &format!("key={ADMIN_SECRET}"),
            None,
            true,
        ),
    )
    .await;
    assert_mint(&v4);
    assert_cookie_flags(&v4.set_cookie(), false);

    let named = send(
        &published,
        post_signin(
            Some("https://gw.example"),
            &format!("key={ADMIN_SECRET}"),
            None,
            true,
        ),
    )
    .await;
    assert_mint(&named);
    assert_cookie_flags(&named.set_cookie(), true);
}

/// The bootstrap redirect carries no secret: the link answers 303 to
/// `/dashboard`, that Location holds neither the sentinel nor a secret-named
/// query, and following it with the session it set opens the dashboard page
/// (200), which carries no sentinel.
#[tokio::test]
async fn n9_the_bootstrap_redirect_carries_no_secret() {
    let (state, _dir) = fixture().await;
    let sentinel = state.dashboard_bootstrap.peek().expect("startup value");
    let redirected = send(&state, redeem(&sentinel, None)).await;
    assert_eq!(
        redirected.status,
        StatusCode::SEE_OTHER,
        "{}",
        redirected.body
    );
    let location = redirected.header(header::LOCATION).unwrap_or_default();
    assert_eq!(location, DASHBOARD);
    assert!(!location.contains(&sentinel), "{location}");
    url_has_no_secret_query(&location);
    // Followed with the session the redemption set, as a browser does.
    let handle = session_handle(&redirected);
    let followed = send(&state, get(&location, Some(&handle))).await;
    assert_eq!(followed.status, StatusCode::OK, "{}", followed.body);
    assert!(
        !followed.body.contains(&sentinel),
        "the dashboard page carries the sentinel"
    );
    assert!(followed.header(header::LOCATION).is_none());
}

/// The shell document answers `Referrer-Policy: same-origin`; the handoff
/// form keeps `same-origin` and its POST keeps `no-referrer`.
#[tokio::test]
async fn n11a_the_shell_document_answers_referrer_policy_same_origin() {
    let (state, _dir) = fixture().await;
    let form = send(&state, get("/dashboard/handoff", None)).await;
    assert_eq!(
        form.header(header::REFERRER_POLICY).as_deref(),
        Some("same-origin")
    );
    let posted = send(
        &state,
        form_post(
            "/dashboard/handoff",
            None,
            Body::from("code=not-a-code"),
            FORM,
            None,
            false,
        ),
    )
    .await;
    assert_eq!(
        posted.header(header::REFERRER_POLICY).as_deref(),
        Some("no-referrer")
    );
    let shell = send(&state, get("/ui/overview/status", None)).await;
    assert_eq!(
        shell.header(header::REFERRER_POLICY).as_deref(),
        Some("same-origin")
    );
}

/// A body that errors mid-read is 400, sets no cookie, and does not check
/// the key.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n_router_body_stream_error_is_400() {
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    let origin = http_origin(&state, "127.0.0.1");
    recorded!(read, {
        let before = read();
        let reply = send(
            &state,
            form_post(
                SIGNIN,
                Some(&origin),
                erroring(&format!("key={ADMIN_SECRET}")),
                FORM,
                None,
                false,
            ),
        )
        .await;
        let after = read();
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert_no_cookie(&reply);
        assert_no_store(&reply);
        assert_delta(&before, &after, "invalid_credential", 0.0);
        assert!(
            signin_records(&log).is_empty(),
            "{:?}",
            signin_records(&log)
        );
    });
}

/// GET is not this route: 405, no-store, no cookie. Origin is omitted so the
/// guard does not answer first.
#[tokio::test]
async fn n_router_get_is_405() {
    let (state, _dir) = fixture().await;
    let reply = send(&state, get(SIGNIN, None)).await;
    assert_eq!(
        reply.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "{}",
        reply.body
    );
    assert_no_store(&reply);
    assert_no_cookie(&reply);
}

/// A body over the router's limit is 413, no-store, no cookie. The limit is
/// 32 and the body is 64, on a permitted Origin so the guard does not answer
/// first.
#[tokio::test]
async fn n_router_over_limit_body_is_413() {
    let (state, _dir) = fixture().await;
    reload(&state, |config| config.server.max_body_size = 32);
    let origin = http_origin(&state, "127.0.0.1");
    let reply = send(
        &state,
        post_signin(Some(&origin), &"x".repeat(64), None, false),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        reply.body
    );
    assert_no_store(&reply);
    assert_no_cookie(&reply);
}

/// A body that is not a form is 415, no-store, no cookie.
#[tokio::test]
async fn n_router_wrong_content_type_is_415() {
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let reply = send(
        &state,
        form_post(
            SIGNIN,
            Some(&origin),
            Body::from(format!("key={ADMIN_SECRET}")),
            "text/plain",
            None,
            false,
        ),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "{}",
        reply.body
    );
    assert_no_store(&reply);
    assert_no_cookie(&reply);
}

/// N3e: the sign-in reads Gateway admin standing. An admin key scoped to one
/// backend (`InScope` standing) is refused exactly as a standard key is; the
/// same key at every backend (`Gateway`) mints. The two posts differ only in
/// the key's backends, and each key is first shown to resolve with the
/// standing named, so the admin check is the rule that decides.
#[tokio::test]
async fn n3e_an_admin_key_scoped_to_one_backend_is_refused() {
    use crate::gateway::authz::AdminStanding;
    const SCOPED_NAME: &str = "n3e-scoped-admin";
    const SCOPED_SECRET: &str = "n3e-scoped-admin-key";
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let post = || post_signin(Some(&origin), &format!("key={SCOPED_SECRET}"), None, true);
    let standing = |state: &AppState| {
        let generation = state.live_config.generation();
        generation
            .auth()
            .validate_token(SCOPED_SECRET)
            .expect("the scoped admin key resolves")
            .admin_standing()
    };
    let mut scoped = named_key(SCOPED_NAME, SCOPED_SECRET, true);
    scoped.backends = vec!["alpha".to_string()];
    reload_keys(&state, vec![scoped]);
    assert_eq!(standing(&state), AdminStanding::InScope, "premise");
    let refused = send(&state, post()).await;
    assert_eq!(refused.status, StatusCode::SEE_OTHER, "{}", refused.body);
    assert_eq!(refused.header(header::LOCATION).as_deref(), Some(REFUSED));
    assert_no_cookie(&refused);
    assert_no_store(&refused);

    reload_keys(&state, vec![named_key(SCOPED_NAME, SCOPED_SECRET, true)]);
    assert_eq!(standing(&state), AdminStanding::Gateway, "premise");
    assert_mint(&send(&state, post()).await);
}
