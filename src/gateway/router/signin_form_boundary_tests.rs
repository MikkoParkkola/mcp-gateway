// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/signin` at its boundary: the origin rule decides before the body
//! is read, no URL or header carries a key, and the router's own answers
//! (stream error, wrong method, over-limit body, wrong content type) are
//! `no-store` and cookie-free. Fixture and helpers are the parent's.

use super::super::e5_dashboard_session_tests::redeem;
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

fn assert_html(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let content_type = reply.header(header::CONTENT_TYPE).unwrap_or_default();
    assert!(
        content_type.starts_with("text/html"),
        "content-type {content_type}"
    );
}

/// The shell's pages and tabs, as request paths. Literals, not read from the
/// document the route serves.
fn shell_urls() -> Vec<String> {
    let pages = [
        "overview", "todo", "servers", "tools", "activity", "costs", "access", "policies",
        "gateway",
    ];
    let tabs = ["status", "actions", "settings"];
    let mut urls = vec!["/ui".to_string(), "/ui/classic".to_string()];
    for page in pages {
        urls.push(format!("/ui/{page}"));
        for tab in tabs {
            urls.push(format!("/ui/{page}/{tab}"));
        }
    }
    urls
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

/// A foreign Origin is refused by the origin guard, which is green today
/// (the regression half): 403, no cookie, the key not checked. The same POST
/// with this gateway's own Origin is the route, and it fails while the route
/// answers 501.
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

/// `Origin: null` is the guard's 403, green today. An absent Origin is
/// admitted by the guard and refused by the route before the body is read,
/// which fails while the route answers 501. The permitted Origin beside them
/// mints. Null is not asserted to be 401.
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

/// `http://127.0.0.2` and `https://gw.example:8443` are the guard's 403s,
/// green today. The loopback spellings the guard admits mint on a gateway
/// with no public URL, and `https://gw.example` mints when `public_url`
/// spells port 443. The first mint fails while the route answers 501.
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

/// Green today. The bootstrap redirect is the named regression: the link
/// answers 303 to `/dashboard` and that Location does not carry the sentinel.
/// Shell pages render as HTML at URLs with no secret query. This row does
/// not POST `/ui/signin`.
#[tokio::test]
async fn n9_shell_urls_and_the_bootstrap_redirect_carry_no_secret() {
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
    let followed = send(&state, get(&location, None)).await;
    if let Some(again) = followed.header(header::LOCATION) {
        assert!(!again.contains(&sentinel), "{again}");
        url_has_no_secret_query(&again);
    }
    for target in [DASHBOARD, REFUSED] {
        url_has_no_secret_query(target);
    }
    for url in shell_urls() {
        url_has_no_secret_query(&url);
        assert_html(&send(&state, get(&url, None)).await);
    }
}

/// The handoff form's `same-origin` and its POST's `no-referrer` are green
/// today (the regression half). The shell document still answers
/// `no-referrer`, so the literal `same-origin` fails.
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
/// the key. The status fails while the route answers 501.
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
/// first. The status fails while the route answers 501.
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
