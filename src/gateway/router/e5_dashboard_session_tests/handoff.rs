// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2130: sign-in by link behind a same-host TLS-terminating proxy. The link
//! is redeemed at the loopback URL, as before; that page shows a one-time code
//! the operator enters in a same-origin form on the public origin, which sets
//! the session cookie there. The code never travels in a URL.

use super::*;

const PUBLIC: &str = "https://gw.example";
const HANDOFF: &str = "/dashboard/handoff";

/// An HTTPS `public_url` in front of this plain-HTTP loopback listener.
async fn behind_https_front() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, dir) = fixture().await;
    reload(&state, |c| c.server.public_url = Some(PUBLIC.to_string()));
    (state, dir)
}

/// A browser request on the public origin as a same-host proxy forwards it:
/// loopback peer, public `Host`, forwarding headers, and the fetch metadata a
/// browser sends for `site`.
fn through_proxy(method: &str, body: &str, site: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(HANDOFF)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))))
        .header(header::HOST, "gw.example")
        .header("x-forwarded-for", "203.0.113.9")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "gw.example")
        .header("sec-fetch-site", site);
    if method == "POST" {
        let origin = if site == "same-origin" {
            PUBLIC
        } else {
            "https://evil.example"
        };
        builder = builder
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    if let Some(handle) = cookie {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    builder
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn submit(code: &str, cookie: Option<&str>) -> Request<Body> {
    through_proxy("POST", &format!("code={code}"), "same-origin", cookie)
}

fn header_is(reply: &Reply, name: &str, value: &str) -> bool {
    reply.headers.get(name).is_some_and(|v| v == value)
}

/// Neither caching nor a `Referer` may carry anything from these pages.
fn assert_private(reply: &Reply) {
    assert!(
        header_is(reply, "cache-control", "no-store"),
        "{:?}",
        reply.headers
    );
    assert!(
        header_is(reply, "referrer-policy", "no-referrer"),
        "{:?}",
        reply.headers
    );
}

fn location(reply: &Reply) -> String {
    reply
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Redeem the startup link at the loopback URL and return the code it shows.
async fn code_from_link(state: &Arc<AppState>) -> (Reply, String) {
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(state, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    let code = out
        .body
        .split_once(r#"<code id="handoff">"#)
        .and_then(|(_, rest)| rest.split_once("</code>"))
        .map_or_else(
            || panic!("a code on the page: {}", out.body),
            |(code, _)| code.to_string(),
        );
    (out, code)
}

fn session_handle(reply: &Reply) -> String {
    reply
        .set_cookie()
        .split(';')
        .next()
        .and_then(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .expect("a session cookie")
        .to_string()
}

/// The loopback redemption spends the link, shows a code and where to enter
/// it, and sets no cookie a browser would scope to the loopback host.
#[tokio::test]
async fn a_loopback_redemption_shows_a_code_for_the_public_origin() {
    let (state, _dir) = behind_https_front().await;
    let (out, code) = code_from_link(&state).await;

    assert!(code.len() >= 22, "a 128-bit or longer code: {code}");
    assert!(
        out.body.contains("https://gw.example/dashboard/handoff"),
        "{}",
        out.body
    );
    assert!(out.set_cookie().is_empty(), "{}", out.set_cookie());
    assert_private(&out);
    assert_eq!(state.dashboard_bootstrap.peek(), None, "the link is spent");
}

/// The form on the public origin holds nothing and is served to anyone.
#[tokio::test]
async fn the_code_form_is_served_on_the_public_origin() {
    let (state, _dir) = behind_https_front().await;
    let out = send(&state, through_proxy("GET", "", "none", None)).await;

    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    assert!(
        out.body.contains(r#"action="/dashboard/handoff""#),
        "{}",
        out.body
    );
    assert!(out.body.contains(r#"name="code""#), "{}", out.body);
    assert_private(&out);
}

/// The code, posted through the proxy, sets a Secure session cookie and sends
/// the browser on to `/dashboard`; the session is an admin one, and nothing
/// in the reply repeats the code.
#[tokio::test]
async fn the_code_signs_in_through_the_proxy() {
    let (state, _dir) = behind_https_front().await;
    let (_, code) = code_from_link(&state).await;

    let out = send(&state, submit(&code, None)).await;

    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(location(&out), "/dashboard");
    assert_private(&out);
    assert!(out.set_cookie().contains("Secure"), "{}", out.set_cookie());
    let handle = session_handle(&out);
    assert!(is_admin_view(
        &send(&state, get(STATUS, Some(&handle))).await
    ));
    for (name, value) in &out.headers {
        let value = value.to_str().unwrap_or_default();
        assert!(!value.contains(&code), "{name} repeats the code: {value}");
    }
    assert!(!out.body.contains(&code), "{}", out.body);
}

/// A code is single use, and a wrong one neither signs in nor spends the
/// live one.
#[tokio::test]
async fn a_code_is_single_use_and_a_wrong_one_spends_nothing() {
    let (state, _dir) = behind_https_front().await;
    let (_, code) = code_from_link(&state).await;

    let wrong = send(&state, submit(&"A".repeat(code.len()), None)).await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.body);
    assert!(wrong.set_cookie().is_empty(), "{}", wrong.set_cookie());
    assert_private(&wrong);

    let first = send(&state, submit(&code, None)).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.body);

    let again = send(&state, submit(&code, None)).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{}", again.body);
    assert!(again.set_cookie().is_empty(), "{}", again.set_cookie());
}

/// A browser already holding a session cookie, live or dead, still signs in
/// with the code: the exchange runs before the cookie is judged.
#[tokio::test]
async fn a_code_signs_in_past_a_live_or_dead_cookie() {
    for dead in [false, true] {
        let (state, _dir) = behind_https_front().await;
        let held = issue(&state);
        if dead {
            age(&state, &held, IDLE + MIN);
        }
        let (_, code) = code_from_link(&state).await;

        let out = send(&state, submit(&code, Some(&held))).await;

        assert_eq!(
            out.status,
            StatusCode::SEE_OTHER,
            "dead={dead}: {}",
            out.body
        );
        assert_ne!(session_handle(&out), held, "dead={dead}: a fresh session");
    }
}

/// A cross-site post is refused by the origin gate and spends nothing.
#[tokio::test]
async fn a_cross_site_post_of_the_code_is_refused() {
    let (state, _dir) = behind_https_front().await;
    let (_, code) = code_from_link(&state).await;

    let forged = through_proxy("POST", &format!("code={code}"), "cross-site", None);
    let out = send(&state, forged).await;
    assert_eq!(out.status, StatusCode::FORBIDDEN, "{}", out.body);

    let real = send(&state, submit(&code, None)).await;
    assert_eq!(real.status, StatusCode::SEE_OTHER, "{}", real.body);
}

/// A link can be minted in this shape: its redemption now works.
#[tokio::test]
async fn a_link_is_minted_behind_an_https_front() {
    let (state, _dir) = behind_https_front().await;
    let out = send(&state, request("POST", LINK, None, Some(ADMIN_KEY), false)).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    assert!(
        out.json()["link"]
            .as_str()
            .is_some_and(|l| l.contains("bootstrap=")),
        "{}",
        out.body
    );
}

/// A code older than a minute is refused.
#[tokio::test]
async fn a_code_expires_after_a_minute() {
    let (state, _dir) = behind_https_front().await;
    let (_, code) = code_from_link(&state).await;
    state
        .dashboard_bootstrap
        .backdate_handoff(Duration::from_secs(61));

    let out = send(&state, submit(&code, None)).await;
    assert_eq!(out.status, StatusCode::UNAUTHORIZED, "{}", out.body);
    assert!(out.set_cookie().is_empty(), "{}", out.set_cookie());
}

/// A code whose minting credential expired between the two steps is refused
/// rather than turned into a session that is already dead.
#[tokio::test]
async fn a_code_past_its_credential_cap_is_refused() {
    let (state, _dir) = behind_https_front().await;
    let past = std::time::SystemTime::now() - Duration::from_secs(1);
    let code = state
        .dashboard_bootstrap
        .mint_handoff(crate::gateway::auth::Now::read(), Some(past));

    let out = send(&state, submit(&code, None)).await;
    assert_eq!(out.status, StatusCode::UNAUTHORIZED, "{}", out.body);
    assert!(out.set_cookie().is_empty(), "{}", out.set_cookie());
}
