// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2130: sign-in by link behind a same-host TLS-terminating proxy. The link
//! is redeemed at the loopback URL, as before; the session cookie is set on the
//! public origin by a one-time handoff that arrives through the proxy.

use super::*;

const PUBLIC: &str = "https://gw.example";
const HANDOFF_PREFIX: &str = "https://gw.example/dashboard?handoff=";

/// An HTTPS `public_url` in front of this plain-HTTP loopback listener.
async fn behind_https_front() -> (Arc<AppState>, tempfile::TempDir) {
    let (state, dir) = fixture().await;
    reload(&state, |c| c.server.public_url = Some(PUBLIC.to_string()));
    (state, dir)
}

/// `uri` as a same-host proxy forwards it: loopback peer, public `Host`, and
/// the forwarding headers every convention-following proxy adds.
fn forwarded(uri: &str) -> Request<Body> {
    let mut request = get(uri, None);
    let headers = request.headers_mut();
    headers.insert(header::HOST, "gw.example".parse().unwrap());
    headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
    headers.insert("x-forwarded-proto", "https".parse().unwrap());
    headers.insert("x-forwarded-host", "gw.example".parse().unwrap());
    request
}

fn location(reply: &Reply) -> String {
    reply
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn no_referrer(reply: &Reply) -> bool {
    reply
        .headers
        .get("referrer-policy")
        .is_some_and(|v| v == "no-referrer")
}

/// Redeem the startup link at the loopback URL and return the handoff value.
async fn hand_off(state: &Arc<AppState>) -> String {
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(state, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    location(&out)
        .strip_prefix(HANDOFF_PREFIX)
        .unwrap_or_else(|| panic!("a handoff to the public origin: {}", location(&out)))
        .to_string()
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

/// The loopback redemption spends the link and hands off to the public origin
/// without setting a cookie a browser would scope to the loopback host.
#[tokio::test]
async fn a_loopback_redemption_hands_off_to_the_public_origin() {
    let (state, _dir) = behind_https_front().await;
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, None)).await;

    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    let target = location(&out);
    let handoff = target.strip_prefix(HANDOFF_PREFIX).unwrap_or_default();
    assert!(handoff.len() >= 22, "a 128-bit or longer handoff: {target}");
    assert!(out.set_cookie().is_empty(), "{}", out.set_cookie());
    assert!(no_referrer(&out), "{:?}", out.headers);
    assert_eq!(state.dashboard_bootstrap.peek(), None, "the link is spent");
}

/// The handoff, arriving through the proxy, sets a Secure session cookie and
/// sends the browser on to a clean `/dashboard`; the session is an admin one.
#[tokio::test]
async fn the_handoff_signs_in_through_the_proxy() {
    let (state, _dir) = behind_https_front().await;
    let handoff = hand_off(&state).await;

    let out = send(&state, forwarded(&format!("/dashboard?handoff={handoff}"))).await;

    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(location(&out), "/dashboard");
    assert!(no_referrer(&out), "{:?}", out.headers);
    assert!(out.set_cookie().contains("Secure"), "{}", out.set_cookie());
    let handle = session_handle(&out);
    assert!(is_admin_view(
        &send(&state, get(STATUS, Some(&handle))).await
    ));
    for (name, value) in &out.headers {
        let value = value.to_str().unwrap_or_default();
        assert!(
            !value.contains(&handoff),
            "{name} echoes the handoff: {value}"
        );
    }
    assert!(!out.body.contains(&handoff), "{}", out.body);
}

/// A handoff is single use, and a wrong value neither signs in nor spends the
/// live one.
#[tokio::test]
async fn a_handoff_is_single_use_and_a_wrong_one_spends_nothing() {
    let (state, _dir) = behind_https_front().await;
    let handoff = hand_off(&state).await;

    let wrong = send(
        &state,
        forwarded("/dashboard?handoff=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{}", wrong.body);
    assert!(wrong.set_cookie().is_empty(), "{}", wrong.set_cookie());

    let first = send(&state, forwarded(&format!("/dashboard?handoff={handoff}"))).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.body);

    let again = send(&state, forwarded(&format!("/dashboard?handoff={handoff}"))).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{}", again.body);
    assert!(again.set_cookie().is_empty(), "{}", again.set_cookie());
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
