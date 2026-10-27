// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A browser whose sign-in link or code is refused lands
//! back in the shell, at one fixed address with one fixed hint word, so it
//! sees the refusal in plain words. Anything that is not a browser
//! navigation keeps today's 401.

use super::*;

const TARGET: &str = "/ui/overview/status?signin=link-refused";

/// A link redemption, from this machine, as `kind` sends it.
fn link(value: &str, kind: Fetch) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/dashboard?bootstrap={value}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))));
    for (name, value) in kind.headers() {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).expect("request builds")
}

/// The Fetch Metadata a request carries.
#[derive(Clone, Copy)]
enum Fetch {
    /// A top-level browser navigation.
    Navigate,
    /// No metadata: curl, a script, an old browser.
    None,
    /// One header missing or with another value.
    Partial(&'static [(&'static str, &'static str)]),
}

impl Fetch {
    fn headers(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Fetch::Navigate => &[
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
            ],
            Fetch::None => &[],
            Fetch::Partial(headers) => headers,
        }
    }
}

fn location(reply: &Reply) -> Option<&str> {
    reply
        .headers
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
}

/// R1: a browser presenting a wrong link goes to the fixed shell address,
/// with no cookie and the private headers.
#[tokio::test]
async fn r1_a_refused_link_sends_a_browser_to_the_shell() {
    let (state, _dir) = fixture().await;
    let out = send(&state, link("not-the-value", Fetch::Navigate)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(location(&out), Some(TARGET));
    assert!(out.set_cookie().is_empty(), "{}", out.set_cookie());
    assert_eq!(
        out.headers
            .get(header::CACHE_CONTROL)
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"no-store"[..])
    );
    assert_eq!(
        out.headers
            .get(header::REFERRER_POLICY)
            .map(axum::http::HeaderValue::as_bytes),
        Some(&b"no-referrer"[..])
    );
}

/// R2: anything that is not a browser navigation keeps today's 401 body.
#[tokio::test]
async fn r2_a_refused_link_without_fetch_metadata_keeps_the_401() {
    let (state, _dir) = fixture().await;
    let out = send(&state, link("not-the-value", Fetch::None)).await;
    assert_eq!(out.status, StatusCode::UNAUTHORIZED);
    assert!(
        out.body.contains("Bootstrap link is invalid or already used. Run `mcp-gateway dashboard-link` for a fresh one."),
        "{}",
        out.body
    );
    assert_eq!(location(&out), None);
}

/// R3: a used link and a wrong one look the same to a browser.
#[tokio::test]
async fn r3_a_used_and_a_wrong_link_are_byte_identical() {
    let (state, _dir) = fixture().await;
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let first = send(&state, link(&value, Fetch::None)).await;
    assert_eq!(
        first.status,
        StatusCode::SEE_OTHER,
        "spends the live link: {}",
        first.body
    );
    let used = send(&state, link(&value, Fetch::Navigate)).await;
    let wrong = send(&state, link("not-the-value", Fetch::Navigate)).await;
    assert_eq!(
        (used.status, &used.headers, &used.body),
        (wrong.status, &wrong.headers, &wrong.body)
    );
}

/// R6: nothing in the request moves the target.
#[tokio::test]
async fn r6_the_target_is_fixed_whatever_the_request_says() {
    let (state, _dir) = fixture().await;
    let request = Request::builder()
        .method("GET")
        .uri("/dashboard?bootstrap=not-the-value&next=//evil.example/x")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_347))))
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .header(header::REFERER, "https://evil.example/")
        .header("x-original-url", "//evil.example")
        .body(Body::empty())
        .expect("request builds");
    let out = send(&state, request).await;
    assert_eq!(location(&out), Some(TARGET));
}

/// R15: a navigation is both headers, exactly; anything less keeps the 401.
#[tokio::test]
async fn r15_only_both_fetch_headers_make_a_navigation() {
    let (state, _dir) = fixture().await;
    let partial: [&'static [(&'static str, &'static str)]; 5] = [
        &[("sec-fetch-mode", "navigate")],
        &[("sec-fetch-dest", "document")],
        &[("sec-fetch-mode", "cors"), ("sec-fetch-dest", "document")],
        &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "iframe")],
        &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "empty")],
    ];
    for headers in partial {
        let out = send(&state, link("not-the-value", Fetch::Partial(headers))).await;
        assert_eq!(out.status, StatusCode::UNAUTHORIZED, "{headers:?}");
    }
}

/// R12: the target serves the shell to a browser nobody has signed in.
#[tokio::test]
async fn r12_the_target_serves_the_shell_signed_out() {
    let (state, _dir) = fixture().await;
    let out = send(&state, request("GET", TARGET, None, None, false)).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    assert!(
        out.body.contains("id=\"signin\""),
        "the shell document: {}",
        out.body
    );
}

/// R7: refusals about where the user stands or the gateway's setup keep their
/// own 401 even for a browser: the operator needs their words, and they say
/// nothing about the value. A (from elsewhere) and D (the clock) here; F is
/// in the hand-off rows.
#[tokio::test]
async fn r7_setup_and_location_refusals_are_not_redirected() {
    let (state, _dir) = fixture().await;
    let mut forwarded = link("not-the-value", Fetch::Navigate);
    forwarded.headers_mut().insert(
        "x-forwarded-for",
        axum::http::HeaderValue::from_static("203.0.113.9"),
    );
    let a = send(&state, forwarded).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
    assert!(
        a.body
            .contains("works only from the machine running the gateway"),
        "{}",
        a.body
    );

    let d = {
        let _clock = crate::clock::test_clock::before_epoch();
        send(&state, link("not-the-value", Fetch::Navigate)).await
    };
    assert_eq!(d.status, StatusCode::UNAUTHORIZED, "{}", d.body);
    assert!(d.body.contains("before 1970"), "{}", d.body);
}
