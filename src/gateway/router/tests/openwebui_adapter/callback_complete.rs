// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/complete`, the connections page a browser opens with its
//! Open `WebUI` session: every refusal reads the same sign-in text, an
//! unreadable descriptor set is a 503 with no list, and only managed
//! descriptors are listed.

use super::*;

const SIGN_IN: &str = "Sign in to Open WebUI in this browser, then retry.";
const UNKNOWN_TOKEN: &str = "owui-session-unknown-1f2e";

fn connections_page(token: &str) -> Request<Body> {
    Request::get(COMPLETE)
        .header("host", HOSTED_HOST)
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document")
        .header("cookie", cookie_of(token))
        .body(Body::empty())
        .unwrap()
}

/// A reload that removed the adapter's `session` block leaves nothing to
/// verify a browser against: the page refuses without asking Open `WebUI`.
#[tokio::test(flavor = "multi_thread")]
async fn complete_page_without_a_session_adapter_never_asks_open_webui() {
    // GIVEN
    let (owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let mut config = (*gw.state.live_config.get()).clone();
    for adapter in &mut config.accounts.as_mut().unwrap().adapters {
        adapter.session = None;
    }
    gw.state.live_config.set(config);
    // WHEN
    let (status, _, body) = send(&gw, connections_page(ALICE_TOKEN)).await;
    // THEN
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains(SIGN_IN), "{body}");
    assert!(owui.seen().is_empty(), "asked Open WebUI: {:?}", owui.seen());
}

/// A session Open `WebUI` does not recognise gets the same refusal, and is
/// the one case where Open `WebUI` was asked.
#[tokio::test(flavor = "multi_thread")]
async fn complete_page_with_a_rejected_session_asks_to_sign_in() {
    // GIVEN
    let (owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    // WHEN
    let (status, _, body) = send(&gw, connections_page(UNKNOWN_TOKEN)).await;
    // THEN
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains(SIGN_IN), "{body}");
    assert_eq!(owui.seen(), [format!("Bearer {UNKNOWN_TOKEN}")]);
}

/// A descriptor set that no longer compiles cannot say who is connected: 503,
/// and the page lists no account at all.
#[tokio::test(flavor = "multi_thread")]
async fn complete_page_with_uncompilable_descriptors_is_503_without_a_list() {
    // GIVEN: a reload drops the managed descriptor's issuer
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let mut config = (*gw.state.live_config.get()).clone();
    let descriptors = config.accounts.as_mut().unwrap().descriptors.as_mut();
    descriptors.unwrap().get_mut(WORK).unwrap().issuer = None;
    gw.state.live_config.set(config);
    // WHEN
    let (status, _, body) = send(&gw, connections_page(ALICE_TOKEN)).await;
    // THEN
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("account service is unavailable"), "{body}");
    assert!(!body.contains(WORK) && !body.contains(HOME), "{body}");
}

/// A shared descriptor has no per-user account, so the page skips it; the
/// managed ones show the caller's own state.
#[tokio::test(flavor = "multi_thread")]
async fn complete_page_lists_only_managed_descriptors() {
    // GIVEN: alice is connected on `work`, and a shared descriptor exists
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &flow).await, "connected");
    let mut config = (*gw.state.live_config.get()).clone();
    let descriptors = config
        .accounts
        .as_mut()
        .unwrap()
        .descriptors
        .as_mut()
        .unwrap();
    let mut shared = descriptors.get(WORK).unwrap().clone();
    shared.mode = crate::personal_accounts::config::DescriptorMode::Shared;
    descriptors.insert("pooled".to_owned(), shared);
    gw.state.live_config.set(config);
    // WHEN
    let (status, _, body) = send(&gw, connections_page(ALICE_TOKEN)).await;
    // THEN
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("work: connected"), "{body}");
    assert!(body.contains("home: not connected"), "{body}");
    assert!(!body.contains("pooled"), "{body}");
}
