// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 D16: the identities a stream was opened under are part of its
//! view. Under an mTLS policy a caller shown nothing without its certificate
//! is told a visible change only if the stream carries that certificate.

use super::audience_fixture::{World, tool};

fn alpha_with(read: &str) -> Vec<crate::protocol::Tool> {
    vec![
        tool("read", read),
        tool("write", "w"),
        tool("scan", "s"),
        tool("fetch", "f"),
    ]
}

fn client_cert() -> crate::mtls::CertIdentity {
    crate::mtls::CertIdentity {
        common_name: Some("svc".to_string()),
        display_name: "svc".to_string(),
        ..Default::default()
    }
}

/// R8: a listen stream opened with a certificate is told a visible change; the
/// certificate it was opened with is part of its view (kills M33c).
#[tokio::test]
async fn r8_listen_with_a_certificate_is_told_a_visible_change() {
    let w = World::start_mtls().await;
    let mut ear = w
        .listen_with("k-std", |request| {
            request.extensions_mut().insert(client_cert());
        })
        .await;
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "the stream's certificate admits alpha, so its change is visible"
    );
}

/// R8 control: the same change sends a stream that presented no certificate
/// nothing, so the row above is told by the certificate and nothing else.
#[tokio::test]
async fn r8_control_listen_without_a_certificate_is_told_nothing() {
    let w = World::start_mtls().await;
    let mut ear = w.listen("k-std").await;
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        0,
        "alpha is not shown without a certificate"
    );
}

/// R7: with agent auth on, a listen stream opened with an agent token is told
/// a visible change; the OAuth agent it was opened with is part of its view
/// (kills M33b).
#[tokio::test]
async fn r7_listen_with_an_agent_token_is_told_a_visible_change() {
    let w = World::start_agent().await;
    let mut ear = w.listen(&super::audience_access::agent_token()).await;
    w.settle().await;
    let _ = ear.told(&w).await;
    w.store_shared("alpha", alpha_with("r2"));
    assert_eq!(
        ear.told(&w).await,
        1,
        "the agent's scope admits alpha, so its change is visible"
    );
}
