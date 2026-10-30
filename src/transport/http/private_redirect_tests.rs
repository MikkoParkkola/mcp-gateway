// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Row 13 of the hardened posture: the redirect rule for a backend listed in
//! `security.hardened.private_backends`.

use url::Url;

use super::RedirectDecision;

/// Row 13: a listed private backend follows a same-origin redirect on its own
/// loopback origin; its policy still refuses link-local, and every other
/// backend keeps the full validation.
#[test]
fn private_backend_follows_a_same_origin_loopback_redirect() {
    use crate::security::ssrf::DestinationPolicy;
    let base = Url::parse("http://127.0.0.1:8080/mcp").unwrap();
    let same = Url::parse("http://127.0.0.1:8080/mcp/").unwrap();
    let metadata = Url::parse("http://169.254.169.254/latest").unwrap();
    assert!(matches!(
        super::evaluate_redirect_for(DestinationPolicy::Private, &base, &same, 0),
        RedirectDecision::Follow
    ));
    assert!(matches!(
        super::evaluate_redirect_for(DestinationPolicy::Private, &base, &metadata, 0),
        RedirectDecision::Reject(_)
    ));
    assert!(matches!(
        super::evaluate_redirect_for(DestinationPolicy::Public, &base, &same, 0),
        RedirectDecision::Reject(_)
    ));
}

/// Row 13, the negative half: the redirect exemption is the backend's own
/// origin only. A listed backend's hop to another private host (even another
/// listed backend's), to another port, or to a metadata address is refused.
#[test]
fn private_backend_redirect_exemption_is_same_origin_only() {
    use crate::security::ssrf::DestinationPolicy;
    let base = Url::parse("http://127.0.0.1:8080/mcp").unwrap();
    for target in [
        "http://10.0.0.5/mcp",
        "http://127.0.0.1:9090/mcp",
        "http://localhost:8080/mcp",
        "http://[fd00:ec2::254]/latest",
        "http://169.254.169.254/latest",
        "http://[::ffff:169.254.169.254]/latest",
    ] {
        let decision = super::evaluate_redirect_for(
            DestinationPolicy::Private,
            &base,
            &Url::parse(target).unwrap(),
            0,
        );
        assert!(
            matches!(decision, RedirectDecision::Reject(_)),
            "{target}: a listed backend followed it ({decision:?})"
        );
    }
}

/// A backend whose answer redirects to a loopback literal comes back as the
/// SSRF refusal, a policy answer: not a transport fault a retry or a fallback
/// would walk past.
#[tokio::test]
async fn a_redirect_hop_to_a_loopback_literal_is_the_ssrf_refusal() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.1:{port}/x\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    let base = Url::parse(&format!("http://127.0.0.1:{port}/mcp")).unwrap();
    let client = super::client::build(
        base.clone(),
        crate::test_wait::HANG_BOUND,
        crate::security::ssrf::DestinationPolicy::Configured,
        Arc::new(AtomicU64::new(0)),
    )
    .unwrap();
    let sent = client
        .get(base)
        .send()
        .await
        .expect_err("the hop was followed");
    let refused = crate::security::http_diagnostics::safe_request_error("probe", &sent);
    assert!(
        crate::security::ssrf::is_ssrf_refusal(&refused),
        "not the SSRF refusal: {refused}"
    );
}
