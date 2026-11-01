// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! With `capabilities.egress_proxy` set, loopback IP literals skip the proxy
//! (#3013) and the synchronous check refuses them; every name goes to the
//! proxy. A loopback NAME is refused before any lookup, as a target, a
//! redirect hop and on every send site, so nothing naming loopback is
//! connected direct and unchecked.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::CapabilityExecutor;
use crate::capability::CapabilityExecutionContext;
use crate::config::CapabilityConfig;

/// A loopback listener that answers every request and counts it.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    answering_listener(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{}"
            .to_owned(),
    )
    .await
}

/// A loopback listener that answers every request with `reply` and counts it.
async fn answering_listener(reply: String) -> (u16, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (port, hits)
}

/// A REST capability whose endpoint is `base_url`.
fn capability(base_url: &str) -> crate::capability::CapabilityDefinition {
    capability_over(
        "rest",
        &format!("base_url: {base_url}\n      path: /probe\n      method: GET"),
    )
}

/// A capability served over `service`, its provider `config` block lines.
fn capability_over(service: &str, config: &str) -> crate::capability::CapabilityDefinition {
    crate::capability::parse_capability(&format!(
        "name: proxy_ssrf_probe\ndescription: Loopback probe\nproviders:\n  primary:\n    \
         service: {service}\n    config:\n      {config}\n"
    ))
    .unwrap()
}

/// One call to `base_url` through an executor whose egress proxy is a
/// counting listener, with no loopback egress allowed: the result, how often
/// the proxy was reached, and how often the target was.
async fn call_through_proxy(base_url: impl Fn(u16) -> String) -> (bool, usize, usize) {
    let (proxy, via_proxy) = counting_listener().await;
    let (target, direct) = counting_listener().await;
    let executor = through_proxy(&format!("http://127.0.0.1:{proxy}"));
    let ok = call(&executor, &base_url(target)).await;
    (
        ok,
        via_proxy.load(Ordering::SeqCst),
        direct.load(Ordering::SeqCst),
    )
}

fn through_proxy(proxy: &str) -> CapabilityExecutor {
    CapabilityExecutor::for_config(&CapabilityConfig {
        egress_proxy: Some(proxy.to_owned()),
        ..CapabilityConfig::default()
    })
}

/// One call to `base_url`, with no loopback egress allowed: whether it
/// succeeded.
async fn call(executor: &CapabilityExecutor, base_url: &str) -> bool {
    call_in(
        executor,
        &capability(base_url),
        CapabilityExecutionContext::default(),
    )
    .await
    .is_ok()
}

/// One bounded call of `capability` in `context`.
async fn call_in(
    executor: &CapabilityExecutor,
    capability: &crate::capability::CapabilityDefinition,
    context: CapabilityExecutionContext,
) -> crate::Result<serde_json::Value> {
    tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        executor.execute_with_context(capability, json!({}), context),
    )
    .await
    .expect("bounded")
}

/// `capability` refused with the SSRF refusal through a counting proxy, with
/// neither the proxy nor the `target` listener reached.
async fn assert_refused_unreached(
    capability: &crate::capability::CapabilityDefinition,
    target: &Arc<AtomicUsize>,
) {
    let (proxy, via_proxy) = counting_listener().await;
    let executor = through_proxy(&format!("http://127.0.0.1:{proxy}"));
    let refused = call_in(&executor, capability, CapabilityExecutionContext::default())
        .await
        .expect_err("the call succeeded");
    assert!(
        crate::security::ssrf::is_ssrf_refusal(&refused),
        "not the SSRF refusal: {refused}"
    );
    assert_eq!(via_proxy.load(Ordering::SeqCst), 0, "the proxy was reached");
    assert_eq!(target.load(Ordering::SeqCst), 0, "the target was reached");
}

/// A capability URL naming `localhost` is refused on the proxied route, and
/// the loopback listener is never reached.
#[tokio::test]
async fn a_capability_naming_localhost_is_refused_through_the_proxy() {
    let (ok, via_proxy, direct) =
        call_through_proxy(|port| format!("http://localhost:{port}")).await;
    assert_eq!(
        via_proxy, 0,
        "premise: loopback never goes to the proxy (#3013)"
    );
    assert_eq!(
        direct, 0,
        "a name resolving to loopback reached the listener"
    );
    assert!(!ok, "the call succeeded");
}

/// Control: the loopback literal is refused by the synchronous check today.
#[tokio::test]
async fn a_capability_naming_the_loopback_literal_is_refused_through_the_proxy() {
    let (ok, via_proxy, direct) =
        call_through_proxy(|port| format!("http://127.0.0.1:{port}")).await;
    assert_eq!((via_proxy, direct), (0, 0), "a listener was reached");
    assert!(!ok, "the call succeeded");
}

/// A proxy at `localhost` (a local egress proxy, `localhost:3128`): a target
/// naming `localhost` is still refused, while a public name in the same
/// executor still reaches the proxy. The proxy's name must exempt nothing.
#[tokio::test]
async fn a_proxy_at_localhost_exempts_no_localhost_target() {
    let (proxy, via_proxy) = counting_listener().await;
    let (target, direct) = counting_listener().await;
    let executor = through_proxy(&format!("http://localhost:{proxy}"));
    let target_ok = call(&executor, &format!("http://localhost:{target}")).await;
    assert_eq!(
        direct.load(Ordering::SeqCst),
        0,
        "a localhost target reached the listener"
    );
    assert!(!target_ok, "the localhost target succeeded");
    let public_ok = call(&executor, "http://api.capability-fixture.test").await;
    assert!(
        via_proxy.load(Ordering::SeqCst) >= 1,
        "a public name did not reach the proxy at localhost"
    );
    assert!(public_ok, "the proxy's answer did not arrive");
}

/// Every loopback-name spelling, as a target, is refused with no connection.
#[tokio::test]
async fn every_loopback_name_spelling_is_refused_as_a_target() {
    let (port, target) = counting_listener().await;
    for host in [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "foo.localhost",
        "foo.localhost.",
    ] {
        assert_refused_unreached(&capability(&format!("http://{host}:{port}")), &target).await;
    }
}

/// Every loopback-literal spelling, as a target, is refused with no connection.
#[tokio::test]
async fn every_loopback_literal_spelling_is_refused_as_a_target() {
    let (port, target) = counting_listener().await;
    for host in [
        "127.1",
        "0x7f000001",
        "0.0.0.0",
        "[::1]",
        "[::ffff:127.0.0.1]",
    ] {
        assert_refused_unreached(&capability(&format!("http://{host}:{port}")), &target).await;
    }
}

/// A public name's answer redirecting to loopback, by name or by literal, is
/// refused at the hop: the proxy answered once, the target never.
#[tokio::test]
async fn a_redirect_hop_to_loopback_is_refused() {
    let (port, target) = counting_listener().await;
    for host in [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "foo.localhost",
        "foo.localhost.",
        "127.1",
        "0x7f000001",
        "0.0.0.0",
        "[::1]",
        "[::ffff:127.0.0.1]",
    ] {
        assert_hop_refused(&format!("http://{host}:{port}/x"), &target).await;
    }
}

/// A literal with extra trailing dots stays a name, so the target check
/// refuses it as one; the hop gets the same refusal.
#[tokio::test]
async fn a_redirect_hop_to_a_dotted_loopback_literal_is_refused() {
    let (port, target) = counting_listener().await;
    assert_hop_refused(&format!("http://127.0.0.1..:{port}/x"), &target).await;
}

/// The cloud metadata address, spelled with extra trailing dots, as a hop.
#[tokio::test]
async fn a_redirect_hop_to_a_dotted_metadata_literal_is_refused() {
    let (_port, target) = counting_listener().await;
    assert_hop_refused("http://169.254.169.254../latest/meta-data/", &target).await;
}

/// A public name whose answer redirects to `location` is refused at the hop
/// with the SSRF refusal: the proxy answered once, `target` never.
async fn assert_hop_refused(location: &str, target: &Arc<AtomicUsize>) {
    let (proxy, via_proxy) = answering_listener(format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    ))
    .await;
    let executor = through_proxy(&format!("http://127.0.0.1:{proxy}"));
    let refused = call_in(
        &executor,
        &capability("http://api.capability-fixture.test"),
        CapabilityExecutionContext::default(),
    )
    .await
    .expect_err(location);
    assert!(
        crate::security::ssrf::is_ssrf_refusal(&refused),
        "{location}: not the SSRF refusal: {refused}"
    );
    assert_eq!(via_proxy.load(Ordering::SeqCst), 1, "{location}: the proxy");
    assert_eq!(
        target.load(Ordering::SeqCst),
        0,
        "{location}: the target was reached"
    );
}

/// The GraphQL and JSON-RPC endpoint checks refuse a loopback name too.
#[tokio::test]
async fn graphql_and_jsonrpc_refuse_a_localhost_endpoint() {
    let (port, target) = counting_listener().await;
    let endpoint = format!("http://localhost:{port}/rpc");
    assert_refused_unreached(
        &capability_over(
            "graphql",
            &format!("endpoint: {endpoint}\n      body: \"{{ probe }}\""),
        ),
        &target,
    )
    .await;
    assert_refused_unreached(
        &capability_over(
            "jsonrpc",
            &format!("endpoint: {endpoint}\n      method: probe"),
        ),
        &target,
    )
    .await;
}

/// The isolated runtime's loopback-literal allowance still holds on the
/// proxied executor: `127.0.0.1` is reached direct, never via the proxy. The
/// IPv4-mapped spelling stays refused there.
#[tokio::test]
async fn the_isolated_loopback_literal_goes_direct_not_via_the_proxy() {
    let (proxy, via_proxy) = counting_listener().await;
    let (port, target) = counting_listener().await;
    let executor = through_proxy(&format!("http://127.0.0.1:{proxy}"));
    let isolated = || CapabilityExecutionContext::default().with_isolated_loopback_egress();
    call_in(
        &executor,
        &capability(&format!("http://127.0.0.1:{port}")),
        isolated(),
    )
    .await
    .expect("the isolated literal is reached");
    assert_eq!(target.load(Ordering::SeqCst), 1, "the target");
    let mapped = call_in(
        &executor,
        &capability(&format!("http://[::ffff:127.0.0.1]:{port}")),
        isolated(),
    )
    .await
    .expect_err("the mapped spelling is refused");
    assert!(crate::security::ssrf::is_ssrf_refusal(&mapped), "{mapped}");
    assert_eq!(
        target.load(Ordering::SeqCst),
        1,
        "the mapped spelling reached it"
    );
    assert_eq!(
        via_proxy.load(Ordering::SeqCst),
        0,
        "a literal went via the proxy"
    );
}

/// A public-looking name whose DNS points at loopback (`localtest.me`) is
/// sent to the proxy, never direct: guarding it is the proxy's policy.
#[tokio::test]
async fn a_public_name_resolving_to_loopback_goes_to_the_proxy() {
    let (ok, via_proxy, direct) =
        call_through_proxy(|port| format!("http://localtest.me:{port}")).await;
    assert!(ok, "the proxy's answer did not arrive");
    assert_eq!((via_proxy, direct), (1, 0), "(via proxy, direct)");
}

/// Without a proxy, a loopback name is refused by name, before any lookup.
#[tokio::test]
async fn without_a_proxy_localhost_is_refused_by_name() {
    let (port, target) = counting_listener().await;
    let refused = call_in(
        &CapabilityExecutor::for_config(&CapabilityConfig::default()),
        &capability(&format!("http://localhost:{port}")),
        CapabilityExecutionContext::default(),
    )
    .await
    .expect_err("the call succeeded");
    assert!(
        refused
            .to_string()
            .contains("host names the loopback interface"),
        "not the by-name refusal: {refused}"
    );
    assert_eq!(target.load(Ordering::SeqCst), 0, "the target was reached");
}
