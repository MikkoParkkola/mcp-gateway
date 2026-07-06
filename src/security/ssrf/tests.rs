//! Unit tests for the `ssrf` module: RFC range checks, [`super::validate_url_not_ssrf`],
//! redirect-chain validation, and the DNS-pinning resolver (MIK-4019).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use super::*;
use crate::Result;

// ── IPv4: loopback ────────────────────────────────────────────────────────

#[test]
fn ipv4_loopback_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::LOCALHOST));
    assert!(is_private_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
}

// ── IPv4: RFC 1918 private ────────────────────────────────────────────────

#[test]
fn ipv4_rfc1918_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
}

// ── IPv4: link-local ──────────────────────────────────────────────────────

#[test]
fn ipv4_link_local_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 255, 255)));
}

// ── IPv4: CGNAT / shared ──────────────────────────────────────────────────

#[test]
fn ipv4_cgnat_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
}

#[test]
fn ipv4_cgnat_boundary_public() {
    // 100.63.x.x is before the /10 range — should be public
    assert!(!is_private_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
    // 100.128.x.x is after the /10 range — should be public
    assert!(!is_private_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
}

// ── IPv4: IETF protocol assignments ──────────────────────────────────────

#[test]
fn ipv4_ietf_protocol_assignments_blocked() {
    // 192.0.0.0/24
    assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 0, 255)));
}

// ── IPv4: TEST-NET (documentation) ───────────────────────────────────────

#[test]
fn ipv4_documentation_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(192, 0, 2, 1))); // TEST-NET-1
    assert!(is_private_ipv4(Ipv4Addr::new(198, 51, 100, 1))); // TEST-NET-2
    assert!(is_private_ipv4(Ipv4Addr::new(203, 0, 113, 1))); // TEST-NET-3
}

// ── IPv4: 6to4 relay anycast ─────────────────────────────────────────────

#[test]
fn ipv4_6to4_relay_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(192, 88, 99, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 88, 99, 255)));
}

// ── IPv4: benchmarking ────────────────────────────────────────────────────

#[test]
fn ipv4_benchmarking_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(198, 18, 0, 0)));
    assert!(is_private_ipv4(Ipv4Addr::new(198, 19, 255, 255)));
}

#[test]
fn ipv4_benchmarking_boundary_public() {
    assert!(!is_private_ipv4(Ipv4Addr::new(198, 17, 255, 255)));
    assert!(!is_private_ipv4(Ipv4Addr::new(198, 20, 0, 0)));
}

// ── IPv4: multicast ───────────────────────────────────────────────────────

#[test]
fn ipv4_multicast_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(239, 255, 255, 255)));
}

// ── IPv4: reserved (240.0.0.0/4) ─────────────────────────────────────────

#[test]
fn ipv4_reserved_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(240, 0, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(254, 255, 255, 255)));
}

// ── IPv4: broadcast + unspecified ─────────────────────────────────────────

#[test]
fn ipv4_broadcast_and_unspecified_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::BROADCAST));
    assert!(is_private_ipv4(Ipv4Addr::UNSPECIFIED));
    assert!(is_private_ipv4(Ipv4Addr::new(0, 1, 2, 3)));
    assert!(is_private_ipv4(Ipv4Addr::new(0, 255, 255, 255)));
}

#[test]
fn ipv4_antissrf_cloud_and_infra_ranges_blocked() {
    assert!(is_private_ipv4(Ipv4Addr::new(168, 63, 129, 16)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 31, 196, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 52, 193, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 175, 48, 1)));
}

// ── IPv4: public addresses pass ───────────────────────────────────────────

#[test]
fn ipv4_public_passes() {
    assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    assert!(!is_private_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
}

// ── IPv6: loopback / unspecified ──────────────────────────────────────────

#[test]
fn ipv6_loopback_blocked() {
    assert!(is_private_ipv6(Ipv6Addr::LOCALHOST));
}

#[test]
fn ipv6_unspecified_blocked() {
    assert!(is_private_ipv6(Ipv6Addr::UNSPECIFIED));
}

// ── IPv6: multicast ───────────────────────────────────────────────────────

#[test]
fn ipv6_multicast_blocked() {
    let addr: Ipv6Addr = "ff02::1".parse().unwrap();
    assert!(is_private_ipv6(addr));
    let addr2: Ipv6Addr = "ff00::".parse().unwrap();
    assert!(is_private_ipv6(addr2));
}

// ── IPv6: link-local ──────────────────────────────────────────────────────

#[test]
fn ipv6_link_local_blocked() {
    let addr: Ipv6Addr = "fe80::1".parse().unwrap();
    assert!(is_private_ipv6(addr));
}

// ── IPv6: unique local ────────────────────────────────────────────────────

#[test]
fn ipv6_unique_local_blocked() {
    let addr1: Ipv6Addr = "fc00::1".parse().unwrap();
    assert!(is_private_ipv6(addr1));
    let addr2: Ipv6Addr = "fd00::1".parse().unwrap();
    assert!(is_private_ipv6(addr2));
}

// ── IPv6: documentation (2001:db8::/32) ──────────────────────────────────

#[test]
fn ipv6_documentation_blocked() {
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(is_private_ipv6(addr));
    let addr2: Ipv6Addr = "2001:db8:cafe::1".parse().unwrap();
    assert!(is_private_ipv6(addr2));
}

// ── IPv6: IPv4-mapped (::ffff:x.x.x.x) ───────────────────────────────────

#[test]
fn ipv6_ipv4_mapped_loopback_blocked() {
    let addr: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
    assert!(is_private_ipv6(addr));
}

#[test]
fn ipv6_ipv4_mapped_private_blocked() {
    let addr1: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(is_private_ipv6(addr1));
    let addr2: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
    assert!(is_private_ipv6(addr2));
}

#[test]
fn ipv6_ipv4_mapped_multicast_blocked() {
    let addr: Ipv6Addr = "::ffff:224.0.0.1".parse().unwrap();
    assert!(is_private_ipv6(addr));
}

#[test]
fn ipv6_ipv4_mapped_public_passes() {
    let addr: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
    assert!(!is_private_ipv6(addr));
}

// ── IPv6: 6to4 ───────────────────────────────────────────────────────────

#[test]
fn ipv6_6to4_private_blocked() {
    // 2002:0a00:0001:: embeds 10.0.0.1
    let addr: Ipv6Addr = "2002:0a00:0001::".parse().unwrap();
    assert!(is_private_ipv6(addr));
}

#[test]
fn ipv6_6to4_public_is_blocked_as_translation_prefix() {
    let addr: Ipv6Addr = "2002:0808:0808::".parse().unwrap();
    assert!(is_private_ipv6(addr));
}

#[test]
fn ipv6_antissrf_recommended_ranges_blocked() {
    let samples = [
        "64:ff9b::8.8.8.8", // NAT64 well-known
        "64:ff9b:1::1",     // NAT64 local-use
        "100::1",           // discard-only
        "100:0:0:1::1",     // dummy
        "2001:2::1",        // benchmarking under IETF protocol assignments
        "2001:3::1",        // AMT under IETF protocol assignments
        "2001:4:112::1",    // AS112 under IETF protocol assignments
        "3fff::1",          // documentation
        "5f00::1",          // SRv6 SIDs
        "2620:4f:8000::1",  // AS112
    ];
    for sample in samples {
        let addr: Ipv6Addr = sample.parse().unwrap();
        assert!(is_private_ipv6(addr), "{sample} should be blocked");
    }
}

// ── IPv6: public passes ───────────────────────────────────────────────────

#[test]
fn ipv6_public_passes() {
    let addr: Ipv6Addr = "2607:f8b0:4004:800::200e".parse().unwrap();
    assert!(!is_private_ipv6(addr));
}

// ── validate_url_not_ssrf ────────────────────────────────────────────────

#[test]
fn url_blocks_loopback() {
    assert!(validate_url_not_ssrf("http://127.0.0.1/api").is_err());
    assert!(validate_url_not_ssrf("http://127.0.0.1:8080/foo").is_err());
}

#[test]
fn url_blocks_private_ranges() {
    assert!(validate_url_not_ssrf("http://10.0.0.1/api").is_err());
    assert!(validate_url_not_ssrf("http://192.168.1.1/api").is_err());
    assert!(validate_url_not_ssrf("http://172.16.0.1/api").is_err());
}

#[test]
fn url_blocks_multicast() {
    assert!(validate_url_not_ssrf("http://224.0.0.1/api").is_err());
}

#[test]
fn url_blocks_reserved() {
    assert!(validate_url_not_ssrf("http://240.0.0.1/api").is_err());
}

#[test]
fn url_blocks_benchmarking() {
    assert!(validate_url_not_ssrf("http://198.18.0.1/api").is_err());
    assert!(validate_url_not_ssrf("http://198.19.0.1/api").is_err());
}

#[test]
fn url_blocks_6to4_relay() {
    assert!(validate_url_not_ssrf("http://192.88.99.1/api").is_err());
}

#[test]
fn url_blocks_ietf_protocol() {
    assert!(validate_url_not_ssrf("http://192.0.0.1/api").is_err());
}

#[test]
fn url_blocks_documentation() {
    assert!(validate_url_not_ssrf("http://192.0.2.1/api").is_err());
    assert!(validate_url_not_ssrf("http://198.51.100.1/api").is_err());
    assert!(validate_url_not_ssrf("http://203.0.113.1/api").is_err());
}

#[test]
fn url_blocks_ipv4_mapped_ipv6() {
    assert!(validate_url_not_ssrf("http://[::ffff:127.0.0.1]/api").is_err());
    assert!(validate_url_not_ssrf("http://[::ffff:10.0.0.1]/api").is_err());
}

#[test]
fn url_blocks_ipv6_loopback() {
    assert!(validate_url_not_ssrf("http://[::1]/api").is_err());
}

#[test]
fn url_blocks_ipv6_documentation() {
    assert!(validate_url_not_ssrf("http://[2001:db8::1]/api").is_err());
}

#[test]
fn url_blocks_ipv6_multicast() {
    assert!(validate_url_not_ssrf("http://[ff02::1]/api").is_err());
}

#[test]
fn url_blocks_unspecified() {
    assert!(validate_url_not_ssrf("http://0.0.0.0/api").is_err());
    assert!(validate_url_not_ssrf("http://0.1.2.3/api").is_err());
}

#[test]
fn url_blocks_antissrf_cloud_and_translation_ranges() {
    assert!(validate_url_not_ssrf("http://168.63.129.16/api").is_err());
    assert!(validate_url_not_ssrf("http://[64:ff9b::8.8.8.8]/api").is_err());
    assert!(validate_url_not_ssrf("http://[2002:0808:0808::]/api").is_err());
}

#[test]
fn url_allows_public_ipv4() {
    assert!(validate_url_not_ssrf("http://8.8.8.8/api").is_ok());
    assert!(validate_url_not_ssrf("https://93.184.216.34/api").is_ok());
}

#[test]
fn url_allows_public_ipv6() {
    assert!(validate_url_not_ssrf("http://[2607:f8b0:4004:800::200e]/api").is_ok());
}

#[test]
fn url_allows_domain_names() {
    // Domain names pass through (DNS resolution happens downstream)
    assert!(validate_url_not_ssrf("https://api.example.com/v1").is_ok());
}

#[test]
fn url_rejects_invalid_url() {
    assert!(validate_url_not_ssrf("not a url").is_err());
}

#[test]
fn url_relative_gives_actionable_error() {
    // A bare relative URL (empty base + path, or a bare token) must fail with
    // an actionable message that names the value and says it is not absolute —
    // not the opaque "relative URL without a base". Regression for trvl#234.
    for relative in ["/rpc", "search_flights"] {
        let err = validate_url_not_ssrf(relative)
            .expect_err("relative URL must be rejected")
            .to_string();
        assert!(
            err.contains("not absolute"),
            "message should explain the URL is not absolute: {err}"
        );
        assert!(
            err.contains(relative),
            "message should name the offending URL {relative:?}: {err}"
        );
        assert!(
            !err.contains("relative URL without a base"),
            "must not surface the opaque parse error: {err}"
        );
    }
}

#[test]
fn url_schemeless_host_port_gives_actionable_error() {
    // "localhost:8080/mcp" parses with scheme="localhost" and no host — the
    // scheme-less host:port misconfiguration. The error must name the value
    // and point at the missing scheme rather than a bare "no host".
    let err = validate_url_not_ssrf("localhost:8080/mcp")
        .expect_err("scheme-less host:port must be rejected")
        .to_string();
    assert!(
        err.contains("localhost:8080/mcp"),
        "should name the URL: {err}"
    );
    assert!(
        err.contains("scheme"),
        "should point at the missing scheme: {err}"
    );
}

#[test]
fn url_rejects_missing_host() {
    // file:// URLs have no host
    assert!(validate_url_not_ssrf("file:///etc/passwd").is_err());
}

// ── validate_redirect_chain ───────────────────────────────────────────────

#[test]
fn redirect_chain_all_public_passes() {
    let chain = &[
        "https://api.example.com/redirect",
        "https://cdn.example.com/resource",
    ];
    assert!(validate_redirect_chain(chain).is_ok());
}

#[test]
fn redirect_chain_blocks_internal_hop() {
    let chain = &[
        "https://api.example.com/redirect",
        "http://10.0.0.1/internal", // redirect to internal
    ];
    let err = validate_redirect_chain(chain).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("hop 1"),
        "error should name the hop index: {msg}"
    );
}

#[test]
fn redirect_chain_blocks_first_hop() {
    let chain = &["http://127.0.0.1/api"];
    let err = validate_redirect_chain(chain).unwrap_err();
    assert!(err.to_string().contains("hop 0"));
}

#[test]
fn redirect_chain_empty_passes() {
    assert!(validate_redirect_chain(&[]).is_ok());
}

// ── check_host_not_ssrf ───────────────────────────────────────────────────

#[test]
fn check_host_blocks_bare_ipv4() {
    assert!(check_host_not_ssrf("127.0.0.1").is_err());
    assert!(check_host_not_ssrf("10.0.0.1").is_err());
}

#[test]
fn check_host_blocks_bracketed_ipv6() {
    assert!(check_host_not_ssrf("[::1]").is_err());
    assert!(check_host_not_ssrf("[fe80::1]").is_err());
}

#[test]
fn check_host_allows_domain() {
    assert!(check_host_not_ssrf("example.com").is_ok());
}

#[test]
fn check_host_allows_public_ipv4() {
    assert!(check_host_not_ssrf("8.8.8.8").is_ok());
}

// ── DNS pinning: resolve_and_validate_host / PinningResolver (MIK-4019) ──

/// Minimal mock resolver for unit tests: returns a fixed IP list.
struct MockResolver {
    ips: Vec<IpAddr>,
}

impl MockResolver {
    fn returning(ips: Vec<IpAddr>) -> Self {
        Self { ips }
    }
}

impl HostResolver for MockResolver {
    fn lookup(
        &self,
        _host: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
        let ips = self.ips.clone();
        Box::pin(async move { Ok(ips) })
    }
}

/// AC2: allowed public domain: mock returns a public IP, passes.
#[tokio::test]
async fn pinning_public_domain_passes() {
    let resolver = MockResolver::returning(vec!["8.8.8.8".parse().unwrap()]);
    let result = resolve_and_validate_host("public.test.invalid", &resolver).await;
    assert!(result.is_ok(), "public domain should pass: {result:?}");
    assert_eq!(result.unwrap(), vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
}

/// AC2: private-rebinding: mock returns 127.0.0.1, blocked.
#[tokio::test]
async fn pinning_loopback_rebinding_blocked() {
    let resolver = MockResolver::returning(vec!["127.0.0.1".parse().unwrap()]);
    let err = resolve_and_validate_host("evil.test.invalid", &resolver)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("127.0.0.1"),
        "error must name the blocked IP: {msg}"
    );
    assert!(
        msg.contains("SSRF blocked"),
        "error must say SSRF blocked: {msg}"
    );
}

/// AC2: metadata-IP rebinding: mock returns 169.254.169.254, blocked.
#[tokio::test]
async fn pinning_metadata_rebinding_blocked() {
    let resolver = MockResolver::returning(vec!["169.254.169.254".parse().unwrap()]);
    let err = resolve_and_validate_host("metadata.test.invalid", &resolver)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("169.254.169.254"),
        "error must name the metadata IP: {msg}"
    );
}

/// AC2: private RFC-1918 rebinding: mock returns 10.0.0.1, blocked.
#[tokio::test]
async fn pinning_private_rfc1918_rebinding_blocked() {
    let resolver = MockResolver::returning(vec!["10.0.0.1".parse().unwrap()]);
    let err = resolve_and_validate_host("corp.test.invalid", &resolver)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("SSRF blocked"));
}

/// AC2: `PinningResolver` blocks private IP via `reqwest::dns::Resolve`.
#[tokio::test]
async fn pinning_resolver_blocks_private_via_reqwest_trait() {
    use reqwest::dns::{Name, Resolve};
    let resolver =
        PinningResolver::new(MockResolver::returning(vec!["127.0.0.1".parse().unwrap()]));
    let name: Name = "evil.test.invalid".parse().unwrap();
    let result = resolver.resolve(name).await;
    assert!(
        result.is_err(),
        "PinningResolver must reject private IP via reqwest Resolve trait"
    );
    let err_msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => String::new(),
    };
    assert!(err_msg.contains("SSRF blocked"), "error: {err_msg}");
}

/// AC2: `PinningResolver` allows public IP via `reqwest::dns::Resolve`.
#[tokio::test]
async fn pinning_resolver_allows_public_via_reqwest_trait() {
    use reqwest::dns::{Name, Resolve};
    let resolver = PinningResolver::new(MockResolver::returning(vec!["8.8.8.8".parse().unwrap()]));
    let name: Name = "dns.google".parse().unwrap();
    let result = resolver.resolve(name).await;
    assert!(result.is_ok(), "PinningResolver must allow public IP");
}

/// AC2: redirect handling: `validate_redirect_chain` blocks loopback redirect hop.
#[test]
fn redirect_to_loopback_is_blocked() {
    let chain = &[
        "https://api.test.invalid/step1",
        "http://127.0.0.1/internal",
    ];
    let err = validate_redirect_chain(chain).unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}

/// AC2: redirect handling: `validate_redirect_chain` blocks metadata IP redirect.
#[test]
fn redirect_to_metadata_ip_is_blocked() {
    let chain = &[
        "https://public.test.invalid/redirect",
        "http://169.254.169.254/latest/meta-data/",
    ];
    let err = validate_redirect_chain(chain).unwrap_err();
    assert!(err.to_string().contains("hop 1"));
}
