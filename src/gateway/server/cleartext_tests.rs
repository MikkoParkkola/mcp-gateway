// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C3 (MIK 7570 TRANSPORT.1): credentials over plain HTTP on a network bind.

use super::{
    cleartext_credential_refusal, cleartext_http_warning, reload_posture_refusal, serve_refusal,
};
use crate::config::{CleartextHttp, Config};

const SERVICE_URL: &str = "http://gw.ns.svc.cluster.local:39400";

/// Authentication on, only `/health` public: the tools need a credential, so
/// the open-tools check passes and only the cleartext question remains.
fn config(host: &str, mode: CleartextHttp, public_url: Option<&str>) -> Config {
    let mut c = Config::default();
    c.server.host = host.to_string();
    c.server.cleartext_http = mode;
    c.server.public_url = public_url.map(str::to_string);
    c.auth.enabled = true;
    c.auth.public_paths = vec!["/health".to_string()];
    c
}

#[test]
fn auth_on_network_bind_without_tls_refused() {
    let refusal = serve_refusal(&config("0.0.0.0", CleartextHttp::Refuse, None))
        .expect("bearer tokens over plain HTTP on 0.0.0.0 must be refused");
    assert!(refusal.contains("the bind address 0.0.0.0"), "{refusal}");
    assert!(refusal.contains("server.cleartext_http"), "{refusal}");
    for remedy in [
        "mtls",
        "tls_terminated_upstream",
        "cluster_internal",
        "host_local_publish",
    ] {
        assert!(refusal.contains(remedy), "names {remedy}: {refusal}");
    }
}

#[test]
fn every_credential_gate_counts() {
    for (gate, enable) in [
        (
            "auth",
            (|c: &mut Config| c.auth.enabled = true) as fn(&mut Config),
        ),
        ("agent_auth", |c: &mut Config| c.agent_auth.enabled = true),
        ("key_server", |c: &mut Config| c.key_server.enabled = true),
    ] {
        let mut c = Config::default();
        c.server.host = "0.0.0.0".to_string();
        enable(&mut c);
        assert!(
            cleartext_credential_refusal(&c).is_some(),
            "{gate} accepts a credential over this listener, so plain HTTP on 0.0.0.0 must be refused"
        );
    }
}

#[test]
fn declared_public_url_counts_as_exposure() {
    let c = config(
        "127.0.0.1",
        CleartextHttp::Refuse,
        Some("http://gw.example"),
    );
    let refusal = serve_refusal(&c).expect("a declared public host is network exposure");
    assert!(refusal.contains("gw.example"), "{refusal}");
}

#[test]
fn mtls_or_enum_or_loopback_passes() {
    let mut mtls = config("0.0.0.0", CleartextHttp::Refuse, None);
    mtls.mtls.enabled = true;
    assert!(cleartext_credential_refusal(&mtls).is_none(), "mTLS is TLS");

    for mode in [
        CleartextHttp::TlsTerminatedUpstream,
        CleartextHttp::HostLocalPublish,
    ] {
        let c = config("0.0.0.0", mode, None);
        assert!(serve_refusal(&c).is_none(), "{mode:?} must serve");
        assert!(
            cleartext_http_warning(&c).is_some(),
            "{mode:?} must WARN on every start"
        );
    }
    assert!(serve_refusal(&config("127.0.0.1", CleartextHttp::Refuse, None)).is_none());
    assert!(cleartext_http_warning(&config("0.0.0.0", CleartextHttp::Refuse, None)).is_none());
}

#[test]
fn cluster_internal_requires_service_host() {
    let accepts = |url: Option<&str>, domain: Option<&str>| {
        let mut c = config("0.0.0.0", CleartextHttp::ClusterInternal, url);
        c.server.cluster_domain = domain.map(str::to_string);
        serve_refusal(&c)
    };
    // The chart smoke reads the same rows, so gateway and chart agree.
    let rows = include_str!("../../../tests/fixtures/c3_service_hosts.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
    let mut seen = 0;
    for row in rows {
        let cols: Vec<&str> = row.split_whitespace().collect();
        let [verdict, url, domain] = cols[..] else {
            panic!("malformed fixture row {row:?}");
        };
        let domain = (domain != "-").then_some(domain);
        let refusal = accepts(Some(url), domain);
        match verdict {
            "accept" => assert_eq!(refusal, None, "{row}: names a Service"),
            "reject" => assert!(refusal.is_some(), "{row}: is not a Service host"),
            other => panic!("unknown verdict {other:?} in {row:?}"),
        }
        seen += 1;
    }
    assert!(seen >= 7, "the fixture lost rows: {seen}");
    assert!(
        accepts(None, None).is_some(),
        "an unset public_url names nothing"
    );
    let ingress = accepts(Some("https://mcp.example.com"), None).expect("an ingress host");
    assert!(ingress.contains("tls_terminated_upstream"), "{ingress}");
    assert!(ingress.contains("mcp.example.com"), "{ingress}");
}

#[test]
fn cluster_internal_warning_names_the_service_host() {
    let c = config("0.0.0.0", CleartextHttp::ClusterInternal, Some(SERVICE_URL));
    let warning = cleartext_http_warning(&c).expect("cluster_internal warns");
    assert!(warning.contains("cluster_internal"), "{warning}");
    assert!(warning.contains("gw.ns.svc.cluster.local"), "{warning}");
}

#[test]
fn reload_to_public_url_refused_for_cleartext_credentials() {
    let running = config("127.0.0.1", CleartextHttp::Refuse, None);
    let mut wanted = running.clone();
    wanted.server.public_url = Some("http://gw.example".to_string());
    let refused = reload_posture_refusal(&running, &wanted)
        .expect("a reload that publishes bearer tokens in cleartext must be refused");
    assert!(
        refused.reason.contains("cleartext_http"),
        "{}",
        refused.reason
    );
    assert!(refused.restart_would_also_refuse);
}

#[test]
fn reload_public_url_with_mtls_passes() {
    let mut running = config("127.0.0.1", CleartextHttp::Refuse, None);
    running.mtls.enabled = true;
    let mut wanted = running.clone();
    wanted.server.public_url = Some("http://gw.example".to_string());
    assert!(reload_posture_refusal(&running, &wanted).is_none());
}

/// The wanted file is authoritative for `public_url`: omitting it clears it,
/// and `cluster_internal` without a Service name is then refused.
#[test]
fn reload_that_drops_the_service_url_is_refused() {
    let running = config("0.0.0.0", CleartextHttp::ClusterInternal, Some(SERVICE_URL));
    assert!(serve_refusal(&running).is_none(), "positive control");
    let mut wanted = running.clone();
    wanted.server.public_url = None;
    let refused = reload_posture_refusal(&running, &wanted).expect("cleared public_url");
    assert!(
        refused.reason.contains("cluster_internal"),
        "{}",
        refused.reason
    );
}

#[test]
fn no_credential_is_not_this_check() {
    let mut c = Config::default();
    c.server.host = "0.0.0.0".to_string();
    c.server.allow_unauthenticated_network_bind = true;
    assert!(cleartext_credential_refusal(&c).is_none());
    assert!(serve_refusal(&c).is_none());
}

/// The enterprise-alpha `ConfigMap` as shipped: it binds `0.0.0.0` with bearer
/// auth and no mTLS, so it starts only through `cluster_internal`.
#[test]
fn the_enterprise_alpha_configmap_starts() {
    let manifest: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../deploy/kubernetes/enterprise-alpha/base/configmap.yaml"
    ))
    .expect("configmap yaml");
    let body = manifest["data"]["gateway.yaml"]
        .as_str()
        .expect("gateway.yaml");
    let c: Config = serde_yaml::from_str(body).expect("gateway.yaml is a Config");
    assert!(
        c.auth.enabled && !c.mtls.enabled,
        "the shape this test is about"
    );
    assert_eq!(c.server.cleartext_http, CleartextHttp::ClusterInternal);
    assert_eq!(serve_refusal(&c), None);
}
