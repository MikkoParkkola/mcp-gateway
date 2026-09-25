// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Plain HTTP carrying credentials on a network bind (C3, MIK 7570 TRANSPORT.1).
//!
//! `network_bind_refusal` asks whether the tools need a credential. This asks
//! the next question: when they do, whether that credential crosses the
//! network in cleartext. Both run before any listener opens and again on every
//! reload, through [`serve_refusal`].

use super::support::network_bind_refusal;
use crate::config::{CleartextHttp, Config};

/// The non-loopback host `server.public_url` declares, if any.
pub(super) fn declared_public_host(config: &Config) -> Option<String> {
    public_url_host(config).filter(|h| !crate::gateway::router::is_loopback_bind(h))
}

fn public_url_host(config: &Config) -> Option<String> {
    let url = url::Url::parse(config.server.public_url.as_deref()?).ok()?;
    url.host_str().map(str::to_string)
}

/// Where a caller off this machine reaches the listener, or `None` when only
/// loopback can: a non-loopback bind, or a declared non-loopback `public_url`.
pub(super) fn network_exposure(config: &Config) -> Option<String> {
    match declared_public_host(config) {
        Some(host) => Some(format!("the declared public_url host {host}")),
        None if crate::gateway::router::is_loopback_bind(&config.server.host) => None,
        None => Some(format!("the bind address {}", config.server.host)),
    }
}

/// The `public_url` host when it names a Kubernetes Service: exactly
/// `<svc>.<ns>.svc`, optionally followed by `.<cluster_domain>`. Whole labels,
/// so `api.svc.example.com` is not one.
fn service_host(config: &Config) -> Option<String> {
    let host = public_url_host(config)?;
    let domain = config
        .server
        .cluster_domain
        .as_deref()
        .unwrap_or("cluster.local");
    let service = host
        .strip_suffix(domain)
        .and_then(|h| h.strip_suffix('.'))
        .unwrap_or(host.as_str());
    let labels: Vec<&str> = service.split('.').collect();
    let is_service =
        matches!(labels.as_slice(), [svc, ns, "svc"] if !svc.is_empty() && !ns.is_empty());
    is_service.then_some(host)
}

/// Why this gateway must not serve credentials over plain HTTP, if it must not.
///
/// Refuses when the listener is reachable from the network, a credential is
/// accepted over it (`auth`, `agent_auth`, or the key server's OIDC ID tokens),
/// the listener is not TLS (`mtls.enabled`), and `server.cleartext_http` does
/// not say who protects the traffic instead. `allow_unauthenticated_network_bind`
/// does not answer it: that asserts authentication happens upstream, not
/// encryption.
pub(super) fn cleartext_credential_refusal(config: &Config) -> Option<String> {
    let exposure = network_exposure(config)?;
    let credential = if config.auth.enabled {
        "authentication is enabled"
    } else if config.agent_auth.enabled {
        "agent_auth is enabled"
    } else if config.key_server.enabled && config.auth.enabled {
        "the key server is enabled"
    } else {
        return None;
    };
    if config.mtls.enabled {
        return None;
    }
    match config.server.cleartext_http {
        CleartextHttp::Refuse => {}
        CleartextHttp::TlsTerminatedUpstream | CleartextHttp::HostLocalPublish => return None,
        CleartextHttp::ClusterInternal => {
            if service_host(config).is_some() {
                return None;
            }
            let named = public_url_host(config)
                .map_or_else(|| "it is unset".to_string(), |h| format!("it names {h}"));
            return Some(format!(
                "refusing to serve HTTP at {exposure}: server.cleartext_http = cluster_internal \
                 needs server.public_url to name this gateway's Kubernetes Service \
                 (<svc>.<ns>.svc, optionally followed by .<server.cluster_domain>), and {named}. \
                 A caller reaching it by another name comes through something that should \
                 terminate TLS: set server.cleartext_http = tls_terminated_upstream."
            ));
        }
    }
    Some(format!(
        "refusing to serve HTTP at {exposure}: {credential}, so bearer tokens and API keys \
         would cross the network in cleartext. Enable mtls (TLS on this listener), or set \
         server.cleartext_http = tls_terminated_upstream if a proxy terminates TLS in front \
         of this gateway."
    ))
}

/// The WARN every start logs while `server.cleartext_http` is not `refuse`.
pub(super) fn cleartext_http_warning(config: &Config) -> Option<String> {
    let trust = match config.server.cleartext_http {
        CleartextHttp::Refuse => return None,
        CleartextHttp::TlsTerminatedUpstream => {
            "tls_terminated_upstream: this listener serves plain HTTP and relies on a proxy \
             in front of it to terminate TLS"
                .to_string()
        }
        CleartextHttp::ClusterInternal => format!(
            "cluster_internal: credentials reach this listener in plain HTTP over the cluster \
             network, by the Service name {}; the cluster network and its NetworkPolicy are \
             the only protection",
            service_host(config).unwrap_or_else(|| "(none declared)".to_string())
        ),
        CleartextHttp::HostLocalPublish => {
            "host_local_publish: this listener serves plain HTTP and relies on the host \
             publishing its port on loopback only"
                .to_string()
        }
    };
    Some(format!("server.cleartext_http = {trust}."))
}

/// Everything that stops this configuration serving HTTP: the open-tools check,
/// then the cleartext-credential check. The start path, the reload overlay and
/// the restart advice all ask this one question.
#[must_use]
pub fn serve_refusal(config: &Config) -> Option<String> {
    network_bind_refusal(config).or_else(|| cleartext_credential_refusal(config))
}

/// The refusal a config reload must answer: [`serve_refusal`] applied to
/// the configuration that will be IN FORCE if this reload publishes.
///
/// `running` is what the process actually applied, fixed at startup; `wanted` is
/// the file. Only fields a reload applies live are taken from `wanted`, and
/// today that is `server.public_url` alone (cleared when the file omits it).
/// Everything else — `auth`, `agent_auth`, `key_server`, `mtls`, the override,
/// `cleartext_http`, `host` — comes from `running`, because a reload does not
/// apply them: the router snapshots `auth_config` at construction and `config_reload`
/// never touches it.
///
/// That distinction is the whole function. Judging the FILE instead lets an
/// operator who declares a `public_url` and enables authentication in one edit
/// — the remediation this project recommends everywhere — produce a config that
/// reads as safe while the request path is still running the old, permissive
/// auth. The same masking works with `allow_unauthenticated_network_bind`, and
/// with any restart-only input [`serve_refusal`] grows later. Overlaying
/// the live fields onto the running config removes the class: a field that is
/// not applied cannot influence a decision about what is in force.
///
/// Lives here, beside the refusals, because the two must agree about which
/// fields are live and the failure to agree is silent — the overlay would
/// simply judge the wrong config. `config_reload` calls this and not the
/// refusal directly.
///
/// Returns `None` when `running` would ALREADY have been refused, so a reload is
/// only refused for a state it would itself cause. Unreachable on the HTTP path,
/// where startup refused it; reachable off it, since `run_stdio` never runs the
/// check.
///
/// Design: `docs/design/unauthenticated-network-posture.md`, Decision C.
#[must_use]
pub fn reload_posture_refusal(running: &Config, wanted: &Config) -> Option<ReloadPostureRefusal> {
    if serve_refusal(running).is_some() {
        return None;
    }
    let mut effective = running.clone();
    effective
        .server
        .public_url
        .clone_from(&wanted.server.public_url);
    serve_refusal(&effective).map(|reason| ReloadPostureRefusal {
        reason,
        restart_would_also_refuse: serve_refusal(wanted).is_some(),
    })
}

/// Why a reload was refused, and what a restart on the same file would do.
///
/// The second answer is not cosmetic. A file that declares a `public_url` AND
/// enables authentication cannot be applied by a reload — the authentication
/// half needs a restart, so applying it would open the origin gate over a
/// request path still running without a credential — and yet it is exactly
/// right on a restart. Telling that operator to revert would be telling them to
/// undo the fix. Telling the one who declared only a `public_url` that a
/// restart applies it would be worse: their next start would refuse to serve.
pub struct ReloadPostureRefusal {
    /// What is wrong with the configuration that would be in force.
    pub reason: String,
    /// `true` when starting fresh on this same file would refuse to serve.
    pub restart_would_also_refuse: bool,
}

#[cfg(test)]
#[path = "cleartext_tests.rs"]
mod tests;
