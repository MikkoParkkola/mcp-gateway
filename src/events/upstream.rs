// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Upstream-notification events (MIK-7630 I5, design
//! `docs/design/2026-10-02-mik-7630-i5-upstream-listener.md`): the three
//! event names a backend's `resources/updated`, `resources/list_changed` and
//! `prompts/list_changed` become, and which backends cannot offer them (§6,
//! §11 D2/D3). A subscription to one of them on such a backend is refused
//! with the reason, never accepted and left silent.

use std::collections::BTreeMap;

use crate::config::{BackendConfig, Config, TransportConfig};

/// The three upstream-notification event kinds (design §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    ResourceUpdated,
    ResourcesChanged,
    PromptsChanged,
}

impl Kind {
    const ALL: [Self; 3] = [
        Self::ResourceUpdated,
        Self::ResourcesChanged,
        Self::PromptsChanged,
    ];

    /// The last segment of the event name.
    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            Self::ResourceUpdated => "resource_updated",
            Self::ResourcesChanged => "resources_changed",
            Self::PromptsChanged => "prompts_changed",
        }
    }
}

/// `backend.<x>.<kind>` as `(x, kind)`. Split on the known suffix, not on
/// the first dot, so a dotted backend name round-trips.
pub(crate) fn parse_name(name: &str) -> Option<(&str, Kind)> {
    let rest = name.strip_prefix("backend.")?;
    Kind::ALL.into_iter().find_map(|kind| {
        let backend = rest.strip_suffix(kind.suffix())?.strip_suffix('.')?;
        (!backend.is_empty()).then_some((backend, kind))
    })
}

/// Why a backend offers no upstream-notification events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ineligible {
    /// An `http_url` without `streamable_http: true`: the SSE-handshake
    /// transport, whose GET stream is read only up to its `endpoint` event
    /// (design §11 D2).
    SseHandshake,
    /// A2A carries no MCP notifications (D2).
    #[cfg_attr(not(feature = "a2a"), allow(dead_code, reason = "a2a feature off"))]
    A2a,
    /// The backend is reached with the caller's propagated identity; the
    /// shared listener would observe under the gateway's own (D3).
    IdentityPropagation,
    /// The backend's credential is one person's (a per-user OAuth login) and
    /// the gateway serves several callers (D3). A personal account compiles
    /// to identity propagation and is refused as that.
    PerUserCredential,
}

impl Ineligible {
    /// The wire value of `data.reason`.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SseHandshake => "sse_handshake_transport",
            Self::A2a => "a2a_transport",
            Self::IdentityPropagation => "identity_propagation",
            Self::PerUserCredential => "per_user_credential",
        }
    }
}

/// Every configured backend that cannot offer the events, with the reason.
/// Read from config alone, so asking never starts a backend.
pub(crate) fn ineligible_backends(config: &Config) -> BTreeMap<String, Ineligible> {
    // Account references compile into the configuration a backend runs with
    // (a `shared` descriptor drops its reference, an external one becomes
    // identity propagation); judge that, not the raw text. The live config
    // passed validation, so a compile error cannot occur here; the raw
    // config is the fallback all the same.
    let bound = crate::config::account_bindings::compile(config).unwrap_or_default();
    let multi_user = config
        .auth
        .implies_multi_user(!config.key_server.oidc.is_empty());
    config
        .backends
        .iter()
        // A disabled backend is absent, not refused: naming its reason would
        // tell a caller what is configured but switched off.
        .filter(|(_, raw)| raw.enabled)
        .filter_map(|(name, raw)| {
            let effective = bound.get(name).map(|b| b.effective(raw));
            reason(effective.as_ref().unwrap_or(raw), multi_user).map(|r| (name.clone(), r))
        })
        .collect()
}

/// The first reason `backend` cannot offer the events, if any.
fn reason(backend: &BackendConfig, multi_user: bool) -> Option<Ineligible> {
    match &backend.transport {
        TransportConfig::Http {
            streamable_http: false,
            ..
        } => return Some(Ineligible::SseHandshake),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => return Some(Ineligible::A2a),
        _ => {}
    }
    if backend.identity_propagation.is_some() {
        return Some(Ineligible::IdentityPropagation);
    }
    let personal = backend
        .oauth
        .as_ref()
        .is_some_and(|o| o.enabled && !o.shared_account)
        || backend.account.is_some();
    (multi_user && personal).then_some(Ineligible::PerUserCredential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_parse_on_the_known_suffix() {
        assert_eq!(
            parse_name("backend.x.resource_updated"),
            Some(("x", Kind::ResourceUpdated))
        );
        assert_eq!(
            parse_name("backend.a.b.prompts_changed"),
            Some(("a.b", Kind::PromptsChanged))
        );
        assert_eq!(
            parse_name("backend.x.resources_changed"),
            Some(("x", Kind::ResourcesChanged))
        );
        for other in [
            "backend.x.tools_changed",
            "backend..resources_changed",
            "backend.resources_changed",
            "backend.xresources_changed",
            "webhook.x.resources_changed",
        ] {
            assert_eq!(parse_name(other), None, "{other}");
        }
    }

    fn backend(yaml: &str) -> BackendConfig {
        serde_yaml::from_str(yaml).expect("backend config")
    }

    #[test]
    fn each_reason_is_found_and_the_eligible_pass() {
        let sse = backend("http_url: http://h/sse");
        assert_eq!(reason(&sse, false), Some(Ineligible::SseHandshake));
        let idp = backend(
            "http_url: http://h/mcp\nstreamable_http: true\nidentity_propagation:\n  \
             strategy: passthrough\n  audience: https://a\n  session_mode: per_user\n",
        );
        assert_eq!(reason(&idp, false), Some(Ineligible::IdentityPropagation));
        let oauth =
            backend("http_url: http://h/mcp\nstreamable_http: true\noauth:\n  enabled: true\n");
        assert_eq!(reason(&oauth, true), Some(Ineligible::PerUserCredential));
        assert_eq!(
            reason(&oauth, false),
            None,
            "single user: the login is theirs"
        );
        let streamable = backend("http_url: http://h/mcp\nstreamable_http: true");
        assert_eq!(reason(&streamable, true), None);
        assert_eq!(reason(&backend("command: echo"), true), None);
        assert_eq!(reason(&backend("ws_url: ws://h/ws"), true), None);
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn a2a_is_refused() {
        assert_eq!(
            reason(&backend("a2a_url: http://h"), false),
            Some(Ineligible::A2a)
        );
    }
}
