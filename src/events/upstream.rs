// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Upstream-notification events (MIK-7630 I5, design
//! `docs/design/2026-10-02-mik-7630-i5-upstream-listener.md`): the three
//! event names a backend's `resources/updated`, `resources/list_changed` and
//! `prompts/list_changed` become, and which backends cannot offer them (§6,
//! §11 D2/D3). A subscription to one of them on such a backend is refused
//! with the reason, never accepted and left silent.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::backend::BackendRegistry;
use crate::config::{BackendConfig, Config, TransportConfig};

/// The upstream-notification event kinds (design §1, §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    ResourceUpdated,
    ResourcesChanged,
    PromptsChanged,
    ToolsChanged,
}

impl Kind {
    const ALL: [Self; 4] = [
        Self::ResourceUpdated,
        Self::ResourcesChanged,
        Self::PromptsChanged,
        Self::ToolsChanged,
    ];

    /// The last segment of the event name.
    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            Self::ResourceUpdated => "resource_updated",
            Self::ResourcesChanged => "resources_changed",
            Self::PromptsChanged => "prompts_changed",
            Self::ToolsChanged => "tools_changed",
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
    /// The SSE-handshake transport, whose GET stream is read only up to its
    /// `endpoint` event (design §11 D2): the transport the backend's live
    /// connection detected, or, with none live, an explicit
    /// `streamable_http: false` (MIK-7969).
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

/// Whether the process serves several callers, by the auth posture it is
/// running: a reload of a restart-only auth field changes nothing until a
/// restart, here as in the meta route's isolation guard.
pub(crate) fn multi_user(running: &Config) -> bool {
    running
        .auth
        .implies_multi_user(!running.key_server.oidc.is_empty())
}

/// How the live config and the live connections judge one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Judged {
    /// It cannot offer the events.
    Refused(Ineligible),
    /// It is reached over HTTP and no live connection has detected which
    /// transport answers, so the answer waits for a connect (MIK-7969).
    Unresolved,
}

/// The HTTP flavour each backend's live connection detected, by name.
pub(crate) type Detected<'a> = &'a dyn Fn(&str) -> Option<bool>;

/// The flavour `registry`'s backends detected, read live at each call.
pub(crate) fn detected_in(registry: &BackendRegistry) -> impl Fn(&str) -> Option<bool> + '_ {
    |name| registry.get(name).and_then(|b| b.connected_streamable())
}

/// The backends the live config and the live connections make ineligible,
/// re-read at every call: the one predicate the events source and its
/// listeners share, so a reload or a transport switch is seen at the next use
/// (MIK-7894, MIK-7969). An unresolved backend is not among them.
pub(crate) fn live_ineligible(
    live: Arc<crate::config_reload::LiveConfig>,
    registry: Arc<BackendRegistry>,
) -> super::backend_source::Ineligible {
    Arc::new(move || {
        ineligible_backends(
            &live.get(),
            multi_user(live.running()),
            &detected_in(&registry),
        )
        .into_keys()
        .collect()
    })
}

/// Every configured backend that cannot offer the events, with the reason.
/// Never starts a backend.
pub(crate) fn ineligible_backends(
    config: &Config,
    multi_user: bool,
    detected: Detected<'_>,
) -> BTreeMap<String, Ineligible> {
    refused(judged_backends(config, multi_user, detected))
}

/// The definite refusals of a judged set; an unresolved backend is not one.
pub(crate) fn refused(judged: BTreeMap<String, Judged>) -> BTreeMap<String, Ineligible> {
    judged
        .into_iter()
        .filter_map(|(name, judged)| match judged {
            Judged::Refused(reason) => Some((name, reason)),
            Judged::Unresolved => None,
        })
        .collect()
}

/// Every configured backend that cannot offer the events yet, refused or
/// unresolved. Never starts a backend.
pub(crate) fn judged_backends(
    config: &Config,
    multi_user: bool,
    detected: Detected<'_>,
) -> BTreeMap<String, Judged> {
    // Account references compile into the configuration a backend runs with
    // (a `shared` descriptor drops its reference, an external one becomes
    // identity propagation); judge that, not the raw text. The live config
    // passed validation, so a compile error cannot occur here; the raw
    // config is the fallback all the same.
    let bound = crate::config::account_bindings::compile(config).unwrap_or_default();
    config
        .backends
        .iter()
        // A disabled backend is absent, not refused: naming its reason would
        // tell a caller what is configured but switched off.
        .filter(|(_, raw)| raw.enabled)
        .filter_map(|(name, raw)| {
            let effective = bound.get(name).map(|b| b.effective(raw));
            judge(
                effective.as_ref().unwrap_or(raw),
                multi_user,
                detected(name),
            )
            .map(|j| (name.clone(), j))
        })
        .collect()
}

/// Why `backend` cannot offer the events yet, if it cannot. The identity
/// reasons come first, so a subscribe never connects a backend they refuse.
fn judge(backend: &BackendConfig, multi_user: bool, detected: Option<bool>) -> Option<Judged> {
    #[cfg(feature = "a2a")]
    if matches!(backend.transport, TransportConfig::A2a { .. }) {
        return Some(Judged::Refused(Ineligible::A2a));
    }
    if backend.identity_propagation.is_some() {
        return Some(Judged::Refused(Ineligible::IdentityPropagation));
    }
    let personal = backend
        .oauth
        .as_ref()
        .is_some_and(|o| o.enabled && !o.shared_account)
        || backend.account.is_some();
    if multi_user && personal {
        return Some(Judged::Refused(Ineligible::PerUserCredential));
    }
    let TransportConfig::Http {
        streamable_http, ..
    } = &backend.transport
    else {
        return None;
    };
    // The live connection decides, whatever the key says: a fallback may have
    // switched transport (ELIG.3). With none live, only an explicit `false`
    // is known; an unset key or an explicit `true` may still fall back.
    match detected.or(streamable_http.filter(|s| !s)) {
        Some(true) => None,
        Some(false) => Some(Judged::Refused(Ineligible::SseHandshake)),
        None => Some(Judged::Unresolved),
    }
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
        assert_eq!(
            parse_name("backend.x.tools_changed"),
            Some(("x", Kind::ToolsChanged))
        );
        for other in [
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

    const SSE: Option<Judged> = Some(Judged::Refused(Ineligible::SseHandshake));

    #[test]
    fn each_reason_is_found_and_the_eligible_pass() {
        let idp = backend(
            "http_url: http://h/mcp\nstreamable_http: true\nidentity_propagation:\n  \
             strategy: passthrough\n  audience: https://a\n  session_mode: per_user\n",
        );
        assert_eq!(
            judge(&idp, false, Some(true)),
            Some(Judged::Refused(Ineligible::IdentityPropagation))
        );
        let oauth =
            backend("http_url: http://h/mcp\nstreamable_http: true\noauth:\n  enabled: true\n");
        assert_eq!(
            judge(&oauth, true, Some(true)),
            Some(Judged::Refused(Ineligible::PerUserCredential))
        );
        assert_eq!(
            judge(&oauth, false, Some(true)),
            None,
            "single user: the login is theirs"
        );
        assert_eq!(judge(&backend("command: echo"), true, None), None);
        assert_eq!(judge(&backend("ws_url: ws://h/ws"), true, None), None);
    }

    /// MIK-7969: the live connection decides; with none, only an explicit
    /// `false` is known.
    #[test]
    fn an_http_backend_is_judged_by_its_live_transport() {
        let unset = backend("http_url: http://h/mcp");
        let on = backend("http_url: http://h/mcp\nstreamable_http: true");
        let off = backend("http_url: http://h/mcp\nstreamable_http: false");
        for config in [&unset, &on, &off] {
            assert_eq!(judge(config, true, Some(true)), None, "{config:?}");
            assert_eq!(judge(config, true, Some(false)), SSE, "{config:?}");
        }
        assert_eq!(judge(&unset, false, None), Some(Judged::Unresolved));
        assert_eq!(judge(&on, false, None), Some(Judged::Unresolved));
        assert_eq!(judge(&off, false, None), SSE);
    }

    /// The identity reasons come before the transport, so a subscribe never
    /// connects a backend they refuse.
    #[test]
    fn identity_is_judged_before_the_transport() {
        let idp = backend(
            "http_url: http://h/mcp\nidentity_propagation:\n  \
             strategy: passthrough\n  audience: https://a\n  session_mode: per_user\n",
        );
        for detected in [None, Some(false)] {
            assert_eq!(
                judge(&idp, false, detected),
                Some(Judged::Refused(Ineligible::IdentityPropagation))
            );
        }
    }

    /// The refused set leaves the unresolved out; the judged set has both.
    #[test]
    fn only_definite_refusals_are_ineligible() {
        let config: Config = serde_yaml::from_str(
            "backends:\n  u:\n    http_url: http://h/mcp\n  \
             s:\n    http_url: http://h/mcp\n    streamable_http: false\n",
        )
        .expect("config");
        let none = |_: &str| None;
        let refused = ineligible_backends(&config, false, &none);
        assert_eq!(refused.get("s"), Some(&Ineligible::SseHandshake));
        assert_eq!(refused.get("u"), None);
        let judged = judged_backends(&config, false, &none);
        assert_eq!(judged.get("u"), Some(&Judged::Unresolved));
        let live = |name: &str| (name == "u").then_some(false);
        assert_eq!(
            ineligible_backends(&config, false, &live).get("u"),
            Some(&Ineligible::SseHandshake)
        );
    }

    /// Accounts compile before the verdict: a personal or external account
    /// is identity propagation whatever the auth posture, a shared one is
    /// the static credential it names.
    #[test]
    fn account_bindings_are_judged_as_they_compile() {
        let yaml = "accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
             deployment: single_process\n  instance_id: gw\n  store_dir: /nonexistent/s\n  \
             authority_dir: /nonexistent/a\n  current_key_id: current\n  \
             keys:\n    current: env:UNUSED\n  \
             descriptors:\n    \
             mine:\n      mode: personal_managed\n      provider: p\n      \
             resource: https://api.example.invalid/\n      \
             issuer: https://issuer.example.invalid\n      \
             authorization_endpoint: https://issuer.example.invalid/authorize\n      \
             token_endpoint: https://issuer.example.invalid/token\n      \
             client_id: c\n      redirect_uri: https://gw.example.invalid/cb\n      \
             scopes: [s]\n      send_resource_parameter: true\n    \
             theirs:\n      mode: external\n      provider: p\n      \
             resource: https://external.example.invalid/\n      \
             issuer: https://issuer.example.invalid\n      \
             external_strategy:\n        strategy: token_exchange\n        \
             audience: https://external.example.invalid/\n        \
             session_mode: stateless\n        required: true\n        \
             token_exchange_endpoint: https://issuer.example.invalid/exchange\n    \
             ours:\n      mode: shared\n      provider: p\n\
             backends:\n  \
             a:\n    http_url: http://h/mcp\n    streamable_http: true\n    account: mine\n  \
             b:\n    http_url: http://h/mcp\n    streamable_http: true\n    account: theirs\n  \
             c:\n    http_url: http://h/mcp\n    streamable_http: true\n    account: ours\n  \
             off:\n    http_url: http://h/sse\n    enabled: false\n";
        let config: Config = serde_yaml::from_str(yaml).expect("config");
        crate::config::account_bindings::compile(&config).expect("the fixture compiles");
        for multi_user in [false, true] {
            let refused = ineligible_backends(&config, multi_user, &|_| None);
            assert_eq!(refused.get("a"), Some(&Ineligible::IdentityPropagation));
            assert_eq!(refused.get("b"), Some(&Ineligible::IdentityPropagation));
            assert_eq!(
                refused.get("c"),
                None,
                "shared: the gateway's own credential"
            );
            assert_eq!(refused.get("off"), None, "disabled is absent, not refused");
        }
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn a2a_is_refused() {
        assert_eq!(
            judge(&backend("a2a_url: http://h"), false, None),
            Some(Judged::Refused(Ineligible::A2a))
        );
    }
}
