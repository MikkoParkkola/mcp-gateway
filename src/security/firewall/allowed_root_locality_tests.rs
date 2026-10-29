// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Locality rows: which backend a covered call reaches, read live from the
//! real registry and capability slot, and the captured sending instance
//! (test plan r2-final 9.1, R22-R23g, R42). Batch 2c.

use std::sync::Arc;

use serde_json::json;

use super::super::*;
use super::tree::{Fx, Seen, backend, code, seen, stdio};
use crate::backend::Backend;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::TransportConfig;
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};

fn http() -> TransportConfig {
    TransportConfig::Http {
        http_url: "http://127.0.0.1:9/mcp".to_string(),
        streamable_http: Some(true),
        protocol_version: None,
    }
}

fn on(server: &str) -> RuleTarget<'_> {
    RuleTarget {
        server: ServerOf::Backend(server),
        tool: "read_file",
        key: KeyOf::NoKey,
    }
}

/// Admission and rescan on `server`, with `sender` as the instance that
/// would send; both must agree.
fn call(fw: &Firewall, server: &str, path: &str, sender: Option<&Backend>) -> Seen {
    let args = json!({"path": path});
    let admitted = fw.check_request_keyed("s1", on(server), &args, "c", "id-1", sender);
    let rescanned = fw.rescan(on(server), &args, ScanSubject::Arguments, sender);
    let (a, r) = (seen(&admitted), seen(&rescanned));
    assert_eq!(a, r, "admission and rescan disagree on {server}");
    a
}

fn refused(reason: RootReason) -> Seen {
    Seen::Refused(code(reason))
}

/// A capability backend `name` holding one CLI capability, `read_file`.
fn capabilities(name: &str) -> Arc<CapabilityBackend> {
    let definition = crate::capability::parse_capability(
        "name: read_file\ndescription: Read a file.\nproviders:\n  primary:\n    \
         service: cli\n    config:\n      command: cat\n      args: []\n",
    )
    .expect("the fixture capability parses");
    let caps = Arc::new(CapabilityBackend::new(
        name,
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.register_capability(definition)
        .expect("the fixture capability registers");
    caps
}

fn fixture() -> Fx {
    Fx::new(&["path"], FirewallAction::Block)
}

/// R22, R22a (both, warn): an Http or WebSocket backend is `remote_backend`;
/// control: the same name as Stdio is judged and allowed inside.
#[test]
fn r22_remote_transports_are_refused() {
    let ws = TransportConfig::WebSocket {
        ws_url: "ws://127.0.0.1:9/mcp".to_string(),
        protocol_version: None,
    };
    for (row, transport) in [("R22", http()), ("R22a", ws)] {
        for action in [FirewallAction::Block, FirewallAction::Warn] {
            let fx = Fx::new(&["path"], action);
            let inside = fx.path("safe/f");
            assert_eq!(
                call(&fx.fw, "fs", &inside, fx.sender().as_deref()),
                Seen::Allowed
            );
            assert!(fx.registry.register(backend("fs", transport.clone())));
            let got = call(&fx.fw, "fs", &inside, fx.sender().as_deref());
            assert_eq!(got, refused(RootReason::RemoteBackend), "{row} {action:?}");
        }
    }
}

/// R22a (A2A): an A2A backend is `remote_backend` too, under block and warn;
/// control: the same name as Stdio is judged and allowed inside.
#[cfg(feature = "a2a")]
#[test]
fn r22a_a2a_backend_is_refused_as_remote() {
    let a2a = TransportConfig::A2a {
        a2a_url: "http://127.0.0.1:9".to_string(),
        a2a_agent_card_path: None,
    };
    for action in [FirewallAction::Block, FirewallAction::Warn] {
        let fx = Fx::new(&["path"], action);
        let inside = fx.path("safe/f");
        assert_eq!(
            call(&fx.fw, "fs", &inside, fx.sender().as_deref()),
            Seen::Allowed
        );
        assert!(fx.registry.register(backend("fs", a2a.clone())));
        let got = call(&fx.fw, "fs", &inside, fx.sender().as_deref());
        assert_eq!(got, refused(RootReason::RemoteBackend), "A2A {action:?}");
    }
}

/// R23: a server the registry does not hold is `unknown_backend`; R23b: so is
/// every call on a firewall built without the registries.
#[test]
fn r23_r23b_unknown_and_unwired_backends_are_refused() {
    let fx = fixture();
    let inside = fx.path("safe/f");
    assert_eq!(
        call(&fx.fw, "ghost", &inside, None),
        refused(RootReason::UnknownBackend)
    );
    assert_eq!(
        call(&fx.fw, "fs", &inside, fx.sender().as_deref()),
        Seen::Allowed
    );

    let rules = vec![super::tree::root_rule(
        "read_file",
        &[fx.dir.path().join("safe").to_string_lossy().into_owned()],
        &["path"],
        FirewallAction::Block,
    )];
    let unwired = Firewall::from_config(
        FirewallConfig {
            rules,
            ..FirewallConfig::default()
        },
        None,
    );
    assert_eq!(
        call(&unwired, "fs", &inside, None),
        refused(RootReason::UnknownBackend)
    );
}

/// R23c: a Stdio backend added after the firewall is built is judged by its
/// transport; R23d: one reloaded from Stdio to Http is refused after the
/// reload, on the live-lookup route.
#[test]
fn r23c_r23d_registry_changes_are_read_live() {
    let fx = fixture();
    let inside = fx.path("safe/f");
    assert_eq!(
        call(&fx.fw, "late", &inside, None),
        refused(RootReason::UnknownBackend)
    );
    assert!(fx.registry.register(backend("late", stdio())));
    assert_eq!(call(&fx.fw, "late", &inside, None), Seen::Allowed);
    assert!(fx.registry.register(backend("late", http())));
    assert_eq!(
        call(&fx.fw, "late", &inside, None),
        refused(RootReason::RemoteBackend)
    );
}

/// R22b, R23g: a capability backend's call is `capability_not_checkable`
/// even inside, before and after the backend is replaced at runtime.
#[test]
fn r23g_capability_calls_are_not_checkable() {
    let fx = fixture();
    let inside = fx.path("safe/f");
    *fx.slot.write() = Some(capabilities("files"));
    let not_checkable = refused(RootReason::CapabilityNotCheckable);
    assert_eq!(call(&fx.fw, "files", &inside, None), not_checkable);
    *fx.slot.write() = Some(capabilities("files"));
    assert_eq!(call(&fx.fw, "files", &inside, None), not_checkable);
    assert_eq!(
        call(&fx.fw, "fs", &inside, fx.sender().as_deref()),
        Seen::Allowed
    );
}

/// R23f: a capability backend attached at runtime under a config backend's
/// name is `ambiguous_backend`; control: before it is attached, allowed.
#[test]
fn r23f_runtime_name_clash_is_ambiguous() {
    let fx = fixture();
    let inside = fx.path("safe/f");
    assert_eq!(
        call(&fx.fw, "fs", &inside, fx.sender().as_deref()),
        Seen::Allowed
    );
    *fx.slot.write() = Some(capabilities("fs"));
    let got = call(&fx.fw, "fs", &inside, fx.sender().as_deref());
    assert_eq!(got, refused(RootReason::AmbiguousBackend));
}

/// R42: the check classifies the instance that sends, never a fresh lookup.
/// A captured Stdio instance is judged after the registry turns Http; a
/// captured Http instance is refused after the registry turns back.
#[test]
fn r42_the_captured_instance_is_classified() {
    let fx = fixture();
    let inside = fx.path("safe/f");
    let stdio_sender = fx.sender().expect("fs is registered");
    assert!(fx.registry.register(backend("fs", http())));
    assert_eq!(
        call(&fx.fw, "fs", &inside, Some(&stdio_sender)),
        Seen::Allowed
    );
    let http_sender = fx.sender().expect("fs is registered");
    assert!(fx.registry.register(backend("fs", stdio())));
    let got = call(&fx.fw, "fs", &inside, Some(&http_sender));
    assert_eq!(got, refused(RootReason::RemoteBackend));
}
