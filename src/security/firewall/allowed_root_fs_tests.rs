// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Folder-check rows on a real temporary tree, through `root_check` and
//! both firewall entry points (test plan r2-final). Batch 2.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::*;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::security::firewall::{
    Firewall, FirewallConfig, FirewallRule, FirewallVerdict, ScanType,
};
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};

pub(super) fn backend(name: &str, transport: TransportConfig) -> Arc<Backend> {
    Arc::new(Backend::new(
        name,
        BackendConfig {
            transport,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

pub(super) fn stdio() -> TransportConfig {
    TransportConfig::Stdio {
        command: "true".to_string(),
        cwd: None,
        protocol_version: None,
    }
}

pub(super) fn root_rule(
    tool: &str,
    roots: &[String],
    args: &[&str],
    action: FirewallAction,
) -> FirewallRule {
    FirewallRule {
        tool_match: tool.to_string(),
        action,
        reason: None,
        scan: Vec::new(),
        servers: None,
        keys: None,
        except: None,
        allowed_roots: Some(roots.to_vec()),
        path_args: Some(args.iter().map(ToString::to_string).collect()),
    }
}

/// A tree with `safe/` (the root) and `outside/`, a registry holding the
/// Stdio backend `fs`, and an empty capability slot. The fixture keeps the
/// registry and slot so a row can change them after the firewall is built.
pub(super) struct Fx {
    pub(super) dir: tempfile::TempDir,
    pub(super) registry: Arc<BackendRegistry>,
    pub(super) slot: CapabilitySlot,
    pub(super) fw: Firewall,
}

impl Fx {
    /// One root rule on `read_file` over `safe/`.
    pub(super) fn new(args: &[&str], action: FirewallAction) -> Self {
        Self::with_rules(|safe| vec![root_rule("read_file", &[safe], args, action)])
    }

    pub(super) fn with_rules(rules: impl FnOnce(String) -> Vec<FirewallRule>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for sub in ["safe", "outside"] {
            std::fs::create_dir(dir.path().join(sub)).expect("mkdir");
        }
        std::fs::write(dir.path().join("safe/f"), "in").expect("write");
        std::fs::write(dir.path().join("outside/f"), "out").expect("write");
        let safe = dir.path().join("safe").to_string_lossy().into_owned();
        let registry = Arc::new(BackendRegistry::new());
        assert!(registry.register(backend("fs", stdio())));
        let slot: CapabilitySlot = Arc::new(parking_lot::RwLock::new(None));
        let config = FirewallConfig {
            rules: rules(safe),
            ..FirewallConfig::default()
        };
        let fw = Firewall::from_config(config, None)
            .with_registries(Arc::clone(&registry), Arc::clone(&slot));
        Self {
            dir,
            registry,
            slot,
            fw,
        }
    }

    /// The absolute spelling of `rel` under the tree, as a backend receives it.
    pub(super) fn path(&self, rel: &str) -> String {
        format!("{}/{rel}", self.dir.path().to_string_lossy())
    }

    pub(super) fn sender(&self) -> Option<Arc<Backend>> {
        self.registry.get("fs")
    }
}

pub(super) const fn target(tool: &str) -> RuleTarget<'_> {
    RuleTarget {
        server: ServerOf::Backend("fs"),
        tool,
        key: KeyOf::NoKey,
    }
}

/// What a caller sees, read only from settled fields: allowed, the action,
/// and a root finding's type. A forced refusal's code is the text before the
/// first `:` of its `root_refused` description (lead D8).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Seen {
    Allowed,
    Outside(FirewallAction),
    Refused(String),
}

pub(super) fn seen(verdict: &FirewallVerdict) -> Seen {
    let of = |t: ScanType| verdict.findings.iter().find(|f| f.scan_type == t);
    if let Some(refusal) = of(ScanType::RootRefused) {
        assert!(!verdict.allowed, "a refusal blocks: {verdict:?}");
        assert_eq!(verdict.action, FirewallAction::Block, "{verdict:?}");
        let code = refusal.description.split(':').next().unwrap_or_default();
        return Seen::Refused(code.to_string());
    }
    if of(ScanType::PathOutsideRoot).is_some() {
        return Seen::Outside(verdict.action);
    }
    assert!(verdict.allowed, "no root finding, yet refused: {verdict:?}");
    Seen::Allowed
}

pub(super) fn code(reason: RootReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .expect("a reason serialises to its code")
}

/// The call through admission and through the chokepoint's rescan, which
/// must agree; returns what both saw.
pub(super) fn both(fx: &Fx, tool: &str, args: &Value) -> Seen {
    let sender = fx.sender();
    let admitted = fx.fw.check_request_keyed(
        "s1",
        target(tool),
        args,
        "caller",
        "id-1",
        sender.as_deref(),
    );
    let rescanned = fx.fw.rescan(
        target(tool),
        args,
        ScanSubject::Arguments,
        sender.as_deref(),
    );
    let (a, r) = (seen(&admitted), seen(&rescanned));
    assert_eq!(a, r, "admission and rescan disagree on {args}");
    a
}

/// `both`, plus the same call under a `warn` copy of the fixture: a forced
/// refusal stays a refusal there.
fn both_warn(args: &[&str], call: impl Fn(&Fx) -> Value) -> Seen {
    let block = Fx::new(args, FirewallAction::Block);
    let got = both(&block, "read_file", &call(&block));
    let warn = Fx::new(args, FirewallAction::Warn);
    let under_warn = both(&warn, "read_file", &call(&warn));
    if let Seen::Refused(_) = got {
        assert_eq!(under_warn, got, "warn softened a forced block");
    }
    got
}

/// R1 [keep], R4: inside allowed, outside refused with the root finding, on
/// the same backend and route.
#[test]
fn r1_r4_inside_allowed_outside_refused() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("safe/f")})),
        Seen::Allowed
    );
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("outside/f")})),
        Seen::Outside(FirewallAction::Block)
    );
}

/// R2, R3 [keep]: a new file and a new nested directory inside are allowed;
/// R7: a new target outside is refused.
#[test]
fn r2_r3_r7_new_paths_judged_by_their_existing_ancestor() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    for inside in ["safe/new.txt", "safe/new/sub/dir"] {
        assert_eq!(
            both(&fx, "read_file", &json!({"path": fx.path(inside)})),
            Seen::Allowed
        );
    }
    assert_eq!(
        both(
            &fx,
            "read_file",
            &json!({"path": fx.path("outside/new.txt")})
        ),
        Seen::Outside(FirewallAction::Block)
    );
}

/// R8: `/data2/x` is not inside `/data`: comparison is by component.
#[test]
fn r8_sibling_with_shared_prefix_is_outside() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    std::fs::create_dir(fx.dir.path().join("safe2")).expect("mkdir");
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("safe/f")})),
        Seen::Allowed
    );
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("safe2/x")})),
        Seen::Outside(FirewallAction::Block)
    );
}

/// R9-R13b, R15 (both, warn): each refused shape names its code; the control
/// is the same argument made absolute and normalised.
#[test]
fn r9_r15_refused_shapes_name_their_code() {
    let na = code(RootReason::NotAbsolute);
    let nn = code(RootReason::NotNormalised);
    let cases: Vec<(&str, Box<dyn Fn(&Fx) -> String>, &String)> = vec![
        ("R9", Box::new(|_| "safe/f".into()), &na),
        ("R10", Box::new(|_| "~/x".into()), &na),
        ("R11", Box::new(|_| "$HOME/x".into()), &na),
        ("R11a", Box::new(|_| "${HOME}/x".into()), &na),
        ("R11b", Box::new(|_| r"%USERPROFILE%\x".into()), &na),
        (
            "R12",
            Box::new(|fx| format!("file://{}", fx.path("safe/f"))),
            &na,
        ),
        ("R12b", Box::new(|_| "file:/x".into()), &na),
        ("R12c", Box::new(|_| "http://x/y".into()), &na),
        ("R13", Box::new(|fx| fx.path("safe/a/../f")), &nn),
        ("R13b", Box::new(|fx| fx.path("safe/./f")), &nn),
        ("R15", Box::new(|fx| fx.path("safe/a\0b")), &nn),
    ];
    for (row, value, want) in &cases {
        let got = both_warn(&["path"], |fx| json!({"path": value(fx)}));
        assert_eq!(got, Seen::Refused((*want).clone()), "{row}");
    }
    let control = Fx::new(&["path"], FirewallAction::Block);
    assert_eq!(
        both(
            &control,
            "read_file",
            &json!({"path": control.path("safe/f")})
        ),
        Seen::Allowed
    );
}
