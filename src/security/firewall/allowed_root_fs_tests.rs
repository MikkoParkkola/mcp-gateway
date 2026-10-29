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
        Self::build(rules, |_| {})
    }

    /// [`Self::with_rules`], with `tweak` applied to the config first.
    pub(super) fn build(
        rules: impl FnOnce(String) -> Vec<FirewallRule>,
        tweak: impl FnOnce(&mut FirewallConfig),
    ) -> Self {
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
        let mut config = FirewallConfig {
            rules: rules(safe),
            ..FirewallConfig::default()
        };
        tweak(&mut config);
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
    type Spell = Box<dyn Fn(&Fx) -> String>;
    let cases: Vec<(&str, Spell, &String)> = vec![
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

fn many(args: &[&str], action: FirewallAction) -> Fx {
    Fx::with_rules(|safe| vec![root_rule("read_multiple_files", &[safe], args, action)])
}

fn refused(reason: RootReason) -> Seen {
    Seen::Refused(code(reason))
}

/// R1b: eight inside paths in one array are all checked and allowed;
/// R17: one outside element refuses the call.
#[test]
fn r1b_r17_array_values_each_checked() {
    let fx = many(&["paths[]"], FirewallAction::Block);
    let inside: Vec<String> = (0..8).map(|i| fx.path(&format!("safe/n{i}"))).collect();
    let call = |paths: &[String]| both(&fx, "read_multiple_files", &json!({"paths": paths}));
    assert_eq!(call(&inside), Seen::Allowed);
    let mut one_out = inside;
    one_out[3] = fx.path("outside/f");
    assert_eq!(call(&one_out), Seen::Outside(FirewallAction::Block));
}

/// R18: a nested `a.b` argument is judged; its sibling keys are not.
#[test]
fn r18_nested_argument_outside() {
    let fx = Fx::new(&["opts.target"], FirewallAction::Block);
    let call = |p: &str| {
        both(
            &fx,
            "read_file",
            &json!({"opts": {"target": fx.path(p), "note": "/outside/f"}}),
        )
    };
    assert_eq!(call("safe/f"), Seen::Allowed);
    assert_eq!(call("outside/f"), Seen::Outside(FirewallAction::Block));
}

/// R19 (both, warn): the wrong type is refused; control: the right type.
#[test]
fn r19_wrong_type_is_refused() {
    let wrong = code(RootReason::WrongType);
    let got = both_warn(&["path"], |_| json!({"path": {"nested": "/x"}}));
    assert_eq!(got, Seen::Refused(wrong.clone()));
    let fx = many(&["paths[]"], FirewallAction::Block);
    let mixed = json!({"paths": [fx.path("safe/f"), 3]});
    assert_eq!(
        both(&fx, "read_multiple_files", &mixed),
        Seen::Refused(wrong)
    );
    let right = json!({"paths": [fx.path("safe/f")]});
    assert_eq!(both(&fx, "read_multiple_files", &right), Seen::Allowed);
}

/// R20 (both, warn): a declared argument omitted without `?` is refused;
/// R21, R21b [keep]: omitted with `?` it is allowed.
#[test]
fn r20_r21_omission_follows_the_optional_mark() {
    let got = both_warn(&["path"], |_| json!({"other": 1}));
    assert_eq!(got, refused(RootReason::MissingArgument));
    let fx = Fx::new(&["path?"], FirewallAction::Block);
    assert_eq!(both(&fx, "read_file", &json!({"other": 1})), Seen::Allowed);
    let fx = many(&["paths[]?"], FirewallAction::Block);
    assert_eq!(both(&fx, "read_multiple_files", &json!({})), Seen::Allowed);
}

/// R27: under `warn` an outside path passes with the root finding.
#[test]
fn r27_warn_passes_outside_with_a_finding() {
    let fx = Fx::new(&["path"], FirewallAction::Warn);
    let args = json!({"path": fx.path("outside/f")});
    assert_eq!(
        both(&fx, "read_file", &args),
        Seen::Outside(FirewallAction::Warn)
    );
    let sender = fx.sender();
    let verdict = fx.fw.check_request_keyed(
        "s1",
        target("read_file"),
        &args,
        "c",
        "id-1",
        sender.as_deref(),
    );
    assert!(verdict.allowed, "warn lets it through: {verdict:?}");
}

/// R29: `scan_requests: false` switches content scanning off, never the
/// folder check.
#[test]
fn r29_scan_requests_off_still_checks() {
    let fx = Fx::build(
        |safe| {
            vec![root_rule(
                "read_file",
                &[safe],
                &["path"],
                FirewallAction::Block,
            )]
        },
        |config| config.scan_requests = false,
    );
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("safe/f")})),
        Seen::Allowed
    );
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("outside/f")})),
        Seen::Outside(FirewallAction::Block)
    );
}

/// R31 (both, warn): a root that does not resolve refuses every call, so a
/// broken rule never degrades to a warning. Control: R1's resolving root.
#[test]
fn r31_unresolvable_root_refuses() {
    for action in [FirewallAction::Block, FirewallAction::Warn] {
        let fx = Fx::with_rules(|safe| {
            let gone = format!("{safe}-missing");
            vec![root_rule("read_file", &[gone], &["path"], action)]
        });
        let got = both(&fx, "read_file", &json!({"path": fx.path("safe/f")}));
        assert_eq!(got, refused(RootReason::RootUnresolvable), "{action:?}");
    }
}

/// R13c: `/outside/link -> /safe/sub`, value `/outside/link/../secret`: the
/// `..` is refused before any link is read.
#[cfg(unix)]
#[test]
fn r13c_dot_dot_through_a_link_is_not_normalised() {
    let got = both_warn(&["path"], |fx| {
        std::fs::create_dir_all(fx.dir.path().join("safe/sub")).expect("mkdir");
        let link = fx.dir.path().join("outside/link");
        if !link.exists() {
            std::os::unix::fs::symlink(fx.dir.path().join("safe/sub"), &link).expect("link");
        }
        json!({"path": fx.path("outside/link/../secret")})
    });
    assert_eq!(got, refused(RootReason::NotNormalised));
}

/// R6: a link inside pointing outside is outside; R30 [keep]: a root that is
/// itself a link is judged by its target.
#[cfg(unix)]
#[test]
fn r6_r30_links_are_judged_by_their_targets() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let out = fx.dir.path().join("outside/f");
    std::os::unix::fs::symlink(&out, fx.dir.path().join("safe/out")).expect("link");
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("safe/out")})),
        Seen::Outside(FirewallAction::Block)
    );
    assert_eq!(
        both(&fx, "read_file", &json!({"path": fx.path("safe/f")})),
        Seen::Allowed
    );

    let linked = Fx::with_rules(|safe| {
        let root = format!("{safe}-link");
        std::os::unix::fs::symlink(&safe, &root).expect("root link");
        vec![root_rule(
            "read_file",
            &[root],
            &["path"],
            FirewallAction::Block,
        )]
    });
    let real = linked.path("safe/f");
    assert_eq!(
        both(&linked, "read_file", &json!({"path": real})),
        Seen::Allowed
    );
}

/// R33 (both, warn): a dangling link inside is `dangling_link`, never absent,
/// so a write through it is refused; R33b: a link loop is `unresolvable`.
#[cfg(unix)]
#[test]
fn r33_r33b_broken_links_are_refused() {
    let dangling = both_warn(&["path"], |fx| {
        let link = fx.dir.path().join("safe/dangle");
        if std::fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(fx.dir.path().join("outside/new.txt"), &link).expect("link");
        }
        json!({"path": fx.path("safe/dangle")})
    });
    assert_eq!(dangling, refused(RootReason::DanglingLink));
    let looped = both_warn(&["path"], |fx| {
        let link = fx.dir.path().join("safe/loop");
        if std::fs::symlink_metadata(&link).is_err() {
            std::os::unix::fs::symlink(&link, &link).expect("loop");
        }
        json!({"path": fx.path("safe/loop/x")})
    });
    assert_eq!(looped, refused(RootReason::Unresolvable));
}
