// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rule rows: which root rules cover a call, through the branch's own
//! `rule_applies` and candidate keys, and how root rules sit beside other
//! rules (R24-R26, R32b, R34-R36b, R39). Batch 2d.

use serde_json::{Value, json};

use super::super::*;
use super::tree::{Fx, Seen, root_rule, seen};
use crate::security::firewall::{FirewallRule, RuleException, ScanType};
use crate::security::response_policy::{KeyOf, RuleTarget, ServerOf};

fn keyed(key: KeyOf<'_>) -> RuleTarget<'_> {
    RuleTarget {
        server: ServerOf::Backend("fs"),
        tool: "read_file",
        key,
    }
}

/// Admission and rescan under `target`; both must agree.
fn call(fx: &Fx, target: RuleTarget<'_>, args: &Value) -> Seen {
    let sender = fx.sender();
    let admitted = fx.fw.check_request_keyed(
        fx.fw.startup_policy(),
        "s1",
        target,
        args,
        "c",
        "id-1",
        sender.as_deref(),
    );
    let rescanned = fx.fw.rescan(
        fx.fw.startup_policy(),
        target,
        args,
        ScanSubject::Arguments,
        sender.as_deref(),
    );
    let (a, r) = (seen(&admitted), seen(&rescanned));
    assert_eq!(a, r, "admission and rescan disagree on {target:?}");
    a
}

fn outside(fx: &Fx) -> Value {
    json!({"path": fx.path("outside/f")})
}

fn block_root(safe: &str) -> FirewallRule {
    root_rule(
        "read_file",
        &[safe.to_string()],
        &["path"],
        FirewallAction::Block,
    )
}

/// R24 [keep]: a tool no root rule covers passes an outside path.
#[test]
fn r24_uncovered_tool_is_not_checked() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let target = RuleTarget {
        tool: "write_note",
        ..keyed(KeyOf::NoKey)
    };
    assert_eq!(call(&fx, target, &outside(&fx)), Seen::Allowed);
}

/// R25: an earlier `match: "*"`, `action: allow`, `scan: []` rule does not
/// neutralise the root rule; R26: of two root rules the most restrictive
/// wins.
#[test]
fn r25_r26_other_rules_do_not_soften_a_root_rule() {
    let fx = Fx::with_rules(|safe| {
        let mut allow_all = root_rule("*", &[], &[], FirewallAction::Allow);
        allow_all.allowed_roots = None;
        allow_all.path_args = None;
        vec![allow_all, block_root(&safe)]
    });
    let got = call(&fx, keyed(KeyOf::NoKey), &outside(&fx));
    assert_eq!(got, Seen::Outside(FirewallAction::Block), "R25");

    let fx = Fx::with_rules(|safe| {
        let warn = root_rule(
            "read_file",
            std::slice::from_ref(&safe),
            &["path"],
            FirewallAction::Warn,
        );
        vec![warn, block_root(&safe)]
    });
    let got = call(&fx, keyed(KeyOf::NoKey), &outside(&fx));
    assert_eq!(got, Seen::Outside(FirewallAction::Block), "R26");
}

/// R32b: a warn root rule does not soften a real request finding in the
/// call it covers: the shell injection still blocks an inside call.
#[test]
fn r32b_warn_root_rule_does_not_soften_content_findings() {
    let fx = Fx::new(&["path"], FirewallAction::Warn);
    let clean = json!({"path": fx.path("safe/f")});
    assert_eq!(call(&fx, keyed(KeyOf::NoKey), &clean), Seen::Allowed);
    let args = json!({"path": fx.path("safe/f"), "cmd": "; rm -rf / #"});
    let sender = fx.sender();
    let verdict = fx.fw.check_request_keyed(
        fx.fw.startup_policy(),
        "s1",
        keyed(KeyOf::NoKey),
        &args,
        "c",
        "id-1",
        sender.as_deref(),
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::ShellInjection),
        "the trigger is real: {verdict:?}"
    );
    assert_eq!(verdict.action, FirewallAction::Block, "{verdict:?}");
}

fn scoped(keys: Option<&[&str]>, except: Option<Vec<RuleException>>) -> Fx {
    Fx::with_rules(|safe| {
        let mut rule = block_root(&safe);
        rule.keys = keys.map(|k| k.iter().map(ToString::to_string).collect());
        rule.except = except;
        vec![rule]
    })
}

fn except_key(server: Option<&str>, key: &str) -> RuleException {
    RuleException {
        server: server.map(str::to_string),
        tool: None,
        key: Some(key.to_string()),
    }
}

/// R34: a `keys`-scoped root rule applies under `NotKnown` when its key is a
/// candidate; R34b [keep]: under `NoKey` it does not apply.
#[test]
fn r34_keys_scope_follows_the_candidates() {
    let fx = scoped(Some(&["k1"]), None);
    let got = call(&fx, keyed(KeyOf::NotKnown), &outside(&fx));
    assert_eq!(got, Seen::Outside(FirewallAction::Block), "R34");
    assert_eq!(call(&fx, keyed(KeyOf::Key("k1")), &outside(&fx)), got);
    assert_eq!(
        call(&fx, keyed(KeyOf::NoKey), &outside(&fx)),
        Seen::Allowed,
        "R34b"
    );
}

/// R35: an `except` naming one possible key does not exempt under `NotKnown`;
/// R36 [keep]: it exempts that exact key; R36b: a server-and-key `except`
/// exempts only when both match.
#[test]
fn r35_r36_except_exempts_only_its_concrete_call() {
    let fx = scoped(None, Some(vec![except_key(None, "k1")]));
    let blocked = Seen::Outside(FirewallAction::Block);
    assert_eq!(
        call(&fx, keyed(KeyOf::NotKnown), &outside(&fx)),
        blocked,
        "R35"
    );
    assert_eq!(
        call(&fx, keyed(KeyOf::Key("k1")), &outside(&fx)),
        Seen::Allowed,
        "R36"
    );

    let fx = scoped(None, Some(vec![except_key(Some("fs"), "k1")]));
    assert_eq!(
        call(&fx, keyed(KeyOf::Key("k1")), &outside(&fx)),
        Seen::Allowed,
        "R36b"
    );
    assert_eq!(
        call(&fx, keyed(KeyOf::Key("k2")), &outside(&fx)),
        blocked,
        "R36b"
    );
    let fx = scoped(None, Some(vec![except_key(Some("other"), "k1")]));
    let got = call(&fx, keyed(KeyOf::Key("k1")), &outside(&fx));
    assert_eq!(got, blocked, "R36b: the key matches, the server does not");
}

/// R39: a serverless `match: "*"` root rule leaves a native tool alone.
#[test]
fn r39_native_tools_are_not_covered() {
    let fx = Fx::with_rules(|safe| vec![root_rule("*", &[safe], &["path"], FirewallAction::Block)]);
    let native = RuleTarget {
        server: ServerOf::NoBackend,
        tool: "gateway_search",
        key: KeyOf::NoKey,
    };
    assert_eq!(call(&fx, native, &json!({"query": "x"})), Seen::Allowed);
    let backend_call = call(&fx, keyed(KeyOf::NoKey), &json!({"other": 1}));
    assert_eq!(
        backend_call,
        Seen::Refused(super::tree::code(RootReason::MissingArgument)),
        "the same rule covers a backend tool"
    );
}

/// R32 (response half): a warn root rule does not soften a credential
/// finding in a covered call's answer; root rules decide only their own
/// findings. Control: no root rule, the same answer blocks too.
#[test]
fn r32_warn_root_rule_does_not_soften_a_response_credential() {
    let token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let answer = || json!({"content": [{"type": "text", "text": format!("key {token}")}]});
    let fx = Fx::new(&["path"], FirewallAction::Warn);
    let verdict = fx
        .fw
        .check_response("s1", "fs", "read_file", &mut answer(), "c");
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::Credentials),
        "the trigger is real: {verdict:?}"
    );
    assert_eq!(verdict.action, FirewallAction::Block, "{verdict:?}");
    let bare = Fx::with_rules(|_| Vec::new());
    let control = bare
        .fw
        .check_response("s1", "fs", "read_file", &mut answer(), "c");
    assert_eq!(control.action, FirewallAction::Block, "{control:?}");
}
