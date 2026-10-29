// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Entry-point rows: both entry points run the check, rescan judges the
//! bytes sent, answers are not path-checked, and no path value leaks into
//! the verdict, the wire text or the audit row (R28, R37, R38, R40, R40b).
//! Batch 2f.

use serde_json::{Value, json};

use super::super::*;
use super::tree::{Fx, Seen, both, code, root_rule, seen, target};
use crate::security::firewall::FirewallVerdict;

const SENTINEL: &str = "SENTINEL-8939-q7";

fn admit(fx: &Fx, args: &Value) -> FirewallVerdict {
    let sender = fx.sender();
    fx.fw.check_request_keyed(
        "s1",
        target("read_file"),
        args,
        "c",
        "id-1",
        sender.as_deref(),
    )
}

fn rescan(fx: &Fx, args: &Value, subject: ScanSubject) -> FirewallVerdict {
    let sender = fx.sender();
    fx.fw
        .rescan(target("read_file"), args, subject, sender.as_deref())
}

/// R28: the route scan saw an inside path, the send carries an outside one:
/// rescan judges what is sent.
#[test]
fn r28_rescan_judges_the_rewritten_arguments() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let checked = json!({"path": fx.path("safe/f")});
    assert_eq!(seen(&admit(&fx, &checked)), Seen::Allowed);
    let sent = json!({"path": fx.path("outside/f")});
    let got = seen(&rescan(&fx, &sent, ScanSubject::Arguments));
    assert_eq!(got, Seen::Outside(FirewallAction::Block));
}

/// R38: the same outside path is refused through `check_request`, the
/// public entry, and through rescan.
#[test]
fn r38_check_request_and_rescan_both_refuse() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let args = json!({"path": fx.path("outside/f")});
    let public = fx
        .fw
        .check_request("s1", "fs", "read_file", &args, "c", "id-1");
    assert_eq!(seen(&public), Seen::Outside(FirewallAction::Block));
    let got = seen(&rescan(&fx, &args, ScanSubject::Arguments));
    assert_eq!(got, Seen::Outside(FirewallAction::Block));
    let inside = json!({"path": fx.path("safe/f")});
    let public = fx
        .fw
        .check_request("s1", "fs", "read_file", &inside, "c", "id-1");
    assert_eq!(seen(&public), Seen::Allowed);
}

/// R40 [keep]: a bridge retry's answers carry no `path`; they are not
/// path-checked, so the retry of an inside call completes. R40b [keep]:
/// content scanning still runs on them.
#[test]
fn r40_r40b_answers_are_content_scanned_only() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    let answers = json!({"approval": "yes"});
    assert_eq!(
        seen(&rescan(&fx, &answers, ScanSubject::Answers)),
        Seen::Allowed
    );
    let hostile = json!({"approval": "; rm -rf / #"});
    let verdict = rescan(&fx, &hostile, ScanSubject::Answers);
    assert!(
        !verdict.allowed,
        "content scanning still refuses: {verdict:?}"
    );
    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.scan_type != ScanType::RootRefused),
        "no root check on answers: {verdict:?}"
    );
}

/// The audit rows a firewall with an audit log wrote, as text.
fn audit_text(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// R37, lead D8 condition 1: a sentinel path value, outside and also refused
/// by shape, never appears in the findings, the wire text or the audit row;
/// the refusal's audit finding carries its reason code.
#[test]
fn r37_no_path_value_leaves_the_check() {
    let log = tempfile::NamedTempFile::new().expect("log");
    let log_path = log.path().to_path_buf();
    let fx = Fx::build(
        |safe| {
            vec![root_rule(
                "read_file",
                &[safe],
                &["path"],
                FirewallAction::Block,
            )]
        },
        |config| config.audit_log = Some(log_path.clone()),
    );
    let outside = json!({"path": fx.path(&format!("outside/{SENTINEL}"))});
    let relative = json!({"path": format!("{SENTINEL}/x")});
    assert_eq!(
        both(&fx, "read_file", &outside),
        Seen::Outside(FirewallAction::Block)
    );
    let not_absolute = Seen::Refused(code(RootReason::NotAbsolute));
    assert_eq!(both(&fx, "read_file", &relative), not_absolute);
    let dir = fx.dir.path().to_string_lossy().into_owned();
    for args in [&outside, &relative] {
        let verdict = admit(&fx, args);
        let findings = serde_json::to_string(&verdict.findings).expect("findings serialise");
        let (_, wire) = verdict.request_refusal().expect("refused");
        for text in [&findings, &wire] {
            assert!(!text.contains(SENTINEL), "value leaked: {text}");
            assert!(!text.contains(&dir), "path leaked: {text}");
        }
    }
    let rows = audit_text(&log_path);
    assert!(!rows.is_empty(), "the refusals were audited");
    assert!(!rows.contains(SENTINEL), "value in the audit row: {rows}");
    assert!(!rows.contains(&dir), "path in the audit row: {rows}");
    assert!(
        rows.contains(r#""reason":"not_absolute""#),
        "the refusal's code is audited: {rows}"
    );
}
