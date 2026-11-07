// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision fixture table's row shape: one concrete scenario per decider,
//! each pinning the serialised decision its call records.
//!
//! A row is one `#[tokio::test]` that builds its own gateway, drives one call
//! and hands the serialised decision to [`assert_row`]. Rows are never looped
//! over in one test: a loop names only the first row that fails.

use serde_json::Value;

use super::decision_record::DECISION_VERSION;

/// The rule id a row expects.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RuleId {
    /// The record names exactly this rule.
    Id(&'static str),
    /// The record carries no rule id; the reason documents why (the decider
    /// has no rule to name, or an allow attribution not yet flipped).
    Absent(&'static str),
}

impl RuleId {
    /// A row expecting an id computed at run time (a keyed id differs per
    /// key, so it cannot be a literal). Leaks one short string per row: test
    /// processes end.
    pub(crate) fn named(id: &str) -> Self {
        Self::Id(Box::leak(id.to_owned().into_boxed_str()))
    }
}

/// One expected request finding: scan type, severity, location.
pub(crate) type Finding = (&'static str, &'static str, &'static str);

/// What the request check is expected to have recorded.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Findings {
    /// The check did not run: no `request_findings` key.
    NotRun,
    /// The check ran clean: an empty list.
    Clean,
    /// The check raised exactly these findings, in order.
    Raised(&'static [Finding]),
}

/// One scenario's expected decision. Every field is checked exactly, and an
/// expected absence means the key is missing: a present `null` fails the row.
/// The row also requires `v` to be [`DECISION_VERSION`] and
/// `request_findings_truncated` to be absent (no row truncates). The config
/// fields (`config_revision`, `running_revision`, `pending_restart`) describe
/// the gateway's state, not the decider, and are left to rows that need them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DecisionRow {
    /// The scenario, named in every failure message.
    pub name: &'static str,
    /// `kind`, in its serialised `snake_case` spelling.
    pub kind: &'static str,
    pub rule_id: RuleId,
    pub grant_id: Option<&'static str>,
    pub findings: Findings,
    /// `(declared_effect, declared_effect_source)`, both serialised; `None`
    /// requires both keys absent.
    pub effect: Option<(&'static str, &'static str)>,
    /// `decided`, in its serialised spelling (`fresh` for a live call).
    pub decided: &'static str,
}

/// `decision[key]` is the string `want`, or the key is missing when `want` is
/// `None` (a present null or non-string fails).
fn assert_str_key(decision: &Value, key: &str, want: Option<&str>, n: &str) {
    match want {
        Some(want) => assert_eq!(
            decision.get(key).and_then(Value::as_str),
            Some(want),
            "{n}: {key}: {decision}"
        ),
        None => assert!(
            decision.get(key).is_none(),
            "{n}: {key} must be absent: {decision}"
        ),
    }
}

/// Checks `decision` (one serialised decision object) against `row`.
pub(crate) fn assert_row(decision: &Value, row: &DecisionRow) {
    let n = row.name;
    assert_eq!(
        decision.get("v").and_then(Value::as_u64),
        Some(u64::from(DECISION_VERSION)),
        "{n}: v: {decision}"
    );
    assert_str_key(decision, "kind", Some(row.kind), n);
    match row.rule_id {
        RuleId::Id(id) => assert_str_key(decision, "rule_id", Some(id), n),
        RuleId::Absent(reason) => assert!(
            decision.get("rule_id").is_none(),
            "{n}: rule_id must be absent ({reason}): {decision}"
        ),
    }
    assert_str_key(decision, "grant_id", row.grant_id, n);
    let findings = match row.findings {
        Findings::NotRun => None,
        Findings::Clean => Some(Value::Array(Vec::new())),
        Findings::Raised(want) => Some(
            want.iter()
                .map(|(scan_type, severity, location)| {
                    serde_json::json!({
                        "scan_type": scan_type, "severity": severity, "location": location
                    })
                })
                .collect(),
        ),
    };
    assert_eq!(
        decision.get("request_findings"),
        findings.as_ref(),
        "{n}: request_findings: {decision}"
    );
    assert_str_key(decision, "declared_effect", row.effect.map(|e| e.0), n);
    assert_str_key(
        decision,
        "declared_effect_source",
        row.effect.map(|e| e.1),
        n,
    );
    assert!(
        decision.get("request_findings_truncated").is_none(),
        "{n}: request_findings_truncated must be absent: {decision}"
    );
    assert_str_key(decision, "decided", Some(row.decided), n);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// One edit to a decision, named for the field it changes.
    type Edit = (&'static str, fn(&mut Value));

    /// A row with every optional field present.
    const FULL: DecisionRow = DecisionRow {
        name: "full",
        kind: "tool_policy",
        rule_id: RuleId::Id("r-1"),
        grant_id: Some("g-1"),
        findings: Findings::Raised(&[("secret", "high", "arguments")]),
        effect: Some(("read_only", "tool_annotation")),
        decided: "fresh",
    };

    /// The decision [`FULL`] describes.
    fn full() -> Value {
        json!({"v": DECISION_VERSION, "kind": "tool_policy", "rule_id": "r-1", "grant_id": "g-1",
               "request_findings": [{"scan_type": "secret", "severity": "high", "location": "arguments"}],
               "declared_effect": "read_only", "declared_effect_source": "tool_annotation",
               "decided": "fresh"})
    }

    /// A row with every optional field absent.
    const BARE: DecisionRow = DecisionRow {
        name: "bare",
        kind: "default_allow",
        rule_id: RuleId::Absent("default allow names no rule"),
        grant_id: None,
        findings: Findings::NotRun,
        effect: None,
        decided: "fresh",
    };

    /// The decision [`BARE`] describes.
    fn bare() -> Value {
        json!({"v": DECISION_VERSION, "kind": "default_allow", "decided": "fresh"})
    }

    fn fails(decision: &Value, row: &DecisionRow) -> bool {
        std::panic::catch_unwind(|| assert_row(decision, row)).is_err()
    }

    fn remove(d: &mut Value, key: &str) {
        d.as_object_mut().expect("an object").remove(key);
    }

    #[test]
    fn a_matching_decision_passes() {
        assert_row(&full(), &FULL);
        assert_row(&bare(), &BARE);
    }

    /// Every pinned field fails the full row when its value changes or its
    /// key is removed.
    #[test]
    fn every_pinned_field_fails_the_full_row_when_it_differs() {
        let edits: [Edit; 21] = [
            ("v", |d| d["v"] = json!(1)),
            ("v removed", |d| remove(d, "v")),
            ("kind", |d| d["kind"] = json!("firewall")),
            ("kind removed", |d| remove(d, "kind")),
            ("rule_id", |d| d["rule_id"] = json!("r-2")),
            ("rule_id removed", |d| remove(d, "rule_id")),
            ("grant_id", |d| d["grant_id"] = json!("g-2")),
            ("grant_id removed", |d| remove(d, "grant_id")),
            ("findings removed", |d| remove(d, "request_findings")),
            ("findings clean", |d| d["request_findings"] = json!([])),
            ("finding scan type", |d| {
                d["request_findings"][0]["scan_type"] = json!("injection");
            }),
            ("finding added", |d| {
                let extra = d["request_findings"][0].clone();
                d["request_findings"]
                    .as_array_mut()
                    .expect("a list")
                    .push(extra);
            }),
            ("finding severity", |d| {
                d["request_findings"][0]["severity"] = json!("low");
            }),
            ("finding location", |d| {
                d["request_findings"][0]["location"] = json!("tool");
            }),
            ("effect", |d| d["declared_effect"] = json!("may_write")),
            ("effect removed", |d| remove(d, "declared_effect")),
            ("effect source", |d| {
                d["declared_effect_source"] = json!("capability_definition");
            }),
            ("effect source removed", |d| {
                remove(d, "declared_effect_source");
            }),
            ("decided", |d| d["decided"] = json!("replayed")),
            ("decided removed", |d| remove(d, "decided")),
            ("truncated", |d| {
                d["request_findings_truncated"] = json!(true);
            }),
        ];
        for (field, edit) in edits {
            let mut decision = full();
            edit(&mut decision);
            assert!(
                fails(&decision, &FULL),
                "a changed {field} passed: {decision}"
            );
        }
    }

    /// Every expected absence fails the bare row when the key is present,
    /// with a value or as null.
    #[test]
    fn every_expected_absence_fails_on_a_present_key_or_null() {
        for key in [
            "rule_id",
            "grant_id",
            "request_findings",
            "declared_effect",
            "declared_effect_source",
            "request_findings_truncated",
        ] {
            for value in [json!("x"), Value::Null] {
                let mut decision = bare();
                decision[key] = value;
                assert!(
                    fails(&decision, &BARE),
                    "a present {key} passed: {decision}"
                );
            }
        }
    }

    /// A clean row needs an empty list: absent and raised both fail it.
    #[test]
    fn a_clean_row_needs_an_empty_findings_list() {
        let row = DecisionRow {
            findings: Findings::Clean,
            ..BARE
        };
        let mut decision = bare();
        assert!(fails(&decision, &row), "absent findings passed a clean row");
        decision["request_findings"] = json!([]);
        assert_row(&decision, &row);
        decision["request_findings"] =
            json!([{"scan_type": "secret", "severity": "high", "location": "arguments"}]);
        assert!(fails(&decision, &row), "a finding passed a clean row");
    }

    /// A capability-defined effect is expressible and pinned by its source.
    #[test]
    fn an_effect_row_pins_its_source() {
        let row = DecisionRow {
            effect: Some(("may_write", "capability_definition")),
            ..BARE
        };
        let mut decision = bare();
        decision["declared_effect"] = json!("may_write");
        decision["declared_effect_source"] = json!("capability_definition");
        assert_row(&decision, &row);
        decision["declared_effect_source"] = json!("tool_annotation");
        assert!(fails(&decision, &row), "the wrong source passed");
    }

    /// Raised findings are compared in order.
    #[test]
    fn raised_findings_are_pinned_in_order() {
        let row = DecisionRow {
            findings: Findings::Raised(&[
                ("secret", "high", "arguments"),
                ("injection", "medium", "arguments"),
            ]),
            ..BARE
        };
        let secret = json!({"scan_type": "secret", "severity": "high", "location": "arguments"});
        let injection =
            json!({"scan_type": "injection", "severity": "medium", "location": "arguments"});
        let mut decision = bare();
        decision["request_findings"] = json!([secret, injection]);
        assert_row(&decision, &row);
        decision["request_findings"] = json!([injection, secret]);
        assert!(fails(&decision, &row), "reordered findings passed");
    }
}
