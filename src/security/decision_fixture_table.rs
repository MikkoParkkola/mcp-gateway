//! The decision fixture table's row shape: one concrete scenario per decider,
//! each pinning the serialised decision its call records.
//!
//! A row is one `#[tokio::test]` that builds its own gateway, drives one call
//! and hands the serialised decision to [`assert_row`]. Rows are never looped
//! over in one test: a loop names only the first row that fails.

use serde_json::Value;

/// The rule id a row expects.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RuleId {
    /// The record names exactly this rule.
    Id(&'static str),
    /// The record carries no rule id; the reason documents why (the decider
    /// has no rule to name, or an allow attribution not yet flipped).
    Absent(&'static str),
}

/// What the request check is expected to have recorded.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Findings {
    /// The check did not run: no `request_findings` key.
    NotRun,
    /// The check ran clean: an empty list.
    Clean,
    /// The check raised findings of exactly these scan types, in order.
    /// Severity and location are not pinned: no row in the table carries a
    /// finding yet; a row that does pins them in its own assertions.
    Raised(&'static [&'static str]),
}

/// One scenario's expected decision. Every field is checked exactly; an
/// absent value means the key is absent, never null. `request_findings_truncated`
/// must be absent (no row truncates).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DecisionRow {
    /// The scenario, named in every failure message.
    pub name: &'static str,
    /// `kind`, in its serialised `snake_case` spelling.
    pub kind: &'static str,
    pub rule_id: RuleId,
    pub grant_id: Option<&'static str>,
    pub findings: Findings,
    /// `declared_effect`; its source is checked as `tool_annotation` when
    /// present (the direct and meta routes' only source in this table).
    pub effect: Option<&'static str>,
    /// `decided`, in its serialised spelling (`fresh` for a live call).
    pub decided: &'static str,
}

/// Checks `decision` (one serialised decision object) against `row`.
pub(crate) fn assert_row(decision: &Value, row: &DecisionRow) {
    let n = row.name;
    assert_eq!(decision["kind"], row.kind, "{n}: kind: {decision}");
    match row.rule_id {
        RuleId::Id(id) => assert_eq!(decision["rule_id"], id, "{n}: rule_id: {decision}"),
        RuleId::Absent(reason) => assert!(
            decision.get("rule_id").is_none(),
            "{n}: rule_id must be absent ({reason}): {decision}"
        ),
    }
    assert_eq!(
        decision.get("grant_id").and_then(Value::as_str),
        row.grant_id,
        "{n}: grant_id: {decision}"
    );
    match row.findings {
        Findings::NotRun => assert!(
            decision.get("request_findings").is_none(),
            "{n}: request_findings must be absent: {decision}"
        ),
        Findings::Clean => assert_eq!(
            decision["request_findings"],
            serde_json::json!([]),
            "{n}: request_findings must be empty: {decision}"
        ),
        Findings::Raised(types) => {
            let got: Vec<&str> = decision["request_findings"]
                .as_array()
                .unwrap_or_else(|| panic!("{n}: request_findings missing: {decision}"))
                .iter()
                .map(|f| f["scan_type"].as_str().unwrap_or_default())
                .collect();
            assert_eq!(got, types, "{n}: request_findings: {decision}");
        }
    }
    assert_eq!(
        decision.get("declared_effect").and_then(Value::as_str),
        row.effect,
        "{n}: declared_effect: {decision}"
    );
    let source = row.effect.map(|_| "tool_annotation");
    assert_eq!(
        decision
            .get("declared_effect_source")
            .and_then(Value::as_str),
        source,
        "{n}: declared_effect_source: {decision}"
    );
    assert!(
        decision.get("request_findings_truncated").is_none(),
        "{n}: request_findings_truncated must be absent: {decision}"
    );
    assert_eq!(decision["decided"], row.decided, "{n}: decided: {decision}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ROW: DecisionRow = DecisionRow {
        name: "sample",
        kind: "tool_policy",
        rule_id: RuleId::Id("r-1"),
        grant_id: None,
        findings: Findings::Clean,
        effect: Some("read_only"),
        decided: "fresh",
    };

    fn sample() -> Value {
        json!({"v": 2, "kind": "tool_policy", "rule_id": "r-1", "request_findings": [],
               "declared_effect": "read_only", "declared_effect_source": "tool_annotation",
               "decided": "fresh"})
    }

    /// One edit to a decision, named for the field it changes.
    type Edit = (&'static str, fn(&mut Value));

    #[test]
    fn a_matching_decision_passes() {
        assert_row(&sample(), &ROW);
    }

    /// Each field the row pins fails the row when it differs.
    #[test]
    fn every_pinned_field_fails_the_row_when_it_differs() {
        let edits: [Edit; 9] = [
            ("kind", |d| d["kind"] = json!("firewall")),
            ("rule_id", |d| d["rule_id"] = json!("r-2")),
            ("grant_id", |d| d["grant_id"] = json!("g-1")),
            ("findings not run", |d| {
                d.as_object_mut().unwrap().remove("request_findings");
            }),
            ("findings raised", |d| {
                d["request_findings"] =
                    json!([{"scan_type": "secret", "severity": "high", "location": "a"}]);
            }),
            ("effect", |d| d["declared_effect"] = json!("may_write")),
            ("effect source", |d| {
                d["declared_effect_source"] = json!("capability_definition");
            }),
            ("decided", |d| d["decided"] = json!("replayed")),
            ("truncated", |d| {
                d["request_findings_truncated"] = json!(true)
            }),
        ];
        for (field, edit) in edits {
            let mut decision = sample();
            edit(&mut decision);
            let failed = std::panic::catch_unwind(|| assert_row(&decision, &ROW)).is_err();
            assert!(failed, "a changed {field} passed the row: {decision}");
        }
    }

    #[test]
    fn an_absent_rule_id_row_fails_on_a_present_one() {
        let row = DecisionRow {
            rule_id: RuleId::Absent("default allow names no rule"),
            ..ROW
        };
        assert!(std::panic::catch_unwind(|| assert_row(&sample(), &row)).is_err());
    }

    /// A row whose request check did not run fails on a decision where it ran.
    #[test]
    fn a_not_run_row_needs_the_findings_key_absent() {
        let row = DecisionRow {
            findings: Findings::NotRun,
            ..ROW
        };
        let mut decision = sample();
        assert!(std::panic::catch_unwind(|| assert_row(&decision, &row)).is_err());
        decision.as_object_mut().unwrap().remove("request_findings");
        assert_row(&decision, &row);
    }

    /// A raised row pins the scan types exactly, in order.
    #[test]
    fn a_raised_row_pins_its_scan_types() {
        let row = DecisionRow {
            findings: Findings::Raised(&["secret"]),
            ..ROW
        };
        let mut decision = sample();
        decision["request_findings"] =
            json!([{"scan_type": "secret", "severity": "high", "location": "a"}]);
        assert_row(&decision, &row);
        decision["request_findings"] =
            json!([{"scan_type": "injection", "severity": "high", "location": "a"}]);
        assert!(std::panic::catch_unwind(|| assert_row(&decision, &row)).is_err());
    }
}
