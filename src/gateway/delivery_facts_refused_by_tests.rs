// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A refused stored delivery's record names its check in every branch that
//! writes `response_effect` (MIK-9191.RULEID.3): scanned or not, vouched or
//! not. The first refusal raised stands.

use serde_json::{Map, Value, json};

use super::{record_fields, refused_by, scanned, scope, snapshot, unvouched};
use crate::security::decision_record::{DecisionKind, RefusedBy};

fn recorded() -> Map<String, Value> {
    let mut fields = Map::new();
    record_fields(snapshot().as_ref(), false, &mut fields);
    fields
}

fn deny_entry() -> RefusedBy {
    RefusedBy {
        kind: DecisionKind::ToolPolicy,
        rule_id: Some("tool_policy:00ff".to_owned()),
    }
}

fn named() -> Value {
    json!({"kind": "tool_policy", "rule_id": "tool_policy:00ff"})
}

#[tokio::test]
async fn a_scanned_refusal_names_its_check() {
    scope(async {
        scanned();
        refused_by(deny_entry());
        let fields = recorded();
        assert_eq!(fields["response_effect"], "refused", "{fields:?}");
        assert_eq!(fields["refused_by"], named(), "{fields:?}");
    })
    .await;
}

#[tokio::test]
async fn an_unscanned_refusal_names_its_check() {
    scope(async {
        refused_by(deny_entry());
        let fields = recorded();
        assert_eq!(fields["response_findings"], Value::Null, "{fields:?}");
        assert_eq!(fields["refused_by"], named(), "{fields:?}");
    })
    .await;
}

#[tokio::test]
async fn an_unvouched_refusal_names_its_check() {
    scope(async {
        unvouched();
        refused_by(deny_entry());
        let fields = recorded();
        assert_eq!(fields["response_effect"], "refused", "{fields:?}");
        assert_eq!(fields["refused_by"], named(), "{fields:?}");
    })
    .await;
}

#[tokio::test]
async fn the_first_refusal_raised_stands() {
    scope(async {
        refused_by(deny_entry());
        refused_by(RefusedBy {
            kind: DecisionKind::Grant,
            rule_id: None,
        });
        assert_eq!(recorded()["refused_by"], named());
    })
    .await;
}

#[tokio::test]
async fn a_kind_only_refusal_omits_the_rule_id() {
    scope(async {
        refused_by(RefusedBy {
            kind: DecisionKind::Provenance,
            rule_id: None,
        });
        assert_eq!(recorded()["refused_by"], json!({"kind": "provenance"}));
    })
    .await;
}
