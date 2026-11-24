// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A deferred plan refusal never labels another refusal: keyed admission
//! notes only the refusal it returns, or the one a replay meets, with that
//! refusal's own pair (kind and rule id). Read here as the record writer reads
//! it, from the request's route scope; the /mcp and stdio rows check the
//! written record.

use serde_json::{Value, json};

use crate::gateway::authz::{AllowAll, ToolAuthorizer};
use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};
use crate::gateway::meta_mcp::invoke::audit::{take_refusal, with_route_scope};
use crate::gateway::meta_mcp::{AdmissionOwner, MetaMcp, MetaMcpCallerContext};
use crate::protocol::RequestId;
use crate::protocol::mrtr::RetryFields;
use crate::security::decision_record::{DecisionKind, Refusal};
use crate::security::rule_id::{RuleId, RuleKey};

use super::admission::SyncAdmission;

/// A rule id the test authorizer names, distinct per `seed`.
fn rule(seed: u8) -> RuleId {
    RuleId::of("test", &RuleKey::from_derived([seed; 32]), b"rule")
}

/// Refuses each listed tool with its own kind and rule, and every server
/// outside `grant` (when scoped) as the backend scope does.
struct Judge {
    grant: Option<Vec<String>>,
    deny: Vec<(&'static str, DecisionKind, RuleId)>,
}

impl Judge {
    fn denying(deny: &[(&'static str, DecisionKind, u8)]) -> Self {
        Self {
            grant: None,
            deny: deny
                .iter()
                .map(|&(tool, kind, seed)| (tool, kind, rule(seed)))
                .collect(),
        }
    }
}

impl ToolAuthorizer for Judge {
    fn generation(&self) -> Option<&crate::config_reload::Generation> {
        None
    }
    fn quota_principal(&self) -> Option<&crate::gateway::auth::QuotaPrincipal> {
        None
    }
    fn backend_grant(&self) -> crate::gateway::authz::BackendGrant<'_> {
        self.grant.as_deref().map_or(
            crate::gateway::authz::BackendGrant::Unscoped,
            crate::gateway::authz::BackendGrant::Scoped,
        )
    }
    fn decide<'a>(
        &'a self,
        target: crate::gateway::authz::ToolTarget<'a>,
    ) -> crate::gateway::authz::Decision<'a> {
        let refuse = |kind, rule: &RuleId| {
            crate::gateway::authz::Decision::of(Err(
                crate::gateway::authz::AuthorizationError::forbidden(
                    kind,
                    -32003,
                    format!("denied by test judge: '{}'", target.tool),
                )
                .with_rule(Some(rule.clone())),
            ))
        };
        if let Some(grant) = &self.grant
            && !grant.iter().any(|server| server == target.server)
        {
            return refuse(DecisionKind::BackendScope, &rule(9));
        }
        match self.deny.iter().find(|(tool, _, _)| *tool == target.tool) {
            Some((_, kind, rule)) => refuse(*kind, rule),
            None => crate::gateway::authz::Decision::of(Ok(())),
        }
    }
    fn admits_backend(&self, server: &str) -> bool {
        self.grant
            .as_ref()
            .is_none_or(|grant| grant.iter().any(|s| s == server))
    }
    fn transport(&self) -> crate::gateway::authz::Transport {
        crate::gateway::authz::Transport::Test
    }
    fn caller_name(&self) -> Option<&str> {
        None
    }
}

/// A keyed `gateway_execute` of `chain` under one key, on `meta`.
struct Keyed {
    meta: MetaMcp,
    retry: RetryFields,
    args: Value,
}

impl Keyed {
    fn new(key: &str, chain: Value) -> Self {
        let (registry, _calls) = counted_backend("beta");
        Self {
            meta: MetaMcp::new(registry).with_code_mode(true),
            retry: RetryFields {
                idempotency_key: Some(key.into()),
                ..RetryFields::default()
            },
            args: Value::Object(serde_json::Map::from_iter([("chain".to_owned(), chain)])),
        }
    }

    /// Admission of the call judged by `authorizer`, inside a route scope,
    /// with the pair it left noted there.
    async fn admit(
        &self,
        authorizer: &(dyn ToolAuthorizer + Sync),
        id: i64,
    ) -> (crate::Result<SyncAdmission>, Option<Refusal>) {
        let caller = MetaMcpCallerContext {
            retry: &self.retry,
            is_modern: true,
            credential_principal: Some("verified-credential-owner"),
            record_principal: crate::gateway::record_principal::RecordPrincipal::none(),
            ..ctx(authorizer)
        };
        with_route_scope(async {
            let admitted = self.meta.admit_meta_sync_for_test(
                AdmissionOwner::for_test(caller.owner_principal()),
                &caller,
                "gateway_execute",
                &self.args,
                Some("legacy:session"),
                &RequestId::Number(id),
            );
            (admitted, take_refusal())
        })
        .await
    }

    /// A first, allowed run that owns the key and was served `served` only.
    async fn completed(&self, authorizer: &(dyn ToolAuthorizer + Sync), served: &[(&str, &str)]) {
        let (Ok(SyncAdmission::Owned(owner)), _) = self.admit(authorizer, 1).await else {
            panic!("premise: the first call owns the key");
        };
        owner.mark_dispatched();
        for step in served {
            owner.note_step(*step);
        }
        owner.complete_secured(&crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            json!({"retained": "yes"}),
        ));
    }
}

fn chain(tools: &[&str]) -> Value {
    tools
        .iter()
        .map(|tool| json!({"tool": tool, "arguments": {}}))
        .collect()
}

/// d1, second case: a replay with two deferred refusals of different kinds,
/// whose first run was served only the second step, meets the second's
/// refusal and notes the second's pair, never the first's. Seeded as
/// `replay_naming` is: a live chain stops at its first hidden step.
#[tokio::test]
async fn a_replay_notes_the_pair_of_the_deferred_refusal_it_meets() {
    let keyed = Keyed::new("two-deferred", chain(&["beta:other", "beta:read"]));
    keyed.completed(&AllowAll, &[("beta", "read")]).await;
    let judge = Judge::denying(&[
        ("other", DecisionKind::ToolPolicy, 1),
        ("read", DecisionKind::AgentScope, 2),
    ]);
    let (answer, noted) = keyed.admit(&judge, 2).await;
    let refusal = answer.err().expect("premise: the replay is refused");
    assert!(
        refusal.to_string().contains("'read'"),
        "premise: the replay meets read's refusal: {refusal}"
    );
    assert_eq!(noted, Some((DecisionKind::AgentScope, Some(rule(2)))));
}

/// d1, third case: an absent step's deferred miss, met by a replay, notes
/// the pair of that step's own policy check (the backend scope), which the
/// plan loop kept beside the miss; never the pair of the hidden step deferred
/// before it, which the first run was not served.
#[tokio::test]
async fn a_replayed_absent_step_notes_its_check_pair() {
    let keyed = Keyed::new("absent-step", chain(&["beta:other", "alpha:x"]));
    let both = Judge {
        grant: Some(vec!["alpha".into(), "beta".into()]),
        deny: Vec::new(),
    };
    keyed.completed(&both, &[("alpha", "x")]).await;
    let beta_only = Judge {
        grant: Some(vec!["beta".into()]),
        ..Judge::denying(&[("other", DecisionKind::ToolPolicy, 1)])
    };
    let (answer, noted) = keyed.admit(&beta_only, 2).await;
    let refusal = answer.err().expect("premise: the replay is refused");
    assert!(
        matches!(refusal, crate::Error::BackendNotFound(ref server) if server == "alpha"),
        "premise: the replay meets the backend miss: {refusal:?}"
    );
    assert_eq!(noted, Some((DecisionKind::BackendScope, Some(rule(9)))));
}

/// Other exits: a fresh call with a deferred step is admitted and notes
/// nothing deferred.
#[tokio::test]
async fn a_fresh_admission_notes_no_deferred_pair() {
    let keyed = Keyed::new("fresh", chain(&["beta:other", "beta:read"]));
    let judge = Judge::denying(&[("other", DecisionKind::ToolPolicy, 1)]);
    let (answer, noted) = keyed.admit(&judge, 1).await;
    assert!(
        matches!(answer, Ok(SyncAdmission::Owned(_))),
        "premise: a fresh call is admitted"
    );
    assert_eq!(noted, None);
}

/// Other exits: a replay whose first run was served no withheld step gets
/// the stored answer and notes nothing deferred.
#[tokio::test]
async fn a_replay_with_no_matching_step_notes_no_deferred_pair() {
    let keyed = Keyed::new("unmatched", chain(&["beta:other", "beta:read"]));
    keyed.completed(&AllowAll, &[("beta", "read")]).await;
    let judge = Judge::denying(&[("other", DecisionKind::ToolPolicy, 1)]);
    let (answer, noted) = keyed.admit(&judge, 2).await;
    assert!(
        matches!(answer, Ok(SyncAdmission::Replay(..))),
        "premise: the stored answer is replayed"
    );
    assert_eq!(noted, None);
}

/// Other exits: a parse refusal after a deferred step is not labelled by
/// it; nothing is noted, so the writer records the site's own kind.
#[tokio::test]
async fn a_parse_refusal_after_a_deferred_step_notes_no_deferred_pair() {
    let keyed = Keyed::new("parse", chain(&["beta:other", "no_prefix"]));
    let judge = Judge::denying(&[("other", DecisionKind::ToolPolicy, 1)]);
    let (answer, noted) = keyed.admit(&judge, 1).await;
    let refusal = answer.err().expect("premise: the chain is refused");
    assert!(
        refusal.to_string().contains("server:tool_name prefix"),
        "premise: the parse refusal: {refusal}"
    );
    assert_eq!(noted, None);
}

/// Other exits: the kill switch met behind a hidden step notes its own
/// pair, not the hidden step's.
#[tokio::test]
async fn a_backend_wide_refusal_after_a_deferred_step_notes_its_own_pair() {
    let keyed = Keyed::new("killed", chain(&["beta:other"]));
    keyed.meta.kill_switch().kill("beta");
    let judge = Judge::denying(&[("other", DecisionKind::ToolPolicy, 1)]);
    let (answer, noted) = keyed.admit(&judge, 1).await;
    let refusal = answer.err().expect("premise: the killed chain is refused");
    assert!(
        refusal.to_string().contains("kill switch"),
        "premise: the kill switch refuses: {refusal}"
    );
    assert_eq!(noted, Some((DecisionKind::KillSwitch, None)));
}
