// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R6: every meta arm, through `handle_tools_call`, moves the recent-write
//! sample by its class. A Write arm counts once at its entry, even when its
//! handler refuses; a Read arm never counts; `Invoke`, `Execute` and `RunPlaybook`
//! never count at the arm, only once per counted leaf they dispatch.
//! Observation: the delta of `recent_writes().sample(now).writes_total`, which
//! is exact and never slides out of the window.

use std::time::Instant;

use super::*;
use crate::gateway::authz::AdminStanding;
use crate::gateway::destructive_confirmation::ConfirmationPolicy;
use crate::gateway::meta_mcp::authz_tests::counted_backend;
use crate::gateway::meta_mcp::dispatch_names::MetaArm;

/// How R6 expects each arm to count. Written out here, not read from
/// `MetaArm::writes`, so a wrong class in that table fails this row as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Leaves,
    Read,
    Write,
}

/// Exhaustive, so a new meta arm does not compile here until it is classed.
const fn class(arm: MetaArm) -> Class {
    match arm {
        MetaArm::Invoke | MetaArm::Execute | MetaArm::RunPlaybook => Class::Leaves,
        MetaArm::Search
        | MetaArm::ListServers
        | MetaArm::ListTools
        | MetaArm::SearchTools
        | MetaArm::GetStats
        | MetaArm::CostReport
        | MetaArm::WebhookStatus
        | MetaArm::ListDisabledCapabilities
        | MetaArm::GetProfile
        | MetaArm::ListProfiles => Class::Read,
        MetaArm::KillServer
        | MetaArm::ReviveServer
        | MetaArm::SetProfile
        | MetaArm::SetState
        | MetaArm::ReloadConfig
        | MetaArm::ReloadCapabilities => Class::Write,
    }
}

/// The arguments each arm is called with. No leaf is ever sent: invoke names
/// no target (refused before the send), execute runs an empty chain, the
/// playbook does not exist, and each write handler refuses its missing
/// target. What is left to count is the arm itself. (A call to a server that
/// does not exist does reach the send step, and counts there.)
fn arguments(arm: MetaArm) -> Value {
    match arm {
        MetaArm::Invoke => json!({}),
        MetaArm::Execute => json!({"chain": []}),
        MetaArm::RunPlaybook => json!({"name": "nowhere"}),
        MetaArm::Search | MetaArm::SearchTools => json!({"query": "nowhere"}),
        MetaArm::ListTools | MetaArm::KillServer | MetaArm::ReviveServer => {
            json!({"server": "nowhere"})
        }
        MetaArm::SetProfile => json!({"profile": "nowhere"}),
        MetaArm::SetState => json!({"state": "nowhere"}),
        MetaArm::ListServers
        | MetaArm::GetStats
        | MetaArm::CostReport
        | MetaArm::WebhookStatus
        | MetaArm::ListDisabledCapabilities
        | MetaArm::GetProfile
        | MetaArm::ListProfiles
        | MetaArm::ReloadConfig
        | MetaArm::ReloadCapabilities => json!({}),
    }
}

/// The proxy a legacy confirmation channel asks through. On the empty session
/// id nobody is asked, and the legacy policy proceeds, so `gateway_kill_server`
/// reaches its arm instead of the destructive gate's refusal.
fn proxy() -> crate::gateway::ProxyManager {
    crate::gateway::ProxyManager::new(Arc::new(crate::gateway::NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        crate::config::StreamingConfig::default(),
    )))
}

/// `allow_all_ctx` as a gateway-wide admin on a legacy confirmation channel:
/// the admin gate and the destructive gate both let every arm through, so
/// each call reaches its arm.
fn reaching_ctx(proxy: &crate::gateway::ProxyManager) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        admin: AdminStanding::Gateway,
        confirmation: ConfirmationChannel::Elicit {
            proxy,
            policy: ConfirmationPolicy::for_legacy(),
        },
        ..allow_all_ctx()
    }
}

fn writes_total(meta: &MetaMcp) -> u64 {
    meta.recent_writes().sample(Instant::now()).writes_total
}

/// One call of `tool` on `meta`; the answer, and how far `writes_total` moved.
async fn delta(meta: &MetaMcp, tool: &str, args: Value) -> (JsonRpcResponse, u64) {
    let proxy = proxy();
    let before = writes_total(meta);
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        Box::pin(meta.handle_tools_call(
            RequestId::Number(1),
            tool,
            args,
            None,
            reaching_ctx(&proxy),
        )),
    )
    .await
    .expect("the call answers within 10 seconds");
    let after = writes_total(meta);
    assert!(after >= before, "writes_total never decreases ({tool})");
    (response, after - before)
}

/// Neither the admin gate nor the destructive gate answered: the call reached
/// its arm. Both refusals are recognisable by their text.
fn reached_the_arm(response: &JsonRpcResponse) -> bool {
    let text = format!("{response:?}");
    !text.contains("requires admin access") && !text.contains("requires confirmation")
}

#[tokio::test]
async fn r6_every_meta_arm_counts_by_its_class() {
    let mut wrong = Vec::new();
    for arm in MetaArm::ALL {
        // A fresh gateway per arm: no arm's side effect reaches another's.
        let meta = make_meta_mcp();
        let (response, moved) = delta(&meta, arm.name(), arguments(arm)).await;
        assert!(
            reached_the_arm(&response),
            "premise: {} reached its arm: {response:?}",
            arm.name()
        );
        let want = match class(arm) {
            Class::Write => 1,
            Class::Read | Class::Leaves => 0,
        };
        if moved != want {
            wrong.push(format!(
                "{} ({:?}): moved {moved}, want {want}",
                arm.name(),
                class(arm)
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} arms counted wrongly:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Two steps on `alpha`, neither tool declared: each is an undeclared leaf.
const TWO_STEPS: &str = r"
name: two_steps
description: two backend steps, each one leaf dispatch
on_error: abort
steps:
  - name: first
    server: alpha
    tool: write_one
  - name: second
    server: alpha
    tool: write_two
";

/// Each composite counts once per leaf it dispatched and nothing at the arm.
/// The leaves are undeclared tools (no `tools/list` ran), which count by the
/// one rule; a declared `MayWrite` leaf and a `ReadOnly` leaf are R1's (Fx), and
/// the composites on Fx are R8's. The backend's own call count is the premise:
/// the delta must equal the leaves that reached it.
#[tokio::test]
async fn r6_a_composite_counts_once_per_leaf_and_not_at_its_arm() {
    let cases: [(&str, Value, usize); 3] = [
        (
            "gateway_invoke",
            json!({"server": "alpha", "tool": "write_one", "arguments": {}}),
            1,
        ),
        (
            "gateway_execute",
            json!({"chain": [
                {"tool": "alpha:write_one", "arguments": {}},
                {"tool": "alpha:write_two", "arguments": {}},
            ]}),
            2,
        ),
        ("gateway_run_playbook", json!({"name": "two_steps"}), 2),
    ];
    for (tool, args, leaves) in cases {
        let (registry, calls) = counted_backend("alpha");
        let meta = MetaMcp::new(registry);
        let definition: crate::playbook::PlaybookDefinition =
            crate::yaml::from_str(TWO_STEPS).expect("the playbook fixture parses");
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);

        let (response, moved) = delta(&meta, tool, args).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            leaves,
            "premise: {tool} dispatched {leaves} leaves: {response:?}"
        );
        assert_eq!(
            moved, leaves as u64,
            "{tool}: one count per dispatched leaf, none at the arm"
        );
    }
}

/// W7: the arm table, written out by name here: three meta-tools count per
/// leaf they dispatch, six count once at entry, the other ten are reads.
#[test]
fn w7_every_meta_arm_has_its_write_class() {
    use crate::gateway::meta_mcp::dispatch_names::ArmWrites;
    let leaves = ["gateway_invoke", "gateway_execute", "gateway_run_playbook"];
    let writes = [
        "gateway_kill_server",
        "gateway_revive_server",
        "gateway_set_profile",
        "gateway_set_state",
        "gateway_reload_config",
        "gateway_reload_capabilities",
    ];
    for name in leaves.iter().chain(&writes) {
        assert!(MetaArm::parse(name).is_some(), "{name} is a meta-tool");
    }
    let mut reads = 0;
    for arm in MetaArm::ALL {
        let want = if leaves.contains(&arm.name()) {
            ArmWrites::Leaves
        } else if writes.contains(&arm.name()) {
            ArmWrites::Write
        } else {
            reads += 1;
            ArmWrites::Read
        };
        assert_eq!(arm.writes(), want, "{}", arm.name());
    }
    assert_eq!((MetaArm::ALL.len(), reads), (19, 10));
}
