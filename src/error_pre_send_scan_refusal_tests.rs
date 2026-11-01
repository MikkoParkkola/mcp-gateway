// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own refusals (`Forbidden`, `GatewayRefused`) are on the
//! never-sent list, so every site that builds one, or calls a builder that
//! does, is a reviewed pre-send site. Keyed as the parent's tables are.

use std::collections::BTreeMap;

use super::construction_sites;

/// `found` summed over each of `names`: a variant's literal constructions and
/// the calls of every builder that returns it.
fn summed_sites(names: &[&str]) -> BTreeMap<String, usize> {
    let mut found = BTreeMap::new();
    for name in names {
        for (item, count) in construction_sites(name) {
            *found.entry(item).or_default() += count;
        }
    }
    found
}

fn reviewed(sites: &[(&str, usize)]) -> BTreeMap<String, usize> {
    sites
        .iter()
        .map(|(item, count)| ((*item).to_string(), *count))
        .collect()
}

/// The items allowed to build `Error::Forbidden`, or to call a builder that
/// does, which `is_pre_dispatch` lists: each refuses before anything reaches
/// the backend. Keyed as above.
const FORBIDDEN_SITES: &[(&str, usize)] = &[
    // A lent-only slot's dispatch with no credential, before anything is built.
    ("backend::lend::Backend::lend_to_slot", 1),
    // A shared slot refused to a per-user call, before it starts.
    ("backend::pool::Backend::refuse_shared_start", 1),
    // Imports of `step_not_permitted`, not constructions.
    ("gateway::meta_mcp::<module>", 1),
    ("gateway::meta_mcp::support::<module>", 1),
    // A forwarded call outside the caller's scope, before dispatch.
    (
        "gateway::meta_mcp::caller_forward::MetaMcp::scope_refusal",
        1,
    ),
    // The request firewall's verdict on the outbound request, before the send.
    (
        "gateway::meta_mcp::invoke::chokepoint::MetaMcp::rescan_outbound",
        2,
    ),
    // The dispatch-time recheck of target authorization, grants and the
    // admin-capability rule: nothing was sent.
    (
        "gateway::meta_mcp::invoke::chokepoint::MetaMcp::recheck_target",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::chokepoint::MetaMcp::route_request_scan",
        2,
    ),
    // The call-level policy, judged before dispatch.
    (
        "gateway::meta_mcp::invoke::gate::MetaMcp::check_call_level_policy",
        1,
    ),
    // The invocation policy, before dispatch.
    (
        "gateway::meta_mcp::invoke::policy::MetaMcp::authorize_invocation",
        1,
    ),
    // The relay check on a call's egress, before secret injection and send.
    (
        "gateway::meta_mcp::invoke::relay::MetaMcp::relay_refusal",
        1,
    ),
    // A relayed catalogue the caller may not read, before any call.
    (
        "gateway::meta_mcp::invoke::relay_catalogue::MetaMcp::catalogue_refusal",
        1,
    ),
    // A playbook step's outcome relabelled to the neutral refusal (A3). A step
    // sent and failed while a grant was revoked is relabelled too, a race
    // tracked on its own; its key is kept by its own send count and the run's
    // lease.
    (
        "gateway::meta_mcp::playbook_invoker::MetaMcpInvoker::invoke",
        1,
    ),
    // The neutral step refusal: its definition and its literal.
    ("gateway::meta_mcp::playbook_invoker::step_not_permitted", 2),
    // A chain step's refusal rebuilt with its index: a step's own refusal.
    ("gateway::meta_mcp::search::chain_exec::step_failure", 1),
    // A stored task's targets judged again before its replay: no send.
    (
        "gateway::meta_mcp::task_replay::judging::MetaMcp::authorize_stored",
        1,
    ),
    // An admin-only capability refused to a non-admin, before dispatch.
    (
        "gateway::meta_mcp::visibility::MetaMcp::admin_capability_rule",
        1,
    ),
    // The visibility check before identity grants, naming the check that
    // refused: no send.
    (
        "gateway::meta_mcp::visibility::MetaMcp::may_invoke_before_grants_explained",
        1,
    ),
    // A match pattern wrapped in `Err(..)`, which the scan counts: no value is
    // built there.
    (
        "gateway::router::handlers::dispatch_tools_call::tools_call",
        1,
    ),
    // `Self::Forbidden` here is the web UI guard's own `Refused` variant, not
    // `Error::Forbidden`: matched by name, reviewed as no denial.
    ("gateway::ui::guard::Refused::from", 1),
    ("gateway::ui::guard::Refused::into_response", 1),
    // The stdio route stage's refusal of a step target, before dispatch.
    ("gateway::server::stdio_route_stage::authorize_targets", 1),
    // The web UI call's gates: before the capability or the send runs.
    ("gateway::ui_call::admit_send", 2),
    ("gateway::ui_call::confirmed", 1),
    ("gateway::ui_call::gate", 1),
    ("gateway::ui_call::task_refused", 1),
    ("gateway::ui_call::ui_call_refused", 2),
    // A playbook refused before its first step, and a step's arguments
    // refused before the step is invoked.
    ("playbook::engine::PlaybookEngine::execute_definition", 1),
    ("playbook::engine::checked_arguments", 1),
    // The lender's refusal while a lent send's headers are built, before the
    // request leaves: the import, the no-lender check, the per-loan checks,
    // and the counted builder and its builder (definitions and calls).
    ("transport::http::requests::<module>", 1),
    ("transport::http::requests::HttpTransport::lent_for", 1),
    ("transport::lender::Lender::lent_for", 4),
    ("transport::lender::counted_refusal", 2),
    ("transport::lender::send_refused", 2),
];

#[test]
fn a_denial_is_built_only_at_reviewed_pre_send_sites() {
    assert_eq!(
        summed_sites(&[
            "Error::Forbidden",
            "Self::Forbidden",
            "step_not_permitted",
            "send_refused",
            "counted_refusal",
            "ui_call_refused",
        ]),
        reviewed(FORBIDDEN_SITES),
        "a denial frees an idempotency key, so it may be built only before \
         anything reaches the backend: review every new or removed site \
         (left: found, right: reviewed)"
    );
}

/// The items allowed to build `Error::GatewayRefused`, or to call its builder,
/// which `is_pre_dispatch` lists: the admission checks, before any send.
const GATEWAY_REFUSED_SITES: &[(&str, usize)] = &[
    // The builder: its definition and its literal.
    ("error::Error::gateway_refused", 2),
    // The admission checks, each before dispatch.
    (
        "gateway::meta_mcp::invoke::dispatch::MetaMcp::admit_spend",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::dispatch_guards::MetaMcp::admit_backend_wide",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::dispatch_guards::MetaMcp::admit_enabled_capability",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::policy::MetaMcp::check_attestation_scoped",
        1,
    ),
    (
        "gateway::meta_mcp::invoke::policy::MetaMcp::refuse_unattested_plan",
        1,
    ),
    // A chain step's refusal rebuilt with its index and its own code.
    ("gateway::meta_mcp::search::chain_exec::step_failure", 1),
];

#[test]
fn a_gateway_refusal_is_built_only_at_reviewed_pre_send_sites() {
    assert_eq!(
        summed_sites(&[
            "Error::GatewayRefused",
            "Self::GatewayRefused",
            "gateway_refused"
        ]),
        reviewed(GATEWAY_REFUSED_SITES),
        "a gateway refusal frees an idempotency key, so it may be built only \
         before anything reaches the backend: review every new or removed \
         site (left: found, right: reviewed)"
    );
}

/// The transport builds a denial only through the lender's refusal, while
/// it builds a lent send's headers, before the request leaves; no transport
/// or agent-to-agent item builds a gateway refusal.
#[test]
fn the_transport_denies_only_while_building_headers() {
    let found = summed_sites(&["Error::Forbidden", "send_refused", "counted_refusal"]);
    let transport: Vec<&String> = found
        .keys()
        .filter(|k| k.starts_with("transport::"))
        .collect();
    assert!(
        transport
            .iter()
            .all(|k| k.starts_with("transport::lender::")
                || k.starts_with("transport::http::requests::")),
        "a transport denial outside the lender's header step: {transport:?}"
    );
    let refused = summed_sites(&["Error::GatewayRefused", "gateway_refused"]);
    assert!(
        refused
            .keys()
            .all(|k| !k.starts_with("transport::") && !k.starts_with("a2a::")),
        "a gateway refusal built in the transport: {refused:?}"
    );
}

/// A denial built as `Self::Forbidden` inside `impl Error` is counted, so a
/// new constructor there cannot skip the review.
#[test]
fn a_denial_built_as_self_is_counted() {
    let src = "impl Error {\n\
               fn refuse() -> Self {\n\
               Self::Forbidden { code: -32003, status: 403, message: String::new() }\n\
               }\n\
               fn is(&self) -> bool { matches!(self, Self::Forbidden { .. }) }\n\
               }\n";
    assert_eq!(super::constructions_of(src, "Self::Forbidden"), 1, "{src}");
}
