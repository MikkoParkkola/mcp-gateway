// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The judge (design §4, §4.5): one walk over the frame's final content,
//! then one check-and-reserve against the process's read history.
//!
//! The scan is a deny-list: the whole emitted document of every payload,
//! minus only the top-level `jsonrpc` and `id`. A new field or variant is
//! scanned by default. `id` is never scanned, so a refusal that keeps a
//! JSON-shaped id cannot refuse itself.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::{Admission, Assessment, OutboundFrame, Payload};
use crate::protocol::JsonRpcResponse;
use crate::security::firewall::Firewall;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuard};
use crate::security::tenant_reads::{ReadAttribution, ReadTicket, ReadVerdict, RejectionEvidence};

/// The code of the refusal that replaces a blocked answer.
pub(super) const REFUSAL_CODE: i32 = -32603;
/// Its text: fixed, carrying no backend content.
pub(super) const REFUSAL_TEXT: &str =
    "Response withheld: this caller already read another tenant's data inside the window";

/// Whether this firewall judges at all: attribution configured and the mode
/// not `off`. The fast path is everything else.
pub(super) fn judging(firewall: &Firewall) -> Option<(&TenantGuard, CrossTenantReads)> {
    let guard = firewall.tenant_guard();
    let mode = guard.config().cross_tenant_reads;
    (guard.attributes() && mode != CrossTenantReads::Off).then_some((guard, mode))
}

/// The attribution of a raw value under the firewall's `arg_keys`, taken
/// before a transform or a redaction can drop fields (§4.4). An outbox
/// record carries it to the delivery.
pub(crate) fn attribute(firewall: &Firewall, value: &Value) -> ReadAttribution {
    let (tenants, uninspected) = firewall.tenant_guard().scan_frame(&[value], &[]);
    ReadAttribution::of(tenants, uninspected)
}

/// One walk over everything the payload emits but `jsonrpc` and `id`.
fn scan(guard: &TenantGuard, payload: &Payload) -> ReadAttribution {
    let (tenants, uninspected) = match payload {
        Payload::Response(response) => {
            let error = response.error.as_ref();
            let values: Vec<&Value> = response
                .result
                .iter()
                .chain(error.and_then(|e| e.data.as_ref()))
                .collect();
            let texts: Vec<&str> = error.map(|e| e.message.as_str()).into_iter().collect();
            guard.scan_frame(&values, &texts)
        }
        Payload::Notification(note) => {
            guard.scan_frame(&note.params.iter().collect::<Vec<_>>(), &[&note.method])
        }
        Payload::Request(doc) | Payload::Answer(doc) => {
            guard.scan_document(doc, &["jsonrpc", "id"])
        }
        Payload::Event(doc) | Payload::Callback(doc) => guard.scan_frame(&[doc], &[]),
        Payload::Batch(items) => {
            let mut all = ReadAttribution::default();
            for item in items.iter().filter_map(OutboundFrame::assessment) {
                all.extend(&item.attribution);
            }
            return all;
        }
        Payload::Withheld => return ReadAttribution::default(),
    };
    ReadAttribution::of(tenants, uninspected)
}

/// Check the frame's attribution against `key`'s history and reserve it.
/// `block` withholds an over frame instead of reserving it.
fn assess(
    firewall: &Firewall,
    guard: &TenantGuard,
    block: bool,
    key: Option<&str>,
    attribution: ReadAttribution,
) -> (Assessment, Option<ReadTicket>) {
    if attribution.is_empty() {
        return (
            Assessment {
                verdict: None,
                attribution,
            },
            None,
        );
    }
    let window = Duration::from_secs(guard.config().window_secs);
    let reservation = key
        .filter(|k| !k.is_empty())
        .and_then(|k| firewall.reads().reserve(k, &attribution, window, block));
    let (verdict, ticket) = match reservation {
        None => (Some(ReadVerdict::Unattributable), None),
        Some(r) if r.over && block => (Some(ReadVerdict::Blocked), None),
        Some(r) => (r.over.then_some(ReadVerdict::Flagged), r.ticket),
    };
    (
        Assessment {
            verdict,
            attribution,
        },
        ticket,
    )
}

/// Whether a verdict withholds the frame.
fn withholds(verdict: Option<ReadVerdict>, block: bool) -> bool {
    match verdict {
        Some(ReadVerdict::Blocked) => true,
        Some(ReadVerdict::Unattributable) => block,
        _ => false,
    }
}

/// Whether an answer carries a result rather than an error.
fn delivers_result(payload: &Payload) -> bool {
    match payload {
        Payload::Response(response) => response.error.is_none(),
        Payload::Answer(answer) => answer.get("error").is_none(),
        _ => false,
    }
}

/// Judge a frame carrying backend-derived content for `key`. `request` is
/// the params of the request it answers; `hidden` is attribution the frame
/// no longer shows (pre-transform, cached, stored). A blocked answer is
/// replaced by a fixed refusal that keeps the assessment as evidence; any
/// other blocked payload is withheld.
pub(crate) fn delivered(
    firewall: &Firewall,
    key: Option<&str>,
    payload: Payload,
    request: Option<&Value>,
    hidden: Option<&ReadAttribution>,
) -> OutboundFrame {
    let Some((guard, mode)) = judging(firewall) else {
        return OutboundFrame::unjudged(payload);
    };
    let block = mode == CrossTenantReads::Block;
    let mut attribution = scan(guard, &payload);
    // The request's tenants are read only by an answer that delivered a
    // result. An error answer (a refusal above all) charges only what its
    // own payload names, so a refused B request does not count as a read of
    // B (row 7).
    if let Some(request) = request.filter(|_| delivers_result(&payload)) {
        attribution.extend(&ReadAttribution::of(guard.request_tenants(request), false));
    }
    if let Some(hidden) = hidden {
        attribution.extend(hidden);
    }
    let (assessment, ticket) = assess(firewall, guard, block, key, attribution);
    let payload = if withholds(assessment.verdict, block) {
        match payload {
            Payload::Response(answer) => Payload::Response(
                JsonRpcResponse::delivery_refusal_error(answer.id, REFUSAL_CODE, REFUSAL_TEXT),
            ),
            Payload::Answer(answer) => Payload::Response(JsonRpcResponse::delivery_refusal_error(
                answer
                    .get("id")
                    .and_then(|id| serde_json::from_value(id.clone()).ok()),
                REFUSAL_CODE,
                REFUSAL_TEXT,
            )),
            _ => Payload::Withheld,
        }
    } else {
        payload
    };
    OutboundFrame {
        payload,
        assessment: Some(assessment),
        ticket,
        key: key.map(Arc::from),
    }
}

/// Judge a frame that is withheld, not replaced, when blocked: a
/// notification, a server-to-client request, an event delivery.
pub(crate) fn admit(
    firewall: &Firewall,
    key: Option<&str>,
    payload: Payload,
    hidden: Option<&ReadAttribution>,
) -> Admission {
    let Some((guard, mode)) = judging(firewall) else {
        return Admission::Admitted(OutboundFrame::unjudged(payload));
    };
    let block = mode == CrossTenantReads::Block;
    let mut attribution = scan(guard, &payload);
    if let Some(hidden) = hidden {
        attribution.extend(hidden);
    }
    let (assessment, ticket) = assess(firewall, guard, block, key, attribution);
    if withholds(assessment.verdict, block) {
        return Admission::Blocked(RejectionEvidence {
            caller_key: key.map(str::to_owned),
            verdict: assessment.verdict.unwrap_or(ReadVerdict::Blocked),
            attribution: assessment.attribution,
        });
    }
    Admission::Admitted(OutboundFrame {
        payload,
        assessment: Some(assessment),
        ticket,
        key: key.map(Arc::from),
    })
}

/// Judge a session-stream item (H7) for one session's caller, without
/// moving it: the item is a `data` document under an SSE event name, both
/// scanned (minus the document's `jsonrpc` and `id`). Admitted, the frame
/// carries no payload, only the judgement and the reservation the stream
/// commits when it writes the item.
pub(crate) fn admit_stream_item(
    firewall: &Firewall,
    key: Option<&str>,
    data: &Value,
    event_type: &str,
    hidden: Option<&ReadAttribution>,
) -> Admission {
    let Some((guard, mode)) = judging(firewall) else {
        return Admission::Admitted(OutboundFrame::unjudged(Payload::Withheld));
    };
    let block = mode == CrossTenantReads::Block;
    let (tenants, uninspected) = guard.scan_document(data, &["jsonrpc", "id"]);
    let mut attribution = ReadAttribution::of(tenants, uninspected);
    let (tenants, uninspected) = guard.scan_frame(&[], &[event_type]);
    attribution.extend(&ReadAttribution::of(tenants, uninspected));
    if let Some(hidden) = hidden {
        attribution.extend(hidden);
    }
    let (assessment, ticket) = assess(firewall, guard, block, key, attribution);
    if withholds(assessment.verdict, block) {
        return Admission::Blocked(RejectionEvidence {
            caller_key: key.map(str::to_owned),
            verdict: assessment.verdict.unwrap_or(ReadVerdict::Blocked),
            attribution: assessment.attribution,
        });
    }
    Admission::Admitted(OutboundFrame {
        payload: Payload::Withheld,
        assessment: Some(assessment),
        ticket,
        key: key.map(Arc::from),
    })
}

/// E1: judge a MIK-7630 event delivery for the subscription principal.
/// `attribution` is what the outbox record carries from before the event
/// firewall's redaction; a record without it counts as unread.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the MIK-7630 event sender converts to it (design row E1, #2651)"
    )
)]
pub(crate) fn callback_frame(
    firewall: &Firewall,
    principal: &str,
    body: Value,
    attribution: Option<&ReadAttribution>,
) -> Admission {
    let unread = ReadAttribution {
        uninspected: true,
        ..ReadAttribution::default()
    };
    admit(
        firewall,
        Some(principal),
        Payload::Callback(body),
        Some(attribution.unwrap_or(&unread)),
    )
}
