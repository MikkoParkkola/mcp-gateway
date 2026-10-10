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
use crate::protocol::{JsonRpcError, JsonRpcResponse};
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

/// The document a response or notification is serialized as: the one value
/// the sink writes, so a new field is in the scan by default (MIK-7883).
/// A response's `result` and `error.data` are `null` placeholders here: `scan`
/// walks the raw values already, and serializing them would copy a large
/// result twice (MIK-7942) and read the `cacheScope` clamp, the gateway's own
/// value, as evidence. Their member names stay; [`slot_name_tenants`] matches
/// a configured key equal to one against the raw value.
fn emitted_document(payload: &Payload) -> Option<Value> {
    match payload {
        Payload::Response(response) => {
            let placeholder = |slot: &Option<Value>| slot.as_ref().map(|_| Value::Null);
            let view = JsonRpcResponse {
                jsonrpc: response.jsonrpc.clone(),
                id: response.id.clone(),
                result: placeholder(&response.result),
                error: response.error.as_ref().map(|e| JsonRpcError {
                    code: e.code,
                    message: e.message.clone(),
                    data: placeholder(&e.data),
                }),
                confirmation_refusal: false,
                delivery_refusal: false,
                egress_scanned: false,
                chain_source: crate::protocol::ChainSource::NotEligible,
                chain_upstream: None,
            };
            serde_json::to_value(view).ok()
        }
        Payload::Notification(note) => serde_json::to_value(note).ok(),
        _ => None,
    }
}

/// The tenants a configured key equal to `result` or to an error's `data`
/// names through the raw value: the one match the placeholders hide.
fn slot_name_tenants(guard: &TenantGuard, response: &JsonRpcResponse) -> Vec<String> {
    let result = response.result.as_ref();
    let data = response.error.as_ref().and_then(|e| e.data.as_ref());
    [("result", result), ("data", data)]
        .into_iter()
        .filter_map(|(key, value)| guard.key_names_tenant(key, value?))
        .collect()
}

/// One walk over everything the payload emits but `jsonrpc` and `id`.
fn scan(guard: &TenantGuard, payload: &Payload) -> ReadAttribution {
    let (mut tenants, mut uninspected) = match payload {
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
        Payload::Event(doc) => guard.scan_frame(&[doc], &[]),
        // The event data the record's attribution covers was redacted
        // before this body was built: rescanning it would read a redaction
        // marker as a tenant of its own. The envelope is scanned with its
        // member names, so a configured key at its root still counts.
        Payload::Callback(doc) => guard.scan_document(doc, &["data"]),
        Payload::Batch(items) => {
            let mut all = ReadAttribution::default();
            for item in items.iter().filter_map(OutboundFrame::assessment) {
                all.extend(&item.attribution);
            }
            return all;
        }
        Payload::Withheld => return ReadAttribution::default(),
    };
    // The emitted document with its member names: a configured key equal to a
    // wrapper member (`message`, `method`) is matched here, not above.
    if let Some(document) = emitted_document(payload) {
        let (more, unread) = guard.scan_document(&document, &["jsonrpc", "id"]);
        tenants.extend(more);
        uninspected |= unread;
    }
    if let Payload::Response(response) = payload {
        tenants.extend(slot_name_tenants(guard, response));
    }
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
    // Likewise what the answer no longer shows: a refusal that replaced the
    // backend content at finalization delivered none of it.
    if let Some(hidden) = hidden.filter(|_| delivers_result(&payload)) {
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
        assessment: Some(Box::new(assessment)),
        ticket,
        record_taken: false,
        key: key.map(Arc::from),
        delivery: None,
        holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
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
        assessment: Some(Box::new(assessment)),
        ticket,
        record_taken: false,
        key: key.map(Arc::from),
        delivery: None,
        holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
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
    (event_type, wrapper): (&str, Option<&Value>),
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
    // A non-message event is written as the whole tagged notification, so its
    // `source` and `event_id` are scanned with their member names (MIK-7883).
    // Its `data` was scanned above (minus `jsonrpc` and `id`): only the name
    // match at the member `data` is left (MIK-7942).
    if let Some(wrapper) = wrapper {
        let (mut tenants, uninspected) = guard.scan_document(wrapper, &["data"]);
        tenants.extend(guard.key_names_tenant("data", data));
        attribution.extend(&ReadAttribution::of(tenants, uninspected));
    }
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
        assessment: Some(Box::new(assessment)),
        ticket,
        record_taken: false,
        key: key.map(Arc::from),
        delivery: None,
        holds: crate::gateway::meta_mcp::sealed_hold::CarriedHolds::none(),
    })
}

#[cfg(test)]
mod emitted_document_tests {
    use serde_json::{Value, json};

    use super::{Payload, emitted_document};
    use crate::protocol::{JsonRpcError, JsonRpcResponse, RequestId};

    /// The member names of `doc` and of its `error` object.
    fn key_set(doc: &Value) -> Vec<String> {
        let mut keys: Vec<String> = doc
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k.clone())
            .collect();
        if let Some(error) = doc.get("error").and_then(Value::as_object) {
            keys.extend(error.keys().map(|k| format!("error.{k}")));
        }
        keys.sort();
        keys
    }

    /// Every field written out: a new serialized member fails to compile
    /// here until it is set, and then the pin below checks the view has it.
    fn every_member(result: Option<Value>, data: Option<Value>) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            id: Some(RequestId::Number(1)),
            result,
            error: Some(JsonRpcError {
                code: -32000,
                message: "no".to_owned(),
                data,
            }),
            confirmation_refusal: true,
            delivery_refusal: true,
            egress_scanned: true,
            chain_source: crate::protocol::ChainSource::NotEligible,
            chain_upstream: None,
        }
    }

    /// MIK-7942 D6.CATALOGUE.8 (pin b): the placeholder view serializes every
    /// envelope member the sink writes for the same response.
    #[test]
    fn the_view_keeps_every_envelope_member() {
        let responses = [
            every_member(Some(json!({"a": 1})), Some(json!([1]))),
            every_member(Some(Value::Null), Some(Value::Null)),
            JsonRpcResponse::success(RequestId::Number(2), json!({"a": 1})),
            JsonRpcResponse::error(None, -32601, "missing"),
        ];
        for response in responses {
            let written = serde_json::to_value(&response).expect("serializes");
            let view = emitted_document(&Payload::Response(response)).expect("a document");
            assert_eq!(key_set(&view), key_set(&written), "{written}");
        }
    }
}
