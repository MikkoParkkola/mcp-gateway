// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7887.RECEIPT.3/.4: a relay receipt commits where delivery is confirmed
//! and describes the answer as it was finally delivered.

use serde_json::Value;

#[cfg(feature = "firewall")]
use super::super::gateway_writes::Layer;
use super::RELAY_RECEIPTS;
use super::{MetaMcp, RelayKey};

impl MetaMcp {
    /// The relay receipt of `value` as delivered to `who` from `server:tool`,
    /// owned so the channel can commit it once delivery is confirmed.
    /// `None` with relay detection off.
    #[cfg_attr(not(feature = "firewall"), allow(clippy::unused_self))]
    pub(super) fn delivery_commit(
        &self,
        who: RelayKey<'_>,
        (server, tool): (&str, &str),
        value: &Value,
    ) -> Option<crate::gateway::input_bridge::DeliveryCommit> {
        #[cfg(feature = "firewall")]
        {
            let fw = std::sync::Arc::clone(self.firewall.as_ref()?);
            let digest = fw.delivery_digest(server, tool, value)?;
            let (key, keyed) = (who.key.to_owned(), who.keyed);
            let (server, tool) = (server.to_owned(), tool.to_owned());
            Some(crate::gateway::input_bridge::DeliveryCommit::new(
                move || {
                    let caller = crate::security::firewall::RelayCaller::new(&key, keyed);
                    fw.record_digest(caller, &server, &tool, &digest);
                },
            ))
        }
        #[cfg(not(feature = "firewall"))]
        {
            let _ = (who, server, tool, value);
            None
        }
    }

    /// A final check may have changed the delivered result (a redaction):
    /// the staged receipts then describe text the caller never got.
    ///
    /// One staged receipt (a single-target call) is rebuilt from what is
    /// delivered, so the text the caller still got keeps its receipt and the
    /// removed text stops being tracked. A plan's step receipts are kept for
    /// [`MetaMcp::rebuild_receipt_from_final`], which keeps each to the text
    /// the final answer still delivers; until then they never commit. A task
    /// envelope with no delivered slot keeps every staged receipt, as the
    /// rebuild does (they came from the stored slot). Otherwise several
    /// receipts of no plan cannot be told apart and are dropped.
    ///
    /// `shape` is how the caller delivered the answer: only a `gateway_invoke`
    /// wrapper is read decoded. A surfaced tool's text is read as delivered,
    /// even when it happens to look like the wrapper (MIK-7906).
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unused_self, clippy::needless_pass_by_value)
    )]
    pub(crate) fn restage_if_changed(
        &self,
        snapshot: Option<Value>,
        result: Option<&Value>,
        shape: AnswerShape,
    ) {
        let Some(before) = snapshot.filter(|before| Some(before) != result) else {
            return;
        };
        #[cfg(feature = "firewall")]
        let shape = result.map_or(shape, |answer| shape.as_built(answer));
        // MIK-7939: an in-place rewrite keeps the gateway's members its own.
        #[cfg(feature = "firewall")]
        if let Some(after) = result {
            use super::super::gateway_writes::rebind;
            rebind(Layer::Answer, &before, after);
            if let (Some(b), Some(a)) = (tool_value(&before, shape), tool_value(after, shape)) {
                rebind(Layer::Value, &b, &a);
            }
        }
        #[cfg(not(feature = "firewall"))]
        drop(before);
        let _ = RELAY_RECEIPTS.try_with(|receipts| {
            let mut receipts = receipts.borrow_mut();
            let mut staged = std::mem::take(&mut *receipts);
            // A plan's step receipts wait for the final answer, which keeps
            // each to the text it still delivers (MIK-7887.RECEIPT.2).
            if staged.iter().any(|r| r.in_plan) {
                staged.retain(|r| r.in_plan);
                for r in &mut staged {
                    r.pending_retain = true;
                }
                *receipts = staged;
                return;
            }
            // No slot: the receipt came from the stored slot, never from the
            // envelope's fields, and stays (as `rebuild_receipt_from_final`).
            #[cfg(feature = "firewall")]
            if shape == AnswerShape::TaskEnvelope && result.is_some_and(|d| task_slot(d).is_none())
            {
                *receipts = staged;
                return;
            }
            #[cfg(feature = "firewall")]
            if shape == AnswerShape::InvokeWrapped
                && staged.len() == 1
                && let (Some(fw), Some(text)) = (
                    &self.firewall,
                    result.and_then(super::super::audit::rewritten_text),
                )
            {
                keep_to_rewritten(fw, &mut staged, text);
                *receipts = staged;
                return;
            }
            #[cfg(feature = "firewall")]
            if let ([one], Some(delivered), Some(fw)) = (staged.as_slice(), result, &self.firewall)
                && let Some(digest) = fw.delivery_digest(
                    &one.server,
                    &one.tool,
                    &*match shape {
                        AnswerShape::InvokeWrapped => {
                            super::super::audit::delivered_value(delivered)
                        }
                        AnswerShape::Literal => std::borrow::Cow::Borrowed(delivered),
                        // A slotless envelope kept its receipt above.
                        AnswerShape::TaskEnvelope => std::borrow::Cow::Borrowed(
                            task_slot(delivered).unwrap_or(&serde_json::Value::Null),
                        ),
                    },
                )
            {
                // A redaction can drop the classification marker with the
                // text; what the call was judged sensitive for stays so.
                let digest = digest.keeping_sensitivity_of(&one.digest);
                receipts.push(super::Receipt {
                    key: one.key.clone(),
                    keyed: one.keyed,
                    server: one.server.clone(),
                    tool: one.tool.clone(),
                    digest,
                    in_plan: false,
                    pending_retain: false,
                });
            }
            #[cfg(not(feature = "firewall"))]
            drop((staged, shape));
        });
    }

    /// MIK-7887.RECEIPT.4: rebuild a single staged receipt from `result` as it
    /// is finally delivered, after every late rewrite (the scope clamp, the
    /// chain, the modern `serverInfo` stamp, a redaction), so the receipt holds
    /// the backend text the caller got and nothing else. Members the gateway
    /// itself wrote on this route are not backend text and are left out.
    ///
    /// A plan's answer is not any one step's text: each step receipt is kept
    /// to what the answer still delivers, never rebuilt from it, so text the
    /// engine wrote is attributed to no backend (MIK-7887.RECEIPT.2).
    #[cfg_attr(
        not(feature = "firewall"),
        allow(clippy::unused_self, clippy::needless_pass_by_value)
    )]
    pub(crate) fn rebuild_receipt_from_final(
        &self,
        result: Option<&Value>,
        stamps: GatewayStamps,
        shape: AnswerShape,
    ) {
        #[cfg(feature = "firewall")]
        {
            let (Some(result), Some(fw)) = (result, self.firewall.as_deref()) else {
                return;
            };
            if !self.relay_active() {
                return;
            }
            let _ = RELAY_RECEIPTS.try_with(|receipts| {
                let mut receipts = receipts.borrow_mut();
                // MIK-7998: a wrapper no longer in the gateway's print keeps
                // its staged receipt, kept to the text delivered.
                if shape.as_built(result) == AnswerShape::InvokeWrapped
                    && receipts.len() == 1
                    && !receipts.iter().any(|r| r.in_plan)
                    && let Some(text) = super::super::audit::rewritten_text(result)
                {
                    keep_to_rewritten(fw, &mut receipts, text);
                    return;
                }
                // A task envelope with no delivered slot keeps the staged
                // receipt: it was staged from the stored slot, never from
                // the envelope's own fields.
                let Some(copy) = receipt_copy(result, stamps, shape) else {
                    return;
                };
                if receipts.iter().any(|r| r.in_plan) {
                    keep_plan_receipts(fw, &mut receipts, &plan_answer(copy));
                    return;
                }
                let [one] = receipts.as_mut_slice() else {
                    return;
                };
                if let Some(digest) = fw.delivery_digest(&one.server, &one.tool, &copy) {
                    one.digest = digest.keeping_sensitivity_of(&one.digest);
                }
            });
        }
        #[cfg(not(feature = "firewall"))]
        let _ = (result, stamps, shape);
    }
}

/// A plan's answer as delivered: the steps' JSON a `wrap_tool_success`
/// envelope carries in its one text block, read decoded whether or not it is
/// the exact pretty print; anything else as it stands.
#[cfg(feature = "firewall")]
fn plan_answer(copy: Value) -> Value {
    let decoded = match copy
        .get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
    {
        Some([block]) => block
            .get("text")
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .filter(|v| v.is_object() || v.is_array()),
        _ => None,
    };
    decoded.unwrap_or(copy)
}

/// Keep each plan step receipt to what `answer` delivers; drop them all when
/// the answer is over the bound they are kept against.
#[cfg(feature = "firewall")]
fn keep_plan_receipts(
    fw: &crate::security::firewall::Firewall,
    receipts: &mut Vec<super::Receipt>,
    answer: &Value,
) {
    // MIK-8094: with the delivery's staged total, so a plan whose receipts
    // were dropped at staging and are dropped again here counts once.
    let staged = super::RELAY_STAGED.try_with(|s| fw.delivered_for_plan(answer, Some(s)));
    let Some(delivered) = staged.unwrap_or_else(|_| fw.delivered_for_plan(answer, None)) else {
        receipts.retain(|r| !r.in_plan);
        return;
    };
    for r in receipts.iter_mut().filter(|r| r.in_plan) {
        let digest = std::mem::take(&mut r.digest);
        r.digest = fw.retain_delivered(digest, &delivered);
        r.pending_retain = false;
    }
}

/// MIK-7998: the single staged receipt kept to a wrapper the gateway's own
/// final pass rewrote, read as the caller reads it. The staged receipt is the
/// backend's value, decoded, without the gateway's members; keeping it to the
/// delivered text removes what the rewrite took out. Dropped and counted when
/// the text is over the bound plans are kept against.
#[cfg(feature = "firewall")]
fn keep_to_rewritten(
    fw: &crate::security::firewall::Firewall,
    receipts: &mut Vec<super::Receipt>,
    text: &str,
) {
    let [one] = receipts.as_mut_slice() else {
        return;
    };
    let read = rewritten_answer(text);
    let staged = super::RELAY_STAGED.try_with(|s| fw.delivered_for_plan(&read, Some(s)));
    match staged.unwrap_or_else(|_| fw.delivered_for_plan(&read, None)) {
        Some(delivered) => {
            let digest = std::mem::take(&mut one.digest);
            one.digest = fw.retain_delivered(digest, &delivered);
        }
        None => receipts.clear(),
    }
}

/// `MIK-8043.JOIN.4`: a rewritten wrapper as the caller reads it, member by
/// member. The pretty print puts every scalar on its own line and a JSON
/// string never holds a raw newline, so each line's string literals are read
/// escape-aware and unescaped: a literal whose closing quote is gone runs to
/// the line's end, and the line is also read from its end, so a damaged key
/// does not take the value beside it. Values come first, then keys, then the
/// flat text, which only widens what counts as delivered.
#[cfg(feature = "firewall")]
fn rewritten_answer(text: &str) -> Value {
    let (mut values, mut keys) = (Vec::new(), serde_json::Map::new());
    for (literal, key) in text.lines().flat_map(line_literals) {
        if key {
            keys.insert(literal, Value::Null);
        } else {
            values.push(Value::String(literal));
        }
    }
    values.push(Value::String(unescape(text)));
    values.push(Value::Object(keys));
    Value::Array(values)
}

/// The string literals on one line of a pretty print, unescaped, each with
/// whether it is a key (a `:` follows it).
#[cfg(feature = "firewall")]
fn line_literals(line: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(open) = line[at..].find('"') {
        let start = at + open + 1;
        let close = closing_quote(&line[start..]).map(|c| start + c);
        let (raw, next) = close.map_or((&line[start..], line.len()), |c| (&line[start..c], c + 1));
        out.push((unescape(raw), line[next..].trim_start().starts_with(':')));
        at = next;
    }
    let tail = line.trim_end().trim_end_matches(',');
    if let Some(body) = tail.strip_suffix('"')
        && let Some(open) = last_open_quote(body)
    {
        let last = unescape(&body[open + 1..]);
        if !out.iter().any(|(literal, _)| *literal == last) {
            out.push((last, false));
        }
    }
    out
}

/// The byte offset of the first unescaped `"` in `rest`.
#[cfg(feature = "firewall")]
fn closing_quote(rest: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(i),
            _ => {}
        }
    }
    None
}

/// The byte offset of the last `"` in `body` that no backslash escapes.
#[cfg(feature = "firewall")]
fn last_open_quote(body: &str) -> Option<usize> {
    body.match_indices('"').map(|(i, _)| i).rev().find(|&i| {
        let slashes = body[..i].bytes().rev().take_while(|&b| b == b'\\').count();
        slashes % 2 == 0
    })
}

/// The text of a JSON print as a caller reads it: each string escape
/// decoded, a malformed escape or an unpaired surrogate kept as written.
#[cfg(feature = "firewall")]
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let escape = &rest[at..];
        let (decoded, used) = escape_at(escape);
        match decoded {
            Some(c) => out.push(c),
            None => out.push_str(&escape[..used]),
        }
        rest = &escape[used..];
    }
    out.push_str(rest);
    out
}

/// The char the escape at the start of `escape` stands for, and its length
/// in bytes; `None` keeps those bytes as written.
#[cfg(feature = "firewall")]
fn escape_at(escape: &str) -> (Option<char>, usize) {
    let simple = |c| (Some(c), 2);
    match escape.as_bytes().get(1) {
        Some(b'n') => simple('\n'),
        Some(b't') => simple('\t'),
        Some(b'r') => simple('\r'),
        Some(b'"') => simple('"'),
        Some(b'\\') => simple('\\'),
        Some(b'/') => simple('/'),
        Some(b'b') => simple('\u{8}'),
        Some(b'f') => simple('\u{c}'),
        Some(b'u') => match hex4(escape, 2) {
            Some(high @ 0xD800..=0xDBFF) => match (escape.get(6..8), hex4(escape, 8)) {
                (Some("\\u"), Some(low @ 0xDC00..=0xDFFF)) => (
                    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)),
                    12,
                ),
                _ => (None, 6),
            },
            Some(code) => (char::from_u32(code), 6),
            None => (None, 1),
        },
        _ => (None, 1),
    }
}

/// The four hex digits at `at` of `text`, as a number.
#[cfg(feature = "firewall")]
fn hex4(text: &str, at: usize) -> Option<u32> {
    let digits = text.get(at..at + 4)?;
    digits
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| u32::from_str_radix(digits, 16).ok())
        .flatten()
}

/// Which members of a delivered result the gateway wrote on its route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayStamps {
    /// A modern answer: the gateway stamps `_meta` `serverInfo` over the
    /// backend's.
    Modern,
    /// A legacy answer: a backend `serverInfo` reaches the caller as sent.
    Legacy,
}

/// How a delivered answer carries its tool's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerShape {
    /// A `gateway_invoke` answer: the gateway wraps the value as JSON text.
    InvokeWrapped,
    /// A surfaced tool's answer: its blocks are read as the caller sees them.
    Literal,
    /// A task's answer: the gateway's task envelope around the slot it
    /// delivers (`result`, `inputRequests` or `error`); only that slot is
    /// the backend's (MIK-7939).
    TaskEnvelope,
}

impl AnswerShape {
    /// The shape the gateway gives an answer to `external_tool`: a
    /// `gateway_invoke` or single-tool `gateway_execute` answer is wrapped
    /// (`wrap_tool_success`), a `tasks/*` answer is a task envelope.
    #[must_use]
    pub(crate) fn of(external_tool: &str) -> Self {
        match external_tool {
            "gateway_invoke" | "gateway_execute" => Self::InvokeWrapped,
            method if method.starts_with("tasks/") => Self::TaskEnvelope,
            _ => Self::Literal,
        }
    }

    /// The shape `answer` was built in: a task envelope the gateway built
    /// on this call (a task-augmented `tools/call`) whatever the method.
    #[cfg(feature = "firewall")]
    fn as_built(self, answer: &Value) -> Self {
        if super::super::gateway_writes::built_task_envelope(answer) {
            Self::TaskEnvelope
        } else {
            self
        }
    }
}

/// Remove what `stamps` says the gateway stamped on a delivered result: a
/// modern answer's `_meta` `serverInfo`, written by the shaper over the
/// backend's. Every receipt copy, on either route, removes it here.
#[cfg(feature = "firewall")]
pub(crate) fn strip_gateway_stamps(value: &mut Value, stamps: GatewayStamps) {
    if stamps == GatewayStamps::Modern
        && let Some(meta) = value.get_mut("_meta").and_then(Value::as_object_mut)
    {
        meta.remove(crate::protocol::meta::KEY_SERVER_INFO);
    }
}

/// The backend text of a finally delivered `result`: the gateway's chain
/// removed, every scope clamped as the wire clamps it (top level and a task
/// envelope's retained result), a modern answer's `serverInfo` stamp removed,
/// and a `gateway_invoke` wrapper read decoded.
#[cfg(feature = "firewall")]
fn receipt_copy(result: &Value, stamps: GatewayStamps, shape: AnswerShape) -> Option<Value> {
    let shape = shape.as_built(result);
    let mut copy = result.clone();
    crate::security::signature_chain::strip_chain(&mut copy);
    // Clamped as the wire clamps it, so a backend's text in a scope, top
    // level or in a task envelope's retained result, is never digested.
    crate::protocol::cacheable::clamp_delivered_scope(&mut copy);
    strip_gateway_stamps(&mut copy, stamps);
    // MIK-7939: what the gateway itself wrote on this call is not backend
    // text, at either layer, and nothing else is removed for its name.
    super::super::gateway_writes::strip(&mut copy, Layer::Answer);
    let mut value = tool_value(&copy, shape)?;
    super::super::gateway_writes::strip(&mut value, Layer::Value);
    Some(value)
}

/// The tool value an answer of `shape` carries: a wrapper read decoded, a
/// task envelope's delivered slot, anything else as it stands.
#[cfg(feature = "firewall")]
fn tool_value(answer: &Value, shape: AnswerShape) -> Option<Value> {
    // An interim answer (`inputRequests`, `requestState`) is a promoted
    // native result, not a wrapper: its members are delivered as they stand.
    let interim = answer.get("inputRequests").is_some() || answer.get("requestState").is_some();
    match shape {
        AnswerShape::InvokeWrapped if !interim => {
            Some(super::super::audit::delivered_value(answer).into_owned())
        }
        AnswerShape::InvokeWrapped | AnswerShape::Literal => Some(answer.clone()),
        AnswerShape::TaskEnvelope => task_slot(answer).cloned(),
    }
}

/// The slot a task envelope delivers: its retained result, its pending input
/// requests, or a failed task's error.
#[cfg(feature = "firewall")]
fn task_slot(envelope: &Value) -> Option<&Value> {
    ["result", "inputRequests", "error"]
        .iter()
        .find_map(|slot| envelope.get(slot))
}

#[cfg(all(test, feature = "firewall"))]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::protocol::meta::KEY_SERVER_INFO;

    /// `MIK-8043.JOIN.4`: each literal on a line, unescaped, with whether it
    /// is a key; a literal that lost its closing quote runs to the line's end.
    #[test]
    fn a_print_line_is_read_literal_by_literal() {
        let lit = |s: &str, key| (s.to_owned(), key);
        assert_eq!(
            line_literals(r#"    "type": "text","#),
            [lit("type", true), lit("text", false)]
        );
        assert_eq!(
            line_literals(r#"    "text": "a \"quoted\" word""#),
            [lit("text", true), lit("a \"quoted\" word", false)]
        );
        assert_eq!(
            line_literals(r#"    "text": "postgres://[REDACTED]"#),
            [lit("text", true), lit("postgres://[REDACTED]", false)]
        );
    }

    /// `MIK-8043.JOIN.4` (G1): a key that lost its closing quote does not take
    /// the value beside it; the line is read from its end too.
    #[test]
    fn a_damaged_key_keeps_the_value_beside_it() {
        let literals = line_literals(r#"    "te[REDACTED] "south terrace rows","#);
        assert!(
            literals.contains(&("south terrace rows".to_owned(), false)),
            "{literals:?}"
        );
    }

    /// `MIK-8043.JOIN.4`: values in print order, then the flat text, then the
    /// keys, as a delivery walk reads them.
    #[test]
    fn a_rewritten_answer_lists_values_then_flat_text_then_keys() {
        let text = "{\n  \"content\": [\n    \"x\",\n    \"y\"\n  ]\n}";
        let read = rewritten_answer(text);
        assert_eq!(read[0], "x");
        assert_eq!(read[1], "y");
        assert_eq!(read[2], unescape(text));
        assert!(read[3].get("content").is_some(), "{read}");
    }

    /// A delivered answer with a `serverInfo` in its `_meta`.
    fn answered() -> Value {
        json!({"content": [], "_meta": {KEY_SERVER_INFO: {"name": "named"}, "keep": 1}})
    }

    /// MIK-7887.RECEIPT.4: a modern answer's `serverInfo` is the gateway's
    /// stamp and leaves the receipt copy; the rest of `_meta` stays.
    #[test]
    fn a_modern_copy_drops_the_server_info_stamp() {
        let copy =
            receipt_copy(&answered(), GatewayStamps::Modern, AnswerShape::Literal).expect("a copy");
        assert!(copy["_meta"].get(KEY_SERVER_INFO).is_none(), "{copy}");
        assert_eq!(copy["_meta"]["keep"], 1, "{copy}");
    }

    /// MIK-7887.RECEIPT.4: a legacy answer's `serverInfo` is the backend's,
    /// delivered as sent, so it stays in the receipt copy.
    #[test]
    fn a_legacy_copy_keeps_the_backends_server_info() {
        let copy =
            receipt_copy(&answered(), GatewayStamps::Legacy, AnswerShape::Literal).expect("a copy");
        assert_eq!(copy["_meta"][KEY_SERVER_INFO]["name"], "named", "{copy}");
    }

    /// `MIK-7998.DECODE.1`: escapes read as the caller reads them, a literal
    /// backslash and a surrogate pair included.
    #[test]
    fn unescape_reads_a_print_as_the_caller_reads_it() {
        assert_eq!(unescape(r#"a\nb \"q\" c\\n"#), "a\nb \"q\" c\\n");
        assert_eq!(unescape(r"\t\r\/\b\f"), "\t\r/\u{8}\u{c}");
        assert_eq!(unescape(r"é 𝄞"), "\u{e9} \u{1D11E}");
    }

    /// `MIK-7998.DECODE.1`: a malformed escape or an unpaired surrogate is kept
    /// as written, never dropped.
    #[test]
    fn unescape_keeps_a_malformed_escape_as_written() {
        for kept in [r"\x", r"\u12", r"\uq1w2", r"\ud834 x", r"\udd1e", "end\\"] {
            assert_eq!(unescape(kept), kept, "{kept}");
        }
    }

    /// MIK-7998: the gateway's own print is read decoded; a block its final
    /// pass rewrote, JSON or not, is read as rewritten text.
    #[test]
    fn only_a_block_that_is_not_the_gateways_print_is_rewritten() {
        use super::super::super::audit::rewritten_text;
        let wrap = |text: &str| json!({"content": [{"type": "text", "text": text}]});
        let printed = serde_json::to_string_pretty(&json!({"a": "x\ny"})).unwrap();
        assert_eq!(rewritten_text(&wrap(&printed)), None);
        let broken = printed.replace("y\"", "[REDACTED]");
        let block = wrap(&broken);
        assert_eq!(rewritten_text(&block), Some(broken.as_str()));
        let compact = serde_json::to_string(&json!({"a": 1})).unwrap();
        assert!(rewritten_text(&wrap(&compact)).is_some());
        let structured =
            json!({"content": [{"type": "text", "text": "x"}], "structuredContent": {}});
        assert_eq!(rewritten_text(&structured), None);
        let interim = json!({"content": [{"type": "text", "text": "confirm?"}],
            "resultType": "input_required", "inputRequests": {}, "requestState": "s"});
        assert_eq!(
            rewritten_text(&interim),
            None,
            "a native answer is read whole"
        );
        let stamped = json!({"content": [{"type": "text", "text": broken}],
            "resultType": "complete", "_signature": {}, "_meta": {}});
        assert!(
            rewritten_text(&stamped).is_some(),
            "the gateway's final stamps stay a wrapper"
        );
    }
}
