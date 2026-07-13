// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Option A: gateway-side per-backend ground-truth extractors (MIK-6914).
//!
//! [`super::claim_capture`] records a *claim-under-test* (what the agent said
//! it rendered — untrusted client input, see [`super::claim_capture::ClientClaim`])
//! and scores it against the gateway's signed
//! [`super::result_provenance::RuntimeProvenanceReceipt`]. For that score to be
//! anything other than "the call succeeded", the receipt needs an *observed*
//! ground-truth fact the scorer can adjudicate against — concretely a
//! [`RuntimeProvenanceReceipt::row_count`](super::result_provenance::RuntimeProvenanceReceipt::row_count).
//!
//! This module is the only place that fact is derived. It is deliberately a
//! *closed* dispatch keyed on `(backend, tool)`: a backend gets an extractor
//! **only** when its result shape carries a genuine authoritative count that
//! reliably distinguishes "the source was queried and was empty" from "the
//! count could not be checked". Every other backend returns [`None`], which the
//! receipt records as `row_count = None` — "not observed", never zero (the
//! [`super::result_provenance`] module contract).
//!
//! ## The stop-line (MIK-5854)
//!
//! The one invariant that makes this honest rather than a fabricated metric:
//! **an extractor may only ever return [`None`] when it cannot cleanly read an
//! authoritative count.** It never guesses a count from an arbitrary array
//! length or a `"results"`/`"items"` field it happens to find. The worst case
//! for an unrecognised or malformed payload is [`None`] → the scorer
//! *abstains*; it can never be a wrong count → a fabricated authoritative
//! negative. Guessing here is the MIK-5854 failure mode and is forbidden.
//!
//! ## Supported backends
//!
//! - **`github_search_repos`** — GitHub's `/search/repositories` response
//!   carries a server-computed `total_count` (the exact number of matching
//!   repositories) alongside `incomplete_results`. `total_count == 0` is an
//!   authoritative empty; `incomplete_results == true` means GitHub's search
//!   did not finish, so the count is *not* authoritative and the extractor
//!   yields [`None`] (could-not-check). This is the one strong candidate the
//!   MIK-6914 catalog survey identified.

use serde_json::Value;

/// Derive the authoritative observed row/item count for one tool result, if —
/// and only if — a per-backend Option A extractor recognises the `(backend,
/// tool)` pair and can read a genuine count from the payload.
///
/// Returns [`None`] ("not observed") for every unrecognised backend, for a
/// failed call (`backend_ok == false` — nothing the source "said" is
/// authoritative when the call errored), and whenever the recognised payload
/// cannot be cleanly read. It never fabricates a count; see the module-level
/// stop-line.
#[must_use]
pub fn extract_row_count(
    backend: &str,
    tool: &str,
    result: &Value,
    backend_ok: bool,
) -> Option<u64> {
    // `backend` is threaded for future per-backend disambiguation (two backends
    // could expose a same-named tool with different shapes); today the tool name
    // alone selects the extractor.
    let _ = backend;
    // A failed call carries no authoritative statement about the source's
    // contents; the scorer already treats every positive claim over a failed
    // call as unsupported, so there is nothing honest to observe here.
    if !backend_ok {
        return None;
    }
    let payload = unwrap_payload(result)?;
    // Closed per-backend dispatch table: a backend is extracted only when its
    // result shape carries a genuine authoritative count. Kept as a `match` (not
    // an `if`) because it grows one arm per qualifying backend; the single-arm
    // form is intentional and forward-looking, not an equality check.
    #[allow(clippy::single_match_else)]
    match tool {
        "github_search_repos" => github_search_row_count(&payload),
        _ => None,
    }
}

/// Unwrap the inner capability payload from the MCP result envelope, mirroring
/// the gateway's own `extract_output_validation_target`: prefer
/// `structuredContent`, else a single `content[0].text` that parses as JSON.
///
/// Anything else (multi-part content, non-JSON text, a bare envelope) yields
/// [`None`] — the extractor then abstains rather than guess.
fn unwrap_payload(result: &Value) -> Option<Value> {
    if let Some(structured) = result.get("structuredContent") {
        return Some(structured.clone());
    }
    let content = result.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let text = content[0].get("text")?.as_str()?;
    serde_json::from_str::<Value>(text).ok()
}

/// Read GitHub's authoritative `total_count` from a search payload.
///
/// `incomplete_results == true` means GitHub's search timed out before
/// completing, so neither `total_count` nor `items` is authoritative — the
/// extractor yields [`None`] (could-not-check), never a partial count dressed
/// up as ground truth. Otherwise a numeric `total_count` (including `0`, an
/// authoritative empty) is returned verbatim.
///
/// If a future projection ever wraps the payload, the untouched backend body is
/// preserved under `_raw` (the [`crate::projection`] contract); the count is
/// read from there when the top level does not carry it.
fn github_search_row_count(payload: &Value) -> Option<u64> {
    let body = github_body(payload);
    if body.get("incomplete_results").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    body.get("total_count").and_then(Value::as_u64)
}

/// Choose the object that actually carries `total_count`: the payload itself
/// when it has the field, otherwise a projection-preserved `_raw` body when
/// *that* has it, otherwise the payload unchanged (the caller then abstains).
fn github_body(payload: &Value) -> &Value {
    if payload.get("total_count").is_some() {
        return payload;
    }
    match payload.get("_raw") {
        Some(raw) if raw.get("total_count").is_some() => raw,
        _ => payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const GH: &str = "github_search_repos";

    fn structured(payload: Value) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("isError".into(), Value::Bool(false));
        map.insert("structuredContent".into(), payload);
        Value::Object(map)
    }

    fn text_result(payload: &Value) -> Value {
        json!({
            "isError": false,
            "content": [{ "type": "text", "text": serde_json::to_string(payload).unwrap() }]
        })
    }

    /// A populated GitHub search yields its exact server-computed `total_count`
    /// — the authoritative non-empty ground truth (`FoundRows`), read from
    /// `structuredContent`.
    #[test]
    fn github_populated_search_returns_total_count() {
        let result = structured(json!({
            "total_count": 42, "incomplete_results": false, "items": [{}, {}]
        }));
        assert_eq!(extract_row_count("caps", GH, &result, true), Some(42));
    }

    /// `total_count == 0` is an *authoritative empty*: the search ran and
    /// matched nothing. This is the signal that lets a "no results" claim be
    /// scored `Supported` instead of forcing an abstain.
    #[test]
    fn github_empty_search_returns_zero_not_none() {
        let result = structured(json!({
            "total_count": 0, "incomplete_results": false, "items": []
        }));
        assert_eq!(extract_row_count("caps", GH, &result, true), Some(0));
    }

    /// `incomplete_results == true` means GitHub's search did not finish, so the
    /// count is not authoritative — the extractor abstains (`None`) rather than
    /// report a partial count as ground truth.
    #[test]
    fn github_incomplete_results_is_could_not_check() {
        let result = structured(json!({
            "total_count": 3, "incomplete_results": true, "items": [{}]
        }));
        assert_eq!(extract_row_count("caps", GH, &result, true), None);
    }

    /// The count is read identically when the payload arrives as a single
    /// JSON `content[0].text` block rather than `structuredContent`.
    #[test]
    fn github_count_read_from_content_text_json() {
        let payload = json!({ "total_count": 7, "incomplete_results": false, "items": [] });
        assert_eq!(
            extract_row_count("caps", GH, &text_result(&payload), true),
            Some(7)
        );
    }

    /// A failed call is never an authoritative statement about the source, so no
    /// count is observed regardless of what the (stale/error) body contains.
    #[test]
    fn failed_call_observes_no_count() {
        let result = structured(json!({ "total_count": 9, "incomplete_results": false }));
        assert_eq!(extract_row_count("caps", GH, &result, false), None);
    }

    /// An unrecognised tool has no Option A extractor: the honest floor is
    /// `None` ("not observed"), never a guessed count from some array length.
    #[test]
    fn unknown_tool_never_guesses_a_count() {
        let result = structured(json!({ "results": [1, 2, 3], "count": 3 }));
        assert_eq!(
            extract_row_count("caps", "some_other_search", &result, true),
            None
        );
    }

    /// A recognised backend whose payload is missing `total_count` abstains
    /// rather than invent one — the stop-line made structural.
    #[test]
    fn github_payload_without_total_count_abstains() {
        let result = structured(json!({ "items": [{}, {}], "message": "rate limited" }));
        assert_eq!(extract_row_count("caps", GH, &result, true), None);
    }

    /// Non-JSON `content` text cannot be a source payload: abstain.
    #[test]
    fn non_json_content_text_abstains() {
        let result = json!({
            "isError": false,
            "content": [{ "type": "text", "text": "not json at all" }]
        });
        assert_eq!(extract_row_count("caps", GH, &result, true), None);
    }

    /// When a projection preserves the untouched body under `_raw`, the count is
    /// read from there — future-proofing without ever reading a projected view.
    #[test]
    fn github_count_read_from_projected_raw_fallback() {
        let result = structured(json!({
            "actor": "torvalds",
            "_raw": { "total_count": 5, "incomplete_results": false, "items": [] }
        }));
        assert_eq!(extract_row_count("caps", GH, &result, true), Some(5));
    }
}
