// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The paged `*/list` drain shared by every cached metadata family.

use std::collections::HashSet;

use serde_json::{Value, json};

use super::metadata::ListFamily;
use super::{CACHE_LIST_DRAIN_BUDGET, LIST_MAX_PAGES};
use crate::Error;
use crate::Result;

/// Drain every `nextCursor` page into one result, then let the caller parse
/// it ONCE: the tools `parse` rewrites `resend_permitted`, so a per-page
/// parse would keep only the last page's retry set. Page 1 sends no params,
/// so a single-page backend sees byte-identical traffic. Returns the merged
/// result (`None` if page 1 had none) and whether the drain stopped early.
///
/// A page error fails the whole fill, keeping the last complete catalogue
/// (design E). A structural stop (page cap, repeated `nextCursor`, the drain
/// budget) keeps the fresh pages: retrying cannot complete them (D, F, G).
pub(super) async fn drain_list_pages(
    transport: &dyn crate::transport::Transport,
    backend: &str,
    family: &ListFamily,
    headers: &[(String, String)],
    identity_key: Option<&str>,
) -> Result<(Option<Value>, bool)> {
    let started = tokio::time::Instant::now();
    let mut merged: Option<Value> = None;
    let mut cursor: Option<String> = None;
    let mut sent: HashSet<String> = HashSet::new();
    let mut stop: Option<&'static str> = None;
    // A page whose list key is missing or not an array says nothing about
    // which entries exist (mirrors the direct route, `direct_list.rs`): the
    // drain keeps going, but the result must never be judged as a complete
    // listing, or an earlier page's withheld name reads as removed (#1441).
    let mut unreadable = false;
    let mut kept = 0usize;
    for page in 0.. {
        if page == LIST_MAX_PAGES {
            stop = Some("page_cap");
            break;
        }
        if page > 0 && started.elapsed() >= CACHE_LIST_DRAIN_BUDGET {
            stop = Some("fill_budget");
            break;
        }
        let params = cursor.clone().map(|c| json!({ "cursor": c }));
        // A `*/list` is in the side-effect-free allowlist
        // (`transport::SIDE_EFFECT_FREE_METHODS`), so a retried fetch
        // cannot duplicate an upstream effect.
        let permission = crate::transport::ResendPermission::Permitted;
        if family.method == "tools/list" {
            // Probe only (throwaway): who sends each tools/list.
            tracing::info!(
                target: "probe_list",
                page,
                at = ?std::time::SystemTime::now(),
                bt = %std::backtrace::Backtrace::force_capture(),
                "PROBE tools/list sent"
            );
        }
        let response = transport
            .request_with_headers(family.method, params, headers, identity_key, permission)
            .await?;
        if let Some(error) = response.error {
            return Err(Error::json_rpc(error.code, error.message));
        }
        // Readable: a string cursor or none; the list an array, or absent
        // beside a cursor. A mistyped cursor would read as the last page.
        let readable = |r: &Value| {
            let cursor = r.get("nextCursor").filter(|c| !c.is_null());
            cursor.is_none_or(Value::is_string)
                && match r.get(family.list_key) {
                    Some(list) => list.is_array(),
                    None => r.is_object() && cursor.is_some(),
                }
        };
        let Some(mut result) = response.result.filter(readable) else {
            // A missing or malformed page is a transient page failure (F13:
            // as zero items it would make a present tool absent); keep the
            // last complete catalogue (design E).
            return Err(Error::json_rpc(
                -32603,
                format!("{} page {} is not a readable list", family.method, page + 1),
            ));
        };
        let next = result
            .as_object_mut()
            .and_then(|m| m.remove("nextCursor"))
            .and_then(|v| v.as_str().map(str::to_owned));
        if let Some(acc) = merged.as_mut() {
            let items = if let Some(items) = result
                .get_mut(family.list_key)
                .and_then(Value::as_array_mut)
            {
                std::mem::take(items)
            } else {
                unreadable = true;
                Vec::new()
            };
            // A continuation page may still legitimately omit the key (an
            // upstream that answers `{nextCursor}` alone); either way create
            // the array so later pages' items are not dropped.
            if let Some(list) = acc
                .as_object_mut()
                .map(|m| m.entry(family.list_key).or_insert_with(|| json!([])))
                .and_then(Value::as_array_mut)
            {
                list.extend(items);
            }
        } else {
            if !result.get(family.list_key).is_some_and(Value::is_array) {
                unreadable = true;
            }
            merged = Some(result);
        }
        kept += 1;
        let Some(next) = next else { break };
        if !sent.insert(next.clone()) {
            stop = Some("cursor_repeat");
            break;
        }
        cursor = Some(next);
    }
    if let Some(reason) = stop.or(unreadable.then_some("unreadable_page")) {
        telemetry_metrics::counter!(
            "mcp_backend_list_truncated_total",
            "backend" => backend.to_owned(),
            "reason" => reason
        )
        .increment(1);
        tracing::warn!(
            backend,
            method = family.method,
            reason,
            pages_kept = kept,
            "Backend list drain stopped early; catalogue truncated"
        );
    }
    Ok((merged, stop.is_some() || unreadable))
}
