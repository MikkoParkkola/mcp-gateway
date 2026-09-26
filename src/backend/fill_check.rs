// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 (MIK-7586): the catalogue fill R2's check runs on a cold slot.
//!
//! A check-site fill is the ordinary single-flight tools fill with a
//! `CallTimeout` bound. Before it touches the wire it asks the slot's breaker,
//! then the failure cooldown, then the limiter (Amendment 1, Revision 1a), and
//! it reports its outcome to the breaker as a dispatch does. Every tools fill,
//! whatever its bound, carries a [`FillGuard`] that stamps the cooldown when
//! the fill ends without storing, and never on a caller cancellation.

use std::sync::Arc;
use std::time::Duration;

use super::LIST_MAX_PAGES;
use super::pool::PooledEntry;
use crate::trust::closed_keys::{count, count_reason};
use crate::{Error, Result};

/// After a tools fill ends without storing, fills of that slot fail fast for
/// this long instead of each taking a `tools/list` of their own.
pub(crate) const LIST_FILL_COOLDOWN: Duration = Duration::from_secs(10);

/// How much longer than `timeout` a check-site caller waits on another
/// caller's fill, so the leader's own inner timeout always fires first.
pub(crate) const LIST_FILL_WAIT_GRACE: Duration = Duration::from_secs(1);

/// What bounds one fill's drain (design §2 step 2, Revision 3).
#[derive(Clone, Copy, Debug)]
pub(crate) enum FillBound {
    /// Discovery, `gateway_search` and every other caller: only the drain's
    /// own structural stop (`CACHE_LIST_DRAIN_BUDGET`), and no failsafe gate.
    DrainBudget,
    /// A check-site fill: the drain is abandoned after this long, and the
    /// fill is gated on and recorded against the slot's failsafe.
    CallTimeout(Duration),
}

/// Whether the list a check-site fill returned is the slot's whole catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completeness {
    /// The slot holds this list and its drain ran to the end.
    Complete,
    /// The slot holds this list, but its drain stopped structurally.
    Truncated,
    /// The slot does not hold this list (a voided store, or the slot moved
    /// on): absence from it proves nothing.
    Unknown,
}

/// How a tools fill ended, as its guard sees it on drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FillEnd {
    /// Still draining: a drop here is a caller cancellation.
    Pending,
    /// The drain, parse, start or inner timeout returned an error.
    Failed,
    /// Drained; reaching drop in this state means the store was voided.
    Drained,
    /// The store was accepted.
    Stored,
}

/// Armed once a tools fill is admitted, carried in the fill's side value, and
/// moved to `Stored` only by `on_stored`. `Failed` and `Drained` stamp the
/// cooldown on drop; `Stored` clears it; `Pending` stamps nothing.
pub(crate) struct FillGuard {
    entry: Arc<PooledEntry>,
    end: FillEnd,
}

impl FillGuard {
    pub(super) fn arm(entry: Arc<PooledEntry>) -> Self {
        Self {
            entry,
            end: FillEnd::Pending,
        }
    }

    pub(super) fn end(&mut self, end: FillEnd) {
        self.end = end;
    }
}

impl Drop for FillGuard {
    // Runs under the cache's write guard when `on_stored` ran, so it touches
    // only the stamp mutex and the counters, never the cache.
    fn drop(&mut self) {
        let stamp = &self.entry.tools_fill_failed_at;
        match self.end {
            FillEnd::Pending => count("input_schema_fill_cancelled"),
            FillEnd::Failed => {
                *stamp.lock() = Some(tokio::time::Instant::now());
                count("input_schema_fetch_failed");
            }
            FillEnd::Drained => {
                *stamp.lock() = Some(tokio::time::Instant::now());
                count("input_schema_fetched");
            }
            FillEnd::Stored => {
                *stamp.lock() = None;
                count("input_schema_fetched");
            }
        }
    }
}

/// Steps 1-3 of a fill closure, before its guard is armed: the breaker (a
/// check-site fill only), the cooldown (tools only), the limiter token (a
/// check-site fill only). A refusal here stamps nothing.
pub(super) fn admit_fill(
    entry: &PooledEntry,
    backend: &str,
    bound: FillBound,
    tools: bool,
) -> Result<()> {
    let gated = matches!(bound, FillBound::CallTimeout(_));
    if gated {
        entry
            .failsafe
            .check_circuit(backend)
            .inspect_err(|_| count_reason("input_schema_fill_refused", "circuit"))?;
    }
    let cooling = tools
        && entry
            .tools_fill_failed_at
            .lock()
            .is_some_and(|at| at.elapsed() < LIST_FILL_COOLDOWN);
    if cooling {
        count("input_schema_fill_cooldown");
        return Err(Error::BackendUnavailable(format!(
            "{backend}: tools/list failed within the last {}s",
            LIST_FILL_COOLDOWN.as_secs()
        )));
    }
    if gated {
        entry
            .failsafe
            .take_token(backend)
            .inspect_err(|_| count_reason("input_schema_fill_refused", "rate"))?;
    }
    Ok(())
}

/// Run an admitted fill's drain under its bound, and record a check-site
/// fill's outcome on the slot's breaker as a dispatch would (Amendment 1
/// item 3). A `DrainBudget` fill is neither bounded here nor recorded.
pub(super) async fn run_bounded<T>(
    entry: &PooledEntry,
    backend: &str,
    bound: FillBound,
    drain: impl Future<Output = Result<T>>,
) -> Result<T> {
    let FillBound::CallTimeout(limit) = bound else {
        return drain.await;
    };
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(limit, drain)
        .await
        .unwrap_or_else(|_| Err(list_timeout(backend, limit)));
    let latency = started.elapsed();
    match &result {
        Ok(_) => entry.failsafe.record_success(latency),
        Err(e) => {
            entry
                .failsafe
                .record_dispatch_failure(&e.to_string(), latency);
        }
    }
    result
}

pub(super) fn list_timeout(backend: &str, limit: Duration) -> Error {
    Error::BackendTimeout(format!(
        "{backend}: tools/list did not finish within {}ms",
        limit.as_millis()
    ))
}

/// Text U: the schema could not be read.
pub(crate) const TEXT_UNAVAILABLE: &str = "the gateway could not read this tool's input schema for you; list the backend's tools and retry";

/// Text P: the tool is not in the part of a truncated list the gateway read.
/// Names no config key: the remedy is the operator's, documented in UPGRADING.
pub(crate) fn text_partial() -> String {
    format!(
        "the gateway could not read this backend's whole tool list (it stopped at the \
         {LIST_MAX_PAGES}-page cap, at a repeated page cursor, or at the list time budget), \
         and this tool is not in the part it read, so its input schema cannot be checked"
    )
}

/// Text A: a fresh, complete list does not hold the tool. No retry advice:
/// the same name fails the same way.
pub(crate) fn text_absent(tool: &str) -> String {
    format!("the backend does not list a tool named `{tool}`")
}

#[cfg(test)]
mod tests {
    use super::{LIST_FILL_COOLDOWN, LIST_MAX_PAGES};

    /// Design §6: the numbers UPGRADING §59 prints are the constants' values,
    /// so a changed constant fails the build until the text follows (M6e's
    /// second pin).
    #[test]
    fn upgrading_section_59_quotes_the_constants() {
        let doc = include_str!("../../docs/UPGRADING-4.0.md");
        let start = doc.find("## 59.").expect("section 59");
        let section = &doc[start..];
        let section = &section[..section[3..].find("\n## ").map_or(section.len(), |e| e + 3)];
        let secs = LIST_FILL_COOLDOWN.as_secs();
        for quoted in [
            format!("{LIST_MAX_PAGES}-page cap"),
            format!("{secs} s."),
            format!("The {LIST_MAX_PAGES} pages and the {secs} s above"),
        ] {
            assert!(section.contains(&quoted), "UPGRADING §59 lacks {quoted:?}");
        }
    }
}
