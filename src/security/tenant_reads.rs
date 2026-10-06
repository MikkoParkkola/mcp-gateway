// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cross-tenant read history (MIK-7116.MIN.2, design
//! docs/design/2026-10-01-min2-min4-tenant-reads.md §4.4-§4.5).
//!
//! Inside `window_secs`, the frames committed to one `caller_key` may name at
//! most one tenant. This module holds the attribution a frame carries and the
//! process-wide history the outbound judge checks it against.
//!
//! Every write path reserves before it emits and commits when it emits, so
//! a frame not yet written still counts against the next one (§4.5).

// Without the `firewall` feature there is no tenant guard, so nothing is
// attributed and the history is never consulted.
#![cfg_attr(not(feature = "firewall"), allow(dead_code))]

#[cfg(feature = "firewall")]
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
#[cfg(feature = "firewall")]
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "firewall")]
use crate::security::firewall::Firewall;
use crate::security::hash_argument;

/// Distinct tenants (committed and pending) one principal may hold; past it
/// only an overflow count grows, which conflicts with everything.
const MAX_TENANTS_PER_PRINCIPAL: usize = 256;
/// Principals the history holds. A new principal past it, after a sweep of
/// expired ones, is unattributable: live history is never evicted.
const MAX_PRINCIPALS: usize = 100_000;

/// The tenants a frame names, hashed with `hash_argument`, never raw, and
/// whether part of it could not be read. Serializable so an outbox record can
/// carry the attribution taken before a redaction (§4.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReadAttribution {
    /// Hashed tenant ids.
    pub(crate) tenants: BTreeSet<String>,
    /// Part of the frame was not read; it counts as a fresh unknown tenant.
    pub(crate) uninspected: bool,
}

impl ReadAttribution {
    /// Neither a tenant nor an unread part.
    pub(crate) fn is_empty(&self) -> bool {
        self.tenants.is_empty() && !self.uninspected
    }
}

/// The verdict on one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ReadVerdict {
    /// A second tenant inside the window, delivered (observe mode).
    Flagged,
    /// A second tenant inside the window, withheld (block mode).
    Blocked,
    /// Tenant data for no identity.
    Unattributable,
}

/// What a blocked frame leaves behind for the rejection audit: the verdict
/// and the hashed denied tenants, never the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RejectionEvidence {
    /// The caller the frame was judged for.
    pub(crate) caller_key: Option<String>,
    /// Always `Blocked` or `Unattributable`.
    pub(crate) verdict: ReadVerdict,
    /// The hashed tenants of the withheld frame.
    pub(crate) attribution: ReadAttribution,
}

impl ReadAttribution {
    /// The attribution of raw tenant ids, hashed.
    pub(crate) fn of(tenants: BTreeSet<String>, uninspected: bool) -> Self {
        Self {
            tenants: tenants
                .into_iter()
                .map(|id| hash_argument(&Value::String(id)))
                .collect(),
            uninspected,
        }
    }

    /// Add `other`'s tenants and unread flag.
    pub(crate) fn extend(&mut self, other: &Self) {
        self.tenants.extend(other.tenants.iter().cloned());
        self.uninspected |= other.uninspected;
    }
}

/// One principal's reads inside the window.
#[derive(Debug, Default)]
struct Principal {
    /// Written tenants and when each was last written; leaves by expiry only.
    committed: HashMap<String, Instant>,
    /// Reserved, not yet (or not yet last) written: a count per open ticket.
    pending: HashMap<String, u32>,
    /// Reservations past [`MAX_TENANTS_PER_PRINCIPAL`].
    pending_overflow: u32,
    /// A written overflow conflicts with everything until then.
    overflow_until: Option<Instant>,
}

impl Principal {
    fn expire(&mut self, now: Instant, window: Duration) {
        self.committed
            .retain(|_, seen| now.saturating_duration_since(*seen) < window);
        if self.overflow_until.is_some_and(|until| until <= now) {
            self.overflow_until = None;
        }
    }

    fn idle(&self) -> bool {
        self.committed.is_empty()
            && self.pending.is_empty()
            && self.pending_overflow == 0
            && self.overflow_until.is_none()
    }

    /// Distinct tenant hashes held, committed and pending counted once.
    fn distinct(&self) -> usize {
        let pending_only = self
            .pending
            .keys()
            .filter(|h| !self.committed.contains_key(*h))
            .count();
        self.committed.len() + pending_only
    }

    fn holds(&self, hash: &str) -> bool {
        self.committed.contains_key(hash) || self.pending.contains_key(hash)
    }

    /// Distinct tenants live now: committed, pending, and overflow as one.
    fn live(&self) -> usize {
        let overflow = self.pending_overflow > 0 || self.overflow_until.is_some();
        self.distinct() + usize::from(overflow)
    }
}

/// What [`ReadHistory::reserve`] found.
#[derive(Debug)]
pub(crate) struct Reservation {
    /// The frame makes more than one tenant live for the principal.
    pub(crate) over: bool,
    /// The frame's reservation; `None` when it named nothing or was refused.
    pub(crate) ticket: Option<ReadTicket>,
}

/// One process's read history, shared by every `Firewall` and stream writer.
/// The lock a frame takes is the principal's map shard, and only for a frame
/// that names a tenant or is unread; a principal's first frame also takes
/// `admitting`.
#[derive(Debug, Default)]
pub(crate) struct ReadHistory {
    principals: DashMap<String, Principal>,
    /// Held to admit a new principal: every insert into `principals` and every
    /// eviction runs under it, so the cap check and the insert cannot
    /// interleave with another new key's (MIK-7975 CAP.1).
    admitting: parking_lot::Mutex<()>,
    /// Source of fresh unread tenants: each unread frame is its own.
    unread: AtomicU64,
    /// Test clock: milliseconds added to `Instant::now()` (MIN.4 corpus).
    #[cfg(test)]
    skew_ms: AtomicU64,
}

impl ReadHistory {
    /// The history's clock.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now + Duration::from_millis(self.skew_ms.load(Ordering::Relaxed));
        now
    }

    /// Move this history's clock forward (tests only).
    #[cfg(test)]
    pub(crate) fn advance_for_test(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.skew_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// A fresh history behind the `Arc` every holder shares.
    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `key`'s first frame: admitted under `admitting`, so the map never
    /// holds more than `MAX_PRINCIPALS`. A concurrent first frame for the same
    /// key may have admitted it meanwhile; then no cap applies. `None` when the
    /// map is full of live principals.
    fn admit(
        &self,
        key: &str,
        now: Instant,
        window: Duration,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, Principal>> {
        let _admitting = self.admitting.lock();
        if let Some(principal) = self.principals.get_mut(key) {
            return Some(principal);
        }
        if self.principals.len() >= MAX_PRINCIPALS {
            self.principals.retain(|_, p| {
                p.expire(now, window);
                !p.idle()
            });
            if self.principals.len() >= MAX_PRINCIPALS {
                return None;
            }
        }
        Some(self.principals.entry(key.to_owned()).or_default())
    }

    /// Count the frame against `key`'s live tenants and, unless it is over
    /// and `refuse_over` is set, reserve its tenants under a ticket; both
    /// under one shard guard, so two concurrent frames serialize. `None`
    /// when the history is full of live principals (unattributable).
    pub(crate) fn reserve(
        self: &Arc<Self>,
        key: &str,
        attribution: &ReadAttribution,
        window: Duration,
        refuse_over: bool,
    ) -> Option<Reservation> {
        let now = self.now();
        let mut hashes: Vec<String> = attribution.tenants.iter().cloned().collect();
        if attribution.uninspected {
            let n = self.unread.fetch_add(1, Ordering::Relaxed);
            hashes.push(format!("?unread-{n}"));
        }
        let mut principal = match self.principals.get_mut(key) {
            Some(principal) => principal,
            None => self.admit(key, now, window)?,
        };
        principal.expire(now, window);
        let fresh = hashes.iter().filter(|h| !principal.holds(h)).count();
        let over = principal.live() + fresh > 1;
        if (over && refuse_over) || hashes.is_empty() {
            return Some(Reservation { over, ticket: None });
        }
        let mut reserved = Vec::with_capacity(hashes.len());
        let mut overflow = 0;
        for hash in hashes {
            let distinct = principal.distinct();
            if let Some(count) = principal.pending.get_mut(&hash) {
                *count += 1;
            } else if principal.committed.contains_key(&hash)
                || distinct < MAX_TENANTS_PER_PRINCIPAL
            {
                principal.pending.insert(hash.clone(), 1);
            } else {
                overflow += 1;
                continue;
            }
            reserved.push(hash);
        }
        principal.pending_overflow += overflow;
        drop(principal);
        let ticket = ReadTicket(Arc::new(TicketInner {
            history: Arc::clone(self),
            key: key.to_owned(),
            hashes: reserved,
            overflow,
            window,
        }));
        Some(Reservation {
            over,
            ticket: Some(ticket),
        })
    }

    /// `(committed, pending)` distinct tenants held for `key`.
    #[cfg(test)]
    pub(crate) fn tenants_held(&self, key: &str) -> (usize, usize) {
        self.principals
            .get(key)
            .map_or((0, 0), |p| (p.committed.len(), p.pending.len()))
    }
}

/// A frame's reservation. Clones are the copies of one frame (fan-out): each
/// write refreshes last-seen, and the last copy to go, written or dropped,
/// releases the pending counts. A drop never clears another ticket's counts.
#[derive(Debug, Clone)]
pub(crate) struct ReadTicket(Arc<TicketInner>);

#[derive(Debug)]
struct TicketInner {
    history: Arc<ReadHistory>,
    key: String,
    hashes: Vec<String>,
    overflow: u32,
    window: Duration,
}

impl ReadTicket {
    /// This copy was written: its tenants are committed as of now.
    pub(crate) fn emitted(&self) {
        let inner = &self.0;
        let Some(mut principal) = inner.history.principals.get_mut(&inner.key) else {
            return;
        };
        let now = inner.history.now();
        for hash in &inner.hashes {
            principal.committed.insert(hash.clone(), now);
        }
        if inner.overflow > 0 {
            principal.overflow_until = Some(now + inner.window);
        }
    }
}

impl Drop for TicketInner {
    fn drop(&mut self) {
        let Some(mut principal) = self.history.principals.get_mut(&self.key) else {
            return;
        };
        for hash in &self.hashes {
            if let Some(count) = principal.pending.get_mut(hash) {
                *count -= 1;
                if *count == 0 {
                    principal.pending.remove(hash);
                }
            }
        }
        principal.pending_overflow -= self.overflow;
    }
}

#[cfg(feature = "firewall")]
tokio::task_local! {
    /// The attribution the request in this scope read before transforms.
    static READS: RefCell<(Arc<Firewall>, ReadAttribution)>;
}

#[cfg(feature = "firewall")]
/// Run `future` with a request-scoped collector of the attribution its inner
/// dispatches read before any transform (§4.4, F1-F2). Returns the output and
/// what was collected.
pub(crate) async fn with_read_scope<F: Future>(
    firewall: Arc<Firewall>,
    future: F,
) -> (F::Output, ReadAttribution) {
    READS
        .scope(
            RefCell::new((firewall, ReadAttribution::default())),
            async {
                let output = future.await;
                let noted = READS.with(|cell| std::mem::take(&mut cell.borrow_mut().1));
                (output, noted)
            },
        )
        .await
}

#[cfg(feature = "firewall")]
/// Note the attribution of a raw value read inside [`with_read_scope`] (F1:
/// the capability executor calls it on the raw upstream response),
/// before a transform maps or drops fields. Outside a scope, or with
/// attribution off, nothing.
pub(crate) fn note_read(value: &Value) -> Option<ReadAttribution> {
    READS
        .try_with(|cell| {
            let mut cell = cell.borrow_mut();
            let (firewall, noted) = &mut *cell;
            let guard = firewall.tenant_guard();
            if !guard.attributes() {
                return None;
            }
            let (tenants, uninspected) = guard.scan_frame(&[value], &[]);
            let read = ReadAttribution::of(tenants, uninspected);
            noted.extend(&read);
            Some(read)
        })
        .ok()
        .flatten()
}

#[cfg(feature = "firewall")]
/// Note attribution a store kept beside a value (a cache hit). A stored
/// value without it is unread, when attribution is on.
pub(crate) fn note_restored(stored: Option<&ReadAttribution>) {
    let _ = READS.try_with(|cell| {
        let mut cell = cell.borrow_mut();
        let (firewall, noted) = &mut *cell;
        if !firewall.tenant_guard().attributes() {
            return;
        }
        match stored {
            Some(read) => noted.extend(read),
            None => noted.uninspected = true,
        }
    });
}

/// Run one dispatch in a read scope of its own nested in the request's, so
/// what it reads is collected apart from its siblings (a cache entry stores
/// exactly that). Returns its reading; the caller merges it into the
/// request's scope with [`note_attribution`] once the dispatch passed its
/// gates. Outside a scope it just runs `fut`.
#[cfg(feature = "firewall")]
pub(crate) async fn with_dispatch_reads<F: Future>(fut: F) -> (F::Output, Option<ReadAttribution>) {
    let Ok(firewall) = READS.try_with(|cell| Arc::clone(&cell.borrow().0)) else {
        return (fut.await, None);
    };
    let (output, reading) = with_read_scope(firewall, fut).await;
    (output, Some(reading))
}

/// Whether a read scope is collecting on this task, with attribution on.
#[cfg(feature = "firewall")]
pub(crate) fn in_read_scope() -> bool {
    READS
        .try_with(|cell| cell.borrow().0.tenant_guard().attributes())
        .unwrap_or(false)
}

/// Note an attribution already read (a dispatch's raw response, read once
/// for the invocation record too) into the scope; nothing outside one.
#[cfg(feature = "firewall")]
pub(crate) fn note_attribution(read: Option<ReadAttribution>) {
    if let Some(read) = read {
        let _ = READS.try_with(|cell| cell.borrow_mut().1.extend(&read));
    }
}

/// What the read scope around this task has collected so far: the hidden
/// attribution of the answer being judged. `None` outside a scope.
#[cfg(feature = "firewall")]
pub(crate) fn noted() -> Option<ReadAttribution> {
    READS.try_with(|cell| cell.borrow().1.clone()).ok()
}

/// Without the firewall nothing is attributed.
#[cfg(not(feature = "firewall"))]
pub(crate) fn note_read(_value: &Value) -> Option<ReadAttribution> {
    None
}

/// Without the firewall there is no read scope.
#[cfg(not(feature = "firewall"))]
pub(crate) async fn with_dispatch_reads<F: std::future::Future>(
    fut: F,
) -> (F::Output, Option<ReadAttribution>) {
    (fut.await, None)
}

/// Without the firewall there is no read scope.
#[cfg(not(feature = "firewall"))]
pub(crate) fn in_read_scope() -> bool {
    false
}

/// Without the firewall nothing is noted.
#[cfg(not(feature = "firewall"))]
pub(crate) fn noted() -> Option<ReadAttribution> {
    None
}

/// Without the firewall nothing is attributed.
#[cfg(not(feature = "firewall"))]
pub(crate) fn note_attribution(_read: Option<ReadAttribution>) {}

/// Without the firewall nothing is attributed.
#[cfg(not(feature = "firewall"))]
pub(crate) fn note_restored(_stored: Option<&ReadAttribution>) {}

#[cfg(test)]
#[path = "tenant_reads_tests.rs"]
mod tests;
