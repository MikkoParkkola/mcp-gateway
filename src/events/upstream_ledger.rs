// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one backend's legacy peer may hold of our `resources/subscribe`
//! calls (MIK-7898 SESS.2b, B06 PR-2 design D5, option B).
//!
//! Invariant: every subscription any holder of this backend may keep is a
//! key, so the peer never holds more than [`MAX_URIS`] of ours. A key whose
//! outcome is uncertain is `stranded` and stays until the ledger is dropped
//! (the backend leaves the config, or the gateway restarts): the cost is our
//! own capacity, never an uncounted subscription.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::warn;

use super::{Full, MAX_URI_BUDGET_BYTES, MAX_URIS, encoded};
use std::sync::Weak;

use crate::transport::upstream_tap::UpstreamListen;

/// Whether the current holder has our subscription for a URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Held {
    No,
    Maybe,
    Yes,
}

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Answered with a result.
    Done,
    /// Answered with a JSON-RPC error: the peer refused it.
    Refused,
    /// Proven never to have left the gateway: nothing changed upstream.
    NotSent,
    /// Timed out, cancelled, or failed in transport: it may still run.
    Uncertain,
}

#[derive(Debug)]
struct Entry {
    wanted: bool,
    in_flight: u8,
    held: Held,
    stranded: bool,
    errors: u8,
    /// A call that left the key still due is not repeated before this.
    retry_at: Option<Instant>,
    backoff: Duration,
}

/// First and last wait between repeated calls on one key.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_CAP: Duration = Duration::from_secs(300);

/// A call in flight, as [`Ledger::sent`] recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Call {
    generation: u64,
    pub uri: String,
    pub subscribe: bool,
    before: Held,
}

/// One backend's keys, `(holder generation, URI)`.
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    generation: u64,
    keys: BTreeMap<(u64, String), Entry>,
    bytes: usize,
    /// Wanted URIs that found no room after a holder change (retried).
    unplaced: BTreeSet<String>,
    /// Identity of the holder the current generation stands for.
    holder: Option<u64>,
    /// The cap-held-by-stranded-keys warning was logged.
    warned: bool,
}

impl Ledger {
    /// Watch `uri`: a new key only if it fits both budgets.
    ///
    /// # Errors
    /// [`Full`] when the ledger has no room; nothing changes then.
    pub(crate) fn want(&mut self, uri: &str) -> Result<(), Full> {
        if let Some(entry) = self.keys.get_mut(&(self.generation, uri.to_owned())) {
            entry.wanted = true;
            entry.retry_at = None;
            entry.backoff = RETRY_FIRST;
            return Ok(());
        }
        self.insert(uri)
    }

    /// Carry counted interest into this ledger. It fits: a need never holds
    /// more URIs than one ledger admits.
    pub(crate) fn want_all(&mut self, uris: Vec<String>) {
        for uri in uris {
            let _ = self.want(&uri);
        }
    }

    /// Stop watching `uri`; the key stays until it is confirmed released.
    pub(crate) fn unwant(&mut self, uri: &str) {
        self.unplaced.remove(uri);
        let key = (self.generation, uri.to_owned());
        if let Some(entry) = self.keys.get_mut(&key) {
            entry.wanted = false;
            entry.retry_at = None;
            entry.backoff = RETRY_FIRST;
        }
        self.prune(&key);
    }

    /// A key for `uri` on the current holder. An existing one is kept as it
    /// is: overwriting it would forget what the holder may already hold.
    fn insert(&mut self, uri: &str) -> Result<(), Full> {
        if self.keys.contains_key(&(self.generation, uri.to_owned())) {
            self.unplaced.remove(uri);
            return Ok(());
        }
        let size = encoded(uri);
        if self.keys.len() >= MAX_URIS || self.bytes + size > MAX_URI_BUDGET_BYTES {
            return Err(Full);
        }
        self.bytes += size;
        self.keys.insert(
            (self.generation, uri.to_owned()),
            Entry {
                wanted: true,
                in_flight: 0,
                held: Held::No,
                stranded: false,
                errors: 0,
                retry_at: None,
                backoff: RETRY_FIRST,
            },
        );
        self.unplaced.remove(uri);
        Ok(())
    }

    fn prune(&mut self, key: &(u64, String)) {
        if self
            .keys
            .get(key)
            .is_some_and(|e| !e.wanted && e.held == Held::No && e.in_flight == 0 && !e.stranded)
        {
            self.keys.remove(key);
            self.bytes -= encoded(&key.1);
            self.place();
        }
    }

    /// Give room freed by a release to the wanted URIs still waiting for it.
    fn place(&mut self) {
        while let Some(uri) = self.unplaced.first().cloned() {
            if self.insert(&uri).is_err() {
                return;
            }
        }
    }

    /// The calls the next pass sends at `now`, one per URI at a time:
    /// `(uri, subscribe)`.
    pub(crate) fn due(&self, now: Instant) -> Vec<(String, bool)> {
        self.keys
            .iter()
            .filter(|((g, _), e)| {
                *g == self.generation && e.in_flight == 0 && e.retry_at.is_none_or(|at| at <= now)
            })
            .filter_map(|((_, uri), e)| wanted_call(e).map(|subscribe| (uri.clone(), subscribe)))
            .collect()
    }

    /// The unsubscribes a stop sends: every current key that may be held
    /// and could still be released by an answer.
    pub(crate) fn releasable(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|((g, _), e)| {
                *g == self.generation && !e.stranded && e.in_flight == 0 && e.held != Held::No
            })
            .map(|((_, uri), _)| uri.clone())
            .collect()
    }

    /// Record a call about to be sent.
    pub(crate) fn sent(&mut self, uri: &str, subscribe: bool) -> Option<Call> {
        let entry = self.keys.get_mut(&(self.generation, uri.to_owned()))?;
        let before = entry.held;
        entry.in_flight = entry.in_flight.saturating_add(1);
        if !subscribe || entry.held == Held::No {
            entry.held = Held::Maybe;
        }
        Some(Call {
            generation: self.generation,
            uri: uri.to_owned(),
            subscribe,
            before,
        })
    }

    /// Record how `call` ended. An answer from an earlier holder is ignored:
    /// that holder's keys are already stranded. `true` when this is the
    /// third error answer to an unsubscribe (warn once).
    pub(crate) fn answered(&mut self, call: &Call, outcome: Outcome, now: Instant) -> bool {
        if call.generation != self.generation {
            return false;
        }
        let key = (call.generation, call.uri.clone());
        let Some(entry) = self.keys.get_mut(&key) else {
            return false;
        };
        entry.in_flight = entry.in_flight.saturating_sub(1);
        let idle = entry.in_flight == 0;
        let mut warn = false;
        match (outcome, call.subscribe) {
            // A stranded key never reads Yes: an earlier uncertain call may
            // still undo this one at the peer, so passes keep re-sending.
            (Outcome::Done, true) => {
                entry.held = if idle && !entry.stranded {
                    Held::Yes
                } else {
                    Held::Maybe
                };
            }
            (Outcome::Done, false) => entry.held = if idle { Held::No } else { Held::Maybe },
            (Outcome::Refused, true) => {
                if idle && call.before == Held::No && !entry.stranded {
                    entry.held = Held::No;
                }
            }
            (Outcome::Refused, false) => {
                entry.errors = entry.errors.saturating_add(1);
                warn = entry.errors == 3;
            }
            (Outcome::NotSent, _) => {
                if idle && !entry.stranded {
                    entry.held = call.before;
                }
            }
            (Outcome::Uncertain, _) => {
                entry.held = Held::Maybe;
                entry.stranded = true;
            }
        }
        if wanted_call(entry).is_some() {
            entry.retry_at = Some(now + entry.backoff);
            entry.backoff = (entry.backoff * 2).min(RETRY_CAP);
        } else {
            entry.retry_at = None;
            entry.backoff = RETRY_FIRST;
        }
        self.prune(&key);
        warn
    }

    /// Note which holder a pass is about to talk to; a different one than
    /// before is a holder change.
    pub(crate) fn observe(&mut self, holder: u64) {
        if self.holder.is_some_and(|h| h != holder) {
            self.holder_changed();
        }
        self.holder = Some(holder);
    }

    /// The holder changed (a new HTTP session id, stdio process or
    /// WebSocket connection): what the old one may hold stays charged, and
    /// each wanted URI needs a fresh key on the new one.
    fn holder_changed(&mut self) {
        let old = self.generation;
        self.generation += 1;
        let current: Vec<(u64, String)> = self
            .keys
            .keys()
            .filter(|(g, _)| *g == old)
            .cloned()
            .collect();
        for key in current {
            let Some(entry) = self.keys.get_mut(&key) else {
                continue;
            };
            if entry.wanted {
                self.unplaced.insert(key.1.clone());
            }
            if entry.held != Held::No || entry.in_flight > 0 {
                entry.stranded = true;
                entry.wanted = false;
                // Its answers carry the old generation and are discarded.
                entry.in_flight = 0;
            } else {
                entry.wanted = false;
                self.prune(&key);
            }
        }
        self.place();
    }

    /// Diagnostics: (keys, bytes, stranded keys).
    pub(crate) fn size(&self) -> (usize, usize, usize) {
        (
            self.keys.len(),
            self.bytes,
            self.keys.values().filter(|e| e.stranded).count(),
        )
    }

    /// Whether any key can still be released by a cleanup pass.
    pub(crate) fn needs_cleanup(&self) -> bool {
        self.keys.iter().any(|((g, _), e)| {
            *g == self.generation && !e.stranded && (e.in_flight > 0 || e.held != Held::No)
        })
    }

    /// Whether a capacity refusal should be logged: once per ledger, and
    /// only while stranded keys hold room.
    pub(crate) fn warn_cap(&mut self) -> bool {
        self.size().2 > 0 && !std::mem::replace(&mut self.warned, true)
    }

    /// Wanted URIs that have no key on the current holder (shown, retried).
    pub(crate) fn unplaced(&self) -> usize {
        self.unplaced.len()
    }
}

/// A call between [`Ledger::sent`] and its answer. Dropped unanswered (a
/// stop or a pass deadline cut it), the call is uncertain.
struct InFlight<'a> {
    ledger: &'a Mutex<Ledger>,
    call: Option<Call>,
}

impl InFlight<'_> {
    fn end(mut self, outcome: Outcome) -> bool {
        self.call
            .take()
            .is_some_and(|call| self.ledger.lock().answered(&call, outcome, Instant::now()))
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if let Some(call) = self.call.take() {
            self.ledger
                .lock()
                .answered(&call, Outcome::Uncertain, Instant::now());
        }
    }
}

/// Who a legacy call on `handle` lands on: the transport instance and the
/// holder its pin names (an HTTP session), as one ledger identity.
pub(crate) fn holder_of(handle: &Weak<dyn UpstreamListen>, pinned: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    Weak::as_ptr(handle).cast::<()>().hash(&mut hasher);
    pinned.hash(&mut hasher);
    hasher.finish()
}

/// Send one due call on the session's own transport, pinned to the holder
/// the ledger charges, and record how it ended. `false` when the peer has
/// no resource interest (`-32601`). A gone transport sends nothing.
pub(crate) async fn drive(
    ledger: &Mutex<Ledger>,
    backend: &str,
    handle: &Weak<dyn UpstreamListen>,
    uri: &str,
    subscribe: bool,
    limit: Duration,
) -> bool {
    let Some(transport) = handle.upgrade() else {
        return true;
    };
    let pin = transport.legacy_pin();
    ledger.lock().observe(holder_of(handle, pin.holder));
    let Some(call) = ledger.lock().sent(uri, subscribe) else {
        return true;
    };
    let in_flight = InFlight {
        ledger,
        call: Some(call),
    };
    let result = tokio::time::timeout(limit, transport.legacy_interest(pin, uri, subscribe)).await;
    let outcome = match &result {
        Ok(Ok(answer)) if answer.error.is_none() => Outcome::Done,
        Ok(Ok(_)) => Outcome::Refused,
        Ok(Err(e)) if e.is_pre_dispatch() => Outcome::NotSent,
        Ok(Err(_)) | Err(_) => Outcome::Uncertain,
    };
    if in_flight.end(outcome) {
        warn!(
            backend,
            "upstream listener: unsubscribe refused three times"
        );
    }
    !matches!(&result, Ok(Ok(answer)) if answer.error.as_ref().is_some_and(|e| e.code == METHOD_NOT_FOUND))
}

/// `-32601`: the peer offers no resource interest at all.
const METHOD_NOT_FOUND: i32 = -32601;

/// The call a key is due for, ignoring timing: `Some(true)` subscribe,
/// `Some(false)` unsubscribe.
fn wanted_call(e: &Entry) -> Option<bool> {
    if e.wanted && e.held != Held::Yes {
        Some(true)
    } else if !e.wanted && !e.stranded && e.held != Held::No {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
#[path = "upstream_ledger_tests.rs"]
mod tests;
