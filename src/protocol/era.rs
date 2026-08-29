// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Which protocol generation a peer speaks, and how we find out.
//!
//! MCP 2026-07-28 removed the `initialize` handshake, so a client can no longer
//! learn a server's version by handshaking with it. It probes `server/discover`
//! instead and reads the *shape* of the answer.
//!
//! The subtlety, and the reason this is a module rather than an `if`: a legacy
//! server does not answer the probe with "I am legacy". It answers with an
//! arbitrary error, or with nothing at all. Only a **recognised modern error**
//! proves a modern peer. The specification's compatibility matrix puts it
//! plainly — *"the probe returns a non-modern error or times out, and the client
//! falls back to `initialize`"*.
//!
//! So the rule is asymmetric, and getting it backwards is the easy mistake:
//! evidence of modernity must be positive, and everything else is legacy.

/// What a peer speaks, as far as we have been able to establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// Speaks 2026-07-28 or later: stateless, per-request `_meta`, no handshake.
    Modern,
    /// Speaks a revision with the `initialize` handshake.
    Legacy,
}

/// JSON-RPC error code for `UnsupportedProtocolVersion` in 2026-07-28.
///
/// Renumbered from `-32004` by that revision's error-code allocation policy,
/// which reserves `-32020..=-32099` for the specification and leaves
/// `-32000..=-32019` implementation-defined.
pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// JSON-RPC error code for `HeaderMismatch` in 2026-07-28 (was `-32001`).
pub const HEADER_MISMATCH: i32 = -32020;

/// JSON-RPC error code for `MissingRequiredClientCapability` (was `-32003`).
pub const MISSING_REQUIRED_CLIENT_CAPABILITY: i32 = -32021;

/// What came back from a `server/discover` probe.
#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// A result object. Whether it is a *valid* discovery document is decided
    /// by [`classify`], not by the caller.
    Result(serde_json::Value),
    /// A JSON-RPC error with this code.
    Error(i32),
    /// Nothing arrived before the deadline, or the transport failed.
    NoAnswer,
}

/// Decide which era a peer speaks from the outcome of one `server/discover`
/// probe.
///
/// Modern requires positive evidence. Everything else is legacy, including
/// silence — a peer that cannot be reached at all is not thereby modern, and
/// treating it as modern would send it requests it cannot parse.
#[must_use]
pub fn classify(outcome: &ProbeOutcome) -> Era {
    match outcome {
        // A document that names a modern revision it speaks.
        //
        // The presence of `supportedVersions` proves the peer implements this
        // RPC. Its **contents** decide what we may send it: the specification
        // says a client "should choose one of these for subsequent requests",
        // so a peer answering with only 2025 revisions has told us it cannot
        // take a modern request — and classifying it Modern on the presence of
        // the field would send it exactly what it said it cannot parse.
        //
        // Found by adversarial review, 2026-08-29. The first version keyed on
        // presence alone, which reads correctly and is wrong in the one case
        // that matters: a dual-era peer mid-migration.
        ProbeOutcome::Result(doc) if names_a_modern_version(doc) => Era::Modern,

        // A recognised modern error proves a modern peer just as well as a
        // document does: only a server that implements this revision knows
        // these codes. The client retries with a version they share rather than
        // falling back — so misreading this as legacy would downgrade a peer
        // that was ready to talk.
        ProbeOutcome::Error(code)
            if matches!(
                *code,
                UNSUPPORTED_PROTOCOL_VERSION | HEADER_MISMATCH | MISSING_REQUIRED_CLIENT_CAPABILITY
            ) =>
        {
            Era::Modern
        }

        // Everything else. `-32601 method not found` is the honest legacy
        // answer, an arbitrary application error is the sloppy one, and silence
        // is the common one. None of them is evidence of modernity.
        _ => Era::Legacy,
    }
}

/// One peer's era, determined once and reused.
///
/// The specification says a client **SHOULD** cache the era for the lifetime of
/// the server process, and re-probe if the cached assumption later fails. Two
/// properties matter beyond "remember the answer":
///
/// * **Concurrent resolution collapses onto one probe.** Warm-start touches a
///   backend from several tasks at once, and a cache that only writes *after*
///   probing turns one cold backend into a thundering herd against a peer that
///   is, by hypothesis, already struggling.
/// * **Invalidation is explicit.** The era is a belief about another process;
///   when acting on it fails, the belief is discarded rather than re-asserted.
#[derive(Debug, Default)]
pub struct EraCache {
    /// `None` until determined. Held across an await, so a `tokio` lock rather
    /// than a `std` one — the probe happens under it, which is what makes eight
    /// racing callers issue one probe instead of eight.
    era: tokio::sync::Mutex<Option<Era>>,
}

impl EraCache {
    /// A cache holding no determination yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The era, if one has been determined and not since invalidated.
    pub async fn cached(&self) -> Option<Era> {
        *self.era.lock().await
    }

    /// Discard the determination, so the next resolution probes again.
    ///
    /// Called when acting on the cached era fails — a modern peer that starts
    /// rejecting modern requests has been restarted or downgraded, and the
    /// belief is stale rather than merely unlucky.
    ///
    /// Async, and it waits for the lock. A `try_lock` version was written first
    /// and is the wrong shape: under contention it would silently do nothing,
    /// leaving the caller believing it had discarded a belief it had not. A
    /// control that fails silently is worse than one that blocks briefly.
    pub async fn invalidate(&self) {
        *self.era.lock().await = None;
    }

    /// Return the cached era, or determine it by probing.
    ///
    /// The probe runs while the lock is held. That is deliberate: it serialises
    /// concurrent resolution onto a single probe, which is the point.
    pub async fn resolve_with<F, Fut>(&self, probe: F) -> Era
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ProbeOutcome>,
    {
        let mut guard = self.era.lock().await;
        if let Some(era) = *guard {
            return era;
        }
        let outcome = probe().await;
        let era = classify(&outcome);

        // Silence is not a finding. `classify` answers Legacy for a probe that
        // never came back, which is the right way to *treat* the next request
        // and the wrong thing to *remember*: a backend briefly unreachable
        // would be pinned to the legacy path for the life of the process, and
        // a dual-era peer that recovered would never be spoken to properly
        // again. Cache only what the peer actually told us.
        if !matches!(outcome, ProbeOutcome::NoAnswer) {
            *guard = Some(era);
        }
        era
    }
}

/// Whether a discovery document names a revision we can speak statelessly.
///
/// Anything unusable — a string where an array belongs, an empty list, entries
/// that are not strings — is treated as naming nothing. Guessing in the modern
/// direction would send a request the peer may not understand; guessing legacy
/// costs a handshake. The cheap error is the right one.
fn names_a_modern_version(doc: &serde_json::Value) -> bool {
    // A discovery document, not merely an object with a familiar key. An
    // unrelated result that happens to carry `supportedVersions` is not a peer
    // announcing this revision, and reading one as such would send a modern
    // request to something that never claimed to be a modern server.
    if !doc
        .get("capabilities")
        .is_some_and(serde_json::Value::is_object)
    {
        return false;
    }
    doc.get("supportedVersions")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|versions| {
            versions
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(|version| crate::protocol::meta::MODERN_VERSIONS.contains(&version))
        })
}
