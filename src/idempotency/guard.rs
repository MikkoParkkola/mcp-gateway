// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    AdmitOutcome, Arc, Duration, Error, IdempotencyCache, IdempotencyReservation, MAX_ENTRIES,
    OwnerToken, Result, Value,
};

/// Outcome of the idempotency guard.
#[derive(Debug)]
pub enum GuardOutcome {
    /// Proceed with execution, holding the reservation for the key.
    Proceed(IdempotencyReservation),
    /// Return the cached result — no execution needed.
    CachedResult(Value),
    /// Return the cached JSON-RPC error object — no execution needed. The key
    /// belongs to a dispatched call that failed, and re-executing it could
    /// duplicate a side effect that already committed.
    CachedError(Value),
}

/// Check the idempotency cache and either return a cached result or register
/// the key as in-flight for execution.
///
/// # Errors
///
/// Returns a 409 error when an identical request is already in flight, a 409
/// error when `key` is already bound to a *different* request, and a 503 error
/// when the cache is at [`MAX_ENTRIES`] and the key is not yet tracked —
/// refusing rather than evicting, since eviction readmits a duplicate.
///
/// `fingerprint` identifies the request the key is being used for. A client key
/// is an opaque string it chose; nothing about the string says which call it
/// was minted for, so without binding, one key reused for a second, different
/// call is served the first call's result as though it were its own.
pub fn enforce(
    cache: &Arc<IdempotencyCache>,
    key: &str,
    fingerprint: &str,
) -> Result<GuardOutcome> {
    // Minted before `admit` publishes the entry that points at it, and moved
    // into the reservation immediately after, so a published in-flight entry is
    // never momentarily ownerless — the window ADR-012 A2 closes.
    let owner = Arc::new(OwnerToken);
    match cache.admit(key, fingerprint, &owner) {
        AdmitOutcome::Proceed => Ok(GuardOutcome::Proceed(IdempotencyReservation::new(
            Arc::clone(cache),
            key,
            fingerprint,
            owner,
        ))),
        AdmitOutcome::InFlight => Err(Error::json_rpc(
            409,
            format!("Duplicate request in progress for key: {key}"),
        )),
        AdmitOutcome::Completed(value, read, writes) => {
            // MIN.2 row 14: a replay restores the reading stored with this
            // very result into the caller's read scope (a no-op outside one).
            crate::security::tenant_reads::note_restored(read.as_ref());
            // MIK-7991: and the gateway's write record, so what the original
            // call wrote stays out of this replay's receipt.
            crate::gateway::gateway_writes::restore(&writes);
            Ok(GuardOutcome::CachedResult(value))
        }
        AdmitOutcome::Failed(error) => Ok(GuardOutcome::CachedError(error)),
        AdmitOutcome::Mismatch => Err(Error::json_rpc(
            409,
            format!(
                "Idempotency key is already in use for a different request: {key}. \
                 A key identifies one call; reuse it only to repeat that same call."
            ),
        )),
        AdmitOutcome::AtCapacity => Err(Error::json_rpc(
            503,
            format!(
                "Idempotency cache at capacity ({MAX_ENTRIES} entries); \
                 refusing new protected request for key: {key}"
            ),
        )),
    }
}

/// Marks a stored error as the gateway's own firewall refusal.
///
/// [`cached_error_parts`] reads `code` and `message` alone, so this member
/// rides along in the stored body and lets the replay restore the typed
/// `ResponseFirewallRefused` the first attempt returned instead of serving a
/// generic JSON-RPC error. A refusal replayed untyped loses the
/// delivery-refusal projection and is accounted against the client, which is
/// the opposite of what it is: the gateway refused, the client did nothing
/// wrong. The member cannot be forged from outside — the only other writer
/// serializes a `JsonRpcError`, whose fields are `code`, `message` and `data`.
pub const FIREWALL_REFUSAL_MARKER: &str = "_gatewayFirewallRefusal";

/// Split the payload of a [`GuardOutcome::CachedError`] into its JSON-RPC code
/// and message.
///
/// Falls back to an internal error when the stored value is not the
/// `{"code", "message"}` object [`IdempotencyReservation::fail`] writes, so a
/// malformed entry is served as an error rather than replayed as a success.
#[must_use]
pub fn cached_error_parts(error: &Value) -> (i32, String) {
    let code = error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(|c| i32::try_from(c).ok())
        .unwrap_or(-32603);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("Idempotent request previously failed")
        .to_owned();
    (code, message)
}

/// Spawn a background tokio task that periodically evicts stale idempotency
/// entries from `cache`.
///
/// The task runs every `interval` and stops when the `Arc` reference count
/// drops to 1 (i.e., all other owners have dropped their handles).
pub fn spawn_cleanup_task(cache: Arc<IdempotencyCache>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            // Stop if we are the sole Arc holder (server is shutting down).
            if Arc::strong_count(&cache) <= 1 {
                break;
            }
            cache.evict_expired();
        }
    });
}
