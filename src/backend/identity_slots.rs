// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admission for `PerUser` pool slots, and the bound on detached eviction
//! closes (#2300, MIK-7547.SLOTS.1).
//!
//! A passthrough caller picks its own slot key: the binding hashes an
//! unverified header. Without admission, N header values mint N slots, each
//! with its own transport. A backend admits at most [`MAX_IDENTITY_SLOTS`],
//! and one principal at most [`MAX_SLOTS_PER_PRINCIPAL`] of them, so one
//! caller cannot fill the backend. Every anonymous caller is one principal.
//! Past either limit the caller is refused, never moved to the shared slot
//! (#727) and never given another caller's slot (no LRU eviction).
//!
//! The count follows ownership, not map membership: a [`SlotLease`] lives in
//! the `PooledEntry` it admitted, so an evicted entry still held by an
//! in-flight request keeps its place until the last owner drops it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::transport::Transport;

/// `PerUser` slots one backend admits.
pub(crate) const MAX_IDENTITY_SLOTS: usize = 64;
/// `PerUser` slots one principal may hold on one backend.
pub(crate) const MAX_SLOTS_PER_PRINCIPAL: usize = 8;
/// Detached eviction closes one backend runs at once.
const MAX_EVICTION_CLOSES: usize = MAX_IDENTITY_SLOTS;

/// Prefix of a passthrough binding, `pt:<principal digest>:<credential digest>`.
/// Distinct from the minting path's `idp:` bindings and the shared `""` bucket.
const PASSTHROUGH_PREFIX: &str = "pt:";

/// Which limit refused a new slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The backend holds [`MAX_IDENTITY_SLOTS`].
    Backend,
    /// The caller's principal holds [`MAX_SLOTS_PER_PRINCIPAL`].
    Principal,
}

impl Refusal {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Backend => "backend",
            Self::Principal => "principal",
        }
    }
}

/// THE DECISION: may a new slot be admitted, given the backend's live slot
/// count and the count its principal already holds?
pub(crate) fn admission(total: usize, of_principal: usize) -> Result<(), Refusal> {
    if total >= MAX_IDENTITY_SLOTS {
        Err(Refusal::Backend)
    } else if of_principal >= MAX_SLOTS_PER_PRINCIPAL {
        Err(Refusal::Principal)
    } else {
        Ok(())
    }
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// The slot binding of a passthrough caller: `principal` is the gateway's
/// stable actor id for the caller (every anonymous caller shares one), and
/// `credential_digest` the SHA-256 hex of its forwarded header, hashed at its
/// single read point. The principal is hashed here, so neither a token nor a
/// subject is ever a map key. Same principal and credential, same binding
/// (session continuity); another credential, another binding (MIK-6785).
pub(crate) fn passthrough_binding(principal: &str, credential_digest: &str) -> String {
    format!(
        "{PASSTHROUGH_PREFIX}{}:{credential_digest}",
        digest(principal)
    )
}

/// The principal a binding is charged to. A passthrough binding names it; any
/// other binding is minted from one verified principal, so it is its own.
pub(crate) fn principal_of(binding: &str) -> &str {
    binding
        .strip_prefix(PASSTHROUGH_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .map_or(binding, |(principal, _)| principal)
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    by_principal: HashMap<String, usize>,
}

/// One backend's admitted `PerUser` slots and its eviction-close permits.
#[derive(Debug)]
pub(crate) struct IdentitySlots {
    counts: parking_lot::Mutex<Counts>,
    closes: Arc<tokio::sync::Semaphore>,
}

impl Default for IdentitySlots {
    fn default() -> Self {
        Self {
            counts: parking_lot::Mutex::default(),
            closes: Arc::new(tokio::sync::Semaphore::new(MAX_EVICTION_CLOSES)),
        }
    }
}

/// One admitted slot. Dropping it frees the place.
#[derive(Debug)]
pub(crate) struct SlotLease {
    slots: Arc<IdentitySlots>,
    principal: String,
}

impl Drop for SlotLease {
    fn drop(&mut self) {
        let mut counts = self.slots.counts.lock();
        counts.total = counts.total.saturating_sub(1);
        if let Some(held) = counts.by_principal.get_mut(&self.principal) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                counts.by_principal.remove(&self.principal);
            }
        }
    }
}

impl IdentitySlots {
    /// Reserve a place for a new slot bound to `binding`, or refuse.
    ///
    /// Check and claim happen under one lock, so two callers racing for the
    /// last place cannot both win. Taken under the pool's shard guard and
    /// never held across anything that takes one, so the order is always
    /// shard, then this lock.
    pub(crate) fn reserve(self: &Arc<Self>, binding: &str) -> Result<SlotLease, Refusal> {
        let principal = principal_of(binding);
        let mut counts = self.counts.lock();
        let held = counts.by_principal.get(principal).copied().unwrap_or(0);
        admission(counts.total, held)?;
        counts.total += 1;
        *counts
            .by_principal
            .entry(principal.to_string())
            .or_insert(0) += 1;
        Ok(SlotLease {
            slots: Arc::clone(self),
            principal: principal.to_string(),
        })
    }

    /// Close an evicted transport off the caller's path, bounded in count by
    /// the close permits and in time by `budget`.
    ///
    /// No permit: the transport is dropped at once (a stdio child is killed on
    /// drop) and the close counted as abandoned. A close that runs out its
    /// budget is counted the same way. Neither sends an HTTP backend's session
    /// DELETE: dropping an HTTP transport does not end the upstream session.
    pub(crate) fn spawn_close(
        &self,
        backend: String,
        budget: Duration,
        transport: Arc<dyn Transport>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Ok(permit) = Arc::clone(&self.closes).try_acquire_owned() else {
            tracing::warn!(%backend, "Eviction close refused a permit; dropping the transport");
            abandoned(&backend);
            return None;
        };
        Some(tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(budget, transport.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%backend, %error, "Evicted transport failed to close cleanly");
                }
                Err(_) => {
                    tracing::warn!(
                        %backend,
                        budget_secs = budget.as_secs(),
                        "Evicted transport did not close within its budget; abandoning the close"
                    );
                    abandoned(&backend);
                }
            }
        }))
    }

    /// Test-only: the live admitted count.
    #[cfg(test)]
    pub(crate) fn in_use(&self) -> usize {
        self.counts.lock().total
    }
}

impl super::Backend {
    /// Admit a new slot for `key`: `None` for the shared slot, which is never
    /// refused; a lease for an admitted `PerUser` slot; the typed refusal,
    /// counted, when either limit is reached.
    pub(super) fn admit(&self, key: &super::PoolKey) -> crate::Result<Option<SlotLease>> {
        let super::PoolKey::PerUser { binding } = key else {
            return Ok(None);
        };
        self.identity_slots
            .reserve(binding)
            .map(Some)
            .map_err(|refusal| {
                telemetry_metrics::counter!(
                    "mcp_backend_identity_slots_refused_total",
                    "backend" => self.name.clone(),
                    "limit" => refusal.label()
                )
                .increment(1);
                crate::Error::IdentitySlotsExhausted {
                    backend: self.name.clone(),
                    limit: refusal.label(),
                }
            })
    }
}

fn abandoned(backend: &str) {
    telemetry_metrics::counter!(
        "mcp_backend_eviction_close_abandoned_total",
        "backend" => backend.to_string()
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_refuses_at_each_limit_and_only_there() {
        assert_eq!(admission(0, 0), Ok(()));
        assert_eq!(
            admission(MAX_IDENTITY_SLOTS - 1, MAX_SLOTS_PER_PRINCIPAL - 1),
            Ok(())
        );
        assert_eq!(admission(MAX_IDENTITY_SLOTS, 0), Err(Refusal::Backend));
        assert_eq!(admission(MAX_IDENTITY_SLOTS + 1, 0), Err(Refusal::Backend));
        assert_eq!(
            admission(0, MAX_SLOTS_PER_PRINCIPAL),
            Err(Refusal::Principal)
        );
        assert_eq!(
            admission(MAX_IDENTITY_SLOTS, MAX_SLOTS_PER_PRINCIPAL),
            Err(Refusal::Backend)
        );
    }

    #[test]
    fn a_passthrough_binding_is_charged_to_its_principal() {
        let (t1, t2) = (digest("t1"), digest("t2"));
        let a1 = passthrough_binding("alpha", &t1);
        let a2 = passthrough_binding("alpha", &t2);
        let b1 = passthrough_binding("beta", &t1);
        assert_ne!(a1, a2);
        assert_ne!(a1, b1);
        assert_eq!(a1, passthrough_binding("alpha", &t1));
        assert_eq!(principal_of(&a1), principal_of(&a2));
        assert_ne!(principal_of(&a1), principal_of(&b1));
        assert!(!a1.contains("alpha"));
        assert_eq!(principal_of("idp:alpha@ledger"), "idp:alpha@ledger");
    }

    #[test]
    fn a_dropped_lease_frees_both_counts() {
        let slots = Arc::new(IdentitySlots::default());
        let leases: Vec<_> = (0..MAX_SLOTS_PER_PRINCIPAL)
            .map(|i| {
                slots
                    .reserve(&passthrough_binding("p", &i.to_string()))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            slots.reserve(&passthrough_binding("p", "x")).unwrap_err(),
            Refusal::Principal
        );
        assert!(slots.reserve(&passthrough_binding("q", "x")).is_ok());
        drop(leases);
        assert_eq!(slots.in_use(), 0);
        assert!(slots.reserve(&passthrough_binding("p", "x")).is_ok());
    }
}
