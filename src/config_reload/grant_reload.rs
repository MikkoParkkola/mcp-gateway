// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identity-grant reload: the sink it publishes into and the reload step.
//!
//! Moved out of `mod.rs` unchanged; that file is over the 800-line ceiling.

use std::path::PathBuf;
use std::sync::Arc;

use tracing::{error, info};

use super::grant_audit::{GrantAuditor, Prepared, Recorded};
use super::{RELOAD_LOCK_WAIT, ReloadContext, env_poll, grant_delta};
use crate::identity_grants::{GrantSubject, IdentityGrant, LocalIdentityGrantStore};

/// The publish target for a grant reload, plus the lock that serializes it.
///
/// GRANTS GET THEIR OWN LOCK, not `lock_reload_within`. That was settled in
/// review: `apply_patch`'s interleaving hazard is backend double-registration,
/// and grants register no backends, so a grant reload can neither cause it nor
/// suffer it. Keeping the shared lock would instead put a revocation behind
/// `backend.stop()` per modified backend — sequential, tens of seconds each —
/// for an entirely unrelated config edit. Serializing grant reloads against
/// each other is still required: two triggers can interleave read-file and
/// publish, the older file wins, and a revocation is silently lost.
#[derive(Debug)]
pub struct IdentityGrantSink {
    pub(super) store: Arc<parking_lot::RwLock<LocalIdentityGrantStore>>,
    pub(super) epoch: Arc<std::sync::atomic::AtomicU64>,
    pub(super) path: PathBuf,
    pub(super) lock: tokio::sync::Mutex<()>,
    /// Records each reload's grant changes; `None` without a governance store.
    pub(super) auditor: Option<Arc<GrantAuditor>>,
    /// Throttles an unchanged grants read error: retries re-read the file.
    read_errors: parking_lot::Mutex<env_poll::WarnLimiter>,
}

impl IdentityGrantSink {
    /// Wrap the live store, its epoch and the file they reload from.
    #[must_use]
    pub fn new(
        store: Arc<parking_lot::RwLock<LocalIdentityGrantStore>>,
        epoch: Arc<std::sync::atomic::AtomicU64>,
        path: PathBuf,
    ) -> Self {
        Self {
            store,
            epoch,
            path,
            lock: tokio::sync::Mutex::new(()),
            auditor: None,
            read_errors: parking_lot::Mutex::new(env_poll::WarnLimiter::default()),
        }
    }

    /// Record every reload's grant changes through `auditor` (MIK-7570.AUDIT.4).
    #[must_use]
    pub(crate) fn with_auditor(mut self, auditor: Arc<GrantAuditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    /// Whether reloads through this sink are recorded.
    #[cfg(test)]
    pub(crate) fn has_auditor(&self) -> bool {
        self.auditor.is_some()
    }
}

/// The subjects whose authorization changed between two grant snapshots.
///
/// A row present in one snapshot and absent from the other, or present in both
/// and unequal, contributes a subject. **An unequal row contributes BOTH its
/// outgoing and its incoming subject**, and that clause is the whole reason
/// this is a function rather than a one-line iterator. A grant whose `subject`
/// is edited A→B under an UNCHANGED `grant_id` is one unequal row: taking only
/// the incoming subject evicts B's slots and leaves A's catalogue bytes live,
/// with no log line naming A — a reassignment that silently preserves the
/// previous holder's view.
///
/// One rule covers both nouns the criterion names: a revocation changes
/// `revoked_at`, a rotation changes `scope`/`tool`/`expires_at`/`agent`, and a
/// removal or addition is a presence difference.
pub(super) fn changed_grant_subjects(
    outgoing: &[IdentityGrant],
    incoming: &[IdentityGrant],
) -> Vec<GrantSubject> {
    use std::collections::BTreeMap;

    let by_id = |rows: &[IdentityGrant]| {
        rows.iter()
            .map(|row| (row.grant_id.clone(), row.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let (before, after) = (by_id(outgoing), by_id(incoming));

    let mut subjects: Vec<GrantSubject> = Vec::new();
    let mut push = |subject: &GrantSubject| {
        if !subjects.contains(subject) {
            subjects.push(subject.clone());
        }
    };
    for (id, old) in &before {
        match after.get(id) {
            None => push(&old.subject),
            Some(new) if new != old => {
                push(&old.subject);
                push(&new.subject);
            }
            Some(_) => {}
        }
    }
    for (id, new) in &after {
        if !before.contains_key(id) {
            push(&new.subject);
        }
    }
    subjects
}

impl ReloadContext {
    /// Reload the identity-grant file, publish it, and evict the pool slots
    /// whose grants changed.
    ///
    /// ITS OWN STEP, ITS OWN OUTCOME, ITS OWN LOCK. A revocation's validity has
    /// nothing to do with config hygiene, so an operator mid-way through
    /// enabling message signing must not hold one hostage: neither step's
    /// refusal refuses the other. Returns `None` when no grants file is
    /// configured.
    ///
    /// FAIL OPEN. An unreadable or unparseable file keeps the live store and
    /// publishes nothing — dropping live grants because a file was briefly
    /// unmountable would turn a read error into a mass revocation. A file that
    /// is VALID with zero grants is applied, because "revoke everything" has to
    /// stay expressible or fail-open becomes a hole.
    ///
    /// NO-CHANGE IS DEFINED ON NORMALISED STORE CONTENTS, never file bytes.
    /// `LocalIdentityGrantStore` is a `BTreeMap` keyed by grant id, so loading
    /// normalises row order for free — but only if the comparison happens on
    /// the LOADED store. Comparing bytes, or the file's `Vec` order, reports a
    /// change whenever an operator reorders rows, and the epoch is global: one
    /// bump strands every caller's result cache, not just the edited one.
    ///
    /// PUBLISH FIRST, EVICT SECOND. The reverse order leaves a window where a
    /// slot is evicted, a concurrent request refills it against the old grants
    /// still in the store, and the refilled catalogue is stale again — an
    /// eviction that ran and achieved nothing.
    pub async fn reload_identity_grants(&self) -> Option<std::result::Result<String, String>> {
        let sink = self.identity_grants.as_ref()?;
        // Bounded like `lock_reload_within`: busy is its own refusal, so an
        // operator retries instead of inspecting a grants file that is fine.
        let Ok(_grants_guard) = tokio::time::timeout(RELOAD_LOCK_WAIT, sink.lock.lock()).await
        else {
            env_poll::report_grants_busy(&sink.read_errors, &sink.path);
            return Some(Err(
                "identity grants reload busy: another grant reload is in progress; retry"
                    .to_string(),
            ));
        };

        // With an auditor, the grant file and journal are read under the
        // journal lock, held through record (design 5.4).
        let (file, locked) = if sink.auditor.is_some() {
            let Some(read) =
                crate::identity_grants::journal::read_locked(&sink.path, RELOAD_LOCK_WAIT).await
            else {
                error!(path = %sink.path.display(), "Identity-grant reload busy: grant journal locked");
                return Some(Err(
                    "identity grants reload busy: a grant change is in progress; retry".to_string(),
                ));
            };
            (read.grants, Some((read.guard, read.journal)))
        } else {
            (
                crate::identity_grants::read_identity_grants_file(&sink.path).await,
                None,
            )
        };
        let file = match file {
            Ok(file) => {
                *sink.read_errors.lock() = env_poll::WarnLimiter::default();
                file
            }
            Err(reason) => {
                env_poll::report_grants_refusal(&sink.read_errors, &sink.path, &reason);
                return Some(Err(format!(
                    "identity grants not reloaded from {}: {reason}",
                    sink.path.display()
                )));
            }
        };

        // Plan before publish: a plan that cannot be made durable refuses the
        // change and publishes nothing (design 5.2 step 6).
        let prepared = match (&sink.auditor, &locked) {
            (Some(auditor), Some((_, journal))) => match auditor.prepare(&file.grants, journal) {
                Ok(prepared) => Some(prepared),
                Err(refusal) => {
                    error!(path = %sink.path.display(), reason = %refusal.0, "Identity-grant reload refused");
                    return Some(Err(refusal.0));
                }
            },
            _ => None,
        };
        let incoming = LocalIdentityGrantStore::from_grants(file.grants);
        let outgoing: Vec<_> = sink.store.read().values().cloned().collect();
        let incoming_rows: Vec<_> = incoming.values().cloned().collect();
        if outgoing == incoming_rows {
            // Still recorded: an identical-content `--replace` has an entry.
            let clause = audit_clause(sink.auditor.as_deref(), prepared);
            return Some(Ok(format!("identity grants unchanged{clause}")));
        }

        let subjects = changed_grant_subjects(&outgoing, &incoming_rows);
        let delta = grant_delta::grant_delta(&outgoing, &incoming_rows);
        crate::gateway::publish_identity_grants(&sink.store, &sink.epoch, incoming);

        // Three distinct outcomes, and they must not share a counter:
        // "skipped by construction" is expected for a non-issuer authority,
        // while "considered, matched nothing" is the reconstruction failing to
        // find a live slot — benign when the caller had none, and the only
        // tripwire for a stored subject that diverges from its binding.
        let mut skipped: Vec<String> = Vec::new();
        let mut evicted = 0usize;
        let mut matched_nothing = 0usize;
        for subject in subjects {
            let Some(prefix) = crate::identity_propagation::identity_binding_prefix(&subject)
            else {
                // Skipped, never fallen through to a match: no `idp:` slot can
                // exist for a grant whose authority is not an issuer.
                skipped.push(subject.authority.clone());
                continue;
            };
            let mut hit = 0usize;
            for backend in self.registry.all() {
                hit += backend.evict_identity_slots(&prefix);
            }
            if hit == 0 {
                matched_nothing += 1;
            }
            evicted += hit;
        }

        info!(
            path = %sink.path.display(),
            rows = incoming_rows.len(),
            %delta,
            slots_evicted = evicted,
            subjects_matching_no_slot = matched_nothing,
            subjects_skipped = ?skipped,
            "Identity grants reloaded"
        );
        // Record after publish: a failed append never unpublishes (AUDIT4.6).
        let clause = audit_clause(sink.auditor.as_deref(), prepared);
        drop(locked);
        Some(Ok(format!(
            "identity grants reloaded ({} rows, {delta}, {evicted} pool slots evicted){clause}",
            incoming_rows.len()
        )))
    }
}

/// Append a prepared plan and say how it went, for the reload outcome.
fn audit_clause(auditor: Option<&GrantAuditor>, prepared: Option<Prepared>) -> String {
    match (auditor, prepared) {
        (Some(auditor), Some(prepared)) => match auditor.record(prepared) {
            Recorded::All(n) => format!("; grant records: {n} written"),
            Recorded::Unrecorded(reason) => format!("; grant change UNRECORDED: {reason}"),
        },
        _ => String::new(),
    }
}
