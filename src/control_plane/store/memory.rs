// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-memory control-plane store (split from `store.rs`).

use super::{
    AuditFilter, AuditPage, ControlPlaneStore, StoreError, StoreResult, audit_cursor, scan_audit,
};
use crate::control_plane::{ControlPlaneAuditEvent, ControlPlaneGrant, ControlPlanePolicy};
use std::sync::Mutex;

/// In-memory [`ControlPlaneStore`], used by tests and ephemeral deployments.
#[derive(Default)]
pub struct InMemoryControlPlaneStore {
    grants: Mutex<Vec<ControlPlaneGrant>>,
    policies: Mutex<Vec<ControlPlanePolicy>>,
    audit: Mutex<Vec<ControlPlaneAuditEvent>>,
}

impl InMemoryControlPlaneStore {
    /// Create an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock<T>(guard: &Mutex<T>) -> StoreResult<std::sync::MutexGuard<'_, T>> {
        guard
            .lock()
            .map_err(|_| StoreError::Serialize("in-memory store mutex poisoned".to_string()))
    }
}

impl ControlPlaneStore for InMemoryControlPlaneStore {
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
        Ok(Self::lock(&self.grants)?.clone())
    }

    fn get_grant(&self, grant_id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
        Ok(Self::lock(&self.grants)?
            .iter()
            .find(|g| g.grant_id == grant_id)
            .cloned())
    }

    fn put_grant(&self, grant: ControlPlaneGrant) -> StoreResult<()> {
        let mut grants = Self::lock(&self.grants)?;
        if let Some(existing) = grants.iter_mut().find(|g| g.grant_id == grant.grant_id) {
            *existing = grant;
        } else {
            grants.push(grant);
        }
        Ok(())
    }

    fn delete_grant(&self, grant_id: &str) -> StoreResult<()> {
        Self::lock(&self.grants)?.retain(|g| g.grant_id != grant_id);
        Ok(())
    }

    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
        Ok(Self::lock(&self.policies)?.clone())
    }

    fn get_policy(&self, policy_id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
        Ok(Self::lock(&self.policies)?
            .iter()
            .find(|p| p.policy_id == policy_id)
            .cloned())
    }

    fn put_policy(&self, policy: ControlPlanePolicy) -> StoreResult<()> {
        let mut policies = Self::lock(&self.policies)?;
        if let Some(existing) = policies
            .iter_mut()
            .find(|p| p.policy_id == policy.policy_id)
        {
            *existing = policy;
        } else {
            policies.push(policy);
        }
        Ok(())
    }

    fn delete_policy(&self, policy_id: &str) -> StoreResult<()> {
        Self::lock(&self.policies)?.retain(|p| p.policy_id != policy_id);
        Ok(())
    }

    fn append_audit(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        Self::lock(&self.audit)?.push(event.clone());
        Ok(())
    }

    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<AuditPage> {
        filter.validate()?;
        let audit = Self::lock(&self.audit)?;
        // The cursor is an exclusive upper-bound index: scan backwards from it.
        let end = filter
            .cursor
            .map_or(audit.len(), |c| {
                usize::try_from(c.offset).unwrap_or(usize::MAX)
            })
            .min(audit.len());
        let scan = scan_audit(
            audit[..end]
                .iter()
                .enumerate()
                .rev()
                .map(|(i, e)| Ok((u64::try_from(i).unwrap_or(u64::MAX), e.clone()))),
            filter,
        )?;
        Ok(AuditPage {
            events: scan.events,
            next_cursor: audit_cursor(scan.stopped_at.unwrap_or(0)),
            records_examined: scan.records_examined,
            bytes_examined: 0,
            cursor_reset: false,
        })
    }
}
