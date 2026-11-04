// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A control-plane store whose every operation fails, for rows that prove a
//! failed read is reported rather than shown as an empty result.

use super::{
    AuditFilter, AuditPage, ControlPlaneAuditEvent, ControlPlaneGrant, ControlPlanePolicy,
    ControlPlaneStore, StoreError, StoreResult,
};

/// A store whose every read fails — used to prove the degraded flag.
pub(crate) struct FailingStore;
impl ControlPlaneStore for FailingStore {
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn get_grant(&self, _id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn put_grant(&self, _grant: ControlPlaneGrant) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn delete_grant(&self, _id: &str) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn get_policy(&self, _id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn put_policy(&self, _policy: ControlPlanePolicy) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn delete_policy(&self, _id: &str) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn append_audit(&self, _event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
    fn read_audit(&self, _filter: &AuditFilter) -> StoreResult<AuditPage> {
        Err(StoreError::Corrupt("boom".to_string()))
    }
}
