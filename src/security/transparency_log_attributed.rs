// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: one invocation record with extra attribution fields.
//!
//! The three D1 writers (meta invoke, direct route, meta pre-dispatch refusal)
//! hand their attribution here as a JSON map, so no public signature changes.

use std::io;

use serde_json::{Map, Value};

use super::{CorrelationKey, TransparencyLogger};
use crate::security::audit::{AuditEnvelope, InvocationTarget};

/// Most tenant hashes one record carries; past it the record keeps the first
/// `MAX_RECORDED_TENANTS` sorted hashes and says how many there were in
/// `tenants_total`.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "MIK-7116.MIN.1 red stub; wired by the implementation"
    )
)]
pub(crate) const MAX_RECORDED_TENANTS: usize = 1024;

impl TransparencyLogger {
    /// As [`Self::log_invocation_correlated`], with `extra` fields (`tenants`,
    /// `data_classes`, ...) inside the chained, signed record.
    ///
    /// # Errors
    ///
    /// As [`Self::log_invocation_correlated`].
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "MIK-7116.MIN.1 red stub; wired by the implementation"
        )
    )]
    pub(crate) fn log_invocation_attributed(
        &self,
        key: CorrelationKey<'_>,
        envelope: &AuditEnvelope,
        target: InvocationTarget<'_>,
        request_hash: &str,
        response_hash: Option<&str>,
        _extra: Map<String, Value>,
    ) -> io::Result<()> {
        self.log_invocation_correlated(key, envelope, target, request_hash, response_hash)
    }
}
