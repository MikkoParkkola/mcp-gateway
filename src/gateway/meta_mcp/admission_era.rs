// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8747 / MIK-8748: a stored delivery records the era it was shaped for,
//! and a keyed replay from the other era is refused.

use serde_json::{Value, json};

use super::{SyncAdmission, stored};
use crate::{Error, Result};

/// The era a request was classified in, as a stored delivery records it.
/// `is_modern` is the transport's classification (`MetaMcpCallerContext::era`
/// on the meta path); this one mapping serves both the stamp and the
/// comparison, because `admit_operation`, where the comparison runs, is
/// shared with Direct and receives only `is_modern`.
fn request_era(is_modern: bool) -> crate::protocol::meta::Era {
    if is_modern {
        crate::protocol::meta::Era::Modern
    } else {
        crate::protocol::meta::Era::Legacy
    }
}

/// MIK-8747/MIK-8748: the refusal of a keyed replay whose stored delivery
/// was shaped for another era. The call already ran, so the message sends the
/// client back to the revision it first used, never to a new key (which
/// would run it again).
fn era_mismatch(stored: crate::protocol::meta::Era, request: crate::protocol::meta::Era) -> Error {
    let name = |era| serde_json::to_value(era).unwrap_or(Value::Null);
    Error::JsonRpc {
        code: 409,
        message: "This idempotency key's call already ran for another protocol revision; \
                  retry it with its original protocol revision"
            .to_string(),
        data: Some(json!({
            "reason": "idempotency_era_mismatch",
            "stored_era": name(stored),
            "request_era": name(request),
            "already_executed": true,
        })),
    }
}

/// MIK-8747: a delivery stored shaped for one era is never served to the
/// other. Only the era is decoded, so a refusal restores none of the record's
/// read or write scope.
pub(super) fn refuse_another_era(bytes: &[u8], is_modern: bool) -> Result<()> {
    let era = request_era(is_modern);
    match stored::stored_era(bytes) {
        Some(stored_era) if stored_era != era => Err(era_mismatch(stored_era, era)),
        _ => Ok(()),
    }
}

/// MIK-8747: a meta-path lease (`/mcp`, stdio) stores its delivery already
/// shaped for the request's era, so it records that era; any other
/// admission passes through unchanged.
pub(super) fn shaped_for_request(admission: SyncAdmission, is_modern: bool) -> SyncAdmission {
    match admission {
        SyncAdmission::Owned(mut lease) => {
            lease.era = Some(request_era(is_modern));
            SyncAdmission::Owned(lease)
        }
        other => other,
    }
}
