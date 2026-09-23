// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `accounts.limits`: the store bounds and the consent-journey limits.
//!
//! Moved out of `config.rs` unchanged when the journey limits arrived, so that
//! file stays under its line ratchet. The path `config::AccountsLimits` is kept
//! by a re-export there.

use serde::{Deserialize, Serialize};

use super::AccountsConfigError;

/// `records_max = RECORDS_PER_ACTIVE x journeys_total` (design §5.1): active
/// records plus retained terminal ones. Derived, never configured.
const RECORDS_PER_ACTIVE: usize = 4;

/// EVERY FIELD IS "reject zero/overflow" (approved configuration table, design
/// doc row 432; journey design §10). The overflow half is not an invented
/// ceiling: `storage.rs`'s `validate_config` refuses a store whose
/// `max_authority_bytes.checked_add(16).and_then(|size| size.checked_mul(4))`
/// overflows, so the largest accepted `authority_bytes` is `(usize::MAX/4)-16`,
/// and `journeys_total` must carry the derived `records_max`. The numbers named
/// on each field below are the approved DEFAULTS, not bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountsLimits {
    /// Default 10000 -> `StoreConfig::max_entries`. Zero and overflow reject.
    pub(crate) store_entries: usize,
    /// Default 16777216 -> `StoreConfig::max_authority_bytes`. Zero rejects, and
    /// so does any value the storage sealing arithmetic above cannot carry.
    pub(crate) authority_bytes: usize,
    /// Default 1024. Active (`pending`/`started`) journeys, gateway-wide.
    pub(crate) journeys_total: usize,
    /// Default 8. Journey CREATIONS per principal in a sliding 10-minute
    /// window: a rate, not a count (review M1).
    pub(crate) journeys_per_user: u32,
    /// Default 10. Start invocations per principal in a sliding 60 s window.
    pub(crate) starts_per_minute_per_user: u32,
    /// Default 120. Journey creations gateway-wide in a sliding 60 s window
    /// (review H3).
    pub(crate) journeys_created_per_minute: u32,
}

impl Default for AccountsLimits {
    fn default() -> Self {
        Self {
            store_entries: 10000,
            authority_bytes: 16_777_216,
            journeys_total: 1024,
            journeys_per_user: 8,
            starts_per_minute_per_user: 10,
            journeys_created_per_minute: 120,
        }
    }
}

/// Every limit, in field order. The first refusal wins.
pub(super) fn validate(limits: &AccountsLimits) -> Result<(), AccountsConfigError> {
    positive("store_entries", limits.store_entries)?;
    positive("authority_bytes", limits.authority_bytes)?;
    // The approved storage bound: `storage::validate_config` refuses a store
    // whose sealed-manifest arithmetic overflows, so a value that cannot carry
    // it is rejected here rather than at open time.
    if limits
        .authority_bytes
        .checked_add(16)
        .and_then(|size| size.checked_mul(4))
        .is_none()
    {
        return Err(AccountsConfigError::Limit {
            field: "authority_bytes",
        });
    }
    positive("journeys_total", limits.journeys_total)?;
    if limits
        .journeys_total
        .checked_mul(RECORDS_PER_ACTIVE)
        .is_none()
    {
        return Err(AccountsConfigError::Limit {
            field: "journeys_total",
        });
    }
    positive("journeys_per_user", limits.journeys_per_user)?;
    positive(
        "starts_per_minute_per_user",
        limits.starts_per_minute_per_user,
    )?;
    positive(
        "journeys_created_per_minute",
        limits.journeys_created_per_minute,
    )
}

/// Zero is the only in-type value no limit may take. A negative value never
/// gets here: the unsigned field refuses it at parse.
fn positive<T: Copy + Default + PartialEq>(
    field: &'static str,
    value: T,
) -> Result<(), AccountsConfigError> {
    if value == T::default() {
        return Err(AccountsConfigError::Limit { field });
    }
    Ok(())
}
