// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a caller's own catalogue slot says about one tool, whatever the
//! argument-key enforcement mode (MIK-8356 design R5.2).
//!
//! The argument-key check (`input_keys.rs`) returns before reading a slot
//! when enforcement is `off`, so on a per-user backend a tool this caller's
//! catalogue withholds or lacks would be forwarded. This verdict reads the
//! same slot through the same single-flight fill, and answers only "is the
//! tool offered to this caller", leaving the argument keys to that check.

use crate::capability::validator::input_schema_is_structurally_valid;
use crate::protocol::Tool;
use crate::transport::LentCredential;

use super::Backend;
use super::fill_check::{Completeness, is_transport_failure};
use crate::config::InputSchemaEnforcement;

/// What `binding`'s catalogue says about a tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CatalogueVerdict {
    /// The catalogue offers it with a structurally valid schema.
    Offers,
    /// The catalogue withholds it: a blocked descriptor, or an invalid schema.
    Withholds,
    /// A complete catalogue lacks it.
    Lacks,
    /// Nothing can be vouched for: a truncated or replaced list lacks it, or
    /// the slot may not be fetched for this caller. The argument-key check
    /// decides, as before.
    Unknown,
}

/// A fill that failed, answered by F13's own table so the verdict refuses
/// exactly what the argument-key check would: the slot's failsafe always;
/// under `closed`, a backend that could not be reached or is waiting for a
/// login. Anything else vouches for nothing ([`CatalogueVerdict::Unknown`]),
/// and the argument-key check decides, as before.
fn refused_fill(
    mode: InputSchemaEnforcement,
    error: crate::Error,
) -> crate::Result<CatalogueVerdict> {
    match error {
        e @ (crate::Error::CircuitOpen { .. }
        | crate::Error::RateLimited(_)
        | crate::Error::IdentitySlotsExhausted { .. }) => Err(e),
        e if mode == InputSchemaEnforcement::Closed
            && (is_transport_failure(&e) || e.is_authorization_wait()) =>
        {
            Err(e)
        }
        _ => Ok(CatalogueVerdict::Unknown),
    }
}

/// The verdict a held entry earns. `catalogue_verdict_inner` and
/// `held_verdict` judge the entry in place with it (MIK-8014 PERF.10).
pub(super) fn judged(tool: &Tool) -> CatalogueVerdict {
    if input_schema_is_structurally_valid(&tool.input_schema) {
        CatalogueVerdict::Offers
    } else {
        CatalogueVerdict::Withholds
    }
}

impl Backend {
    /// [`CatalogueVerdict`] for `tool` in `binding`'s slot. A cold or stale
    /// slot is listed once as the caller, with `headers` (F13's fill).
    ///
    /// # Errors
    ///
    /// The fill's error when a slot holding nothing for `tool` could not be
    /// listed: the call answers with the error a failed dispatch gets.
    ///
    /// Type-erased for the reason `undeclared_key_refusal` is.
    pub(crate) fn catalogue_verdict<'a>(
        &'a self,
        binding: Option<&'a str>,
        headers: LentCredential,
        tool: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = crate::Result<CatalogueVerdict>> + Send + 'a>> {
        Box::pin(self.catalogue_verdict_inner(binding, headers, tool))
    }

    async fn catalogue_verdict_inner(
        &self,
        binding: Option<&str>,
        headers: LentCredential,
        tool: &str,
    ) -> crate::Result<CatalogueVerdict> {
        if self.blocked_tool_refusal(binding, tool).is_some() {
            return Ok(CatalogueVerdict::Withholds);
        }
        // A fresh slot, or a stale one inside its refresh cooldown, is served
        // by the fill without a fetch (`get_cached_list_for`).
        // Judged in place, under the slot's read guard: a deep copy of the
        // whole tool used to be made for this one read (MIK-8014 PERF.10).
        let cached = self.with_cached_tool_for(binding, tool, judged);
        // A3: a shared slot is never fetched for a caller that sent its own
        // credential (the fill runs under the gateway's login).
        if !self.fetch_carries_caller_identity(binding) && !headers.headers.is_empty() {
            return Ok(cached.unwrap_or(CatalogueVerdict::Unknown));
        }
        let (tools, completeness) = match self
            .tools_for_check(binding, headers, cached.is_some())
            .await
        {
            Ok(fetched) => fetched,
            // A stale hit falls back to what the slot holds now.
            Err(_) if cached.is_some() => match self.held_tools_for(binding) {
                Some(now) => now,
                None => return Ok(cached.unwrap_or(CatalogueVerdict::Unknown)),
            },
            Err(e) => return refused_fill(self.config.input_schema_enforcement, e),
        };
        let newer = matches!(completeness, Completeness::Unknown)
            .then(|| self.held_tools_for(binding))
            .flatten();
        let (tools, completeness) = newer.unwrap_or((tools, completeness));
        // The fill is itself a listing and may have just blocked the name.
        if self.blocked_tool_refusal(binding, tool).is_some() {
            return Ok(CatalogueVerdict::Withholds);
        }
        if let Some(found) = tools.iter().find(|t| t.name == tool) {
            return Ok(judged(found));
        }
        Ok(match completeness {
            Completeness::Complete => CatalogueVerdict::Lacks,
            Completeness::Truncated | Completeness::Unknown => CatalogueVerdict::Unknown,
        })
    }
}
