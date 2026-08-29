// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT

//! Cacheability of a result, and how completed results are told from interim
//! ones (MCP 2026-07-28).

use serde_json::Value;

/// Who may reuse a cached response.
///
/// From the schema: `public` means *"the response does not contain
/// user-specific data. Any client or intermediary (e.g., shared gateway,
/// caching proxy) MAY cache the response and serve it across authorization
/// contexts."* `private` means it *"MAY be cached and reused only within the
/// same authorization context. Caches MUST NOT be shared across authorization
/// contexts."*
///
/// Read that first sentence again from a gateway's position: `public` is a
/// claim about **every future caller**, made by a server that has seen exactly
/// one. So the burden runs one way — a response is private unless it provably
/// does not depend on who asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScope {
    /// Reusable across authorization contexts. Requires proof of invariance.
    Public,
    /// Reusable only within the authorization context that fetched it.
    Private,
}

impl CacheScope {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    /// The scope for a list whose content did or did not depend on the caller.
    ///
    /// One argument, and it is the whole decision: if the assembly consulted
    /// anything about who asked, the answer is private.
    #[must_use]
    pub const fn for_list(caller_dependent: bool) -> Self {
        if caller_dependent {
            Self::Private
        } else {
            Self::Public
        }
    }

    /// The scope this gateway's `tools/list` currently warrants.
    ///
    /// Private, and not provisionally: the list varies by the credential
    /// presented — an API key's scope decides which backends a caller sees.
    /// That variation is legal (credentials are per-request input, not
    /// connection state) and it is exactly what `private` describes.
    ///
    /// A future `public` needs the decision table MIK-7213 asks for, naming a
    /// response that provably does not vary. It is not reached by relaxing this
    /// function.
    #[must_use]
    pub const fn current_for_tools_list() -> Self {
        Self::for_list(true)
    }
}

/// The `resultType` of a result, defaulting as the specification requires.
///
/// > Clients **MUST** treat results from earlier-protocol servers that omit the
/// > field as `"complete"`.
///
/// Every pre-2026 backend omits it. Reading the absence as anything else would
/// make every legacy backend's answer unusable, which is why the default is
/// specified rather than left to the implementer.
#[must_use]
pub fn result_type_of(result: &Value) -> &str {
    result
        .get("resultType")
        .and_then(Value::as_str)
        .unwrap_or("complete")
}
