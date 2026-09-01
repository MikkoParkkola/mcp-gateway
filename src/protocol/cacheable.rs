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
    /// anything about who asked, the answer is private. Which methods this
    /// gateway has answered that question for is [`scope_for_method`].
    #[must_use]
    pub const fn for_list(caller_dependent: bool) -> Self {
        if caller_dependent {
            Self::Private
        } else {
            Self::Public
        }
    }
}

/// The methods this gateway has assessed, and what each one warrants.
///
/// Every row is private and the default below is private too, so the table
/// changes no answer today. What it carries is which methods were *assessed*:
/// without it, a method nobody considered and a method considered and found
/// caller-dependent are the same silence, and a later `public` is a default
/// nobody had to argue for rather than an edit someone has to make.
const SCOPE_TABLE: &[(&str, CacheScope)] = &[
    // Filtered by the presented credential's scope — an API key decides which
    // backends, prompts and resources a caller is shown.
    ("tools/list", CacheScope::for_list(true)),
    ("prompts/list", CacheScope::for_list(true)),
    ("resources/list", CacheScope::for_list(true)),
    ("resources/templates/list", CacheScope::for_list(true)),
    // Not a list, so not `for_list`: reachability of a URI is decided per
    // caller, so the body is too. The bare value is the honest form here — a
    // row that named the list rule would be citing a rule it was not decided by.
    ("resources/read", CacheScope::Private),
];

/// The methods this gateway has assessed, and what each one warrants.
///
/// Exposed because *assessed* is not observable through [`scope_for_method`]:
/// every row is private and so is the fallback, so a row that was deleted and a
/// row nobody ever wrote return the same answer. The set is the artifact the
/// criterion asks for, and reading it is the only way to ask whether a method
/// is in it.
#[must_use]
pub fn assessed_methods() -> &'static [(&'static str, CacheScope)] {
    SCOPE_TABLE
}

/// What `method`'s result may claim on the wire.
///
/// An unlisted method is private. That is the direction the burden runs in
/// [`CacheScope`]: `public` is a claim about callers this gateway has never
/// seen, and a method nobody assessed has nobody's proof behind it.
#[must_use]
pub fn scope_for_method(method: &str) -> CacheScope {
    assessed_methods()
        .iter()
        .find(|(name, _)| *name == method)
        .map_or(CacheScope::Private, |(_, scope)| *scope)
}

/// The `resultType` of a result, defaulting as the specification requires.
///
/// > Clients **MUST** treat results from earlier-protocol servers that omit the
/// > field as `"complete"`.
///
/// Every pre-2026 backend omits it. Reading the absence as anything else would
/// make every legacy backend's answer unusable, which is why the default is
/// specified rather than left to the implementer.
///
/// That default covers an **omitted** field and nothing else. A field that is
/// present but not a string — `null`, a number, an object — is a malformed
/// result, not a legacy one, and answering `"complete"` for it would let a
/// backend opt out of the finality check by sending the field wrong. Those
/// return `""`, which no specified `resultType` can equal.
#[must_use]
pub fn result_type_of(result: &Value) -> &str {
    match result.get("resultType") {
        None => "complete",
        Some(present) => present.as_str().unwrap_or(""),
    }
}

/// Whether `result` is a finished answer, and so safe to cache and replay.
///
/// Anything else — `"input_required"` above all — is a step in an exchange that
/// is still running. Replaying one from a cache returns the *request* rather
/// than the answer, and the call can never finish. Because
/// [`result_type_of`] defaults a missing field to `"complete"`, every
/// pre-2026 backend's result stays cacheable, as the specification requires.
#[must_use]
pub fn is_final(result: &Value) -> bool {
    result_type_of(result) == "complete"
}
