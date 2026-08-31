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

/// The methods whose responses carry `ttlMs` and `cacheScope`.
///
/// This set and the decision table below are one decision seen from two sides,
/// which is why they live in one module rather than beside the router: a method
/// declared cacheable here with no row there is a scope nobody decided.
pub const CACHEABLE_METHODS: &[&str] = &[
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

/// The MIK-7213.CACHE.3 decision table — which endpoints may ever be `public`.
///
/// Source: `docs/design/2026-08-31-cluster-f-response-cache-keying.md`
/// §CACHE.3. Each row records a decision about one endpoint, and no row is
/// `public`:
///
/// - the three list methods and `resources/templates/list` vary by the
///   credential presented, which decides which backends a caller sees;
/// - `resources/read` returns content that is backend- and grant-dependent.
///
/// An endpoint absent from this table resolves `Private` (see
/// [`CacheScope::for_endpoint`]), so the table fails closed: adding a cacheable
/// endpoint cannot widen a cache scope by omission.
const CACHE_SCOPE_TABLE: &[(&str, CacheScope)] = &[
    ("tools/list", CacheScope::Private),
    ("prompts/list", CacheScope::Private),
    ("resources/list", CacheScope::Private),
    ("resources/read", CacheScope::Private),
    ("resources/templates/list", CacheScope::Private),
];

impl CacheScope {
    /// The wire value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }

    /// The row this method has in the CACHE.3 decision table, if it has one.
    ///
    /// `None` is a finding, not a default: every method in
    /// [`CACHEABLE_METHODS`] is expected to have a row, and a missing one means
    /// a response is emitting `cacheScope` under a scope nobody recorded.
    #[must_use]
    pub fn table_row(method: &str) -> Option<Self> {
        CACHE_SCOPE_TABLE
            .iter()
            .find_map(|&(name, scope)| (name == method).then_some(scope))
    }

    /// The scope this method's response may claim, per the CACHE.3 decision
    /// table.
    ///
    /// Table: `docs/design/2026-08-31-cluster-f-response-cache-keying.md`
    /// §CACHE.3, encoded in [`CACHE_SCOPE_TABLE`]. An endpoint with no row is
    /// `Private` — it has not proved invariance, so it cannot claim it.
    #[must_use]
    pub fn for_endpoint(method: &str) -> Self {
        match Self::table_row(method) {
            Some(scope) => scope,
            None => Self::Private,
        }
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
