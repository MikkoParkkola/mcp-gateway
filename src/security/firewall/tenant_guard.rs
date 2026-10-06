// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Cross-tenant data-minimisation guard (MIK-7116.TENANT.1).
//!
//! Refuses a caller that reaches across more customers in a short span than
//! its work plausibly requires. One tenant at a time is ordinary; twenty in a
//! minute is a caller enumerating a customer table, whatever it was asked to
//! do.
//!
//! # Why the principal, not the session
//!
//! The requirement was written as "within one session". Under a stateless
//! transport there is no session to be within: each request is its own, so
//! every request carries exactly one tenant and the limit is never reached.
//! That guard would pass every test that asserts an *allow* and fail nothing —
//! which is why every acceptance test for this control asserts a *refusal*.
//! The counting key is therefore the authenticated principal, and the span is
//! an explicit window ([`crate::security::firewall::principal_window`]).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::principal_window::{PrincipalWindow, Usage};

/// What the guard decided about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantVerdict {
    /// Proceed: no tenant identifiers, or a caller still inside its span.
    Allowed,
    /// Refuse: this principal has reached across too many tenants.
    Refused {
        /// Distinct tenants this principal has touched inside the window.
        distinct: usize,
        /// The configured ceiling that was exceeded.
        limit: usize,
    },
    /// Refuse: tenant data was requested by nobody in particular.
    ///
    /// Distinct from [`Self::Refused`] because the reasons differ and the
    /// operator response differs: a refusal means a caller went too wide, this
    /// means the request carried no identity to hold responsible. Counting
    /// unattributed requests together would let the busiest anonymous caller
    /// spend everyone else's allowance; counting them separately is a limit of
    /// one per caller that never binds. Neither is a budget, so neither is
    /// offered.
    Unattributable,
}

/// Tenant-guard policy. Disabled unless switched on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantGuardConfig {
    /// Whether the guard may refuse a request. Tenant attribution in the audit
    /// logs (MIK-7116.MIN.1) runs whenever `arg_keys` is set, even when this
    /// is `false`: the observe-only rollout.
    pub enabled: bool,
    /// Distinct tenants one principal may touch inside the window.
    pub max_tenants_per_window: usize,
    /// How long a tenant observation counts against its principal.
    pub window_secs: u64,
    /// Argument keys whose values name a tenant, at any nesting depth. The
    /// same keys attribute tool results (text-JSON included) to tenants in
    /// the audit logs, hashed, never raw.
    pub arg_keys: Vec<String>,
    /// What the cross-tenant read verdict (MIK-7116.MIN.2) does with a caller
    /// whose delivered frames name a second tenant inside the window.
    pub cross_tenant_reads: CrossTenantReads,
}

/// Mode of the cross-tenant read verdict on outbound frames (MIK-7116.MIN.2).
///
/// Observe-first: blocking by default waits for the MIN.KILL week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrossTenantReads {
    /// No verdict.
    Off,
    /// Flag the frame in the audit record and deliver it.
    #[default]
    Observe,
    /// Withhold the frame and record the refusal.
    Block,
}

impl Default for TenantGuardConfig {
    /// Disabled, with a limit and window that apply only once switched on.
    ///
    /// Off by default because a wrong `arg_keys` list on an existing
    /// deployment refuses legitimate traffic, and a security control that
    /// arrives unannounced as an outage does not stay switched on.
    fn default() -> Self {
        Self {
            enabled: false,
            max_tenants_per_window: 3,
            window_secs: 300,
            arg_keys: Vec::new(),
            cross_tenant_reads: CrossTenantReads::Observe,
        }
    }
}

/// Largest JSON-carrying string [`TenantGuard::response_tenants`] parses.
const MAX_PARSED_TEXT_BYTES: usize = 1024 * 1024;

/// How many nested JSON-in-a-string layers the response scan decodes before
/// it reports the rest unread (MIN.1 gap 3).
const MAX_DECODE_DEPTH: usize = 3;

/// What one response scan found.
#[derive(Default)]
struct ResponseScan {
    tenants: Vec<String>,
    uninspected: bool,
}

/// Per-principal cross-tenant reach limiter.
pub struct TenantGuard {
    config: TenantGuardConfig,
    seen: PrincipalWindow,
}

impl TenantGuard {
    /// Build a guard from policy.
    #[must_use]
    pub fn new(config: TenantGuardConfig) -> Self {
        let seen = PrincipalWindow::new(Duration::from_secs(config.window_secs));
        Self { config, seen }
    }

    /// Judge one request's arguments on behalf of `principal`.
    ///
    /// Records the tenants named in `args` and reports whether this principal
    /// has now reached across more of them than the policy allows.
    pub fn check(&self, principal: Option<&str>, args: &Value) -> TenantVerdict {
        if !self.config.enabled {
            return TenantVerdict::Allowed;
        }

        let mut tenants = Vec::new();
        self.collect(args, &mut tenants);
        if tenants.is_empty() {
            // No tenant data in play, so nothing to minimise — including when
            // the caller is anonymous. An unattributable *non-tenant* request
            // is an ordinary request.
            return TenantVerdict::Allowed;
        }

        let mut verdict = TenantVerdict::Allowed;
        for tenant in tenants {
            match self.seen.record(principal, &tenant) {
                Usage::Unkeyed => return TenantVerdict::Unattributable,
                Usage::Counted { distinct, .. }
                    if distinct > self.config.max_tenants_per_window =>
                {
                    verdict = TenantVerdict::Refused {
                        distinct,
                        limit: self.config.max_tenants_per_window,
                    };
                }
                Usage::Counted { .. } => {}
            }
        }
        verdict
    }

    /// The tenants a request names, under the configured `arg_keys`, with the
    /// guard's own walk. Pure: it records nothing, so attribution never counts
    /// against the guard, and it runs whether or not the guard may refuse.
    pub(crate) fn request_tenants(&self, args: &Value) -> BTreeSet<String> {
        let mut tenants = Vec::new();
        self.collect(args, &mut tenants);
        tenants.into_iter().collect()
    }

    /// The tenants a tool result names: the guard's walk over the result, also
    /// into every JSON document a string carries (`content[].text`, a string
    /// field, a double-encoded text). Pure, like [`Self::request_tenants`].
    pub(crate) fn response_tenants(&self, result: &Value) -> BTreeSet<String> {
        self.scan_response(result).0
    }

    /// [`Self::response_tenants`] and [`Self::response_uninspected`] in one
    /// walk.
    pub(crate) fn response_reading(&self, result: &Value) -> (BTreeSet<String>, bool) {
        self.scan_response(result)
    }

    /// Whether tenant attribution is configured (`arg_keys` set).
    pub(crate) fn attributes(&self) -> bool {
        !self.config.arg_keys.is_empty()
    }

    /// MIN.1 gaps 2 and 3: whether any part of `result` could not be read for
    /// tenants: a document over the parse bound, one that fails to parse (depth
    /// limit included), or encoding nested past [`MAX_DECODE_DEPTH`].
    pub(crate) fn response_uninspected(&self, result: &Value) -> bool {
        self.scan_response(result).1
    }

    /// MIN.2: one walk over the parts of an outbound frame: whole values and
    /// bare strings (a `method`, an error message), each decoded like a
    /// response string. Empty when attribution is off.
    pub(crate) fn scan_frame(&self, values: &[&Value], texts: &[&str]) -> (BTreeSet<String>, bool) {
        if self.config.arg_keys.is_empty() {
            return (BTreeSet::new(), false);
        }
        let mut scan = ResponseScan::default();
        for value in values {
            self.walk_response(value, 0, &mut scan);
        }
        for text in texts {
            self.decode_response(text, 0, &mut scan);
        }
        (scan.tenants.into_iter().collect(), scan.uninspected)
    }

    /// MIN.2: [`Self::scan_frame`] over a whole document but its top-level
    /// `skip` keys (`jsonrpc`, `id`).
    pub(crate) fn scan_document(&self, doc: &Value, skip: &[&str]) -> (BTreeSet<String>, bool) {
        let Value::Object(map) = doc else {
            return self.scan_frame(&[doc], &[]);
        };
        if self.config.arg_keys.is_empty() {
            return (BTreeSet::new(), false);
        }
        let mut scan = ResponseScan::default();
        for (key, child) in map {
            if skip.contains(&key.as_str()) {
                continue;
            }
            if self.config.arg_keys.iter().any(|k| k == key)
                && let Some(tenant) = Self::tenant_name(child)
            {
                scan.tenants.push(tenant);
            }
            self.walk_response(child, 0, &mut scan);
        }
        (scan.tenants.into_iter().collect(), scan.uninspected)
    }

    /// The configuration this guard was built from.
    pub(crate) const fn config(&self) -> &TenantGuardConfig {
        &self.config
    }

    /// One walk: the tenants read, and whether anything was left unread.
    // ponytail: each public caller rescans; merge into one call if a profile shows it.
    fn scan_response(&self, result: &Value) -> (BTreeSet<String>, bool) {
        if self.config.arg_keys.is_empty() {
            return (BTreeSet::new(), false);
        }
        let mut scan = ResponseScan::default();
        self.walk_response(result, 0, &mut scan);
        (scan.tenants.into_iter().collect(), scan.uninspected)
    }

    fn walk_response(&self, value: &Value, decoded: usize, scan: &mut ResponseScan) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if self.config.arg_keys.iter().any(|k| k == key)
                        && let Some(tenant) = Self::tenant_name(child)
                    {
                        scan.tenants.push(tenant);
                    }
                    // A keyed string is the tenant id and may also carry JSON:
                    // read it too, or report it unread.
                    self.walk_response(child, decoded, scan);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.walk_response(item, decoded, scan);
                }
            }
            Value::String(text) => self.decode_response(text, decoded, scan),
            _ => {}
        }
    }

    /// Read the JSON a string carries. Prose is not JSON and holds no keyed
    /// tenant, so it is skipped. Text that opens like a document (`{`, `[`)
    /// must parse, or it is unread: fail closed, even for bracket-led prose. A
    /// quoted text is decoded when it is exactly one JSON string. One cut short
    /// (its quote never closes) is decoded as far as it goes, so a
    /// double-encoded document cut short is unread as well (MIK-7881).
    fn decode_response(&self, text: &str, decoded: usize, scan: &mut ResponseScan) {
        // A byte-order mark is not whitespace to `trim_start`, nor JSON to the
        // parser: strip marks and whitespace in any order so neither hides a
        // document.
        let text = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
        let opens = text.as_bytes().first().copied();
        let document = matches!(opens, Some(b'{' | b'['));
        let quoted = opens == Some(b'"');
        if !document && !quoted {
            return;
        }
        // Past the parse bound or the decode bound: unread, without parsing,
        // so both bounds also cap the work.
        if text.len() > MAX_PARSED_TEXT_BYTES || decoded > MAX_DECODE_DEPTH {
            scan.uninspected = true;
            return;
        }
        match serde_json::from_str::<Value>(text) {
            Ok(value) => self.walk_response(&value, decoded + 1, scan),
            Err(e) if quoted && e.is_eof() => match cut_string(text) {
                Some(head) => self.decode_response(&head, decoded + 1, scan),
                None => scan.uninspected = true,
            },
            Err(_) => scan.uninspected |= document,
        }
    }

    /// Gather every value under a configured tenant key, at any depth.
    ///
    /// Recursive because tenant identifiers arrive nested — a `customer_id`
    /// inside a `filter` object is the same reach as one at the top level, and
    /// a guard that inspects only the top level is evaded by wrapping the
    /// argument in an object.
    fn collect(&self, value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if self.config.arg_keys.iter().any(|k| k == key)
                        && let Some(tenant) = Self::tenant_name(child)
                    {
                        out.push(tenant);
                        continue;
                    }
                    self.collect(child, out);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.collect(item, out);
                }
            }
            _ => {}
        }
    }

    /// The tenant `value` names when it sits under the member `key`: what a
    /// document walk reads at that member, for a caller that scans the
    /// member's contents elsewhere and only needs the name match (MIK-7942).
    pub(crate) fn key_names_tenant(&self, key: &str, value: &Value) -> Option<String> {
        self.config
            .arg_keys
            .iter()
            .any(|k| k == key)
            .then(|| Self::tenant_name(value))
            .flatten()
    }

    /// Render a tenant identifier as a string, if the value is one.
    ///
    /// Strings and numbers both name tenants in practice. A structure under a
    /// tenant key is not an identifier, and is recursed into instead.
    fn tenant_name(value: &Value) -> Option<String> {
        match value {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }
}

/// The text of a JSON string cut short: `text` closed with a quote, or, when
/// the cut split an escape (`\u00`, half a surrogate pair), closed before it.
/// `None` when it still does not decode.
fn cut_string(text: &str) -> Option<String> {
    let close = |head: &str| serde_json::from_str::<String>(&format!("{head}\"")).ok();
    close(text).or_else(|| close(&text[..text.rfind('\\')?]))
}

#[cfg(test)]
#[path = "tenant_attribution_tests.rs"]
mod attribution_tests;
