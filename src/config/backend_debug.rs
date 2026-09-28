// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `BackendConfig`'s hand-written `Debug`: credential-bearing maps print as counts.

use super::BackendConfig;

// Manual `Debug` that redacts the credential-injection rules (CWE-532, mirrors
// PR #323). A derived `Debug` would recurse into `secrets` and print the
// injected credential material verbatim into any trace or error context; only
// the rule count is surfaced.

impl std::fmt::Debug for BackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendConfig")
            .field("description", &self.description)
            .field("enabled", &self.enabled)
            .field("transport", &self.transport)
            .field("stop_when_idle_for", &self.stop_when_idle_for)
            .field("timeout", &self.timeout)
            // `env` and `headers` values routinely carry credentials
            // (Authorization bearers, API keys, env-injected secrets). The
            // field names are neutral, so the name-based leak lint cannot see
            // them — redact to counts here, matching `secrets` below.
            .field("env", &format!("<{} vars>", self.env.len()))
            .field("headers", &format!("<{} headers>", self.headers.len()))
            .field("oauth", &self.oauth)
            .field("secrets", &format!("<{} rules>", self.secrets.len()))
            .field("passthrough", &self.passthrough)
            .field("input_schema_enforcement", &self.input_schema_enforcement)
            .field("allow_flagged_tools", &self.allow_flagged_tools)
            .field(
                "allow_cleartext_credentials",
                &self.allow_cleartext_credentials,
            )
            .field("runtime_profile", &self.runtime_profile)
            .field("identity_propagation", &self.identity_propagation)
            .field("account", &self.account)
            .finish()
    }
}
