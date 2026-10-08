// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hand-written `Debug` for `BackendConfig` and `TransportConfig`:
//! credential-bearing maps print as counts, and URLs and commands print as
//! diagnostics show them, without userinfo, query or arguments.

use super::{BackendConfig, TransportConfig};
use crate::security::{diagnostic_url, summarize_stdio_command};

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
            .field("max_frame_bytes", &self.max_frame_bytes)
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
            .field("signature_chain", &self.signature_chain)
            .field("chain_origins", &self.chain_origins)
            .field("chain_signer", &self.chain_signer)
            .finish()
    }
}

// A URL can carry userinfo (`https://user:pass@host`) and a query with a key,
// and a stdio command can carry a token argument. A derived `Debug` would put
// them into every log line and error chain that formats a backend.
impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio {
                command,
                cwd,
                protocol_version,
            } => f
                .debug_struct("Stdio")
                .field("command", &summarize_stdio_command(command))
                .field("cwd", cwd)
                .field("protocol_version", protocol_version)
                .finish(),
            Self::Http {
                http_url,
                streamable_http,
                protocol_version,
            } => f
                .debug_struct("Http")
                .field("http_url", &diagnostic_url(http_url))
                .field("streamable_http", streamable_http)
                .field("protocol_version", protocol_version)
                .finish(),
            Self::WebSocket {
                ws_url,
                protocol_version,
            } => f
                .debug_struct("WebSocket")
                .field("ws_url", &diagnostic_url(ws_url))
                .field("protocol_version", protocol_version)
                .finish(),
            #[cfg(feature = "a2a")]
            Self::A2a {
                a2a_url,
                a2a_agent_card_path,
            } => f
                .debug_struct("A2a")
                .field("a2a_url", &diagnostic_url(a2a_url))
                .field("a2a_agent_card_path", a2a_agent_card_path)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_url_or_command_credentials() {
        let userinfo = ["operator", "debug-secret"].join(":");
        let transports = [
            TransportConfig::Stdio {
                command: "server --token debug-secret".into(),
                cwd: None,
                protocol_version: None,
            },
            TransportConfig::Stdio {
                command: "server 'debug-secret".into(),
                cwd: None,
                protocol_version: None,
            },
            TransportConfig::Http {
                http_url: format!("https://{userinfo}@api.invalid/mcp?key=debug-secret"),
                streamable_http: None,
                protocol_version: None,
            },
            TransportConfig::WebSocket {
                ws_url: format!("wss://{userinfo}@ws.invalid/mcp"),
                protocol_version: None,
            },
            #[cfg(feature = "a2a")]
            TransportConfig::A2a {
                a2a_url: format!("https://{userinfo}@agent.invalid"),
                a2a_agent_card_path: None,
            },
        ];
        for transport in transports {
            let printed = format!("{transport:?}");
            assert!(!printed.contains("debug-secret"), "{printed}");
            let backend = BackendConfig {
                transport,
                ..BackendConfig::default()
            };
            let printed = format!("{backend:?}");
            assert!(!printed.contains("debug-secret"), "{printed}");
        }
    }
}
