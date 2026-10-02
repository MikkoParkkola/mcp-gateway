// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Pieces `mcp-gateway add` needs to write a whole backend (MIK-7787).

use super::OAuthConfig;

/// The stanza `oauth: {}` deserialises to: enabled, no fixed client, so the
/// backend OAuth client follows the server's metadata and registers itself.
impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: super::default_true(),
            scopes: Vec::new(),
            client_id: None,
            client_secret: None,
            callback_host: None,
            callback_port: None,
            callback_path: None,
            token_refresh_buffer_secs: super::default_token_refresh_buffer(),
            shared_account: false,
        }
    }
}
