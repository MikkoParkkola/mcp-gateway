// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one generator of a random credential: 32 random bytes, base64url
//! without padding, behind a caller's prefix (`mcpgw_` for gateway tokens and
//! API keys, `mcp_` for the auto bearer, none for a dashboard session handle).
//!
//! Shared by the gateway and `gateway init` through the library. It holds no
//! state: no `static`, lock, atomic or once-cell, which a lexical test in
//! `random_secret_tests.rs` holds. A test seam that picks a known secret
//! belongs to its caller, never here.

/// `prefix` followed by 32 random bytes as base64url without padding: 256
/// bits of entropy in 43 characters.
pub(crate) fn random_secret(prefix: &'static str) -> String {
    use rand::RngExt as _;
    let bytes: [u8; 32] = rand::rng().random();
    format!(
        "{prefix}{}",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    )
}
