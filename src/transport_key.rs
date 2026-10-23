// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The transport key a backend `url` stands for (MIK-8667).
//!
//! Compiled into both the library and the binary (`mod transport_key;` in
//! each), so the config loader, the strict-key check and the CLI's rewrite
//! read one table and no item becomes public.

/// The transport key a backend `url` stands for, chosen by its scheme, or
/// `None` for a scheme no transport reads.
pub(crate) fn transport_key_for(url: &str) -> Option<&'static str> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("http_url")
    } else if lower.starts_with("ws://") || lower.starts_with("wss://") {
        Some("ws_url")
    } else {
        None
    }
}
