// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The name clash refusal's wire data, kept beside `error.rs`.

use super::Error;

impl Error {
    /// The fixed data a clash refusal carries on the wire: the reason a
    /// client branches on, the name, the two routes it resolves to, and the
    /// covering rule when one names it. `None` for every other error.
    #[must_use]
    pub(crate) fn ambiguous_backend_data(&self) -> Option<serde_json::Value> {
        let Self::AmbiguousBackend { server, rule } = self else {
            return None;
        };
        let mut data = serde_json::json!({
            "reason": "ambiguous_backend",
            "server": server,
            "routes": ["backend", "capability"],
        });
        if let Some(rule) = rule {
            data["rule"] = serde_json::json!(rule);
        }
        Some(data)
    }
}
