// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How an update's transport merges with the stored one.

use crate::config::TransportConfig;

/// `new` of `stored`'s kind changes only the command or address; the other
/// members (folder, protocol version, HTTP mode, card path) stay as written.
/// An HTTP address on an A2A server is that kind too (a URL never parses as
/// A2A). Another kind replaces the transport whole.
pub(super) fn merged_transport(stored: TransportConfig, new: TransportConfig) -> TransportConfig {
    use TransportConfig as T;
    match (stored, new) {
        (
            T::Stdio {
                cwd,
                protocol_version,
                ..
            },
            T::Stdio { command, .. },
        ) => T::Stdio {
            command,
            cwd,
            protocol_version,
        },
        (
            T::Http {
                streamable_http,
                protocol_version,
                ..
            },
            T::Http { http_url, .. },
        ) => T::Http {
            http_url,
            streamable_http,
            protocol_version,
        },
        (
            T::WebSocket {
                protocol_version, ..
            },
            T::WebSocket { ws_url, .. },
        ) => T::WebSocket {
            ws_url,
            protocol_version,
        },
        #[cfg(feature = "a2a")]
        (
            T::A2a {
                a2a_agent_card_path,
                ..
            },
            T::Http {
                http_url: a2a_url, ..
            }
            | T::A2a { a2a_url, .. },
        ) => T::A2a {
            a2a_url,
            a2a_agent_card_path,
        },
        (_, new) => new,
    }
}
