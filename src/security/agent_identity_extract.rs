// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a declared agent label is read from: the `x-agent-id` header and the
//! `agent_id` query parameter.

pub(super) fn extract_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// An invalid UTF-8 value yields no label.
pub(super) fn extract_from_query(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == "agent_id").then_some(v)
        })
        .filter(|s| !s.is_empty())
        .and_then(percent_decode)
}

/// Percent-decode a query parameter value (`%XX` sequences only; `+` kept as-is).
/// Returns `None` when the decoded bytes are not valid UTF-8.
pub(super) fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
