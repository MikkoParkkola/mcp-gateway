// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-message credential headers, merged the same way for requests and
//! notifications (#2292).

use reqwest::header;

/// Merge per-request credential headers (e.g. `Authorization: Bearer
/// <assertion>`) over the built set: each overrides any static header of the
/// same name for this message. One helper for requests and notifications, so
/// both carry a caller's credential by the same rule (#2292).
///
/// A value that does not parse is not sent, and neither is the static header
/// of that name: falling back to the static credential in the caller's place
/// is the defect #2292 closes. A name that does not parse names no static
/// header, so there is nothing to withhold.
pub(super) fn merge_extra_headers(
    headers: &mut header::HeaderMap,
    extra_headers: &[(String, String)],
) {
    for (k, v) in extra_headers {
        let Ok(name) = k.parse::<header::HeaderName>() else {
            continue;
        };
        match v.parse::<header::HeaderValue>() {
            Ok(value) => {
                headers.insert(name, value);
            }
            Err(_) => {
                headers.remove(name);
            }
        }
    }
}
