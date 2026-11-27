// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Activity routes' rows (the list, its export, a receipt and the outcome
//! counts), kept beside the parent table so it stays under the file-size
//! ceiling. The parent's tests read them through `all_rows`.

use super::*;

pub(super) const ROWS: &[Row] = &[
    // src/gateway/ui/activity/access.rs (resolve: no credential 401, a key
    // with no Activity role 403); mod.rs (admit: no transparency log 404)
    row(
        "/ui/api/activity",
        Method::GET,
        "/ui/api/activity",
        Payload::None,
        [401, 401, 403, 404],
    ),
    row(
        "/ui/api/activity/export",
        Method::GET,
        "/ui/api/activity/export",
        Payload::None,
        [401, 401, 403, 404],
    ),
    row(
        "/ui/api/activity/{id}",
        Method::GET,
        "/ui/api/activity/1-0123456789abcdef",
        Payload::None,
        [401, 401, 403, 404],
    ),
    // counts.rs (the same Admitted extractor; no window is refused only after admission)
    row(
        "/ui/api/activity/counts",
        Method::GET,
        "/ui/api/activity/counts",
        Payload::None,
        [401, 401, 403, 404],
    ),
];
