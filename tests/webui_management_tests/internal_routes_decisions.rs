// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/ui/api/decisions` row of the parent table, kept beside it so the
//! table stays under the file-size limit. The parent's tests read it through
//! `all_rows`; the rules for a row are the parent's.

use super::*;

pub(super) const ROWS: &[Row] = &[
    // src/gateway/ui/decisions.rs (list_decisions; this fixture never starts
    // the decision set, so the admin's answer is the 503 naming no source)
    row(
        "/ui/api/decisions",
        Method::GET,
        "/ui/api/decisions",
        Payload::None,
        [401, 403, 403, 503],
    ),
];
