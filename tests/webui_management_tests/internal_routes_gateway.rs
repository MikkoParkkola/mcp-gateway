// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/ui/api/gateway` row of the parent table, kept beside it so the
//! table stays under the file-size limit. The parent's tests read it through
//! `all_rows`; the rules for a row are the parent's.

use super::*;

pub(super) const ROWS: &[Row] = &[
    // src/gateway/ui/gateway_status.rs (gateway; admin-only read, like refusals)
    row(
        "/ui/api/gateway",
        Method::GET,
        "/ui/api/gateway",
        Payload::None,
        [401, 403, 403, 200],
    ),
];
