// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/ui/api/registry` rows of the parent table, kept beside it so the
//! table stays under the file-size limit. The parent's tests read them
//! through `all_rows`; the rules for a row are the parent's.

use super::*;

pub(super) const ROWS: &[Row] = &[
    // backends.rs:510 (list_registry)
    row(
        "/ui/api/registry",
        Method::GET,
        "/ui/api/registry",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // backends.rs:527 (search_registry)
    row(
        "/ui/api/registry/search",
        Method::GET,
        "/ui/api/registry/search?q=tavily",
        Payload::None,
        [401, 403, 403, 200],
    ),
];
