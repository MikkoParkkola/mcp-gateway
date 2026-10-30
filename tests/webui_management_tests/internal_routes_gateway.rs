// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows of the parent table kept beside it (the gateway status read, the web
//! UI tool call) so the table stays under the file-size limit. The parent's tests read it through
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
    // src/gateway/ui/tool_call.rs (call; admin-only, and an empty body is
    // refused before anything runs)
    row(
        "/ui/api/tools/call",
        Method::POST,
        "/ui/api/tools/call",
        Payload::None,
        [401, 403, 403, 400],
    ),
];
