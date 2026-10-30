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
    // src/gateway/ui/backends/signin.rs (start_sign_in; an admin bearer has no
    // dashboard session, so the admin cell is the session refusal)
    row(
        "/ui/api/backends/{name}/signin",
        Method::POST,
        "/ui/api/backends/docs/signin",
        Payload::Json("{}"),
        [401, 0, 403, 0],
    ),
    // signin.rs (confirm_sign_in; same session rule as the start)
    row(
        "/ui/api/backends/{name}/signin/confirm",
        Method::POST,
        "/ui/api/backends/docs/signin/confirm",
        Payload::Json(r#"{"attempt_id":"a","decision":"cancel"}"#),
        [401, 0, 403, 0],
    ),
];
