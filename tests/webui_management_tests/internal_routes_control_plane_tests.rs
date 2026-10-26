// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/ui/api/control-plane` rows of the parent table, kept beside it so
//! the table stays under the file-size limit. The parent's tests read both
//! through `all_rows`; the rules for a row are the parent's.

use super::*;

const GRANT: &str = r#"{"grant":{"grant_id":"grant-1","subject_id":"user-1","server_id":"srv-1","status":"approved"},"reason":"MIK-1","rollback":{"summary":"revert","step":"restore prior grant"}}"#;
const POLICY: &str = r#"{"policy":{"policy_id":"pol-1","name":"p","enforced":false},"reason":"MIK-1","rollback":{"summary":"revert","step":"restore prior grant"}}"#;
const DECISION: &str = r#"{"target_kind":"grant","target_id":"grant-1","decision":"approve","reason":"MIK-1","rollback":{"summary":"revert","step":"restore prior grant"}}"#;

pub(super) const ROWS: &[Row] = &[
    // src/gateway/ui/control_plane.rs:72 (require_authenticated layer), :116 (snapshot)
    row(
        "/ui/api/control-plane",
        Method::GET,
        "/ui/api/control-plane",
        Payload::None,
        [401, 403, 200, 200],
    ),
    // control_plane.rs:72, mutations.rs:53 (mutate_grant), :310 (store), :330 (RBAC), :342 (409)
    row_cfg(
        "/ui/api/control-plane/grants",
        Method::POST,
        "/ui/api/control-plane/grants",
        Payload::Json(GRANT),
        [401, 403, 503, 503],
        [401, 403, 409],
    ),
    // control_plane.rs:72, mutations.rs:79 (mutate_policy), :310, :330, :342
    row_cfg(
        "/ui/api/control-plane/policies",
        Method::POST,
        "/ui/api/control-plane/policies",
        Payload::Json(POLICY),
        [401, 403, 503, 503],
        [401, 403, 409],
    ),
    // control_plane.rs:72, mutations.rs:131 (resolve_decision), :194 (store), :245 (RBAC), :258 (409)
    row_cfg(
        "/ui/api/control-plane/decisions",
        Method::POST,
        "/ui/api/control-plane/decisions",
        Payload::Json(DECISION),
        [401, 403, 503, 503],
        [401, 403, 409],
    ),
    // control_plane.rs:72, :89 (export_status_handler: 404 `configured: false` when unset)
    row_cfg(
        "/ui/api/control-plane/export-status",
        Method::GET,
        "/ui/api/control-plane/export-status",
        Payload::None,
        [401, 403, 404, 404],
        [401, 200, 200],
    ),
];
