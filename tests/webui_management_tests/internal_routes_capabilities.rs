// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `/ui/api/capabilities` rows of the parent table, kept beside it so
//! the table stays under the file-size limit. The parent's tests read them
//! through `all_rows`; the rules for a row are the parent's.

use super::*;

pub(super) const ROWS: &[Row] = &[
    // src/gateway/ui/capabilities.rs:217 (list_capabilities)
    row(
        "/ui/api/capabilities",
        Method::GET,
        "/ui/api/capabilities",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:397 (create_capability; `{}` returns the template)
    row(
        "/ui/api/capabilities",
        Method::POST,
        "/ui/api/capabilities",
        Payload::Json("{}"),
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:319 (put_capability)
    // The admin reaches the handler, which refuses a save without If-Match.
    row(
        "/ui/api/capabilities/{name}",
        Method::PUT,
        "/ui/api/capabilities/test_cap",
        Payload::Yaml,
        [401, 403, 403, 428],
    ),
    // src/gateway/ui/capabilities.rs (validate_capability_route; writes nothing)
    row(
        "/ui/api/capabilities/{name}/validate",
        Method::POST,
        "/ui/api/capabilities/test_cap/validate",
        Payload::Yaml,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:278 (get_capability)
    row(
        "/ui/api/capabilities/{name}",
        Method::GET,
        "/ui/api/capabilities/test_cap",
        Payload::None,
        [401, 403, 403, 200],
    ),
    // src/gateway/ui/capabilities.rs:486 (delete_capability)
    // The admin reaches the handler, which refuses a delete without If-Match.
    row(
        "/ui/api/capabilities/{name}",
        Method::DELETE,
        "/ui/api/capabilities/test_cap",
        Payload::None,
        [401, 403, 403, 428],
    ),
];
