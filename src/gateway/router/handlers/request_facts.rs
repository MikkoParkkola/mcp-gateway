// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request facts for the MCP handlers.

use super::{AuthenticatedClient, CatalogueCaller, CertIdentity, HeaderMap, Value};

/// The caller's `Mcp-Session-Id`, one rule for every session route: missing,
/// non-UTF-8, empty and whitespace-only values are all "no session" (F9).
pub(super) fn session_id_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .filter(|id| !id.trim().is_empty())
}

/// The extension a task-augmented request must declare.
pub(in crate::gateway::router) const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Whether this request reaches the tasks extension AT ALL.
///
/// Deliberately not a method-family test: `subscriptions/listen` is not a
/// `tasks/*` method and reaches the extension the moment it names a task, so a
/// gate keyed on the prefix refuses the wrong set.
///
/// NOTHING TIES THIS LIST TO THE DISPATCHER. A method added below without an arm
/// here reaches the task store unguarded, and no test goes red: the arms and the
/// dispatcher agree today only because a person kept them in step. The residual
/// is recorded here rather than in a review document because here is where the
/// next method gets added -- ADD THE ARM IN THE SAME EDIT.
pub(super) fn reaches_tasks_extension(method: &str, params: Option<&Value>) -> bool {
    match method {
        "tools/call" => params.is_some_and(|p| p.get("task").is_some()),
        "tasks/get" | "tasks/update" | "tasks/cancel" => true,
        "subscriptions/listen" => {
            params.is_some_and(crate::protocol::subscriptions::names_task_ids)
        }
        _ => false,
    }
}

/// The task ids a `subscriptions/listen` names, if it names any, in either
/// placement.
pub(super) fn listened_task_ids(params: Option<&Value>) -> Vec<String> {
    params
        .map(crate::protocol::subscriptions::named_task_ids)
        .unwrap_or_default()
}

/// The caller a `prompts/get` or `resources/read` runs for, keyed as the same
/// caller's `tools/call` is: the key the grant, certificate or API key names,
/// else the unkeyed session bucket.
pub(super) fn catalogue_caller(
    grant_subject: Option<&crate::identity_grants::GrantSubject>,
    cert_identity: Option<&CertIdentity>,
    client: Option<&AuthenticatedClient>,
    session_id: &str,
) -> CatalogueCaller {
    let key = super::super::identity::caller_key(grant_subject, cert_identity, client);
    let keyed = !key.is_empty();
    CatalogueCaller {
        key: if keyed { key } else { session_id.to_owned() },
        keyed,
        name: client.map_or_else(|| "anonymous".to_owned(), |c| c.name.clone()),
        session: session_id.to_owned(),
    }
}
