// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a backend may send each protocol member it shares with the gateway.
//!
//! The member table ([`super::reserved_members::MEMBERS`]) lets a backend
//! carry the protocol members `taskId`, `requestState`, `cacheScope`, `ttlMs`
//! and `resultType`, because the protocol has a backend send them. It has a
//! backend send each only on certain answers, though, and on any other a
//! member is a directive the backend has no standing to give: a cache hint on
//! an interim answer, a task handle on a call that asked for none. This table
//! says where each one belongs, from the MCP 2026-07-28 schema and the tasks
//! extension, and the ingress strip removes it everywhere else.
//!
//! `resultType` is on every result (the base `Result` requires it), so it has
//! no row: [`PROTOCOL_UNSCOPED`] records that on purpose.

use serde_json::Value;

use super::cacheable::{CACHEABLE_METHODS, is_cacheable_answer, result_type_of};

/// Whether the send this answer answers declared the tasks extension
/// upstream. Only a send that did may be answered with a task handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Declared {
    /// The send declared `io.modelcontextprotocol/tasks`.
    Tasks,
    /// It declared nothing: no task handle may answer it.
    Nothing,
}

/// The methods a member may arrive on.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Method {
    /// One method by name.
    One(&'static str),
    /// Every method whose result is a `CacheableResult` ([`CACHEABLE_METHODS`]).
    Cacheable,
}

/// The answer shape a member may arrive in.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Shape {
    /// A final answer that is not an error: `resultType` absent or `complete`
    /// (absent means complete), and no `isError: true`.
    Final,
    /// An answer whose `resultType` is this value.
    ResultType(&'static str),
    /// A task handle (`resultType: "task"`) to a send that declared tasks.
    DeclaredTask,
    /// Any answer of the method.
    Any,
}

/// One place a member may arrive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Allowed {
    pub(crate) method: Method,
    pub(crate) shape: Shape,
}

/// A scoped member and every place it may arrive.
#[derive(Debug)]
pub(crate) struct Scope {
    /// The member, a top-level key of a result.
    pub(crate) member: &'static str,
    pub(crate) allowed: &'static [Allowed],
    /// The specification text that places it there.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "a citation for the reader; tests pin it")
    )]
    pub(crate) spec: &'static str,
}

const fn at(method: Method, shape: Shape) -> Allowed {
    Allowed { method, shape }
}

/// Every scoped protocol member.
pub(crate) const SCOPED: &[Scope] = &[
    Scope {
        member: "requestState",
        allowed: &[
            at(
                Method::One("tools/call"),
                Shape::ResultType("input_required"),
            ),
            at(
                Method::One("resources/read"),
                Shape::ResultType("input_required"),
            ),
            at(
                Method::One("prompts/get"),
                Shape::ResultType("input_required"),
            ),
        ],
        spec: "MCP 2026-07-28 schema: InputRequiredResult; CallToolResultResponse, \
               ReadResourceResultResponse and GetPromptResultResponse are \
               `InputRequiredResult | ...`",
    },
    Scope {
        member: "cacheScope",
        allowed: &[at(Method::Cacheable, Shape::Final)],
        spec: "MCP 2026-07-28 schema: CacheableResult (ListToolsResult, ListPromptsResult, \
               ListResourcesResult, ListResourceTemplatesResult, ReadResourceResult, \
               DiscoverResult)",
    },
    Scope {
        member: "ttlMs",
        allowed: &[
            at(Method::Cacheable, Shape::Final),
            at(Method::One("tools/call"), Shape::DeclaredTask),
            at(Method::One("tasks/get"), Shape::Any),
        ],
        spec: "MCP 2026-07-28 schema: CacheableResult; tasks extension (SEP-2663): Task.ttlMs \
               on CreateTaskResult and GetTaskResult",
    },
    Scope {
        member: "taskId",
        allowed: &[
            at(Method::One("tools/call"), Shape::DeclaredTask),
            at(Method::One("tasks/get"), Shape::Any),
        ],
        spec: "tasks extension (SEP-2663): CreateTaskResult answers tools/call, the only \
               supported method, to a client that declared the extension; GetTaskResult",
    },
];

/// Protocol members a backend may send on every result.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "a record for the reader; tests pin it")
)]
pub(crate) const PROTOCOL_UNSCOPED: &[&str] = &["resultType"];

/// Whether `method` is one of `allowed`'s methods.
fn method_matches(allowed: Method, method: &str) -> bool {
    match allowed {
        Method::One(name) => name == method,
        Method::Cacheable => CACHEABLE_METHODS.contains(&method),
    }
}

/// Whether `result` has `shape`, answering a send that declared `declared`.
fn shape_matches(shape: Shape, result: &Value, declared: Declared) -> bool {
    match shape {
        Shape::Final => is_cacheable_answer(result),
        Shape::ResultType(value) => result_type_of(result) == value,
        Shape::DeclaredTask => result_type_of(result) == "task" && declared == Declared::Tasks,
        Shape::Any => true,
    }
}

/// The scoped members `result` carries that `method`'s answer may not.
pub(crate) fn misplaced(method: &str, result: &Value, declared: Declared) -> Vec<&'static str> {
    SCOPED
        .iter()
        .filter(|scope| result.get(scope.member).is_some())
        .filter(|scope| {
            !scope.allowed.iter().any(|allowed| {
                method_matches(allowed.method, method)
                    && shape_matches(allowed.shape, result, declared)
            })
        })
        .map(|scope| scope.member)
        .collect()
}

/// Every scoped member: what a task envelope's `result` slot loses whatever
/// it claims, since that slot is the original request's final result.
pub(crate) fn every_scoped() -> impl Iterator<Item = &'static str> {
    SCOPED.iter().map(|scope| scope.member)
}

/// A task handle answering a send that declared no tasks: the backend started
/// work the gateway asked for no handle to, and the answer carries none it
/// could poll. `Some` names the refusal.
pub(crate) fn undeclared_task(method: &str, result: &Value, declared: Declared) -> Option<String> {
    (declared == Declared::Nothing && result_type_of(result) == "task").then(|| {
        format!(
            "the backend answered `{method}` with a task handle, but this call did not \
             declare the tasks extension"
        )
    })
}

#[cfg(test)]
#[path = "member_scope_tests.rs"]
mod tests;
