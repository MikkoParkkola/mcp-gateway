//! Trace ID generation and task-local propagation.
//!
//! A `TraceId` is a UUID v4 string prefixed with `"gw-"` that is minted
//! once per `gateway_invoke` call and:
//!
//! - Returned in the response JSON as `"trace_id"`.
//! - Propagated to all outbound HTTP requests as the `X-Trace-Id` header.
//! - Attached to all [`tracing`] spans for the duration of the call.
//!
//! # Task-local propagation
//!
//! The current trace ID is stored in [`TRACE_ID`], a `tokio::task_local!`
//! slot.  Call [`with_trace_id`] to scope a future to a particular ID, and
//! [`current`] to read it from anywhere in the call stack.
//!
//! # Example
//!
//! ```rust,ignore
//! use mcp_gateway::gateway::trace;
//!
//! let id = trace::generate();
//! let result = trace::with_trace_id(id.clone(), async {
//!     assert_eq!(trace::current(), Some(id));
//!     // ... work ...
//! }).await;
//! ```

use uuid::Uuid;

tokio::task_local! {
    /// Task-local storage for the current request trace ID.
    ///
    /// Set by [`with_trace_id`]; read by [`current`].
    pub static TRACE_ID: String;
}

/// Generate a new gateway trace ID: `"gw-<uuid-v4>"`.
///
/// # Example
///
/// ```rust,ignore
/// let id = mcp_gateway::gateway::trace::generate();
/// assert!(id.starts_with("gw-"));
/// ```
#[must_use]
pub fn generate() -> String {
    format!("gw-{}", Uuid::new_v4())
}

/// Return the trace ID set for the current task, or `None` if none is set.
///
/// This is a zero-cost read when called from within a [`with_trace_id`] scope.
#[must_use]
pub fn current() -> Option<String> {
    TRACE_ID.try_with(Clone::clone).ok()
}

/// Run `future` with `trace_id` installed as the task-local trace ID.
///
/// Any call to [`current`] from within `future` (or any future it spawns
/// via `.await`) will return `Some(trace_id.clone())`.
pub async fn with_trace_id<F, T>(trace_id: String, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    TRACE_ID.scope(trace_id, future).await
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── generate ──────────────────────────────────────────────────────────

    #[test]
    fn generate_returns_gw_prefixed_string() {
        let id = generate();
        assert!(id.starts_with("gw-"), "trace ID must start with 'gw-': {id}");
    }

    #[test]
    fn generate_embeds_valid_uuid_v4() {
        let id = generate();
        let uuid_part = id.strip_prefix("gw-").expect("prefix must be 'gw-'");
        let uuid = Uuid::parse_str(uuid_part).expect("UUID part must parse");
        assert_eq!(uuid.get_version_num(), 4, "must be UUID v4");
    }

    #[test]
    fn generate_produces_unique_ids_on_each_call() {
        let id1 = generate();
        let id2 = generate();
        assert_ne!(id1, id2, "each call must produce a unique ID");
    }

    // ── current / with_trace_id ───────────────────────────────────────────

    #[tokio::test]
    async fn current_returns_none_outside_scope() {
        // GIVEN: no with_trace_id scope
        // WHEN: current() is called
        // THEN: returns None
        assert_eq!(current(), None);
    }

    #[tokio::test]
    async fn current_returns_id_inside_scope() {
        // GIVEN: a known trace ID
        let id = generate();
        // WHEN: inside a with_trace_id scope
        let found = with_trace_id(id.clone(), async { current() }).await;
        // THEN: current() returns the installed ID
        assert_eq!(found, Some(id));
    }

    #[tokio::test]
    async fn nested_scope_shadows_outer_scope() {
        // GIVEN: two distinct trace IDs
        let outer = "gw-outer".to_string();
        let inner = "gw-inner".to_string();
        // WHEN: nested with_trace_id scopes
        let result = with_trace_id(outer.clone(), async {
            let outer_seen = current();
            let inner_seen = with_trace_id(inner.clone(), async { current() }).await;
            (outer_seen, inner_seen)
        })
        .await;
        // THEN: each scope sees its own ID
        assert_eq!(result.0, Some(outer));
        assert_eq!(result.1, Some(inner));
    }

    #[tokio::test]
    async fn current_returns_none_after_scope_exits() {
        // GIVEN: a scope that completes
        let id = generate();
        with_trace_id(id, async {}).await;
        // THEN: after the scope, current() is None again
        assert_eq!(current(), None);
    }
}
