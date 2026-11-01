// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the fixture's backends answer and record: split out of
//! `account_resolver_fixture.rs` to keep that file under its size ceiling.

use std::time::Duration;

use super::{Answer, Dispatch, Dispatches};
use crate::protocol::{JsonRpcResponse, RequestId};

/// How one backend answers `tools/list`: after a delay, under another name.
#[derive(Clone, Debug, Default)]
pub(super) struct ListShape {
    delay: Option<Duration>,
    name: Option<String>,
}

impl Dispatches {
    /// Answer the next dispatches with these HTTP statuses (A11 cells).
    /// Run `hook` once, as the next `tools/call` is answered.
    pub(in crate::gateway::meta_mcp) fn on_next_call(&self, hook: impl FnOnce() + Send + 'static) {
        *self.on_call.lock() = Some(Box::new(hook));
    }

    /// Make `server` wait `delay` (tokio time) before it answers a
    /// `tools/list`: a slow backend against a listing's deadline.
    pub(in crate::gateway::meta_mcp) fn delay_lists_on(&self, server: &str, delay: Duration) {
        self.list_shapes
            .lock()
            .entry(server.to_string())
            .or_default()
            .delay = Some(delay);
    }

    /// Make `server` list `name` instead of `read`: two backends surfacing
    /// one name would collide, and the second is skipped.
    pub(in crate::gateway::meta_mcp) fn name_list_tool_on(&self, server: &str, name: &str) {
        self.list_shapes
            .lock()
            .entry(server.to_string())
            .or_default()
            .name = Some(name.to_string());
    }

    /// How long `server` waits before it answers a `tools/list`.
    pub(super) fn list_delay(&self, server: &str) -> Option<Duration> {
        self.list_shapes.lock().get(server)?.delay
    }

    /// `server`'s `tools/list` answer when it lists another tool than `read`.
    pub(super) fn renamed_list(&self, server: &str) -> Option<JsonRpcResponse> {
        let name = self.list_shapes.lock().get(server)?.name.clone()?;
        Some(JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({"tools": [{"name": name, "inputSchema": {"type": "object"}}]}),
        ))
    }

    /// Let the script answer `tools/list` as well as `tools/call`.
    pub(in crate::gateway::meta_mcp) fn script_lists(&self) {
        self.lists_scripted
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(in crate::gateway::meta_mcp) fn answer_with(&self, statuses: &[u16]) {
        let answers = statuses.iter().copied().map(Answer::Status);
        self.answers.lock().extend(answers);
    }

    /// Answer the next dispatches with this script (A11 cells).
    pub(in crate::gateway::meta_mcp) fn script(&self, answers: &[Answer]) {
        self.answers.lock().extend(answers.iter().cloned());
    }

    pub(in crate::gateway::meta_mcp) fn count(&self) -> usize {
        self.calls.lock().len()
    }

    /// Every dispatch, whatever its method (#2231's listings).
    pub(in crate::gateway::meta_mcp) fn all(&self) -> Vec<Dispatch> {
        self.calls.lock().clone()
    }

    /// The `tools/call` dispatches, in order. `count()` still counts every
    /// method, so a refusal proved by `count() == 0` also rules out the
    /// gateway's own cold-slot `tools/list` (F13).
    pub(in crate::gateway::meta_mcp) fn calls(&self) -> Vec<Dispatch> {
        self.calls
            .lock()
            .iter()
            .filter(|d| d.method == "tools/call")
            .cloned()
            .collect()
    }

    /// The single dispatch expected by a positive case; panics loudly if the
    /// count is anything else, so "reached transport" is never assumed.
    pub(in crate::gateway::meta_mcp) fn only(&self) -> Dispatch {
        let calls = self.calls();
        assert_eq!(calls.len(), 1, "expected exactly one backend call");
        calls.into_iter().next().expect("checked above")
    }
}
