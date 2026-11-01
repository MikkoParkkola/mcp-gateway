// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What reached the fixture's backends, and how they answer next: split out
//! of `account_direct_bridge.rs` to keep that file under its size ceiling.

use super::super::Answer;
use super::DirectAccountGateway;

impl DirectAccountGateway {
    /// Requests that reached the fixture's capturing transport.
    pub(crate) fn dispatched(&self) -> usize {
        self.dispatches.count()
    }

    /// The `tools/call` requests that reached the backend, each as its
    /// `Authorization` header and the identity key that selected its slot.
    pub(crate) fn tool_calls(&self) -> Vec<(Option<String>, Option<String>)> {
        self.dispatches
            .calls()
            .into_iter()
            .map(|call| (call.authorization(), call.identity_key))
            .collect()
    }

    /// Every request that reached the backend, as its method, `Authorization`
    /// header and slot identity key (#2231: listings, not only `tools/call`).
    pub(crate) fn requests(&self) -> Vec<(String, Option<String>, Option<String>)> {
        self.dispatches
            .all()
            .into_iter()
            .map(|call| (call.method.clone(), call.authorization(), call.identity_key))
            .collect()
    }

    /// The `tools/call` requests sent to `backend`.
    pub(crate) fn tool_calls_to(&self, backend: &str) -> usize {
        self.dispatches
            .calls()
            .iter()
            .filter(|call| call.server == backend)
            .count()
    }

    /// The `tools/list` requests sent to `backend`: one per fill of a slot.
    pub(crate) fn lists_to(&self, backend: &str) -> usize {
        self.dispatches
            .all()
            .iter()
            .filter(|call| call.server == backend && call.method == "tools/list")
            .count()
    }

    /// Fail the next non-`tools/list` request with the HTTP `status` the
    /// transport would report, with every account left live.
    pub(crate) fn fail_next(&self, status: u16) {
        self.dispatches.answer_with(&[status]);
    }

    /// Answer the next non-`tools/list` request with `result`.
    pub(crate) fn answer_next(&self, result: serde_json::Value) {
        self.dispatches.script(&[Answer::Result(result)]);
    }

    /// Make `backend` wait `delay` (tokio time) before it answers a
    /// `tools/list`.
    pub(crate) fn delay_lists_on(&self, backend: &str, delay: std::time::Duration) {
        self.dispatches.delay_lists_on(backend, delay);
    }

    /// Make `backend` list a tool named `name` instead of `read`
    /// (two surfaced backends need distinct tool names).
    pub(crate) fn name_list_tool_on(&self, backend: &str, name: &str) {
        self.dispatches.name_list_tool_on(backend, name);
    }

    /// Shut custody down: every later read answers a non-busy error, which
    /// the vault classifies as unavailable.
    pub(crate) async fn shut_custody_for_test(&self) {
        self.custody
            .handle
            .shutdown()
            .await
            .expect("custody shuts down");
    }

    /// Answer the next requests, `tools/list` included, with these HTTP
    /// statuses: a cold slot's first list gets a 401, for one.
    pub(crate) fn answer_lists_with(&self, statuses: &[u16]) {
        self.dispatches.script_lists();
        self.dispatches.answer_with(statuses);
    }
}
