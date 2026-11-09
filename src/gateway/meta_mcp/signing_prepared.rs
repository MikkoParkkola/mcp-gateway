// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The target signing prepared and the allow its policy check noted: one box
//! on the invocation context, which rides a stdio delivery's boxed dispatch
//! futures by value under a fixed allocation budget. A child of `signing`, so
//! it reaches the context's private fields without widening any of them.

use super::SigningInvocationContext;

/// A target signing prepared, and the allow its policy check noted, taken
/// once by the dispatch that skips its own check, so no later call or request
/// inherits it.
pub(super) struct Prepared {
    server: String,
    tool: String,
    allow: std::sync::Mutex<Option<crate::security::decision_record::Allow>>,
}

impl Prepared {
    pub(super) const fn new(server: String, tool: String) -> Self {
        Self {
            server,
            tool,
            allow: std::sync::Mutex::new(None),
        }
    }
}

impl SigningInvocationContext {
    /// Keep `allow` as the prepared target's signing-time allow.
    pub(crate) fn store_prepared_allow(
        &self,
        allow: Option<crate::security::decision_record::Allow>,
    ) {
        if let Some(prepared) = &self.prepared_target
            && let Ok(mut held) = prepared.allow.lock()
        {
            *held = allow;
        }
    }

    /// The prepared target's signing-time allow, taken: a second read finds
    /// nothing.
    pub(crate) fn take_prepared_allow(&self) -> Option<crate::security::decision_record::Allow> {
        self.prepared_target.as_ref()?.allow.lock().ok()?.take()
    }

    pub(crate) fn prepared_for(&self, server: &str, tool: &str) -> bool {
        self.prepared_target
            .as_ref()
            .is_some_and(|prepared| prepared.server == server && prepared.tool == tool)
    }
}
