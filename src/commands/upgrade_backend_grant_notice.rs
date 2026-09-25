// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The 4.0.0 notice item for BACKENDGRANT.1 (UPGRADING-4.0 item 32).
//!
//! Its own file only because `upgrade.rs` is held at its line baseline.

/// An empty or omitted `backends` list now reaches no backend.
pub(super) const ITEM: &str = "An API key or key-server policy rule with no `backends` (omitted or empty) now reaches \
NO backend; 3.x treated it as all. Add `backends: [\"*\"]` to keep that, or list the \
backends it needs. The gateway warns once per such key at startup, and the key server \
refuses to issue a token for such a rule (403 `no_backends_granted`).";
