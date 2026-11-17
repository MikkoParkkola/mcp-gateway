// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Identifiers, never secrets: the one caller of `uuid::Uuid::new_v4`.
//!
//! A v4 UUID names a record, request, task or temp file. It is random, but
//! nothing may treat it as a credential: a token, key or anything a caller
//! must not guess comes from `crate::random_secret`. The direct call is
//! banned everywhere else (clippy.toml), and the callers of this module are
//! pinned by an exact-count list in `random_secret_tests.rs`, so a new one
//! arrives in a reviewed diff.

/// A random (version 4) UUID that names something.
pub(crate) fn new_v4() -> uuid::Uuid {
    // An allow, not an expect: the registry-ban lint pass runs with its own
    // config, where this entry is absent and an expect would go unfulfilled.
    #[allow(
        clippy::disallowed_methods,
        reason = "id: the one place a v4 UUID is drawn; identifiers, never secrets"
    )]
    let id: uuid::Uuid = uuid::Uuid::new_v4();
    id
}
