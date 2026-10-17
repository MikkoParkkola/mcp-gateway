// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B router choke point (design §2.5): the router's caller
//! reads of the backend registry go through [`backend_for`], so a name
//! absent for the caller's grant is absent here too. T2c pins every
//! reference to it, so a new reader before S4 is a reviewed diff.

use std::sync::Arc;

use super::AppState;
use crate::backend::Backend;
use crate::gateway::authz::BackendGrant;
use crate::gateway::meta_mcp::scoped_backends::ScopedBackends;

/// `name`'s backend as `grant` sees it: `None` when the name is absent for
/// the grant, whether out of scope or unregistered.
pub(super) fn backend_for(
    state: &AppState,
    grant: BackendGrant<'_>,
    name: &str,
) -> Option<Arc<Backend>> {
    view_for(state, grant).scoped_get(name)
}

/// The view [`backend_for`] reads through: the stored registry with this
/// gateway's capability provider, the view the Meta-MCP layer builds.
pub(super) fn view_for<'a>(state: &'a AppState, grant: BackendGrant<'a>) -> ScopedBackends<'a> {
    state.meta_mcp.scoped(grant)
}
