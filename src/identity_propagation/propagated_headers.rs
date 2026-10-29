// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The caller credential the public propagation calls hand out (MIK-9070 A).

use std::ops::Deref;

use zeroize::Zeroizing;

/// A caller's minted credential headers, as
/// [`MetaMcp::resolve_propagation_credential`] and
/// [`MetaMcp::resolve_propagation_headers`] return them.
///
/// The value is wiped when it is dropped, and its `Debug` shows header names
/// only, never a value. Read the headers by borrowing them, for example
/// `for (name, value) in headers.iter()`. There is no way to take the inner
/// list out: a caller that needs a plain list copies it with `.to_vec()`, and
/// that copy is the caller's to wipe. Formatting the borrowed slice
/// (`{:?}` on `&*headers`) prints the values; only this type's own `Debug`
/// redacts them.
///
/// [`MetaMcp::resolve_propagation_credential`]: crate::gateway::meta_mcp::MetaMcp::resolve_propagation_credential
/// [`MetaMcp::resolve_propagation_headers`]: crate::gateway::meta_mcp::MetaMcp::resolve_propagation_headers
#[derive(Default)]
pub struct PropagatedHeaders(Zeroizing<Vec<(String, String)>>);

impl PropagatedHeaders {
    /// Takes ownership of headers already held in the zeroizing holder; no
    /// copy is made.
    pub(crate) fn new(headers: Zeroizing<Vec<(String, String)>>) -> Self {
        Self(headers)
    }
}

impl Deref for PropagatedHeaders {
    type Target = [(String, String)];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Header names only: each value is a caller's credential.
impl std::fmt::Debug for PropagatedHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| (name.as_str(), "<redacted>")))
            .finish()
    }
}
