// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a call is sent with: the secret rules and the header mirror, split
//! out of the request path in `ops.rs`.

use serde_json::Value;

use crate::Result;
use crate::backend::Backend;

impl Backend {
    /// The params and headers a call is sent with: this backend's `secrets:`
    /// rules applied, and the arguments its tool's schema declares mirrored.
    ///
    /// The keys the rules own are dropped before the mirror reads the
    /// arguments, and the values are added after it, so neither a caller's
    /// value for such a key nor the secret is mirrored into a header.
    /// Synchronous, so nothing it builds is held in the send's future.
    ///
    /// SEP-2243: the mirror sits here, not in each
    /// dispatcher, because every tools/call — the MCP provider, meta-MCP
    /// invoke, the router's direct backend route — funnels through
    /// [`Self::request_attempted`], so a per-caller mirror would leave the
    /// siblings unmirrored.
    pub(super) fn outbound(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<crate::backend::secret_send::Outbound> {
        let secrets = self.prepare_secrets(method, params)?;
        let headers =
            self.param_header_set(method, secrets.params.as_ref(), extra_headers, identity_key);
        Ok(secrets.apply(headers))
    }
}
