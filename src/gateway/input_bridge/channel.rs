// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The delivery commit a channel runs once a request reached the client, and
//! the channel for transports that reach none.

use serde_json::Value;

use super::{ClientChannel, DeliveryError};

/// Work to run once, when a request is known to have reached the client: the
/// relay receipt of a bridged prompt (MIK-7887.RECEIPT.3). Owned, so it can
/// ride on a queued frame past the future that built it.
pub struct DeliveryCommit(Box<dyn FnOnce() + Send + Sync>);

impl DeliveryCommit {
    /// Wrap `work`, run by [`Self::commit`].
    pub fn new(work: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self(Box::new(work))
    }

    /// Run the work. Consumes the commit, so it runs at most once.
    pub fn commit(self) {
        (self.0)();
    }
}

impl std::fmt::Debug for DeliveryCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeliveryCommit")
    }
}

/// A [`ClientChannel`] for a transport that cannot reach a client at all.
///
/// A null object rather than an `Option<&dyn ClientChannel>` on the caller
/// context: an `Option` puts the "is there anywhere to send this" decision at
/// every read site, where one site forgetting it fails open. Here the answer
/// is the channel itself, and the only thing it can do is refuse.
///
/// Stdio's serve loop no longer carries this: since MIK-7387 it passes its own
/// channel, and a legacy stdio client is asked in-band
/// (`tests/mik_7212_mrtr7_stdio_acs.rs`). The stdio dispatchers outside the
/// serve loop — a batch and `dispatch_single` — still carry it, because no
/// reader exists there to deliver a reply, and so does every transport with no
/// session. [`DeliveryError::NoSession`] is then the literal truth, not a
/// stand-in for one. The refusal is pinned over the whole admitted method set
/// in `tests/mik_7212_mrtr7_bridge_acs.rs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoClientChannel;

#[async_trait::async_trait]
impl ClientChannel for NoClientChannel {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        Err(DeliveryError::NoSession)
    }
}
