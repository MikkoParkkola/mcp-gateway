// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Opening a session's channel: the first one, and the era's listen call.

use std::sync::{Arc, Weak};
use std::time::Instant;

use tracing::debug;

use super::{OPEN_LIMIT, Outcome, State, failed, requested, watched_by};
use crate::backend::listen::ListenTarget;
use crate::events::upstream_listener::Shared;
use crate::transport::upstream_tap::{FrameStream, Refused, Requested, UpstreamListen, Watched};

/// Open the session's first channel; `Err` carries how the session ends.
pub(super) async fn open_first(
    shared: &Arc<Shared>,
    state: &mut State<'_>,
    target: &ListenTarget,
    modern: bool,
) -> Result<(), Outcome> {
    let first = requested(shared);
    let opened = tokio::select! {
        () = shared.stop.cancelled() => return Err(Outcome::Stopped),
        opened = tokio::time::timeout(OPEN_LIMIT, open(&target.handle, modern, first.clone(), watched_by(shared))) => {
            opened.unwrap_or(Err(Refused::Expired))
        }
    };
    match opened {
        Ok(stream) => {
            state.opened = Instant::now();
            state.current = Some((stream, first));
            Ok(())
        }
        Err(Refused::Unsupported) => Err(Outcome::Unsupported),
        Err(Refused::Expired) => Err(failed()),
        Err(Refused::Failed(error)) => {
            debug!(backend = %shared.name, %error, "upstream listener: stream refused");
            Err(failed())
        }
    }
}

/// Open the era's channel; the upgraded `Arc` lives only for this call.
pub(super) async fn open(
    handle: &Weak<dyn UpstreamListen>,
    modern: bool,
    requested: Requested,
    watched: Watched,
) -> Result<FrameStream, Refused> {
    let Some(transport) = handle.upgrade() else {
        return Err(Refused::Failed(crate::Error::Transport(
            "transport gone".to_owned(),
        )));
    };
    if modern {
        transport.listen(requested).await
    } else {
        transport.unsolicited(watched).await
    }
}
