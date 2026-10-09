// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How a session routes what its streams deliver: acknowledgements and
//! notices in, coalesced events out through the hub (design §3, §8).

use std::sync::Weak;
use std::time::Instant;

use chrono::Utc;
use serde_json::json;
use tracing::warn;

use super::{State, TICK, event_name, requested};
use crate::events::EventsHub;
use crate::events::fanout::SourceEvent;
use crate::events::types::{SourceKind, Visibility};
use crate::events::upstream_need::Verdict;
use crate::protocol::era::Era;
use crate::transport::upstream_tap::{KindSet, NoteKind, UpstreamNote};

impl State<'_> {
    /// Route one projected frame. `true` when the stream is over.
    pub(super) fn note(&mut self, note: UpstreamNote, from_pending: bool) -> bool {
        match note {
            UpstreamNote::Ack { kinds, uris } => {
                self.on_ack(kinds, &uris, from_pending);
                false
            }
            UpstreamNote::Notice { kind, uri } => {
                if !self.honours(kind, uri.as_deref(), from_pending) {
                    return false;
                }
                if kind == NoteKind::ResourcesChanged && !requested(self.shared).uris.is_empty() {
                    self.reread = true;
                }
                if kind == NoteKind::ToolsChanged {
                    // Not coalesced here: the hub's own quiet window does it.
                    if self.shared.need.lock().emits(kind, None) {
                        let mut debt = self.shared.tools.lock();
                        debt.due.get_or_insert(Instant::now() + TICK);
                        debt.unannounced = true;
                    }
                } else if self.shared.need.lock().emits(kind, uri.as_deref()) {
                    self.coalescer.offer(kind, uri, Instant::now());
                }
                false
            }
            UpstreamNote::End => !from_pending,
            UpstreamNote::Unsupported => {
                // A replacement the peer refuses ends nothing; it is dropped
                // at its acknowledgement deadline like any unacknowledged one.
                self.unsupported |= !from_pending;
                !from_pending
            }
        }
    }

    /// Whether an acknowledgement covers a notice. A legacy stream has none
    /// and is not gated; on a modern one, a notice before the stream's
    /// acknowledgement (a replacement's, or the first listen's) is dropped:
    /// the acknowledgement must be the first frame (§3).
    pub(super) fn honours(&self, kind: NoteKind, uri: Option<&str>, from_pending: bool) -> bool {
        if self.era == Era::Legacy {
            return true;
        }
        let (false, Some((kinds, uris))) = (from_pending, &self.honoured) else {
            return false;
        };
        match kind {
            NoteKind::ResourceUpdated => uri.is_some_and(|u| uris.iter().any(|w| w == u)),
            NoteKind::ResourcesChanged => kinds.resources_changed,
            NoteKind::PromptsChanged => kinds.prompts_changed,
            NoteKind::ToolsChanged => kinds.tools_changed,
        }
    }

    pub(super) fn on_ack(&mut self, kinds: KindSet, uris: &[String], from_pending: bool) {
        let asked = if from_pending {
            self.pending.as_ref().map(|p| p.requested.clone())
        } else {
            self.current.as_ref().map(|(_, r)| r.clone())
        };
        if let Some(asked) = asked
            && (asked.kinds != kinds || asked.uris.len() != uris.len())
        {
            warn!(
                backend = %self.shared.name,
                "backend honoured less of the upstream listen than asked; the rest stays silent"
            );
        }
        if from_pending && let Some(p) = self.pending.take() {
            // Make before break: the replacement is live, the old one goes.
            // Closed first, so no new frame lands on it; what it had already
            // queued was asked for under the old acknowledgement, which still
            // stands here, so it is routed before the new one replaces it.
            if let Some((mut old, _)) = self.current.take() {
                old.rx.close();
                while let Ok(note) = old.rx.try_recv() {
                    if !note.ends() {
                        self.note(note, false);
                    }
                }
            }
            self.current = Some((p.stream, p.requested));
            self.opened = Instant::now();
        }
        self.honoured = Some((kinds, uris.to_vec()));
        self.acked = Some(Instant::now());
        self.open_failures = 0;
    }

    /// Emit the coalescing windows that closed (§8), through the hub only.
    /// `true` when the backend is now ineligible: nothing was sent, and the
    /// caller ends the listener through [`end_ineligible`].
    pub(super) fn flush(&mut self, hub: &Weak<EventsHub>) -> bool {
        self.flush_at(hub, Instant::now())
    }

    /// [`Self::flush`] of the windows closed by `at`.
    pub(super) fn flush_at(&mut self, hub: &Weak<EventsHub>, at: Instant) -> bool {
        // Re-checked at every delivery: a reload can make the backend
        // ineligible while its listener runs (MIK-7894).
        let due = self.coalescer.due(at);
        if (self.tools_pending || !due.is_empty()) && self.shared.is_ineligible() {
            self.tools_pending = false;
            return true;
        }
        if std::mem::take(&mut self.tools_pending)
            && let Some(hub) = hub.upgrade()
        {
            hub.backend_tools_changed(&self.shared.name);
        }
        if due.is_empty() {
            return false;
        }
        let Some(hub) = hub.upgrade() else {
            return false;
        };
        for (kind, uri) in due {
            if !self.shared.need.lock().emits(kind, uri.as_deref()) {
                continue;
            }
            if let Some(uri) = &uri
                && self.shared.snapshot.lock().verdict(uri) != Verdict::Deliver
            {
                continue;
            }
            let backend = self.shared.name.clone();
            hub.emit(SourceEvent {
                kind: SourceKind::BackendNotification,
                name: event_name(&backend, kind),
                backend: backend.clone(),
                scope: Visibility::Backend(backend),
                owner: None,
                upstream_id: uuid::Uuid::new_v4().to_string(),
                occurred_at: Utc::now(),
                data: uri.map_or_else(|| json!({}), |uri| json!({ "uri": uri })),
                lifecycle_key: None,
            });
        }
        false
    }
}
