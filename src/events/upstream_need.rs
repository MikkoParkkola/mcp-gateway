// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What one backend's listener must ask upstream for, and the coalescing
//! window between it and the hub (MIK-7630 I5 design §5, §7 limits, §8).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::transport::upstream_tap::{KindSet, NoteKind};

/// URIs one backend listener tracks, and their encoded size (§7).
pub(crate) const MAX_URIS: usize = 1024;
pub(crate) const MAX_URI_BUDGET_BYTES: usize = 32 * 1024;
/// The trailing-edge coalescing window (§8).
pub(crate) const WINDOW: Duration = Duration::from_secs(1);

/// One live lifecycle key's interest in a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Interest {
    ResourceUpdated(String),
    ResourcesChanged,
    PromptsChanged,
    ToolsChanged,
}

/// The URI budget is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Full;

/// The union of what a backend's live lifecycle keys need, each counted by
/// the keys naming it, so the last of two keys sharing a URI keeps it.
#[derive(Debug, Default)]
pub(crate) struct Need {
    resources_changed: u32,
    prompts_changed: u32,
    tools_changed: u32,
    uris: BTreeMap<String, u32>,
    uri_bytes: usize,
}

/// A URI's share of the filter: its JSON string plus a separator.
fn encoded(uri: &str) -> usize {
    serde_json::to_string(uri).map_or(uri.len() + 2, |s| s.len()) + 1
}

impl Need {
    /// Count one more key. `Ok(true)` when the upstream filter changed.
    ///
    /// # Errors
    /// [`Full`] for a new URI over either budget; nothing is counted then.
    pub(crate) fn add(&mut self, interest: &Interest) -> Result<bool, Full> {
        let before = self.filter();
        match interest {
            Interest::ResourcesChanged => self.resources_changed += 1,
            Interest::PromptsChanged => self.prompts_changed += 1,
            Interest::ToolsChanged => self.tools_changed += 1,
            Interest::ResourceUpdated(uri) => {
                if let Some(n) = self.uris.get_mut(uri) {
                    *n += 1;
                } else {
                    let size = encoded(uri);
                    if self.uris.len() >= MAX_URIS || self.uri_bytes + size > MAX_URI_BUDGET_BYTES {
                        return Err(Full);
                    }
                    self.uri_bytes += size;
                    self.uris.insert(uri.clone(), 1);
                }
            }
        }
        Ok(self.filter() != before)
    }

    /// Count one key fewer; `true` when the upstream filter changed. A key
    /// never counted is ignored, so a replayed last-subscriber is harmless.
    pub(crate) fn remove(&mut self, interest: &Interest) -> bool {
        let before = self.filter();
        match interest {
            Interest::ResourcesChanged => {
                self.resources_changed = self.resources_changed.saturating_sub(1);
            }
            Interest::PromptsChanged => {
                self.prompts_changed = self.prompts_changed.saturating_sub(1);
            }
            Interest::ToolsChanged => {
                self.tools_changed = self.tools_changed.saturating_sub(1);
            }
            Interest::ResourceUpdated(uri) => {
                if let Some(n) = self.uris.get_mut(uri) {
                    *n -= 1;
                    if *n == 0 {
                        self.uris.remove(uri);
                        self.uri_bytes -= encoded(uri);
                    }
                }
            }
        }
        self.filter() != before
    }

    /// Whether a live key watches `uri`.
    pub(crate) fn watches(&self, uri: &str) -> bool {
        self.uris.contains_key(uri)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.resources_changed == 0
            && self.prompts_changed == 0
            && self.tools_changed == 0
            && self.uris.is_empty()
    }

    /// Whether anyone subscribed to `kind` itself; `resources_changed` is
    /// asked upstream for URI interest too, but emitted only for this.
    pub(crate) fn emits(&self, kind: NoteKind, uri: Option<&str>) -> bool {
        match kind {
            NoteKind::ResourcesChanged => self.resources_changed > 0,
            NoteKind::PromptsChanged => self.prompts_changed > 0,
            NoteKind::ToolsChanged => self.tools_changed > 0,
            NoteKind::ResourceUpdated => uri.is_some_and(|u| self.uris.contains_key(u)),
        }
    }

    /// The upstream filter: URI interest also asks for `resources_changed`,
    /// which keeps the catalogue snapshot current (§7).
    pub(crate) fn filter(&self) -> (KindSet, Vec<String>) {
        (
            KindSet {
                resources_changed: self.resources_changed > 0 || !self.uris.is_empty(),
                prompts_changed: self.prompts_changed > 0,
                tools_changed: self.tools_changed > 0,
            },
            self.uris.keys().cloned().collect(),
        )
    }
}

/// Trailing-edge coalescing per `(kind, uri)`: the first note opens a
/// window, later ones inside it are absorbed, one event leaves when it
/// closes, after the last change it stands for.
#[derive(Debug, Default)]
pub(crate) struct Coalescer {
    open: BTreeMap<(NoteKind, Option<String>), Instant>,
}

impl Coalescer {
    pub(crate) fn offer(&mut self, kind: NoteKind, uri: Option<String>, now: Instant) {
        self.open.entry((kind, uri)).or_insert(now + WINDOW);
    }

    /// The windows closed at `now`, removed.
    pub(crate) fn due(&mut self, now: Instant) -> Vec<(NoteKind, Option<String>)> {
        let due: Vec<_> = self
            .open
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &due {
            self.open.remove(key);
        }
        due
    }

    /// When the next window closes, if any is open.
    #[cfg(test)]
    pub(crate) fn next(&self) -> Option<Instant> {
        self.open.values().min().copied()
    }
}

/// What a backend's catalogue snapshot says about one URI (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Listed in a successfully read snapshot.
    Deliver,
    /// No good snapshot yet, or the URI is absent from a truncated read:
    /// skip this occurrence, keep the subscription (an error is not absence).
    Skip,
    /// Absent from a complete snapshot: revoke (parent F9).
    Revoke,
}

/// The backend's last successfully read resource URIs. A failed read never
/// replaces a good snapshot, so a transient failure deletes nothing.
#[derive(Debug, Default)]
pub(crate) struct Snapshot {
    good: Option<(std::collections::HashSet<String>, bool)>,
}

impl Snapshot {
    /// Record a successful read; `complete` is false when the page cap cut it.
    pub(crate) fn read(&mut self, uris: std::collections::HashSet<String>, complete: bool) {
        self.good = Some((uris, complete));
    }

    /// Whether any read has succeeded yet.
    pub(crate) fn is_known(&self) -> bool {
        self.good.is_some()
    }

    pub(crate) fn verdict(&self, uri: &str) -> Verdict {
        match &self.good {
            Some((uris, _)) if uris.contains(uri) => Verdict::Deliver,
            Some((_, true)) => Verdict::Revoke,
            None | Some((_, false)) => Verdict::Skip,
        }
    }
}

#[path = "upstream_ledger.rs"]
pub(crate) mod ledger;

#[cfg(test)]
#[path = "upstream_need_tests.rs"]
mod tests;
