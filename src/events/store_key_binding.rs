// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 §13.6, §14.3: the events store records the identity of the
//! record key it was written under. When that key changes the store adopts
//! the current one: a key change only renames handles, so it never refuses a
//! start.

use std::io::Write as _;
use std::path::Path;

use crate::gateway::record_principal::RecordPrincipalKey;

/// The file naming the record key the store was written under.
const KEY_ID_FILE: &str = "record-key.id";

impl super::Store {
    /// Bind the store to `key`. An empty store adopts it silently; a store
    /// holding state under no recorded key, or under another one, adopts it
    /// with one warning naming the store and both identities. A failure to
    /// record the identity is logged and the start continues; the next start
    /// warns again.
    pub(crate) fn bind_key(&self, key: &RecordPrincipalKey) {
        let Some(root) = self.subs_dir.parent() else {
            return;
        };
        let current = key.identity();
        let recorded = std::fs::read_to_string(root.join(KEY_ID_FILE))
            .ok()
            .map(|text| text.trim_end().to_owned());
        if recorded.as_deref() == Some(current.as_str()) {
            return;
        }
        if self.holds_state() {
            let short = |id: &str| id.get(..8).unwrap_or(id).to_owned();
            let previous = recorded.as_deref().map_or_else(|| "none".to_owned(), short);
            let now = short(&current);
            tracing::warn!(
                store = %root.display(),
                previous_key = %previous,
                current_key = %now,
                "events store {} adopts the current record key {now} (was {previous}): \
                 every subscription handle and eventId changes; delivery continues",
                root.display(),
            );
        }
        if let Err(error) = write_key_id(root, &current) {
            tracing::error!(
                store = %root.display(),
                %error,
                "events store could not record its record-key identity"
            );
        }
    }

    /// Whether the store holds durable state: a subscription, a verification
    /// record, an outbox record or a dead letter (§14.3).
    fn holds_state(&self) -> bool {
        [
            &self.subs_dir,
            &self.verified_dir,
            &self.outbox_dir,
            &self.dead_dir,
        ]
        .into_iter()
        .any(|dir| std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some()))
    }
}

/// Write `id` to `root/record-key.id` owner-only, through a temp file and a
/// rename, then sync `root`.
fn write_key_id(root: &Path, id: &str) -> std::io::Result<()> {
    let temp = root.join(format!(".{KEY_ID_FILE}.{}.tmp", rand::random::<u64>()));
    let written = {
        let mut file = crate::config_persistence::create_new_private(&temp)?;
        writeln!(file, "{id}").and_then(|()| file.sync_all())
    };
    let placed =
        written.and_then(|()| super::super::records::rename(&temp, &root.join(KEY_ID_FILE)));
    if placed.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    placed?;
    super::super::records::sync_dir(root)
}
