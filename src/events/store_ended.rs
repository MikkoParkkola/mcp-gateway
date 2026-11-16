// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ended rows: an ending moves a live row out of
//! `State::subs` into `State::ended`, persisted under `ended/`, and its one
//! notice travels as an outbox record that maps to the ended row. Every
//! live-row reader keeps reading `State::subs` only, so an ended row takes
//! no event, no cap slot and no listing; only the outbox paths that ready,
//! claim, sign, settle or cancel a notice read the ended map.

use std::path::Path;

use chrono::{DateTime, Utc};

use super::{State, Store, TailPolicy};
use crate::events::outbox::{EndedRow, EndedStamp, OutboxRecord};
use crate::events::records::{
    Subscription, load_records, remove_record, verified_file, write_record,
};

#[cfg(test)]
thread_local! {
    /// Test-only: the next ended-file write on this thread is refused, the one
    /// way an ending fails after its notice record is in place.
    pub(crate) static FAIL_NEXT_ENDED_WRITE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Which pending records of a subscription id a cancellation takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cancel {
    /// The live row's events only: an ending keeps the notices of the id's
    /// earlier endings.
    Events,
    /// Every record of the id, notices included, with their ended rows: the
    /// owner said stop, which supersedes an earlier ending (SILENT.4).
    All,
}

/// Load `ended/` into `state.ended`: routed by the directory, never by a
/// file name.
pub(super) fn load(state: &mut State, ended_dir: &Path) {
    for (_, ended) in load_records::<EndedRow>(ended_dir) {
        let key = (ended.row.id.clone(), ended.row.incarnation);
        state.ended.insert(key, ended);
    }
}

impl State {
    /// The row an outbox record maps to: an ended notice's ended row, an
    /// event's live row.
    pub(super) fn row_of(&self, record: &OutboxRecord) -> Option<&Subscription> {
        match record.ended_key() {
            Some(key) => self.ended.get(&key).map(|ended| &ended.row),
            None => self.subs.get(&record.subscription_id),
        }
    }
}

impl Store {
    /// End live row `id`, when `still` holds for it under the store lock:
    /// its pending events are cancelled, its one notice is enqueued and the
    /// row moves to the ended rows, stamped `stamp`. In order (design Y' 2):
    /// the notice record, the ended file, then the live file. A failed write
    /// of the record or the ended file undoes both and fails the call with
    /// the row still live, so the caller retries as for any failed removal;
    /// a live file that cannot be unlinked is logged and the move stands in
    /// memory (design Y'' 7). `false` when no row `still` matched.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the revoke paths, a later step, call it")
    )]
    pub(crate) fn end_where(
        &self,
        id: &str,
        stamp: EndedStamp,
        tail: TailPolicy,
        still: impl FnOnce(&Subscription) -> bool,
    ) -> std::io::Result<bool> {
        let at = stamp.at;
        let mut state = self.state.lock();
        self.sweep(&mut state, at)?;
        let Some(sub) = state.subs.get(id).cloned().filter(|s| still(s)) else {
            self.trim_tails(&mut state, at, tail)?;
            return Ok(false);
        };
        self.cancel_pending(&mut state, id, mutant!("m10", Cancel::All, Cancel::Events))?;
        let ended = EndedRow {
            row: sub.clone(),
            ended: stamp,
        };
        if let Err(error) = self.write_ending(&mut state, &ended) {
            let event_id = &ended.ended.event_id;
            state.outbox.remove(event_id);
            let undone =
                remove_record(&self.outbox_dir, &OutboxRecord::file(event_id)).and_then(|()| {
                    remove_record(&self.ended_dir, &EndedRow::file(id, sub.incarnation))
                });
            if let Err(undo) = undone {
                tracing::warn!(%undo, "events store: an unfinished ending was not undone");
            }
            return Err(error);
        }
        if let Err(error) = mutant!(
            "m20",
            Ok(()),
            remove_record(&self.subs_dir, &format!("{id}.json"))
        ) {
            tracing::warn!(%error, "events store: an ended row's live file was not removed");
        }
        state.drop_row(id);
        state.ended.insert((id.to_owned(), sub.incarnation), ended);
        self.stamp_removed(&mut state, &sub, Some(at), tail)?;
        Ok(true)
    }

    /// After `sub` left the live rows: a live row that was its pair's last
    /// starts the pair's tail. An expired row kept for its burials keeps the
    /// expiry stamp the sweep gave its pair: removing it never restarts the
    /// tail.
    pub(super) fn stamp_removed(
        &self,
        state: &mut State,
        sub: &Subscription,
        now: Option<DateTime<Utc>>,
        tail: TailPolicy,
    ) -> std::io::Result<()> {
        let Some(now) = now else {
            return Ok(());
        };
        if sub.live(now) && !state.pair_live(&sub.principal, &sub.url, now) {
            let key = verified_file(&sub.principal, &sub.url);
            if let Some(mut record) = state.verified.get(&key).cloned() {
                record.last_subscription_ended_at = Some(now);
                let placed = write_record(&self.verified_dir, &key, &record)?;
                state.verified.insert(key, record);
                placed.durable()?;
            }
        }
        self.trim_tails(state, now, tail)
    }

    /// Steps (a) and (b) of an ending: the notice record, then the ended
    /// file, each durable before the next.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the revoke paths, a later step, call it")
    )]
    fn write_ending(&self, state: &mut State, ended: &EndedRow) -> std::io::Result<()> {
        let record = ended.notice_record();
        let file = OutboxRecord::file(&record.event_id);
        let placed = write_record(&self.outbox_dir, &file, &record)?;
        state.outbox.insert(record.event_id.clone(), record);
        placed.durable()?;
        #[cfg(test)]
        if FAIL_NEXT_ENDED_WRITE.with(|fail| fail.replace(false)) {
            return Err(std::io::Error::other(
                "test: the ended file write was refused",
            ));
        }
        let file = EndedRow::file(&ended.row.id, ended.row.incarnation);
        mutant!(
            "m19",
            Ok(()),
            write_record(&self.ended_dir, &file, ended)?.durable()
        )
    }

    /// Delete ended row `key` and its file. Memory follows the disk.
    pub(super) fn drop_ended(&self, state: &mut State, key: &(String, u64)) -> std::io::Result<()> {
        if state.ended.contains_key(key) {
            remove_record(&self.ended_dir, &EndedRow::file(&key.0, key.1))?;
            state.ended.remove(key);
        }
        Ok(())
    }

    /// Cancel every pending notice of subscription `id` and delete its ended
    /// rows (owner unsubscribe); `true` when there was one.
    pub(super) fn forget_ended(&self, id: &str) -> std::io::Result<bool> {
        let mut state = self.state.lock();
        let had = state.ended.keys().any(|(ended, _)| ended == id);
        self.cancel_pending(&mut state, id, Cancel::All)?;
        Ok(had)
    }

    /// Delete every ended row of subscription `id`.
    pub(super) fn drop_ended_of(&self, state: &mut State, id: &str) -> std::io::Result<()> {
        let keys: Vec<(String, u64)> = state
            .ended
            .keys()
            .filter(|(ended, _)| ended == id)
            .cloned()
            .collect();
        for key in keys {
            self.drop_ended(state, &key)?;
        }
        Ok(())
    }

    /// Test-only: the ended rows now, in memory.
    #[cfg(test)]
    pub(crate) fn ended_rows(&self) -> Vec<EndedRow> {
        self.state.lock().ended.values().cloned().collect()
    }

    /// Test-only: the directory ended rows are written to.
    #[cfg(test)]
    pub(crate) fn ended_dir(&self) -> &Path {
        &self.ended_dir
    }

    /// Test-only: the directory live rows are written to.
    #[cfg(test)]
    pub(crate) fn subs_dir(&self) -> &Path {
        &self.subs_dir
    }
}
