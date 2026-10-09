// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Inbound dedupe (design §3.6): one 24 h seen-set per webhook route, keyed
//! on the route's delivery id or, when the route opts in, the signed body's
//! hash. Persisted under `seen/`, one owner-only file per route, so a
//! restart does not reopen the window.

use std::collections::HashMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::records::{load_records, write_record};

/// How long an id is remembered.
const WINDOW: chrono::Duration = crate::duration_bound::delta!(hours, 24);

#[derive(Serialize, Deserialize, Default)]
struct SeenFile {
    v: u32,
    route: String,
    seen: HashMap<String, DateTime<Utc>>,
}

/// Every route's seen-set.
pub(crate) struct Seen {
    dir: PathBuf,
    max_per_route: usize,
    routes: Mutex<Option<HashMap<String, SeenFile>>>,
}

impl Seen {
    pub(crate) fn new(dir: PathBuf, max_per_route: usize) -> Self {
        Self {
            dir,
            max_per_route,
            routes: Mutex::new(None),
        }
    }

    /// Record `key` for `route` at `now`; `false` when it was already seen
    /// inside the window (the occurrence is a repeat and is dropped).
    ///
    /// ponytail: the route's whole set is rewritten per new id (up to
    /// `seen_max_per_route` ids); an append log with periodic compaction is
    /// the upgrade if a busy route makes this measurable.
    pub(crate) fn first_sighting(&self, route: &str, key: &str, now: DateTime<Utc>) -> bool {
        let mut guard = self.routes.lock();
        let routes = guard.get_or_insert_with(|| self.load());
        let file = routes.entry(route.to_owned()).or_insert_with(|| SeenFile {
            v: 1,
            route: route.to_owned(),
            seen: HashMap::new(),
        });
        file.seen.retain(|_, at| now - *at < WINDOW);
        if file.seen.contains_key(key) {
            return false;
        }
        file.seen.insert(key.to_owned(), now);
        if file.seen.len() > self.max_per_route {
            let mut by_age: Vec<(DateTime<Utc>, String)> =
                file.seen.iter().map(|(k, at)| (*at, k.clone())).collect();
            by_age.sort();
            let over = file.seen.len() - self.max_per_route;
            for (_, old) in by_age.into_iter().take(over) {
                file.seen.remove(&old);
            }
        }
        if let Err(error) = write_record(&self.dir, &file_name(route), &*file)
            .and_then(super::records::Placed::durable)
        {
            // The id is still remembered in memory; only a restart could
            // reopen the window for it.
            tracing::warn!(%error, "events: inbound seen-set not persisted");
        }
        true
    }

    fn load(&self) -> HashMap<String, SeenFile> {
        if let Err(error) = super::records::create_private_dir(&self.dir) {
            tracing::warn!(%error, "events: seen directory not created");
        }
        load_records::<SeenFile>(&self.dir)
            .into_iter()
            .map(|(_, file)| (file.route.clone(), file))
            .collect()
    }
}

fn file_name(route: &str) -> String {
    use sha2::Digest as _;
    format!(
        "{}.json",
        hex::encode(sha2::Sha256::digest(route.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_drop_inside_the_window_and_survive_reopen() {
        let dir = tempfile::tempdir().expect("dir");
        let now = Utc::now();
        let seen = Seen::new(dir.path().join("seen"), 2);
        assert!(seen.first_sighting("r", "a", now));
        assert!(!seen.first_sighting("r", "a", now), "repeat");
        assert!(seen.first_sighting("other", "a", now), "per route");
        let seen = Seen::new(dir.path().join("seen"), 2);
        assert!(!seen.first_sighting("r", "a", now), "persisted");
        assert!(seen.first_sighting("r", "a", now + WINDOW), "window passed");
        assert!(seen.first_sighting("r", "b", now + WINDOW));
        assert!(
            seen.first_sighting("r", "c", now + WINDOW),
            "cap evicts oldest"
        );
    }
}
