// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What only a restart would apply, as the Gateway page reads it, and the
//! first-key wait the reload records beside it. A child of `live_config`, so
//! it reads the holder's own state.

#[cfg(any(test, feature = "webui"))]
use std::sync::Arc;

use super::LiveConfig;
#[cfg(any(test, feature = "webui"))]
use super::pending_restart_fields;

/// A first-key file's wait, as the most recent reload that read the file
/// judged it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirstKeyWait {
    /// The waiting keys, in file order; never empty.
    pub(crate) keys: Vec<String>,
    /// Why a start from the file would be refused; `None` when it would start.
    #[cfg_attr(
        not(any(test, feature = "webui")),
        expect(dead_code, reason = "served by the web UI's gateway read")
    )]
    pub(crate) start_refusal: Option<String>,
}

impl LiveConfig {
    /// Everything only a restart would apply, as the Gateway page shows it:
    /// the published config's fields plus the startup-environment marker,
    /// read from one snapshot.
    #[cfg(any(test, feature = "webui"))]
    #[must_use]
    pub(crate) fn pending_restart(&self) -> Vec<&'static str> {
        // One read, so a publish cannot land between taking the stored set and
        // the generation it was computed for.
        let (applied, generation) = {
            let inner = self.inner.read();
            (inner.applied.clone(), Arc::clone(&inner.generation))
        };
        let mut fields = match applied {
            Some(applied) => applied.pending_restart.clone(),
            // No revision published (a config built in memory): no reload of
            // an env file can have happened, so the config fields are all.
            None => pending_restart_fields(&self.running, generation.config()),
        };
        // A waiting first key is in the file and not in the published config.
        if self.first_key.read().is_some() && !fields.contains(&"auth.api_keys") {
            fields.push("auth.api_keys");
        }
        fields
    }

    /// The keys a first-key file waits on for a restart: the verdict of the
    /// most recent reload that read the file. `None` when nothing waits.
    #[must_use]
    pub(crate) fn waiting_keys(&self) -> Option<Vec<String>> {
        self.first_key.read().as_ref().map(|wait| wait.keys.clone())
    }

    /// The whole wait: the keys and whether a start from the file would be
    /// refused, as the most recent reload that read the file judged them.
    #[cfg_attr(
        not(any(test, feature = "webui")),
        expect(dead_code, reason = "served by the web UI's gateway read")
    )]
    #[must_use]
    pub(crate) fn first_key_wait(&self) -> Option<FirstKeyWait> {
        self.first_key.read().clone()
    }

    /// Record a file-reading reload's verdict on a first key: the wait, or
    /// `None` for every other outcome of a reload that read the file.
    pub(crate) fn note_first_key(&self, waiting: Option<FirstKeyWait>) {
        *self.first_key.write() = waiting;
    }
}
