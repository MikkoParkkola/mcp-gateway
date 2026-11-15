// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The private restart confirmation registry (restart slice 7b; design
//! mik-9447 r3): a single-use, 120 s confirmation bound to the caller's
//! per-session principal, the boot id, the invocation digest, the target
//! file and the recent-write sample the admin was shown. Only the SHA-256 of a
//! token is kept; the token itself is never stored, logged or printed.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the restart routes, slice 7c, call the registry")
)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::gateway::recent_writes::{RecentWrites, WriteSample};
use crate::restart::invocation::{FileId, InvocationDigest};

/// A confirmation is good while less than this has passed since its mint.
const LIFETIME: Duration = Duration::from_secs(120);
/// At most this many confirmations are held, one per principal.
const MAX_ENTRIES: usize = 64;
const PREFIX: &str = "rc1.";
/// `rc1.` and the unpadded base64url of 32 bytes.
const TOKEN_LEN: usize = PREFIX.len() + 43;

fn expired(minted: Instant, now: Instant) -> bool {
    mutant!("m11", now.saturating_duration_since(minted) > LIFETIME, now.saturating_duration_since(minted) >= LIFETIME)
}

fn digest(token: &str) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(token.as_bytes()).into()
}

/// The instance's clock.
pub(crate) type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;
/// The instance's random source; an error mints nothing.
pub(crate) type Fill = Arc<dyn Fn(&mut [u8]) -> Result<(), ()> + Send + Sync>;

/// Where the route reads the write sample it shows and binds.
pub(crate) enum SampleSource {
    /// The gateway's own write counter.
    Counter,
    /// A test's samples, handed out in order; an empty script is no sample.
    Scripted(Arc<Mutex<VecDeque<Option<WriteSample>>>>),
}

/// The values a confirmation binds, all read at mint.
#[derive(Clone, Debug)]
pub(crate) struct Live {
    pub(crate) principal: String,
    pub(crate) boot: u64,
    pub(crate) invocation: InvocationDigest,
    pub(crate) target: FileId,
    pub(crate) sample: WriteSample,
}

/// The values a POST reads, each possibly missing.
pub(crate) struct Presented {
    pub(crate) principal: Option<String>,
    pub(crate) boot: u64,
    pub(crate) invocation: Option<InvocationDigest>,
    pub(crate) target: Option<std::io::Result<FileId>>,
    pub(crate) sample: Option<WriteSample>,
}

/// Why a confirmation was refused; each kind has its own audit kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Invalid,
    Expired,
    PrincipalChanged,
    BootChanged,
    InvocationChanged,
    TargetChanged,
    SampleMissing,
    SampleInvalid,
    WritesSincePreview,
}

/// An accepted confirmation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Accepted {
    /// Writes counted between the bound sample and the presented one.
    pub(crate) writes_since: u64,
}

struct Entry {
    live: Live,
    minted: Instant,
}

/// The registry and its seams, one per process (on `ProcessFacts`).
pub(crate) struct RestartConfirm {
    enabled: bool,
    clock: Clock,
    fill: Fill,
    samples: SampleSource,
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

/// Shows whether confirmation is on, never an entry or a seam.
impl std::fmt::Debug for RestartConfirm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestartConfirm")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl RestartConfirm {
    /// Production seams; restart confirmation is off.
    pub(crate) fn new() -> Self {
        Self {
            enabled: mutant!("m1", true, false),
            clock: Arc::new(Instant::now),
            fill: Arc::new(|bytes: &mut [u8]| {
                use ring::rand::SecureRandom as _;
                ring::rand::SystemRandom::new().fill(bytes).map_err(|_| ())
            }),
            samples: SampleSource::Counter,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Enabled, on a test's clock and random source.
    #[cfg(test)]
    pub(crate) fn for_test(clock: Clock, fill: Fill) -> Self {
        Self {
            enabled: true,
            clock,
            fill,
            ..Self::new()
        }
    }

    /// A test's sample source.
    #[cfg(test)]
    pub(crate) fn with_samples(self, samples: SampleSource) -> Self {
        Self { samples, ..self }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// The write sample the route shows and binds, read once per request.
    pub(crate) fn sample(&self, counter: &RecentWrites) -> Option<WriteSample> {
        match &self.samples {
            SampleSource::Counter => mutant!("m23", None, Some(counter.sample((self.clock)()))),
            SampleSource::Scripted(script) => script
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .flatten(),
        }
    }

    /// A confirmation binding `live`, or None: the registry is full of other
    /// principals' live entries, or the random source failed. A principal's
    /// new confirmation replaces its earlier one; a failed mint replaces nothing.
    pub(crate) fn mint(&self, live: Live) -> Option<String> {
        // A second line behind the route's own check: off mints nothing.
        if (mutant!("m2", false, !self.enabled)) {
            return None;
        }
        let mut entries = self.entries();
        // Read under the lock, so time spent waiting for it is not lost.
        let now = (self.clock)();
        if mutant!("m3", false, true) {
            entries.retain(|_, entry| !expired(entry.minted, now));
        }
        let held = entries
            .iter()
            .find(|(_, entry)| entry.live.principal == live.principal)
            .map(|(key, _)| *key);
        if (mutant!("m4", false, held.is_none() && entries.len() >= MAX_ENTRIES)) {
            return None;
        }
        let mut bytes = [0u8; 32];
        mutant!("m5", { let _ = (self.fill)(&mut bytes); Some(()) }, (self.fill)(&mut bytes).ok())?;
        let token = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if let Some(key) = held.filter(|_| mutant!("m6", false, true)) {
            entries.remove(&key);
        }
        entries.insert(mutant!("m7", bytes, digest(&token)), Entry { live, minted: now });
        Some(token)
    }

    /// Judge `token` against the values a POST read. The entry is removed
    /// before it is judged, so a token is used once whatever the outcome.
    pub(crate) fn consume(&self, token: &str, presented: &Presented) -> Result<Accepted, Refusal> {
        // A string no mint could have made is refused before it is hashed.
        if (mutant!("m8", false, token.len() != TOKEN_LEN) || mutant!("m9", false, !token.starts_with(PREFIX))) {
            return Err(Refusal::Invalid);
        }
        let entry = {
            let mut entries = self.entries();
            // Read under the lock: a consume that waited for it is judged at
            // the time it ran, never earlier.
            let now = (self.clock)();
            let entry = mutant!("m10", entries.get(&digest(token)).map(|e| Entry { live: e.live.clone(), minted: e.minted }), entries.remove(&digest(token))).ok_or(Refusal::Invalid)?;
            if expired(entry.minted, now) {
                return Err(Refusal::Expired);
            }
            entry
        };
        let bound = &entry.live;
        if (mutant!("m13", presented.principal.as_deref().is_some_and(|p| p != bound.principal), mutant!("m12", false, presented.principal.as_deref() != Some(bound.principal.as_str())))) {
            return Err(Refusal::PrincipalChanged);
        }
        if (mutant!("m14", false, presented.boot != bound.boot)) {
            return Err(Refusal::BootChanged);
        }
        if (mutant!("m16", presented.invocation.is_some_and(|i| i != bound.invocation), mutant!("m15", false, presented.invocation != Some(bound.invocation)))) {
            return Err(Refusal::InvocationChanged);
        }
        if (mutant!("m18", matches!(&presented.target, Some(Ok(id)) if *id != bound.target), mutant!("m17", false, !matches!(&presented.target, Some(Ok(id)) if *id == bound.target)))) {
            return Err(Refusal::TargetChanged);
        }
        let fresh = mutant!("m19", Ok::<_, Refusal>(presented.sample.unwrap_or(bound.sample)), presented.sample.ok_or(Refusal::SampleMissing))?;
        let writes_since = mutant!("m20", Ok::<u64, Refusal>(fresh.writes_total.saturating_sub(bound.sample.writes_total)), fresh.writes_total.checked_sub(bound.sample.writes_total).ok_or(Refusal::SampleInvalid))?;
        // The admin confirmed "nothing is writing"; refuse once that is false.
        if (mutant!("m22", fresh.count == 0 && writes_since > 0, mutant!("m21", false, bound.sample.count == 0 && writes_since > 0))) {
            return Err(Refusal::WritesSincePreview);
        }
        Ok(Accepted { writes_since })
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries().len()
    }

    #[cfg(test)]
    pub(crate) fn has_key(&self, key: &[u8; 32]) -> bool {
        self.entries().contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn plant(&self, key: [u8; 32], live: Live) {
        let minted = (self.clock)();
        self.entries().insert(key, Entry { live, minted });
    }
}
