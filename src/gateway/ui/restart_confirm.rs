// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The private restart confirmation registry (restart slice 7b; design
//! mik-9447 r3). RED STUB: the shape the rows need, no behaviour.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the restart routes, slice 7c, call the registry")
)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::gateway::recent_writes::{RecentWrites, WriteSample};
use crate::restart::invocation::{FileId, InvocationDigest};

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
            enabled: false,
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

    pub(crate) fn sample(&self, _counter: &RecentWrites) -> Option<WriteSample> {
        None
    }

    pub(crate) fn mint(&self, _live: Live) -> Option<String> {
        let _ = &self.fill;
        Some(format!("rc1.{}", URL_SAFE_NO_PAD.encode([0u8; 32])))
    }

    pub(crate) fn consume(
        &self,
        _token: &str,
        _presented: &Presented,
    ) -> Result<Accepted, Refusal> {
        let _ = (&self.clock, &self.entries);
        Ok(Accepted { writes_since: 0 })
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(crate) fn has_key(&self, _key: &[u8; 32]) -> bool {
        false
    }

    #[cfg(test)]
    pub(crate) fn plant(&self, _key: [u8; 32], _live: Live) {}
}
