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

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
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
    now.saturating_duration_since(minted) >= LIFETIME
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
    #[cfg(test)]
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

/// Why restart is unavailable, in the order readiness checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    /// Windows: the service or process manager restarts the gateway.
    WindowsManualRestart,
    /// Restart is off, or this process has no restart target it can re-exec.
    RestartNotAvailable,
    /// No transparency log: an accepted restart would have nowhere to be audited.
    AuditLogRequired,
}

impl Reason {
    /// The reason this platform gives before anything else is checked.
    pub(crate) const PLATFORM: Self = if cfg!(windows) {
        Self::WindowsManualRestart
    } else {
        Self::RestartNotAvailable
    };

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::WindowsManualRestart => "windows_manual_restart",
            Self::RestartNotAvailable => "restart_not_available",
            Self::AuditLogRequired => "audit_log_required",
        }
    }

    pub(crate) const fn recovery(self) -> &'static str {
        match self {
            Self::WindowsManualRestart => {
                "Restart the service or process through its service or process manager."
            }
            Self::RestartNotAvailable => {
                "Restart the gateway with the service manager that runs it, for example systemctl restart, brew services restart or docker restart; if you launched it by hand, stop this process, then start it again with the start command."
            }
            Self::AuditLogRequired => {
                "Turn on the transparency log (security.transparency_log.enabled): a restart is refused \
                 without its audit record."
            }
        }
    }
}

/// Restart readiness, read once per request; the availability body and the
/// mint both take this one value, so they cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// Ready, with the invocation and target identity read for this request.
    Ready {
        invocation: InvocationDigest,
        target: FileId,
    },
    Unavailable(Reason),
}

/// The platform readiness checks first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    Unix,
    Windows,
}

impl Platform {
    const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

#[path = "restart_advice.rs"]
mod advice;

/// The restart keys one UI answer carries (`restart_advice`, `start_command` or
/// `start_refusal`), or none when no restart is pending. `refusal` is what
/// `next_start_refusal` said of the config a restart would boot; `config_path`
/// is the file this gateway was started with.
pub(crate) fn restart_advice(
    pending: bool,
    refusal: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    if !pending {
        return None;
    }
    // current_exe, not the process arguments: the command names the running
    // file, whatever the invocation looked like.
    let start = config_path.and_then(|config| {
        let exe = std::env::current_exe().ok()?;
        advice::StartCommand::new(&exe, config)
    });
    advice::advice(pending, refusal, Platform::current(), start.as_ref())
}

/// Where readiness reads the process's restart binding.
pub(crate) enum InvocationSource {
    /// The capture taken once at CLI entry.
    Process,
    /// A test's binding, with a count of the reads.
    #[cfg(test)]
    Scripted(Arc<ScriptedInvocation>),
}

/// A test's invocation digest and target identity.
#[cfg(test)]
pub(crate) struct ScriptedInvocation {
    pub(crate) digest: Option<InvocationDigest>,
    pub(crate) target: Option<Result<FileId, std::io::ErrorKind>>,
    pub(crate) reads: std::sync::atomic::AtomicUsize,
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
    invocation: InvocationSource,
    platform: Platform,
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
                #[allow(
                    clippy::disallowed_methods,
                    reason = "nonce: a single-use 120 s restart confirmation, never a credential"
                )]
                let filled: Result<(), ()> =
                    ring::rand::SystemRandom::new().fill(bytes).map_err(|_| ());
                filled
            }),
            samples: SampleSource::Counter,
            invocation: InvocationSource::Process,
            platform: Platform::current(),
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

    /// A test's invocation binding.
    #[cfg(test)]
    pub(crate) fn with_invocation(self, invocation: InvocationSource) -> Self {
        Self { invocation, ..self }
    }

    /// A test's platform.
    #[cfg(test)]
    pub(crate) fn with_platform(self, platform: Platform) -> Self {
        Self { platform, ..self }
    }

    /// The same seams with confirmation off.
    #[cfg(test)]
    pub(crate) fn switched_off(self) -> Self {
        Self {
            enabled: false,
            ..self
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// The write sample the route shows and binds, read once per request.
    /// Only a test's script can be empty; a release build always samples.
    #[cfg_attr(
        not(test),
        expect(
            clippy::unnecessary_wraps,
            reason = "a release build always samples; the Option is a test script's missing sample"
        )
    )]
    pub(crate) fn sample(&self, counter: &RecentWrites) -> Option<WriteSample> {
        match &self.samples {
            SampleSource::Counter => Some(counter.sample((self.clock)())),
            #[cfg(test)]
            SampleSource::Scripted(script) => script
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .flatten(),
        }
    }

    /// Restart readiness for one request, first match wins: the platform,
    /// then restart off or no restart target, then no transparency log
    /// (`audit_log` false). The invocation binding is read once, here.
    pub(crate) fn readiness(&self, audit_log: bool) -> Readiness {
        if self.platform == Platform::Windows {
            return Readiness::Unavailable(Reason::WindowsManualRestart);
        }
        if !self.enabled {
            return Readiness::Unavailable(Reason::RestartNotAvailable);
        }
        let (Some(invocation), Some(Ok(target))) = self.binding() else {
            return Readiness::Unavailable(Reason::RestartNotAvailable);
        };
        if !audit_log {
            return Readiness::Unavailable(Reason::AuditLogRequired);
        }
        Readiness::Ready { invocation, target }
    }

    /// The process's invocation digest and its target's identity now.
    fn binding(&self) -> (Option<InvocationDigest>, Option<std::io::Result<FileId>>) {
        match &self.invocation {
            InvocationSource::Process => {
                let capture = crate::restart::invocation::invocation();
                (capture.digest(), capture.target_file_id())
            }
            #[cfg(test)]
            InvocationSource::Scripted(script) => {
                script
                    .reads
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (
                    script.digest,
                    script.target.map(|read| read.map_err(std::io::Error::from)),
                )
            }
        }
    }

    /// The confirmation a `?confirm=1` GET in the full admin view adds: a
    /// mint binding the caller's per-session principal, the boot id, the
    /// invocation and target read for `readiness`, and the sample the GET
    /// shows. None when restart is not ready, there is no principal or no
    /// sample, or the mint refuses.
    pub(crate) fn confirmation(
        &self,
        readiness: Readiness,
        sample: Option<WriteSample>,
        client: Option<&crate::gateway::auth::AuthenticatedClient>,
        headers: &axum::http::HeaderMap,
        boot: u64,
    ) -> Option<String> {
        let Readiness::Ready { invocation, target } = readiness else {
            return None;
        };
        let principal = super::principal::cursor_principal(client, headers)?;
        self.mint(Live {
            principal,
            boot,
            invocation,
            target,
            sample: sample?,
        })
    }

    /// A confirmation binding `live`, or None: the registry is full of other
    /// principals' live entries, or the random source failed. A principal's
    /// new confirmation replaces its earlier one; a failed mint replaces nothing.
    pub(crate) fn mint(&self, live: Live) -> Option<String> {
        // A second line behind the route's own check: off mints nothing.
        if !self.enabled {
            return None;
        }
        let mut entries = self.entries();
        // Read under the lock, so time spent waiting for it is not lost.
        let now = (self.clock)();
        entries.retain(|_, entry| !expired(entry.minted, now));
        let held = entries
            .iter()
            .find(|(_, entry)| entry.live.principal == live.principal)
            .map(|(key, _)| *key);
        if held.is_none() && entries.len() >= MAX_ENTRIES {
            return None;
        }
        let mut bytes = [0u8; 32];
        (self.fill)(&mut bytes).ok()?;
        let token = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        if let Some(key) = held {
            entries.remove(&key);
        }
        entries.insert(digest(&token), Entry { live, minted: now });
        Some(token)
    }

    /// Judge `token` against the values a POST read. The entry is removed
    /// before it is judged, so a token is used once whatever the outcome.
    pub(crate) fn consume(&self, token: &str, presented: &Presented) -> Result<Accepted, Refusal> {
        // A string no mint could have made is refused before it is hashed.
        if token.len() != TOKEN_LEN || !token.starts_with(PREFIX) {
            return Err(Refusal::Invalid);
        }
        let entry = {
            let mut entries = self.entries();
            // Read under the lock: a consume that waited for it is judged at
            // the time it ran, never earlier.
            let now = (self.clock)();
            let entry = entries.remove(&digest(token)).ok_or(Refusal::Invalid)?;
            if expired(entry.minted, now) {
                return Err(Refusal::Expired);
            }
            entry
        };
        let bound = &entry.live;
        if presented.principal.as_deref() != Some(bound.principal.as_str()) {
            return Err(Refusal::PrincipalChanged);
        }
        if presented.boot != bound.boot {
            return Err(Refusal::BootChanged);
        }
        if presented.invocation != Some(bound.invocation) {
            return Err(Refusal::InvocationChanged);
        }
        if !matches!(&presented.target, Some(Ok(id)) if *id == bound.target) {
            return Err(Refusal::TargetChanged);
        }
        let fresh = presented.sample.ok_or(Refusal::SampleMissing)?;
        let writes_since = fresh
            .writes_total
            .checked_sub(bound.sample.writes_total)
            .ok_or(Refusal::SampleInvalid)?;
        // The admin confirmed "nothing is writing"; refuse once that is false.
        if bound.sample.count == 0 && writes_since > 0 {
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
