// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The control socket's messages, one JSON object per line. The gateway
//! (`control.rs`) and the sandbox helper (`linux/control_client.rs`) both
//! encode and parse these, so the two sides cannot drift apart. Every
//! message refuses unknown keys, and every flag must be `true`.
#![cfg_attr(
    not(any(test, target_os = "linux")),
    expect(dead_code, reason = "only the Linux fetch step drives it so far")
)]

use serde::{Deserialize, Serialize};

/// The longest control line, its newline included.
pub(crate) const MAX_LINE: usize = 1024;

/// The helper's request for a fetch: `{"fetch_start":true}`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchStart {
    pub(crate) fetch_start: bool,
}

/// The helper's report that the fetch and its teardown ended:
/// `{"fetch_done":true}`, or `{"fetch_done":true,"refused":"<step>"}` when a
/// step failed. `refused` is the one key beyond FETCH.1's set; a present one
/// must name a [`FetchStep`] (`null` refuses the line).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchDone {
    pub(crate) fetch_done: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "named_step"
    )]
    pub(crate) refused: Option<FetchStep>,
}

/// A present `refused` names a step; anything else, `null` included, fails.
fn named_step<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<FetchStep>, D::Error> {
    FetchStep::deserialize(d).map(Some)
}

/// A step of the helper's fetch that can fail after `fetch_start`. Only its
/// name crosses the control socket: no npm output, URL, credential or path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FetchStep {
    Setup,
    NpmInstall,
    LockCheck,
    NpmCi,
    Sweep,
    Relay,
    ProxySocket,
    UvInstall,
    DirectUrlCheck,
}

impl FetchStep {
    /// Every step, for the rows.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 9] = [
        Self::Setup,
        Self::NpmInstall,
        Self::LockCheck,
        Self::NpmCi,
        Self::Sweep,
        Self::Relay,
        Self::ProxySocket,
        Self::UvInstall,
        Self::DirectUrlCheck,
    ];

    /// The gateway's fixed words for the step, read after "failed at" in the
    /// caller's refusal.
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::Setup => "preparing the fetch",
            Self::NpmInstall => "the fetch's npm install",
            Self::LockCheck => "the fetch's lock check",
            Self::NpmCi => "the fetch's npm ci",
            Self::Sweep => "the fetch's sweep",
            Self::Relay => "stopping the fetch's relay",
            Self::ProxySocket => "removing the fetch's proxy socket",
            Self::UvInstall | Self::DirectUrlCheck => "preparing the fetch",
        }
    }
}

/// The helper's acknowledgement of `expired`: `{"run":true}`. The gateway
/// reports the preview started only once it has read this line.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Run {
    pub(crate) run: bool,
}

/// The gateway's answer to `fetch_start`: the fetch's proxy credential and
/// the milliseconds left to the fetch's deadline.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Issued {
    pub(crate) credential: String,
    pub(crate) deadline_ms: u128,
}

/// The credential is a live proxy secret: a debug print never shows it.
impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("credential", &"<redacted>")
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

/// The gateway's answer to `fetch_done`, sent only once every tunnel of the
/// credential is shut: `{"expired":true}`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Expired {
    pub(crate) expired: bool,
}
