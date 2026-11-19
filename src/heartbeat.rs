// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The daily anonymous heartbeat: at most one POST per UTC day per data
//! directory to the shared receiver, with five fields and nothing else.
//! Skipped in development builds, CI, a hardened install, a proxied
//! environment, and under `DO_NOT_TRACK` or `NO_TELEMETRY`. docs/PRIVACY.md,
//! "Daily heartbeat", states exactly what is sent and stored.
//!
//! RED STUB: the shape the rows in `heartbeat_tests.rs` drive, with no
//! behaviour yet. The implementation commit replaces every body.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::security::posture::SecurityPosture;

/// `project`, always this.
pub(crate) const PROJECT: &str = "mcp-gateway";
/// `event`, always this.
pub(crate) const EVENT: &str = "heartbeat";
/// The receiver. Release code holds only this URL.
pub(crate) const URL: &str = "https://telemetry.revaluator.ai/v1/heartbeat";
/// The opt-out variables: any value but empty, `0` or `false` turns it off.
pub(crate) const OPT_OUT: [&str; 2] = ["DO_NOT_TRACK", "NO_TELEMETRY"];
/// CI runners' own variables, with the same truthiness.
pub(crate) const CI: [&str; 18] = [
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "BUILDKITE",
    "DRONE",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
    "BITBUCKET_BUILD_NUMBER",
    "APPVEYOR",
    "CODEBUILD_BUILD_ID",
    "TF_BUILD",
    "CIRRUS_CI",
    "SEMAPHORE",
    "BITRISE_IO",
    "BUDDY",
];
/// Proxy variables: any non-empty value skips the heartbeat.
pub(crate) const PROXY: [&str; 6] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Which build this is: a build with debug assertions (or a test build) is
/// a development build and never sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Build {
    Dev,
    Release,
}

impl Build {
    /// This binary's build.
    pub(crate) const fn current() -> Self {
        if cfg!(debug_assertions) || cfg!(test) {
            Self::Dev
        } else {
            Self::Release
        }
    }
}

/// Everything the decision reads, taken once per check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) build: Build,
    pub(crate) posture: SecurityPosture,
    /// The named variables that are present, by name (values as read).
    pub(crate) env: BTreeMap<String, String>,
}

impl Snapshot {
    /// The snapshot `lookup` gives for the named variables.
    pub(crate) fn read(
        build: Build,
        posture: SecurityPosture,
        lookup: impl Fn(&str) -> Option<OsString>,
    ) -> Self {
        let _ = lookup;
        Self {
            build,
            posture,
            env: BTreeMap::new(),
        }
    }

    /// The process's own snapshot.
    pub(crate) fn from_process(posture: SecurityPosture) -> Self {
        Self::read(Build::current(), posture, |name| std::env::var_os(name))
    }
}

/// Why a check sends nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Skip {
    DevBuild,
    OptOut,
    Ci,
    Proxy,
    Hardened,
}

/// `Ok` when this snapshot may send.
pub(crate) fn decide(snapshot: &Snapshot) -> Result<(), Skip> {
    let _ = snapshot;
    Ok(())
}

/// What one check did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Skipped(Skip),
    NoId,
    NoClaim,
    DateMoved,
    Sent,
    Failed,
}

/// Today's UTC date (`None` when the clock reads before the epoch, which
/// sends nothing); injected so a row can move the day. Production reads
/// `crate::clock::utc_now`.
pub(crate) type Today = fn() -> Option<chrono::NaiveDate>;

/// One check: decide, read or publish the id, claim the day, re-read the
/// date, send. Awaited by rows; the task spawns it.
pub(crate) async fn heartbeat_once(
    snapshot: &Snapshot,
    dir: &Path,
    client: &reqwest::Client,
    url: &str,
    today: Today,
) -> Outcome {
    let _ = (snapshot, dir, client, url, today);
    Outcome::Failed
}

/// The client policy every heartbeat client shares: 3 s, no redirects, no
/// proxy, no cookies.
pub(crate) fn base_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

/// The release client: [`base_builder`] plus HTTPS only.
pub(crate) fn production_client() -> reqwest::Client {
    base_builder().build().unwrap_or_default()
}

/// Start the server's heartbeat task: a check at start, then hourly, ending
/// on `shutdown`.
pub(crate) fn start(
    posture: SecurityPosture,
    data_dir: PathBuf,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let _ = (posture, data_dir, shutdown);
    tokio::spawn(async {})
}

/// Test-only targets, keyed by data dir: a row registers its own temp dir, so
/// a server another row starts can never reach its listener. Compiled out of
/// release builds with the rest of `cfg(test)`.
#[cfg(test)]
pub(crate) mod seam {
    use std::path::{Path, PathBuf};

    /// What `start` uses for a registered data dir instead of the process's
    /// own build, URL, client and clock.
    pub(crate) struct Target {
        pub(crate) url: String,
        pub(crate) client: reqwest::Client,
        pub(crate) today: super::Today,
        /// The check interval for this dir (production: one hour).
        pub(crate) every: std::time::Duration,
        /// When set, the check's filesystem thread waits on it before its
        /// first filesystem call (a stalled disk).
        pub(crate) stall: Option<std::sync::mpsc::Receiver<()>>,
    }

    /// Removes the registration when dropped.
    pub(crate) struct Guard(PathBuf);

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = &self.0;
        }
    }

    /// Register `target` for `dir` (RED STUB: not yet consulted).
    pub(crate) fn register(dir: &Path, target: Target) -> Guard {
        let _ = target;
        Guard(dir.to_path_buf())
    }
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "heartbeat_tests.rs"]
mod tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "heartbeat_wiring_tests.rs"]
mod wiring_tests;

#[cfg(tp3)]
#[cfg(test)]
#[path = "heartbeat_fail_tests.rs"]
mod fail_tests;
