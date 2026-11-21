// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The daily anonymous heartbeat: at most one POST per UTC day per data
//! directory to the shared receiver, with five fields and nothing else.
//! Skipped in development builds, CI, a hardened install, a proxied
//! environment, and under `DO_NOT_TRACK` or `NO_TELEMETRY`. docs/PRIVACY.md,
//! "Daily heartbeat", states exactly what is sent and stored.

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
        let env = OPT_OUT
            .iter()
            .chain(CI.iter())
            .chain(PROXY.iter())
            .filter_map(|name| {
                lookup(name).map(|v| ((*name).to_owned(), v.to_string_lossy().into_owned()))
            })
            .collect();
        Self {
            build,
            posture,
            env,
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
    // Set and not empty, `0` or `false`: the opt-out and CI truthiness.
    let truthy = |name: &&str| {
        // Exact values: whitespace is a value, so `DO_NOT_TRACK=" "` opts out.
        snapshot
            .env
            .get(*name)
            .is_some_and(|v| !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false")))
    };
    if snapshot.build == Build::Dev {
        return Err(Skip::DevBuild);
    }
    if OPT_OUT.iter().any(truthy) {
        return Err(Skip::OptOut);
    }
    if CI.iter().any(truthy) {
        return Err(Skip::Ci);
    }
    if PROXY
        .iter()
        .any(|name| snapshot.env.get(*name).is_some_and(|v| !v.is_empty()))
    {
        return Err(Skip::Proxy);
    }
    if snapshot.posture == SecurityPosture::Hardened {
        return Err(Skip::Hardened);
    }
    Ok(())
}

/// What one check did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Skipped(Skip),
    NoId,
    NoClaim,
    /// The clock read before the epoch: no date, nothing claimed or sent.
    NoDate,
    DateMoved,
    Sent,
    Failed,
}

/// Today's UTC date (`None` when the clock reads before the epoch, which
/// sends nothing); injected so a row can move the day. Production reads
/// `crate::clock::utc_now`.
pub(crate) type Today = fn() -> Option<chrono::NaiveDate>;

/// The heartbeat's own dir under `data_dir`: created owner-only (and the new
/// entry synced into the data dir), or an existing one that is owner-only.
/// An existing dir that others can reach is left as it is and stops the check.
fn state_dir(data_dir: &Path) -> std::io::Result<PathBuf> {
    let dir = data_dir.join("heartbeat");
    std::fs::create_dir_all(data_dir)?;
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)
    };
    #[cfg(windows)]
    let created = crate::private_fs::create_dir_private(&dir);
    match created {
        Ok(()) => crate::config_persistence::sync_dir_of(&dir)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    require_private(&dir, Kind::Dir)?;
    Ok(dir)
}

/// What an existing entry must be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
}

/// `path` is a real `kind` (not a link) that only this account can reach.
fn require_private(path: &Path, kind: Kind) -> std::io::Result<()> {
    let refused =
        |why: &str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, why.to_owned());
    let meta = std::fs::symlink_metadata(path)?;
    let right_kind = match kind {
        Kind::Dir => meta.is_dir(),
        Kind::File => meta.is_file(),
    };
    if !right_kind {
        return Err(refused("not the expected kind of entry"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(refused("group or world access"));
        }
    }
    #[cfg(windows)]
    {
        let judged = match kind {
            Kind::Dir => crate::private_fs::open_dir(path).and_then(|f| {
                crate::private_fs::judge_dir(&f, path).map_err(|_| refused("not owner-only"))
            }),
            Kind::File => crate::private_fs::open_file_read(path).and_then(|f| {
                crate::private_fs::judge_file(&f).map_err(|_| refused("not owner-only"))
            }),
        };
        judged?;
    }
    Ok(())
}

/// The install id's exact form: 32 lowercase hex characters, nothing else.
fn is_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The published id, `None` when there is none yet. An entry that is not a
/// private file, or does not hold exactly an id, is an error: it is never
/// replaced, so that install stays silent rather than minting a second id.
fn read_install_id(dir: &Path) -> std::io::Result<Option<String>> {
    let path = dir.join("install-id");
    if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(None);
    }
    require_private(&path, Kind::File)?;
    let id = std::fs::read_to_string(&path)?;
    if !is_id(&id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not an install id",
        ));
    }
    Ok(Some(id))
}

/// Publish a new id whole: a private scratch file, synced, hard-linked to
/// `install-id` (a link never replaces a name). When another process won the
/// name first, its id is the one used.
fn publish_id(dir: &Path) -> std::io::Result<String> {
    use std::io::Write as _;
    let id = crate::ids::new_v4().simple().to_string();
    let scratch = dir.join(format!("scratch-{id}"));
    let written = crate::config_persistence::create_new_private(&scratch).and_then(|mut f| {
        f.write_all(id.as_bytes())?;
        f.sync_all()
    });
    let linked = written.and_then(|()| std::fs::hard_link(&scratch, dir.join("install-id")));
    let _ = std::fs::remove_file(&scratch);
    match linked {
        Ok(()) => {
            crate::config_persistence::sync_dir_of(&dir.join("install-id"))?;
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_install_id(dir)?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "the winner's id vanished")
            }),
        Err(e) => Err(e),
    }
}

/// Claim `date` for this data dir: `true` when this process made the claim.
/// Claims are never removed, so no clock change reopens a used date.
fn claim_day(dir: &Path, date: chrono::NaiveDate) -> std::io::Result<bool> {
    let path = dir.join(format!("day-{date}"));
    match crate::config_persistence::create_new_private(&path) {
        Ok(file) => {
            file.sync_all()?;
            crate::config_persistence::sync_dir_of(&path)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// The filesystem half of a check: the dir, the id, the day's claim. Runs
/// on its own thread; any failure stops the check before the send.
fn prepare(data_dir: &Path, date: chrono::NaiveDate) -> Result<String, Outcome> {
    let dir = state_dir(data_dir).map_err(|_| Outcome::NoId)?;
    let id = match read_install_id(&dir) {
        Ok(Some(id)) => id,
        Ok(None) => publish_id(&dir).map_err(|_| Outcome::NoId)?,
        Err(_) => return Err(Outcome::NoId),
    };
    match claim_day(&dir, date) {
        Ok(true) => Ok(id),
        Ok(false) | Err(_) => Err(Outcome::NoClaim),
    }
}

/// One check: decide, read or publish the id, claim the day, re-read the
/// date, send. Awaited by rows; the task spawns it.
pub(crate) async fn heartbeat_once(
    snapshot: &Snapshot,
    dir: &Path,
    client: &reqwest::Client,
    url: &str,
    today: Today,
) -> Outcome {
    if let Err(why) = decide(snapshot) {
        return Outcome::Skipped(why);
    }
    let Some(date) = today() else {
        return Outcome::NoDate;
    };
    // The filesystem work runs on a thread of its own, never a runtime
    // worker or the blocking pool: a stalled disk holds only that thread,
    // and the caller (the task) can stop waiting for it.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let data_dir = dir.to_path_buf();
    #[cfg(test)]
    let stall = seam::take_stall(&data_dir);
    let spawned = std::thread::Builder::new()
        .name("heartbeat-fs".to_owned())
        .spawn(move || {
            #[cfg(test)]
            if let Some(s) = &stall {
                let _ = s.reached.send(());
                let _ = s.release.recv();
            }
            let _ = tx.send(prepare(&data_dir, date));
            #[cfg(test)]
            if let Some(s) = stall {
                let _ = s.done.send(());
            }
        });
    if spawned.is_err() {
        return Outcome::NoId;
    }
    let id = match rx.await {
        Ok(Ok(id)) => id,
        Ok(Err(outcome)) => return outcome,
        Err(_) => return Outcome::NoId,
    };
    // A check whose filesystem work ran past midnight sends nothing: no
    // check sends for a date other than the one it claimed. (A request sent
    // just before midnight can still arrive just after it; register row.)
    if today() != Some(date) {
        return Outcome::DateMoved;
    }
    send(client, url, &id).await
}

/// The request: exactly the five fields. Any status but 2xx, and any error,
/// is a failed send; none is retried.
async fn send(client: &reqwest::Client, url: &str, install_id: &str) -> Outcome {
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        project: &'a str,
        event: &'a str,
        version: &'a str,
        runtime: String,
        install_id: &'a str,
    }
    let payload = Payload {
        project: PROJECT,
        event: EVENT,
        version: env!("CARGO_PKG_VERSION"),
        runtime: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        install_id,
    };
    let Ok(body) = serde_json::to_vec(&payload) else {
        return Outcome::Failed;
    };
    let sent = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await;
    match sent {
        Ok(response) if response.status().is_success() => Outcome::Sent,
        Ok(_) | Err(_) => {
            tracing::debug!("heartbeat not delivered");
            Outcome::Failed
        }
    }
}

/// The client policy every heartbeat client shares: 3 s, no redirects, no
/// proxy, no cookies.
pub(crate) fn base_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
}

/// The release client's builder: [`base_builder`] plus HTTPS only, with
/// certificate verification on. Shared so a row's trusting control differs
/// from the release client only by one extra root.
pub(crate) fn production_builder() -> reqwest::ClientBuilder {
    let builder = base_builder().https_only(true);
    // A row stands in for a build with no usable TLS backend: an unknown TLS
    // config makes `build()` fail the same way, so the fallback after a failed
    // build is what the row exercises.
    #[cfg(test)]
    if seam::release_client_broken() {
        return builder.use_preconfigured_tls(());
    }
    builder
}

/// The release client, or `None` when it cannot be built (no TLS backend):
/// then nothing is sent, rather than a client without these limits.
pub(crate) fn production_client() -> Option<reqwest::Client> {
    // `base_builder` already refuses redirects; the policy is stated again on
    // the chain that builds, because the redirect scan (security::ssrf) reads only
    // the function that calls `build()`.
    production_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
}

/// Where and how the release task sends: the literal receiver URL and the
/// release client. The task reads only this outside a test.
pub(crate) fn production_target() -> Option<(&'static str, reqwest::Client)> {
    production_client().map(|client| (URL, client))
}

/// What the task for one data dir uses.
pub(crate) struct Resolved {
    pub(crate) url: String,
    pub(crate) client: reqwest::Client,
    pub(crate) today: Today,
    pub(crate) every: std::time::Duration,
    /// True only for a target a test registered for this dir.
    pub(crate) from_seam: bool,
}

/// The target `start` uses for `data_dir`: a registered test target (test
/// builds only), else [`production_target`], the system clock and one hour;
/// `None` when the release client cannot be built.
pub(crate) fn resolve(data_dir: &Path) -> Option<Resolved> {
    #[cfg(test)]
    if let Some(registered) = seam::resolved(data_dir) {
        return Some(registered);
    }
    #[cfg(not(test))]
    let _ = data_dir;
    let (url, client) = production_target()?;
    Some(Resolved {
        url: url.to_owned(),
        client,
        today: utc_today,
        every: std::time::Duration::from_secs(3600),
        from_seam: false,
    })
}

/// The system clock's UTC date; `None` before the epoch.
fn utc_today() -> Option<chrono::NaiveDate> {
    crate::clock::utc_now().ok().map(|now| now.date_naive())
}

/// Start the server's heartbeat task: a check at start, then hourly, ending
/// on `shutdown`. Neither startup nor a request ever awaits it.
pub(crate) fn start(
    posture: SecurityPosture,
    data_dir: PathBuf,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // No release client (no TLS backend): the task ends and sends nothing.
        let Some(target) = resolve(&data_dir) else {
            tracing::debug!("heartbeat off: no client");
            return;
        };
        loop {
            // A registered test target stands for a release build with
            // nothing set; everything else reads this process.
            let snapshot = if target.from_seam {
                Snapshot {
                    build: Build::Release,
                    posture,
                    env: BTreeMap::new(),
                }
            } else {
                Snapshot::from_process(posture)
            };
            let check = heartbeat_once(
                &snapshot,
                &data_dir,
                &target.client,
                &target.url,
                target.today,
            );
            // Shutdown wins over a check in flight and over the wait.
            tokio::select! {
                _ = shutdown.recv() => return,
                outcome = check => {
                    // A row waits on this event, never on a sleep.
                    #[cfg(test)]
                    seam::record(&data_dir, outcome);
                    #[cfg(not(test))]
                    let _ = outcome;
                }
            }
            tokio::select! {
                _ = shutdown.recv() => return,
                () = tokio::time::sleep(target.every) => {}
            }
        }
    })
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
        /// When set, the check's filesystem thread stalls before its first
        /// filesystem call (a stalled disk).
        pub(crate) stall: Option<Stall>,
    }

    /// A stalled disk: the filesystem thread sends `reached` on arrival,
    /// waits for `release`, and sends `done` as it exits.
    pub(crate) struct Stall {
        pub(crate) reached: std::sync::mpsc::Sender<()>,
        pub(crate) release: std::sync::mpsc::Receiver<()>,
        pub(crate) done: std::sync::mpsc::Sender<()>,
    }

    /// Removes the registration when dropped.
    pub(crate) struct Guard(PathBuf);

    impl Drop for Guard {
        fn drop(&mut self) {
            targets().remove(&self.0);
            outcomes_by_dir().remove(&self.0);
        }
    }

    /// The registered targets, by data dir.
    fn targets() -> std::sync::MutexGuard<'static, std::collections::BTreeMap<PathBuf, Target>> {
        static TARGETS: std::sync::Mutex<std::collections::BTreeMap<PathBuf, Target>> =
            std::sync::Mutex::new(std::collections::BTreeMap::new());
        TARGETS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register `target` for `dir`, until the guard drops.
    pub(crate) fn register(dir: &Path, target: Target) -> Guard {
        targets().insert(dir.to_path_buf(), target);
        Guard(dir.to_path_buf())
    }

    /// What `start` uses for a registered `dir`.
    pub(super) fn resolved(dir: &Path) -> Option<super::Resolved> {
        targets().get(dir).map(|t| super::Resolved {
            url: t.url.clone(),
            client: t.client.clone(),
            today: t.today,
            every: t.every,
            from_seam: true,
        })
    }

    /// The stall registered for `dir`, taken once.
    /// What the started task's checks returned, by data dir.
    fn outcomes_by_dir()
    -> std::sync::MutexGuard<'static, std::collections::BTreeMap<PathBuf, Vec<super::Outcome>>>
    {
        static OUTCOMES: std::sync::Mutex<
            std::collections::BTreeMap<PathBuf, Vec<super::Outcome>>,
        > = std::sync::Mutex::new(std::collections::BTreeMap::new());
        OUTCOMES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Record a finished check for a registered `dir`.
    pub(super) fn record(dir: &Path, outcome: super::Outcome) {
        if targets().contains_key(dir) {
            outcomes_by_dir()
                .entry(dir.to_path_buf())
                .or_default()
                .push(outcome);
        }
    }

    /// The outcomes of every check the task ran for `dir`, in order.
    pub(crate) fn outcomes(dir: &Path) -> Vec<super::Outcome> {
        outcomes_by_dir().get(dir).cloned().unwrap_or_default()
    }

    pub(super) fn take_stall(dir: &Path) -> Option<Stall> {
        targets().get_mut(dir).and_then(|t| t.stall.take())
    }

    // Per thread: a `#[tokio::test]` runtime is single-threaded, so the task
    // `start` spawns sees the flag of the row that set it, and no other row does.
    thread_local! {
        static NO_RELEASE_CLIENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// While this is held, the release client cannot be built on this thread.
    pub(crate) struct ClientBroken;

    impl Drop for ClientBroken {
        fn drop(&mut self) {
            NO_RELEASE_CLIENT.with(|flag| flag.set(false));
        }
    }

    /// Make [`super::production_builder`]'s client fail to build on this
    /// thread until the returned guard drops.
    pub(crate) fn break_release_client() -> ClientBroken {
        NO_RELEASE_CLIENT.with(|flag| flag.set(true));
        ClientBroken
    }

    pub(super) fn release_client_broken() -> bool {
        NO_RELEASE_CLIENT.with(std::cell::Cell::get)
    }
}

#[cfg(test)]
#[path = "heartbeat_fixtures.rs"]
pub(crate) mod fixtures;

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

// The source scans (D10-D12, DOC1) live in gateway::meta_mcp::boundary_pins::heartbeat_scans,
// beside the packaged-crate helper their repo reads need.
