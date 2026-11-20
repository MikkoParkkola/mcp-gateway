// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The daily anonymous heartbeat: at most one POST per UTC day per data
//! directory to the shared receiver, with five fields and nothing else.
//! Skipped on Windows (the 3.5 line sends none there), in development
//! builds, CI and a proxied environment, and under `DO_NOT_TRACK` or
//! `NO_TELEMETRY`. README.md, "Privacy", states exactly what is sent and stored.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

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
    /// The operating system: `std::env::consts::OS` in production.
    pub(crate) os: &'static str,
    /// The named variables that are present, by name (values as read).
    pub(crate) env: BTreeMap<String, String>,
}

impl Snapshot {
    /// The snapshot `lookup` gives for the named variables.
    pub(crate) fn read(
        build: Build,
        os: &'static str,
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
        Self { build, os, env }
    }

    /// The process's own snapshot.
    pub(crate) fn from_process() -> Self {
        Self::read(Build::current(), std::env::consts::OS, |name| {
            std::env::var_os(name)
        })
    }
}

/// Why a check sends nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Skip {
    DevBuild,
    OptOut,
    Ci,
    Proxy,
    /// Windows: the 3.5 line keeps no heartbeat state there.
    Windows,
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
    if snapshot.os == "windows" {
        return Err(Skip::Windows);
    }
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
    Ok(())
}

/// What one check did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Skipped(Skip),
    NoId,
    /// The day was already claimed. Unix only in use: the 3.5 line makes no
    /// claim on Windows.
    #[cfg_attr(not(unix), allow(dead_code))]
    NoClaim,
    /// The clock read before the epoch: no date, nothing claimed or sent.
    NoDate,
    DateMoved,
    Sent,
    Failed,
}

/// Today's UTC date (`None` when the clock reads before the epoch, which
/// sends nothing); injected so a row can move the day. Production reads
/// `chrono::Utc::now`.
pub(crate) type Today = fn() -> Option<chrono::NaiveDate>;

/// A new owner-only (0o600) file at `path`, refused when anything is there.
#[cfg(unix)]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Make the entry `path` durable in its directory: sync the parent dir.
#[cfg(unix)]
fn sync_dir_of(path: &Path) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir)?.sync_all()
}

/// Off unix there is no heartbeat state, so a check never touches a file.
#[cfg(not(unix))]
fn prepare(_data_dir: &Path, _date: chrono::NaiveDate) -> Result<String, Outcome> {
    Err(Outcome::Skipped(Skip::Windows))
}

/// The heartbeat's own dir under `data_dir`: created owner-only (and the new
/// entry synced into the data dir), or an existing one that is owner-only.
/// An existing dir that others can reach is left as it is and stops the check.
/// Unix only: the 3.5 line keeps no heartbeat state on Windows.
#[cfg(unix)]
fn state_dir(data_dir: &Path) -> std::io::Result<PathBuf> {
    let dir = data_dir.join("heartbeat");
    std::fs::create_dir_all(data_dir)?;
    let created = {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new().mode(0o700).create(&dir)
    };
    match created {
        Ok(()) => sync_dir_of(&dir)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    require_private(&dir, Kind::Dir)?;
    Ok(dir)
}

/// What an existing entry must be.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
}

/// `path` is a real `kind` (not a link) that only this account can reach.
#[cfg(unix)]
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
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(refused("group or world access"));
        }
    }
    Ok(())
}

/// The install id's exact form: 32 lowercase hex characters, nothing else.
#[cfg(unix)]
fn is_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The published id, `None` when there is none yet. An entry that is not a
/// private file, or does not hold exactly an id, is an error: it is never
/// replaced, so that install stays silent rather than minting a second id.
#[cfg(unix)]
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
#[cfg(unix)]
fn publish_id(dir: &Path) -> std::io::Result<String> {
    use std::io::Write as _;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let scratch = dir.join(format!("scratch-{id}"));
    let written = create_new_private(&scratch).and_then(|mut f| {
        f.write_all(id.as_bytes())?;
        f.sync_all()
    });
    let linked = written.and_then(|()| std::fs::hard_link(&scratch, dir.join("install-id")));
    let _ = std::fs::remove_file(&scratch);
    match linked {
        Ok(()) => {
            sync_dir_of(&dir.join("install-id"))?;
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
#[cfg(unix)]
fn claim_day(dir: &Path, date: chrono::NaiveDate) -> std::io::Result<bool> {
    let path = dir.join(format!("day-{date}"));
    match create_new_private(&path) {
        Ok(file) => {
            file.sync_all()?;
            sync_dir_of(&path)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// The filesystem half of a check: the dir, the id, the day's claim. Runs
/// on its own thread; any failure stops the check before the send.
#[cfg(unix)]
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
    /// The variables a registered target's snapshot carries (empty outside a
    /// test): how a start-site row sets an opt-out without `set_var`.
    pub(crate) seam_env: BTreeMap<String, String>,
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
        seam_env: BTreeMap::new(),
    })
}

/// The data dir the server's heartbeat uses: the gateway's data dir,
/// resolved as 4.0 resolves it (`MCP_GATEWAY_CONFIG_DIR`, else
/// home/.mcp-gateway), so 3.5.3 and 4.0 keep one install id. Not the 3.5
/// server's own data dir, which ignores that variable.
// One signature with the test build's `root`, which has none when no row
// registered one.
#[allow(clippy::unnecessary_wraps)]
#[cfg(not(test))]
pub(crate) fn root() -> Option<PathBuf> {
    Some(crate::config_persistence::gateway_data_dir())
}

/// In a test build only a root a row registered on this thread counts, and
/// with none the server starts no heartbeat: never the real home.
#[cfg(test)]
pub(crate) fn root() -> Option<PathBuf> {
    seam::registered_root()
}

/// The system clock's UTC date; `None` when the clock reads before the epoch,
/// which sends nothing (as on 4.0, whose clock refuses such a time).
fn utc_today() -> Option<chrono::NaiveDate> {
    date_of(std::time::SystemTime::now())
}

/// The UTC date of `at`, or `None` before the epoch: [`utc_today`] at a time
/// a row can choose.
fn date_of(at: std::time::SystemTime) -> Option<chrono::NaiveDate> {
    let since = at.duration_since(std::time::UNIX_EPOCH).ok()?;
    let secs = i64::try_from(since.as_secs()).ok()?;
    chrono::DateTime::from_timestamp(secs, 0).map(|t| t.date_naive())
}

/// Start the server's heartbeat task: a check at start, then hourly, ending
/// on `shutdown`. Neither startup nor a request ever awaits it.
pub(crate) fn start(
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
                    os: std::env::consts::OS,
                    env: target.seam_env.clone(),
                }
            } else {
                Snapshot::from_process()
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
            envs().remove(&self.0);
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

    /// The variables registered for a dir's snapshot, by data dir.
    fn envs() -> std::sync::MutexGuard<
        'static,
        std::collections::BTreeMap<PathBuf, super::BTreeMap<String, String>>,
    > {
        static ENVS: std::sync::Mutex<
            std::collections::BTreeMap<PathBuf, super::BTreeMap<String, String>>,
        > = std::sync::Mutex::new(std::collections::BTreeMap::new());
        ENVS.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Give the target registered for `dir` these variables in its snapshot
    /// (W1', W2': an opt-out set on the start site's own input, never `set_var`).
    /// Unix only, as the start rows that use it are.
    #[cfg(unix)]
    pub(crate) fn set_env(dir: &Path, env: &[(&str, &str)]) {
        envs().insert(
            dir.to_path_buf(),
            env.iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        );
    }

    thread_local! {
        static ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    }

    /// Clears this thread's root when dropped.
    #[cfg(unix)]
    pub(crate) struct RootGuard;

    #[cfg(unix)]
    impl Drop for RootGuard {
        fn drop(&mut self) {
            ROOT.with(|r| *r.borrow_mut() = None);
        }
    }

    /// Make `dir` the root a server started on this thread uses, until the
    /// guard drops. Unix only, as the start rows that use it are.
    #[cfg(unix)]
    pub(crate) fn register_root(dir: &Path) -> RootGuard {
        ROOT.with(|r| *r.borrow_mut() = Some(dir.to_path_buf()));
        RootGuard
    }

    /// This thread's registered root.
    pub(super) fn registered_root() -> Option<PathBuf> {
        ROOT.with(|r| r.borrow().clone())
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
            seam_env: envs().get(dir).cloned().unwrap_or_default(),
        })
    }

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

    /// The stall registered for `dir`, taken once.
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

#[cfg(test)]
#[path = "heartbeat_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "heartbeat_wiring_tests.rs"]
mod wiring_tests;

#[cfg(test)]
#[path = "heartbeat_fail_tests.rs"]
mod fail_tests;

#[cfg(test)]
#[path = "heartbeat_scan_tests.rs"]
mod scan_tests;
