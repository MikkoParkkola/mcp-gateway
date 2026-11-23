// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's two halves of a preview's start (ADR-027). [`prepare`] does
//! everything before `unshare` exists: the plan, the control socket the
//! helper reports over and, for a fetch, the preview's proxy. [`launch_prepared`]
//! spawns `unshare` and returns only once the helper has sent its setup
//! status and closed the connection; any refusal after the spawn kills
//! `unshare` and waits up to [`TEARDOWN_CAP`] for it.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use tokio::process::{Child, ChildStderr};

use super::plan::{FetchPaths, Plan};
use super::{
    Ambient, HostFacts, build_plan, ca_bundle, find_unshare, utf8, uv_probe, with_elapsed,
};
use crate::preview_sandbox::control::{
    CONTROL_BOUNDS, ControlBounds, Ended, accept_helper, serve_control_marked,
};
use crate::preview_sandbox::control_msg::SetupStatus;
use crate::preview_sandbox::proxy::{AllowlistProxy, Connect, Resolve, System};
use crate::preview_sandbox::{Isolation, Refusal, StartFailed, Started, TEARDOWN_CAP, Target};

/// Whether a preview has a fetch phase, and if so the resolver and dialer
/// its proxy uses: production passes `System`, only the rows' fakes others.
pub(super) enum Phase {
    /// The helper builds the root, reports, and the target runs.
    Run,
    /// The fetch step first, through the preview's own proxy.
    Fetch {
        resolve: Arc<dyn Resolve>,
        connect: Arc<dyn Connect>,
    },
}

/// A non-fetching preview's owner-only directory for its control socket,
/// removed with everything in it when this drops (a fetching preview's
/// socket sits in its proxy's directory instead).
pub(super) struct ControlDir(PathBuf);

impl ControlDir {
    fn new(runtime_dir: Option<std::ffi::OsString>) -> std::io::Result<Self> {
        use crate::preview_sandbox::proxy::{private_dir, runtime_base};
        private_dir(&runtime_base(runtime_dir)).map(Self)
    }
}

impl Drop for ControlDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Everything a launch needs, made before `unshare` exists. Its fields drop
/// in order: the listener, then the proxy and its directory, then the
/// control directory.
pub(super) struct Prepared {
    pub(super) unshare: &'static Path,
    pub(super) plan: Plan,
    /// Taken by the one launch.
    pub(super) listener: Option<tokio::net::UnixListener>,
    pub(super) proxy: Option<AllowlistProxy>,
    /// Held for its drop alone, which removes the directory.
    pub(super) _control_dir: Option<ControlDir>,
}

impl Prepared {
    /// What the sandbox enforces for this preview, from the plan that drives
    /// the binds and, when the plan fetches a package, from the proxy's own
    /// allowlist: the one place a started preview's record is built.
    pub(super) fn isolation(&self) -> Isolation {
        let mut isolation = Isolation::linux(&self.plan);
        let fetches = self
            .plan
            .fetch
            .as_ref()
            .is_some_and(|f| f.npm.is_some() || f.uv.is_some());
        if let (true, Some(proxy)) = (fetches, &self.proxy) {
            isolation.network.fetch = Some(proxy.allowlist());
        }
        isolation
    }
}

/// Everything before the spawn: `unshare` found, the plan built, the control
/// listener bound and, for a fetch, the proxy, the CA snapshot and the
/// package's fetch planned. Nothing is left behind on a refusal. Binding
/// needs a current tokio runtime.
pub(super) fn prepare(
    target: &Target,
    protected: &[PathBuf],
    ambient: Ambient,
    phase: Phase,
) -> Result<Prepared, Refusal> {
    let Ambient {
        ca_bundle,
        runtime_dir,
        path,
    } = ambient;
    let unshare = find_unshare()?;
    let mut plan = build_plan(target, protected, path.as_deref())?;
    let (control, proxy, control_dir) = match phase {
        Phase::Run => {
            let dir = ControlDir::new(runtime_dir).map_err(|e| {
                Refusal::Step(format!("making the control socket's directory ({e})"))
            })?;
            (dir.0.join("control.sock"), None, Some(dir))
        }
        Phase::Fetch { resolve, connect } => {
            let proxy = AllowlistProxy::bind(runtime_dir, resolve, connect, Arc::new(System))
                .map_err(|e| Refusal::Step(format!("starting the fetch proxy ({e})")))?;
            // Beside the proxy socket, in the proxy's owner-only directory,
            // removed with it when the proxy drops.
            let control = proxy.unix_path().with_file_name("control.sock");
            (control, Some(proxy), None)
        }
    };
    let listener = tokio::net::UnixListener::bind(&control)
        .map_err(|e| Refusal::Step(format!("binding the control socket ({e})")))?;
    plan.control = utf8(&control)?;
    if let Some(proxy) = &proxy {
        // The one CA bundle the fetch trusts, chosen here and snapshotted by
        // its bytes beside the sockets, so it goes with the proxy's directory.
        let bundle = ca_bundle::HostBundle::choose(ca_bundle.as_deref(), Path::new("/"))?;
        let ca = bundle
            .snapshot(proxy.unix_path().parent().unwrap_or(Path::new("/")))
            .map_err(|e| {
                Refusal::Step(format!(
                    "writing the CA snapshot of {} ({e})",
                    bundle.source.display()
                ))
            })?;
        let (npm, uv) =
            uv_probe::package_fetch(target, &mut plan, path.as_deref(), proxy.unix_path())?;
        plan.fetch = Some(FetchPaths {
            ca: utf8(&ca)?,
            npm,
            uv,
        });
    }
    Ok(Prepared {
        unshare,
        plan,
        listener: Some(listener),
        proxy,
        _control_dir: control_dir,
    })
}

/// How a refused launch ended, for the one caller that may read stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum How {
    /// A status, a session error or a fetch that had begun decided it.
    Reported,
    /// `unshare` ended first, with no status and no credential out: the host
    /// refused before any helper step could be reported.
    EndedSilently,
}

/// A refused launch's ending: how it ended and the child's untouched
/// stderr, taken before the kill. Only the probe reads that stderr.
pub(super) struct Ending {
    pub(super) how: How,
    pub(super) stderr: Option<ChildStderr>,
}

/// The wait a refused launch gives its killed `unshare`: production waits
/// for the exit; rows pass futures that never end or end on cue.
pub(super) type Reap = for<'c> fn(&'c mut Child) -> Pin<Box<dyn Future<Output = ()> + Send + 'c>>;

/// The production [`Reap`]: the child's own exit.
pub(super) fn reap_exit(child: &mut Child) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
    Box::pin(async move {
        let _ = child.wait().await;
    })
}

/// Spawn `unshare` with the helper and serve the helper's session to its
/// status. A run never reads the child's stderr: it may hold package output.
pub(super) async fn launch_prepared(
    prepared: &mut Prepared,
    helper: &Path,
    deadline: tokio::time::Instant,
) -> Result<Started, Box<StartFailed>> {
    let unshare = prepared.unshare;
    let spawn = |plan: &Plan| super::launch(unshare, helper, plan);
    let (launched, _ending) =
        launch_with(prepared, spawn, deadline, CONTROL_BOUNDS, reap_exit).await;
    // Boxed: a refusal may carry the unreaped process, which makes the error
    // large beside a started preview.
    launched.map_err(Box::new)
}

/// [`launch_prepared`] with the spawn, the bounds and the reap given, and,
/// beside a refusal, how the launch ended with the child's stderr: the probe
/// reads that stderr, every run drops it unread.
pub(super) async fn launch_with(
    prepared: &mut Prepared,
    spawn: impl FnOnce(&Plan) -> Result<Child, Refusal>,
    deadline: tokio::time::Instant,
    bounds: ControlBounds,
    reap: Reap,
) -> (Result<Started, StartFailed>, Option<Ending>) {
    // The fetch step's clock starts here, at the launch; the prepare (plan,
    // sockets, version probes) is not part of that step. Only the fetch
    // half's refusals (Ended::Fetch) say how far into the step they came; a
    // spawn failure, a status refusal and an early exit carry no time.
    let begun = tokio::time::Instant::now();
    let Some(listener) = prepared.listener.take() else {
        let refusal = Refusal::Step("launching the preview (it was launched already)".into());
        return (
            Err(StartFailed {
                refusal,
                unreaped: None,
            }),
            None,
        );
    };
    let mut child = match spawn(&prepared.plan) {
        Ok(child) => child,
        Err(refusal) => {
            return (
                Err(StartFailed {
                    refusal,
                    unreaped: None,
                }),
                None,
            );
        }
    };
    let (refusal, how) = match child.id() {
        None => (
            Refusal::Step("unshare ended as it started".into()),
            How::EndedSilently,
        ),
        Some(unshare_pid) => {
            let uid = rustix::process::getuid().as_raw();
            let proxy = prepared.proxy.as_ref();
            let session = async {
                let stream = accept_helper(listener, unshare_pid, uid, bounds, deadline)
                    .await
                    .map_err(Ended::Status)?;
                serve_control_marked(stream, proxy, deadline, bounds).await
            };
            // tokio's `Child::wait` closes the child's stdin when first polled,
            // and the race below polls it at once: the preview's stdin stays out
            // of its reach until the race is over.
            let stdin = child.stdin.take();
            let served = tokio::select! {
                served = session => Some(served),
                _ = child.wait() => None,
            };
            child.stdin = stdin;
            match served {
                Some(Ok(SetupStatus::Done)) => {
                    let isolation = prepared.isolation();
                    return (Ok(Started { child, isolation }), None);
                }
                Some(Ok(SetupStatus::Refused { step, denied })) => (
                    step.refusal(denied, HostFacts::read().restricts_userns()),
                    How::Reported,
                ),
                Some(Err(Ended::Fetch(refusal))) => (with_elapsed(refusal, begun), How::Reported),
                Some(Err(Ended::Status(refusal))) => (refusal, How::Reported),
                None => ended_first(
                    prepared
                        .proxy
                        .as_ref()
                        .is_some_and(|p| p.fetches_begun() > 0),
                ),
            }
        }
    };
    let stderr = child.stderr.take();
    let failed = tear_down(child, refusal, reap).await;
    (Err(failed), Some(Ending { how, stderr }))
}

/// The refusal when `unshare` ended before any status: fixed words, since
/// once a credential was out its stderr may hold npm output, URLs or paths,
/// and before that it may hold what a queued helper wrote for the target.
pub(super) fn ended_first(credential_issued: bool) -> (Refusal, How) {
    if credential_issued {
        (
            Refusal::Step("the fetch (the sandbox ended before it finished)".into()),
            How::Reported,
        )
    } else {
        (
            Refusal::Step("the sandbox helper sent no valid status".into()),
            How::EndedSilently,
        )
    }
}

/// Kill `child` and give `reap` up to [`TEARDOWN_CAP`]: reaped in time, the
/// refusal alone; not, the killed process rides back with it.
pub(super) async fn tear_down(mut child: Child, refusal: Refusal, reap: Reap) -> StartFailed {
    // Ignored: unshare may already be gone.
    let _ = child.start_kill();
    let reaped = tokio::time::timeout(TEARDOWN_CAP, reap(&mut child))
        .await
        .is_ok();
    StartFailed {
        refusal,
        unreaped: (!reaped).then_some(child),
    }
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "launcher_tests.rs"]
mod tests;
