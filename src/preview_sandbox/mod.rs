// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Start a typed command server once, sandboxed, so the web UI can list its
//! tools before the server is added (ADR-027).
//!
//! A preview runs inside a per-OS sandbox or does not run at all: where the
//! host cannot provide one, [`start`] answers a [`Refusal`] naming the reason
//! and, where one exists, the one-time step that fixes it. There is no
//! unsandboxed fallback and no setting that turns the sandbox off.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;

/// Every other OS: no sandbox in this release, so every command preview is
/// refused and no helper subcommand exists.
#[cfg(not(target_os = "linux"))]
mod os {
    use super::{Refusal, Started, Target};

    pub(super) fn dispatch(_: &[std::ffi::OsString]) -> Option<std::process::ExitCode> {
        None
    }

    pub(super) fn start(
        _: &std::path::Path,
        _: &Target,
        _: &[std::path::PathBuf],
    ) -> Result<Started, Refusal> {
        Err(Refusal::Unsupported)
    }

    pub(super) fn classify(stderr: &str) -> Refusal {
        Refusal::Step(stderr.trim().to_owned())
    }
}

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncReadExt as _;

/// The command to preview: a program and its arguments, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

/// A sandboxed preview process. Its stdio is piped: the caller speaks MCP on
/// stdin and stdout, and reads a refusal from stderr. Dropping `child` ends
/// the sandbox and everything in it.
#[derive(Debug)]
pub struct Started {
    pub child: tokio::process::Child,
    pub isolation: Isolation,
}

/// What the sandbox enforced, built from the same table that drove the binds,
/// so the UI cannot describe isolation the host did not provide (SBX.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Isolation {
    pub os: &'static str,
    /// Read-only paths. Anything under `hidden` is empty inside even where
    /// it lies below one of these.
    pub readable: Vec<String>,
    /// Paths covered by an empty read-only mount: system secrets and the
    /// gateway's own state, config and data.
    pub hidden: Vec<String>,
    pub writable: Vec<String>,
    pub network: Network,
    pub cleanup: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Network {
    /// Where the fetch phase may connect; `None` when there is no fetch phase.
    pub fetch: Option<&'static str>,
    pub run: &'static str,
}

impl Isolation {
    #[cfg(target_os = "linux")]
    fn linux(plan: &linux::plan::Plan) -> Self {
        Self {
            os: "linux",
            readable: plan
                .read_only
                .iter()
                .chain(&plan.bound_back)
                .cloned()
                .collect(),
            hidden: plan.masked.iter().chain(&plan.hidden).cloned().collect(),
            // The fresh home and /tmp, the two writable devices and the PID
            // namespace's own /proc: the mounts the helper leaves writable.
            writable: [linux::plan::HOME, "/tmp", "/dev/null", "/dev/zero", "/proc"]
                .map(ToOwned::to_owned)
                .into(),
            network: Network {
                fetch: None,
                run: "none",
            },
            cleanup: "process namespace killed",
        }
    }
}

/// Why a command preview cannot run on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Ubuntu 23.10 and later restrict unprivileged user namespaces through
    /// `AppArmor` until a profile allows them for this binary.
    AppArmorRestricted,
    /// `user.max_user_namespaces = 0` (STIG-hardened RHEL and the like).
    UserNamespacesDisabled,
    /// Inside a container, whose seccomp profile denies new namespaces.
    Container,
    /// A tool the sandbox starts is not installed.
    MissingTool(&'static str),
    /// This operating system has no sandbox in this release.
    Unsupported,
    /// A sandbox step failed; the text names the step and the error.
    Step(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::AppArmorRestricted => "command previews need unprivileged user namespaces, \
                 which this host's AppArmor restricts \
                 (kernel.apparmor_restrict_unprivileged_userns = 1); the one-time fix, as \
                 root, is the AppArmor profile in SECURITY.md, loaded with apparmor_parser -r"
                .to_owned(),
            Self::UserNamespacesDisabled => "command previews need user namespaces, which this \
                 host's hardening turns off (user.max_user_namespaces = 0)"
                .to_owned(),
            Self::Container => "command previews cannot nest their sandbox inside a container; \
                 preview from a host install"
                .to_owned(),
            Self::MissingTool(tool) => {
                format!("command previews need {tool}, which is not installed")
            }
            Self::Unsupported => {
                "command previews need a sandbox this platform does not have in 4.0.0".to_owned()
            }
            Self::Step(step) => format!("the command preview sandbox failed at {step}"),
        };
        write!(f, "{text}; the server can still be added without a preview")
    }
}

impl std::error::Error for Refusal {}

/// Run the helper subcommand `args` names, if any. `main` calls this first,
/// before the CLI parser, the main-stack thread and any runtime, so the helper
/// is single-threaded when it changes its own privileges.
#[must_use]
pub fn dispatch_helper(args: &[OsString]) -> Option<ExitCode> {
    os::dispatch(args)
}

/// Start `target` in the sandbox. `protected` adds the gateway's own config
/// paths (the loaded config file's directory) to those it hides itself.
///
/// # Errors
///
/// A [`Refusal`] when the sandbox cannot be set up on this host. The
/// sandbox's own steps refuse from inside the child; [`probe`] reads those.
pub fn start(target: &Target, protected: &[PathBuf]) -> Result<Started, Refusal> {
    let gateway = std::env::current_exe()
        .map_err(|e| Refusal::Step(format!("finding the gateway binary ({e})")))?;
    os::start(&gateway, target, protected)
}

/// [`start`] with the gateway binary named, for integration tests, whose own
/// executable is the test harness rather than the gateway.
///
/// # Errors
///
/// As [`start`].
#[doc(hidden)]
pub fn start_with_helper(
    gateway: &Path,
    target: &Target,
    protected: &[PathBuf],
) -> Result<Started, Refusal> {
    os::start(gateway, target, protected)
}

/// How long the probe's `/bin/true` may take through the whole setup.
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

/// Run the real setup once with `/bin/true` as the target. Any failure is the
/// refusal every command preview answers.
///
/// # Errors
///
/// The [`Refusal`] naming the step that failed.
pub async fn probe() -> Result<(), Refusal> {
    let target = Target {
        program: PathBuf::from("/bin/true"),
        args: Vec::new(),
    };
    let Started { mut child, .. } = start(&target, &[])?;
    drop(child.stdin.take());
    let mut stderr = child.stderr.take();
    let finished = tokio::time::timeout(PROBE_DEADLINE, async {
        let mut text = String::new();
        if let Some(stderr) = stderr.as_mut() {
            // Bounded by the deadline; the helper prints one line at most.
            let _ = stderr.take(64 * 1024).read_to_string(&mut text).await;
        }
        (child.wait().await, text)
    })
    .await;
    match finished {
        Ok((Ok(status), _)) if status.success() => Ok(()),
        Ok((Ok(_), stderr)) => Err(os::classify(&stderr)),
        Ok((Err(e), _)) => Err(Refusal::Step(format!("waiting for the probe ({e})"))),
        // Dropping the child kills `unshare` and the namespace with it.
        Err(_) => Err(Refusal::Step(format!(
            "the probe (no answer within {} s)",
            PROBE_DEADLINE.as_secs()
        ))),
    }
}

static AVAILABILITY: tokio::sync::OnceCell<Result<(), Refusal>> =
    tokio::sync::OnceCell::const_new();

/// The probe's answer, run once and kept for the life of the process.
pub async fn availability() -> &'static Result<(), Refusal> {
    AVAILABILITY.get_or_init(probe).await
}
