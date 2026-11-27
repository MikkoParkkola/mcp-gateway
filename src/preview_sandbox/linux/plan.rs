// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the gateway tells `__preview-sandbox` and `__preview-drop`: one JSON
//! argument each, built by the launcher from the path table.
//!
//! Paths are UTF-8 here; the launcher refuses a preview whose paths are not,
//! rather than carrying raw bytes through an argument.

use std::ffi::CStr;

use serde::{Deserialize, Serialize};

/// The gateway's own namespace inodes. The helper compares `/proc/self/ns/*`
/// against them and refuses unless every one differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HostNamespaces {
    pub(crate) user: u64,
    pub(crate) mnt: u64,
    pub(crate) pid: u64,
    pub(crate) net: u64,
    pub(crate) ipc: u64,
    pub(crate) uts: u64,
}

/// Resource limits `__preview-drop` sets on itself before the exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Limits {
    pub(crate) address_space: u64,
    pub(crate) file_size: u64,
    pub(crate) open_files: u64,
    pub(crate) processes: u64,
}

/// Everything the helper does inside the namespaces, in plan form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Plan {
    pub(crate) host: HostNamespaces,
    /// Host paths bound read-only at the same path in the new root. A host
    /// symlink is recreated as a symlink, so merged-`/usr` hosts keep `/bin`.
    pub(crate) read_only: Vec<String>,
    /// System paths covered by an empty read-only tmpfs (directories) or an
    /// empty read-only file (files) once the binds are in place; the
    /// interpreter's bind-backs are restored under them.
    pub(crate) masked: Vec<String>,
    /// The gateway's own state, config and data paths, covered the same way
    /// after the system masks and their bind-backs, and never bound back.
    pub(crate) hidden: Vec<String>,
    /// Paths bound back read-only under a mask (an interpreter under
    /// `/usr/local`).
    pub(crate) bound_back: Vec<String>,
    pub(crate) limits: Limits,
    /// The run phase's environment, already filtered by the launcher.
    pub(crate) env: Vec<(String, String)>,
    /// The absolute file the drop execs.
    pub(crate) program: String,
    /// The argv: the name the program was asked for, then its arguments.
    pub(crate) target: Vec<String>,
    /// The gateway's control socket (a host path in an owner-only directory),
    /// which every helper connects to before it builds the root and reports
    /// its setup over.
    pub(crate) control: String,
    /// The fetch step's paths, when the preview fetches its package first;
    /// `None` runs the target once the setup is reported.
    pub(crate) fetch: Option<FetchPaths>,
    /// Debug builds only: a failure or a stray descriptor a row plants in the
    /// helper, which the helper's own checks must then catch. The gateway
    /// never sets it, and a release build has no such field.
    #[cfg(debug_assertions)]
    #[serde(
        default,
        rename = "MCP_GATEWAY_TEST_SANDBOX_FAULT",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) fault: Option<Fault>,
}

/// What a debug build's helper is told to do wrong, for the rows. Each arm
/// only adds a failure or a descriptor; none skips a check.
#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Fault {
    /// The step's first fallible call fails with an injected error, of kind
    /// `PermissionDenied` when `denied`, else `Other`.
    FailAt {
        step: crate::preview_sandbox::control_msg::SetupStep,
        denied: bool,
    },
    /// `/dev/null` opened and kept just before the status is sent.
    PlantBeforeStatus,
    /// `/dev/null` opened and kept just after the connection is dropped.
    PlantAfterClose,
    /// An order line on stderr at four points, and a hold on stdin between
    /// the strict descriptor check and the spawn.
    TraceAndHold,
}

/// Where the helper finds the fetch step's files: host paths, used before
/// the helper enters its new root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FetchPaths {
    /// The fetch's CA snapshot, beside the control socket: opened by the helper before it
    /// stages the root (never a bind target, so not refused under `/tmp`).
    pub(crate) ca: String,
    /// The npm package fetched before the run; `None` is the handshake alone.
    pub(crate) npm: Option<NpmFetch>,
    /// The `PyPI` package fetched before the run; never set with `npm`.
    #[serde(default)]
    pub(crate) uv: Option<UvFetch>,
}

/// The one fetcher a plan names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fetcher<'a> {
    Npm(&'a NpmFetch),
    Uv(&'a UvFetch),
}

impl Fetcher<'_> {
    /// The proxy's Unix socket the fetcher reaches the network through.
    pub(crate) fn proxy(&self) -> &str {
        match self {
            Self::Npm(npm) => &npm.proxy,
            Self::Uv(uv) => &uv.proxy,
        }
    }
}

impl FetchPaths {
    /// The fetcher this plan names, if any; a plan naming both refuses.
    pub(crate) fn fetcher(&self) -> Result<Option<Fetcher<'_>>, String> {
        match (&self.npm, &self.uv) {
            (Some(_), Some(_)) => {
                Err("checking the plan (it names both an npm and a uv fetch)".to_owned())
            }
            (Some(npm), None) => Ok(Some(Fetcher::Npm(npm))),
            (None, Some(uv)) => Ok(Some(Fetcher::Uv(uv))),
            (None, None) => Ok(None),
        }
    }
}

/// A `PyPI` package the fetch step installs with the host's uv before the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UvFetch {
    /// The validated spec: `name` or `name==version`.
    pub(crate) spec: String,
    /// The spec's PEP 503 name: the tool env's directory.
    pub(crate) name: String,
    /// The server's own arguments, after the spec.
    pub(crate) run_args: Vec<String>,
    /// uv's real file inside the root.
    pub(crate) uv: String,
    /// The interpreter's real file inside the root.
    pub(crate) python: String,
    /// The interpreter's directory, first on the fetch's and the run's PATH.
    pub(crate) python_dir: String,
    /// `ip`, for `ip link set lo up` inside the root.
    pub(crate) ip: String,
    /// The proxy's Unix socket (a host path), bound at `/tmp/proxy.sock`.
    pub(crate) proxy: String,
}

/// An npm package the fetch step installs before the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NpmFetch {
    /// The registry spec: `name` or `@scope/name`, optional `@version`.
    pub(crate) spec: String,
    /// The server's own arguments, after the spec.
    pub(crate) run_args: Vec<String>,
    /// npm's executable inside the root (the launcher's probe found it).
    pub(crate) npm: String,
    /// node's directory inside the root, first on the fetch's and the run's PATH.
    pub(crate) node_dir: String,
    /// `ip`, for `ip link set lo up` inside the root.
    pub(crate) ip: String,
    /// The proxy's Unix socket (a host path), bound at `/tmp/proxy.sock`.
    pub(crate) proxy: String,
}

/// The preview's home inside the new root: a fresh tmpfs, `HOME`, working
/// directory and every package cache.
pub(crate) const HOME: &str = "/preview-home";
/// Sizes the ADR fixes for the tmpfs mounts the helper creates.
pub(crate) const ROOT_SIZE: &CStr = c"size=16M,mode=755";
pub(crate) const HOME_SIZE: &CStr = c"size=1G,mode=700";
pub(crate) const TMP_SIZE: &CStr = c"size=256M,mode=1777";
pub(crate) const MASK_SIZE: &CStr = c"size=4k,mode=755";

/// The limits every preview process gets, `processes` excepted: that one is
/// the user's current process count plus 256, which only the host can count.
pub(crate) const fn limits(processes: u64) -> Limits {
    Limits {
        address_space: 4 << 30,
        file_size: 512 << 20,
        open_files: 1024,
        processes,
    }
}
