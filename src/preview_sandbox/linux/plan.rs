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
    /// Absolute program path, then its arguments.
    pub(crate) target: Vec<String>,
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
