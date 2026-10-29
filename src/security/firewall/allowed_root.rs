// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-tool allowed folders for file tools (frame 47 "path-outside-folder").
//!
//! A firewall rule with `allowed_roots` and `path_args` confines the named path
//! arguments of the calls it covers to those folders. The check runs on the
//! exact string the backend receives, before dispatch, from both firewall
//! entry points (`check_request_keyed` and `rescan`).
//!
//! This commit is inert scaffolding: the types and signatures exist so the
//! rows can be written against them, and `root_check` decides nothing yet.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{Finding, FirewallAction};
use crate::security::response_policy::RuleTarget;

/// The production resolution budget for one call: every value, root and
/// directory read in it shares this deadline.
pub(crate) const ROOT_CHECK_DEADLINE: Duration = Duration::from_secs(2);
/// Resolver threads for the whole process.
pub(crate) const RESOLVER_THREADS: usize = 4;
/// Directory entries read for the equivalent-spelling check before refusing.
pub(crate) const DIRECTORY_ENTRY_CAP: usize = 10_000;

/// The capability backend slot the firewall shares with `MetaMcp`, so a
/// capability backend attached or replaced at runtime is seen at check time.
pub(crate) type CapabilitySlot =
    Arc<parking_lot::RwLock<Option<Arc<crate::capability::CapabilityBackend>>>>;

/// The live views the folder check classifies a call's backend through.
/// Absent on a firewall built without them (every fixture): a covered call
/// is then refused, never treated as local.
#[derive(Clone, Default)]
pub(crate) struct Registries {
    pub(crate) backends: Option<Arc<crate::backend::BackendRegistry>>,
    pub(crate) capabilities: Option<CapabilitySlot>,
}

/// One filesystem read the folder check makes. Every read in one call is
/// given that call's deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolveOp {
    /// `symlink_metadata` on one component: never follows a link.
    Metadata(std::path::PathBuf),
    /// `canonicalize` on an existing prefix or a root.
    Canonicalize(std::path::PathBuf),
    /// `read_dir` on a checked component's parent.
    ReadDir(std::path::PathBuf),
}

/// What a component is, as `symlink_metadata` saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Directory,
    File,
    Symlink,
}

/// The answer to one [`ResolveOp`], in the same order.
#[derive(Debug)]
pub(crate) enum Resolved {
    Kind(EntryKind),
    Path(std::path::PathBuf),
    /// Each entry's name, or the error reading it: an entry error is never
    /// dropped, so an unreadable directory is never seen as empty.
    Entries(Vec<std::io::Result<std::ffi::OsString>>),
}

/// The filesystem as the folder check reads it. Production reads the real
/// one; a row substitutes a gated or failing one per firewall.
pub(crate) trait Resolve: Send + Sync {
    fn resolve(&self, op: &ResolveOp, deadline: Instant) -> std::io::Result<Resolved>;
}

/// The instant the remaining budget is computed from, before each read.
pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// Per-firewall replacements for the filesystem, the clock and the resolver
/// pool, so a multi-thread row sees them (never thread-local).
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Seams {
    pub(crate) resolver: Option<Arc<dyn Resolve>>,
    pub(crate) clock: Option<Arc<dyn Clock>>,
    /// Resolver threads this firewall owns instead of the process pool.
    pub(crate) pool: Option<usize>,
}

#[cfg(test)]
impl super::Firewall {
    /// Read the filesystem through `resolver` instead of the real one.
    pub(crate) fn with_resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.seams.resolver = Some(resolver);
        self
    }

    /// Compute the remaining budget from `clock` instead of the system's.
    pub(crate) fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.seams.clock = Some(clock);
        self
    }

    /// Give this firewall its own pool of `threads` resolvers.
    pub(crate) fn with_resolver_pool(mut self, threads: usize) -> Self {
        self.seams.pool = Some(threads);
        self
    }
}

/// What `rescan` is looking at: the dispatched arguments, or a bridge retry's
/// answers. The folder check runs on the arguments only; content scanning runs
/// on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanSubject {
    /// The arguments the send carries.
    Arguments,
    /// A bridge retry's answer object.
    Answers,
}

/// One compiled `path_args` entry: `name`, `name[]`, `a.b`, with an optional
/// trailing `?` when a call may omit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathArg {
    /// The key path, outermost first.
    pub(crate) segments: Vec<String>,
    /// `name[]`: an array of strings.
    pub(crate) array: bool,
    /// `?`: a call may omit it.
    pub(crate) optional: bool,
}

/// Why a covered call was refused without a path judgement. Stable and
/// machine-readable; never carries a path value. The audit row's `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RootReason {
    NotAbsolute,
    NotNormalised,
    DevicePath,
    MissingArgument,
    WrongType,
    RemoteBackend,
    UnknownBackend,
    AmbiguousBackend,
    CapabilityNotCheckable,
    InjectedPathArgument,
    DanglingLink,
    Unresolvable,
    RootUnresolvable,
    EquivalentSpelling,
    DirectoryTooLarge,
    Timeout,
    ResolverBusy,
}

/// A forced block: the rule, the argument and the reason, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootRefusal {
    /// The rule's `reason`, else `rules[i]`.
    pub(crate) rule: String,
    /// The argument name, when the refusal concerns one.
    pub(crate) argument: Option<String>,
    pub(crate) reason: RootReason,
}

/// What the folder check decided for one call.
#[derive(Debug, Clone, Default)]
pub(crate) struct RootOutcome {
    /// A forced block; no rule action softens it.
    pub(crate) forced: Option<RootRefusal>,
    /// PathOutsideRoot findings, each already decided by its producing rule.
    pub(crate) findings: Vec<(Finding, FirewallAction)>,
}

/// The folder check. Inert in this commit: decides nothing.
pub(crate) fn root_check(
    _firewall: &super::Firewall,
    _target: RuleTarget<'_>,
    _args: &Value,
    _backend: Option<&crate::backend::Backend>,
) -> RootOutcome {
    RootOutcome::default()
}

/// Fold a folder outcome into the content action. Inert in this commit:
/// returns the content action and no findings.
pub(crate) fn apply_roots(
    _outcome: RootOutcome,
    content_action: FirewallAction,
) -> (FirewallAction, Vec<Finding>) {
    (content_action, Vec::new())
}

/// `path_args` entries suggested from a tool's input schema. Inert in this
/// commit: suggests nothing.
pub(crate) fn suggest_path_args(_input_schema: &Value) -> Vec<String> {
    Vec::new()
}

/// The string-only half of the check: is `value` a normalised absolute native
/// path the gateway can judge exactly as the backend receives it? `None` when
/// it is; otherwise the refusal reason. Inert in this commit: accepts all.
pub(crate) fn precheck(_value: &str) -> Option<RootReason> {
    None
}

/// Compile one `path_args` entry. Inert in this commit: compiles nothing.
pub(crate) fn compile_path_arg(_entry: &str) -> Result<PathArg, String> {
    Err("not a path argument".to_string())
}

#[cfg(test)]
#[path = "allowed_root_tests.rs"]
mod tests;
