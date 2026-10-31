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
    /// That pool, created on the firewall's first check.
    pub(crate) own_pool: std::sync::OnceLock<Arc<resolve::Pool>>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RootReason {
    NotAbsolute,
    NotNormalised,
    DevicePath,
    MissingArgument,
    WrongType,
    RemoteBackend,
    UnknownBackend,
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
    /// `PathOutsideRoot` findings, each already decided by its producing rule.
    pub(crate) findings: Vec<(Finding, FirewallAction)>,
}

#[path = "allowed_root_check.rs"]
mod check;
pub(crate) use check::{apply_roots, root_check};

/// The declared path argument whose top-level key a secret rule owns, if
/// any (`a` over a declared `a.b`). One predicate for the runtime refusal
/// and the load warning, so the two cannot drift.
pub(crate) fn owned_path_arg<'a>(owned: &[String], args: &'a [PathArg]) -> Option<&'a PathArg> {
    args.iter().find(|arg| owned.contains(&arg.segments[0]))
}

#[path = "allowed_root_resolve.rs"]
mod resolve;

/// One declared argument's values, to judge against its rule's roots.
pub(crate) struct Item {
    pub(crate) roots: Vec<Option<std::path::PathBuf>>,
    pub(crate) values: Vec<String>,
}

/// A refusal that names no argument: the pool was full or the call's
/// deadline passed.
pub(crate) const NO_ARGUMENT: usize = usize::MAX;

/// Judges one call's items on one resolver slot within one deadline. `Ok`
/// holds, per item, whether every value is inside a root; `Err` the item it
/// was refused on (or [`NO_ARGUMENT`]) and why.
fn judge(firewall: &super::Firewall, items: Vec<Item>) -> Result<Vec<bool>, (usize, RootReason)> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let (io, clock, pool) = seams_of(firewall);
    let deadline = clock.now() + ROOT_CHECK_DEADLINE;
    let work = move || {
        let mut walk = resolve::Walk::new(&*io, &*clock, deadline);
        judge_items(&mut walk, &items)
    };
    let Some(answer) = pool.run(work) else {
        return Err((NO_ARGUMENT, RootReason::ResolverBusy));
    };
    resolve::wait(&answer, ROOT_CHECK_DEADLINE).unwrap_or(Err((NO_ARGUMENT, RootReason::Timeout)))
}

fn judge_items(
    walk: &mut resolve::Walk<'_>,
    items: &[Item],
) -> Result<Vec<bool>, (usize, RootReason)> {
    let mut inside = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let at = |reason| (i, reason);
        let mut roots = Vec::with_capacity(item.roots.len());
        for root in &item.roots {
            let root = root.as_ref().ok_or(at(RootReason::RootUnresolvable))?;
            roots.push(walk.root(root).map_err(at)?);
        }
        // Every value is resolved, even after one is outside: under `warn`
        // an outside value does not block, and a later value's forced
        // refusal (a dangling link, say) still must.
        let mut all = true;
        for value in &item.values {
            let resolved = walk.resolve(std::path::Path::new(value)).map_err(at)?;
            if !roots.iter().any(|root| resolved.starts_with(root)) {
                all = false;
            }
        }
        inside.push(all);
    }
    Ok(inside)
}

type Io = (Arc<dyn Resolve>, Arc<dyn Clock>, Arc<resolve::Pool>);

/// The filesystem, clock and pool this firewall's checks use.
#[cfg(not(test))]
fn seams_of(_firewall: &super::Firewall) -> Io {
    (
        Arc::new(resolve::Real),
        Arc::new(resolve::System),
        resolve::Pool::shared(),
    )
}

/// Under test each firewall owns its pool, so rows never share slots, and
/// its seams replace the filesystem and the clock.
#[cfg(test)]
fn seams_of(firewall: &super::Firewall) -> Io {
    let seams = &firewall.seams;
    let pool = seams
        .own_pool
        .get_or_init(|| resolve::Pool::new(RESOLVER_THREADS));
    (
        seams
            .resolver
            .clone()
            .unwrap_or_else(|| Arc::new(resolve::Real)),
        seams
            .clock
            .clone()
            .unwrap_or_else(|| Arc::new(resolve::System)),
        Arc::clone(pool),
    )
}

/// `path_args` entries suggested from a tool's input schema, sorted by name:
/// a string property, or an array of strings (`name[]`), whose name is a
/// path name or ends in `_path`, `_file` or `_dir`, marked `?` when the
/// schema does not require it. It enforces nothing; the screen asks the
/// operator to confirm.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the policies screen is its first caller")
)]
pub(crate) fn suggest_path_args(input_schema: &Value) -> Vec<String> {
    // Argument names the suggester treats as paths (design section 7).
    const PATH_NAMES: [&str; 16] = [
        "path",
        "paths",
        "file",
        "files",
        "filename",
        "file_path",
        "filepath",
        "dir",
        "directory",
        "folder",
        "source",
        "destination",
        "src",
        "dst",
        "target",
        "root",
    ];
    let Some(properties) = input_schema["properties"].as_object() else {
        return Vec::new();
    };
    let required: Vec<&str> = input_schema["required"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut suggested: Vec<String> = properties
        .iter()
        .filter(|(name, _)| {
            PATH_NAMES.contains(&name.as_str())
                || ["_path", "_file", "_dir"].iter().any(|s| name.ends_with(s))
        })
        .filter_map(|(name, schema)| {
            let array = match schema["type"].as_str() {
                Some("string") => false,
                Some("array") if schema["items"]["type"] == "string" => true,
                _ => return None,
            };
            let mark = if required.contains(&name.as_str()) {
                ""
            } else {
                "?"
            };
            Some(format!("{name}{}{mark}", if array { "[]" } else { "" }))
        })
        .collect();
    suggested.sort();
    suggested
}

/// Whether `value` names the Windows device namespace: `\\.\`, `//./` or any
/// mix of the two separators, which Windows reads alike, or any other
/// spelling the standard library parses as a device-namespace prefix.
fn device_namespace(value: &str) -> bool {
    let sep = |c: &u8| *c == b'/' || *c == b'\\';
    matches!(value.as_bytes(), [a, b, b'.', c, ..] if sep(a) && sep(b) && sep(c))
        || matches!(
            std::path::Path::new(value).components().next(),
            Some(std::path::Component::Prefix(p))
                if matches!(p.kind(), std::path::Prefix::DeviceNS(_))
        )
}

/// The string-only half of the check: is `value` a normalised absolute native
/// path the gateway can judge exactly as the backend receives it? `None` when
/// it is; otherwise the refusal reason.
///
/// Segments are the raw string split on the platform's separators, never
/// `Path::components()`, which silently drops an interior `.`. On Windows a
/// trailing dot or space, and an 8.3 short name (`~` then a digit), are
/// refused too: Windows strips or expands them, so each could open a name
/// the gateway did not check (W18). A file really named with `~1` is refused
/// there, a stated limit.
pub(crate) fn precheck(value: &str) -> Option<RootReason> {
    if cfg!(windows) && device_namespace(value) {
        return Some(RootReason::DevicePath);
    }
    if !std::path::Path::new(value).is_absolute() {
        return Some(RootReason::NotAbsolute);
    }
    if value.contains('\0') {
        return Some(RootReason::NotNormalised);
    }
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let unnormalised = value.split(separators).any(|segment| {
        segment == "." || segment == ".." || (cfg!(windows) && windows_alias(segment))
    });
    unnormalised.then_some(RootReason::NotNormalised)
}

/// A segment Windows resolves to another name: a trailing dot or space, or
/// an 8.3 short name.
fn windows_alias(segment: &str) -> bool {
    let short_name = segment
        .split('~')
        .skip(1)
        .any(|after| after.starts_with(|c: char| c.is_ascii_digit()));
    segment.ends_with(['.', ' ']) || short_name
}

/// Compile one `path_args` entry: `segment ("." segment)* ("[]")? ("?")?`,
/// where a segment is `[A-Za-z0-9_-]+`.
pub(crate) fn compile_path_arg(entry: &str) -> Result<PathArg, String> {
    let (body, optional) = entry
        .strip_suffix('?')
        .map_or((entry, false), |b| (b, true));
    let (body, array) = body.strip_suffix("[]").map_or((body, false), |b| (b, true));
    let segments: Vec<String> = body.split('.').map(str::to_string).collect();
    let valid = |s: &String| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    if segments.iter().all(valid) {
        Ok(PathArg {
            segments,
            array,
            optional,
        })
    } else {
        Err("not a path argument".to_string())
    }
}

/// `root` after `~` expansion: a bare `~` or a leading `~/` uses the
/// gateway's home directory, with every further leading separator trimmed
/// (`home_dir::tilde_rest`), so `~//` is the home directory, never `/`.
/// `None` for `~user/...`, for any `~` root when the home directory is
/// unknown, and for a root that is not absolute.
pub(crate) fn expand_root(root: &str) -> Option<std::path::PathBuf> {
    let expanded = if root.starts_with('~') {
        crate::home_dir::home_dir()?.join(crate::home_dir::tilde_rest(root)?)
    } else {
        std::path::PathBuf::from(root)
    };
    expanded.is_absolute().then_some(expanded)
}

/// A rule's folder part, compiled once: its identity, each root after `~`
/// expansion, and its path arguments.
#[derive(Debug, Clone)]
pub(crate) struct CompiledRoot {
    /// The rule's `reason`, else `rules[i]`: what a refusal names.
    pub(crate) identity: String,
    /// `None` for a root that cannot be expanded (refused at load).
    pub(crate) roots: Vec<Option<std::path::PathBuf>>,
    /// `None` when the folder keys have a shape the load refuses; such a
    /// rule refuses every call it covers rather than checking nothing.
    pub(crate) args: Option<Vec<PathArg>>,
}

/// The folder part of rule `i`, if it has one.
pub(crate) fn compile(i: usize, rule: &super::FirewallRule) -> Option<CompiledRoot> {
    if rule.allowed_roots.is_none() && rule.path_args.is_none() {
        return None;
    }
    let roots = rule
        .allowed_roots
        .iter()
        .flatten()
        .map(|r| expand_root(r))
        .collect();
    let args = rule
        .path_args
        .as_ref()
        .filter(|args| {
            !args.is_empty() && rule.allowed_roots.as_ref().is_some_and(|r| !r.is_empty())
        })
        .and_then(|args| args.iter().map(|a| compile_path_arg(a).ok()).collect());
    Some(CompiledRoot {
        identity: rule.reason.clone().unwrap_or_else(|| format!("rules[{i}]")),
        roots,
        args,
    })
}

/// The finding types no rule's `scan` may list: only the folder check
/// produces them.
const OUTPUT_ONLY: [super::ScanType; 2] = [
    super::ScanType::PathOutsideRoot,
    super::ScanType::RootRefused,
];

/// Load checks for rule `i`'s folder keys (L1-L8). Messages name the key
/// path, never a value.
pub(crate) fn validate_rule(i: usize, rule: &super::FirewallRule) -> Result<(), String> {
    let path = format!("security.firewall.rules[{i}]");
    if let Some(j) = rule.scan.iter().position(|t| OUTPUT_ONLY.contains(t)) {
        return Err(format!(
            "{path}.scan[{j}] is output-only: only a folder rule's own check produces it"
        ));
    }
    let (roots, args) = match (&rule.allowed_roots, &rule.path_args) {
        (None, None) => return Ok(()),
        (Some(_), None) => {
            return Err(format!("{path}.path_args is required with allowed_roots"));
        }
        (None, Some(_)) => {
            return Err(format!("{path}.allowed_roots is required with path_args"));
        }
        (Some(roots), Some(args)) => (roots, args),
    };
    for (key, empty) in [
        ("allowed_roots", roots.is_empty()),
        ("path_args", args.is_empty()),
    ] {
        if empty {
            return Err(format!("{path}.{key} must not be empty"));
        }
    }
    if let Some(j) = roots.iter().position(|root| expand_root(root).is_none()) {
        return Err(format!(
            "{path}.allowed_roots[{j}] must be absolute (a bare ~ or ~/ uses the home \
             directory; ~user is not expanded)"
        ));
    }
    if let Some(j) = args.iter().position(|arg| compile_path_arg(arg).is_err()) {
        return Err(format!("{path}.path_args[{j}] is not a path argument"));
    }
    if !rule.scan.is_empty() {
        return Err(format!(
            "{path}.scan must be empty: a root rule decides only its own findings"
        ));
    }
    if rule.action == FirewallAction::Allow {
        return Err(format!(
            "{path}.action must be warn or block on a root rule"
        ));
    }
    Ok(())
}

/// Best-effort load warnings for folder rules (L9, L10, R22d). None refuses
/// the config: the per-call refusals stay the guarantee. Each names key
/// paths and rule names, never a value.
pub(crate) fn warn_at_load(config: &crate::config::Config) {
    let firewall = &config.security.firewall;
    if !firewall.enabled {
        return;
    }
    let covers = |rule: &super::FirewallRule, server: &str| {
        rule.servers.as_ref().is_none_or(|globs| {
            globs
                .iter()
                .any(|g| glob::Pattern::new(g).is_ok_and(|p| p.matches(server)))
        })
    };
    for (i, rule) in firewall.rules.iter().enumerate() {
        let (Some(roots), Some(args)) = (&rule.allowed_roots, &rule.path_args) else {
            continue;
        };
        let path = format!("security.firewall.rules[{i}]");
        for (j, root) in roots.iter().enumerate() {
            if expand_root(root).is_some_and(|r| std::fs::canonicalize(r).is_err()) {
                tracing::warn!(
                    "{path}.allowed_roots[{j}] does not resolve now; every call this rule \
                     covers is refused until it does"
                );
            }
        }
        let capabilities = &config.capabilities.name;
        if covers(rule, capabilities) {
            tracing::warn!(
                "{path} covers the capabilities backend {capabilities:?}: its calls will be \
                 refused; confine CLI capabilities with capabilities.files"
            );
        }
        let declared: Vec<PathArg> = args
            .iter()
            .filter_map(|a| compile_path_arg(a).ok())
            .collect();
        for (name, backend) in &config.backends {
            if !covers(rule, name) {
                continue;
            }
            for secret in &backend.secrets {
                let owned = secret.inject_key.as_str();
                let overlaps = secret.inject_as == crate::secret_injection::InjectTarget::Argument
                    && owned_path_arg(std::slice::from_ref(&secret.inject_key), &declared)
                        .is_some();
                if overlaps {
                    tracing::warn!(
                        "secret {:?} of backends.{name} owns {owned:?}, a declared argument in \
                         {path}.path_args: covered calls are refused",
                        secret.name
                    );
                }
            }
        }
    }
}

/// A rule on `tool` with `action` and every other field unset, for test
/// fixtures that set one field on top.
#[cfg(test)]
pub(crate) fn plain_rule(tool: &str, action: FirewallAction) -> super::FirewallRule {
    super::FirewallRule {
        tool_match: tool.to_string(),
        action,
        reason: None,
        scan: Vec::new(),
        servers: None,
        keys: None,
        except: None,
        allowed_roots: None,
        path_args: None,
    }
}

#[cfg(test)]
#[path = "allowed_root_tests.rs"]
mod tests;
