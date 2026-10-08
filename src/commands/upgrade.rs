// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Implementation of `mcp-gateway upgrade` and the `check_upgrade()` startup hook.
//!
//! # Overview
//!
//! The module manages a version stamp at `~/.mcp-gateway/version.stamp` and a
//! migration registry (`MIGRATIONS`).  On every `serve` startup `check_upgrade`
//! is called; the `upgrade` subcommand exposes the same logic interactively.
//!
//! # Migration pattern
//!
//! ```rust,ignore
//! // Future migration example — add to MIGRATIONS slice:
//! Migration {
//!     // Apply this migration when the installed stamp is older than "3.0.0"
//!     applies_below: "3.0.0",
//!     description: "Rename 'backends.*.http_url' to 'backends.*.url'",
//!     apply: |config_dir| {
//!         let path = config_dir.join("gateway.yaml");
//!         let text = std::fs::read_to_string(&path)?;
//!         let patched = text.replace("http_url:", "url:");
//!         std::fs::write(&path, patched)?;
//!         Ok(())
//!     },
//! }
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[path = "upgrade_backend_grant_notice.rs"]
mod backend_grant_notice;
#[path = "upgrade_notice_items.rs"]
mod notice_items;
#[path = "upgrade_url_keys.rs"]
mod url_keys;
#[path = "upgrade_webhook_notice.rs"]
mod webhook_notice;
use notice_items::NOTICE_4_0_0_ITEMS;
pub use url_keys::run_upgrade_with_config;

// ── Semver comparison ─────────────────────────────────────────────────────────

#[path = "upgrade_semver.rs"]
mod stamp_version;
pub use stamp_version::SemVer;

// ── Migration registry ────────────────────────────────────────────────────────

/// A single schema/config migration.
///
/// `applies_below` is a semver string: the migration runs when the installed
/// version is strictly less than this value.  Use `"99.0.0"` to apply to all
/// existing installs unconditionally.
pub struct Migration {
    /// Run this migration when the old stamp version is strictly less than this.
    pub applies_below: &'static str,
    /// Human-readable description shown during upgrade.
    pub description: &'static str,
    /// Apply the migration; receives the gateway data directory (`~/.mcp-gateway/`).
    pub apply: fn(&Path) -> std::io::Result<()>,
    /// `true` when the migration only tells the operator something and leaves
    /// every file alone. A notice earns no config backup. It is addressed to a
    /// person and goes to stderr, so `--quiet` does NOT silence it: the startup
    /// path always runs quiet, and suppressing notices there delivered none.
    pub notice: bool,
}

/// All registered migrations in ascending `applies_below` order.
///
/// # Adding a new migration
///
/// Append a `Migration` whose `applies_below` is the *first* version that will
/// ship *without* requiring this migration.  Keep the slice sorted.
///
/// ```rust,ignore
/// Migration {
///     applies_below: "3.0.0",
///     description: "Rename deprecated 'http_url' key to 'url'",
///     apply: |dir| { /* patch gateway.yaml */ Ok(()) },
/// }
/// ```
static MIGRATIONS: &[Migration] = &[
    Migration {
        applies_below: "3.0.0",
        description: "v3.0.0: informational per-user OAuth isolation notice (config unchanged)",
        apply: migrate_3_0_0_multi_user_notice,
        notice: true,
    },
    Migration {
        applies_below: "4.0.0",
        description: "v4.0.0: informational breaking-change notice (config unchanged)",
        apply: migrate_4_0_0_release_notice,
        notice: true,
    },
];

// ── 3.0.0 migration: multi-user-default posture notice ─────────────────────────
//
// v3.0.0 makes per-user OAuth isolation the default behavior for any
// auth-enabled gateway (ADR-008 INV-2, fail-closed). A v2.x `gateway.yaml`
// loads completely unchanged on 3.0.0 — this migration NEVER edits the file.
// Its only job is to detect the deployment's posture and emit a one-time,
// actionable startup notice so the behavior change (backends that require
// per-user identity now refuse calls lacking it) doesn't surprise operators.

/// Detected multi-user posture of a config, as relevant to the 3.0.0 upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultiUserPosture {
    /// `auth.enabled` is false — no per-user boundary exists to protect.
    AuthDisabled,
    /// Auth is enabled and the operator has not declared a posture yet.
    Undeclared,
    /// Auth is enabled and the operator already declared `single_user` or a
    /// backend's `oauth.shared_account`.
    AlreadyDeclared,
}

const NOTICE_MULTI_USER_DEFAULT: &str = "\
v3.0.0: per-user OAuth isolation is now the default for auth-enabled gateways (ADR-008 INV-2, fail-closed).\n\
    What changed: backends whose OAuth token requires a per-user identity now REFUSE calls that lack a \
verified end-user identity (HTTP 403 / JSON-RPC -32001..-32003) instead of silently sharing one stored \
token across every caller.\n\
    This gateway has auth enabled but has not declared a posture. Pick one:\n\
      - Single-user / personal gateway -> add `auth.single_user: true` to gateway.yaml\n\
      - Shared service account for one backend -> add `oauth.shared_account: true` under that backend\n\
    No config was changed automatically — this is an informational notice only.";

const NOTICE_AUTH_DISABLED: &str = "\
v3.0.0: auth is disabled on this gateway, so the admin UI and config endpoints are reachable by anyone \
who can reach the port (single-user/local posture assumed). Bind to 127.0.0.1 or a trusted network, or \
enable `auth.enabled: true`.";

const NOTICE_ALREADY_CONFIGURED: &str = "migration: v3.0.0 multi-user posture already configured (auth.single_user or oauth.shared_account set) — no action needed.";

/// Look up a dotted boolean path in a parsed YAML document (e.g. `["auth", "enabled"]`).
fn yaml_bool(yaml: &serde_yaml::Value, path: &[&str]) -> Option<bool> {
    let mut cur = yaml;
    for key in path {
        cur = cur.get(key)?;
    }
    cur.as_bool()
}

/// `true` when any `backends.*.oauth.shared_account` is explicitly `true`.
fn any_backend_shared_account(yaml: &serde_yaml::Value) -> bool {
    yaml.get("backends")
        .and_then(serde_yaml::Value::as_mapping)
        .is_some_and(|backends| {
            backends.values().any(|backend| {
                backend
                    .get("oauth")
                    .and_then(|oauth| oauth.get("shared_account"))
                    .and_then(serde_yaml::Value::as_bool)
                    .unwrap_or(false)
            })
        })
}

/// Classify a parsed config's multi-user posture without mutating it.
fn detect_multi_user_posture(yaml: &serde_yaml::Value) -> MultiUserPosture {
    if !yaml_bool(yaml, &["auth", "enabled"]).unwrap_or(false) {
        return MultiUserPosture::AuthDisabled;
    }
    let single_user = yaml_bool(yaml, &["auth", "single_user"]).unwrap_or(false);
    if single_user || any_backend_shared_account(yaml) {
        return MultiUserPosture::AlreadyDeclared;
    }
    MultiUserPosture::Undeclared
}

/// 3.0.0 migration entry point. Read-only: emits a tracing notice tailored to
/// the detected posture and never mutates `gateway.yaml` or any of the
/// security-relevant fields it inspects (`auth.single_user`,
/// `oauth.shared_account`). Idempotent — the migration engine only invokes
/// this once per data directory because `check_upgrade`/`run_upgrade_command`
/// skip already-applicable migrations once the version stamp reaches 3.0.0.
// This migration is deliberately infallible — it never fails the upgrade over
// an informational notice — but it must match `Migration::apply`'s
// `fn(&Path) -> std::io::Result<()>` signature, which other (file-mutating)
// migrations genuinely need. Hence the always-`Ok` wrap is intentional, not
// an oversight.
#[allow(clippy::unnecessary_wraps)]
fn migrate_3_0_0_multi_user_notice(data_dir: &Path) -> std::io::Result<()> {
    let path = data_dir.join("gateway.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        // No config file at this location: nothing to detect, nothing to warn about.
        return Ok(());
    };
    let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
        // Config::load() will surface the real parse error at startup; the
        // migration must not fail the upgrade over an informational notice.
        tracing::warn!(
            path = %path.display(),
            "migration v3.0.0: could not parse gateway.yaml for posture detection — skipping notice"
        );
        return Ok(());
    };

    match detect_multi_user_posture(&yaml) {
        // Printed for the same reason as the 4.0.0 notice: a log filter must
        // not be able to swallow a one-time message addressed to a person.
        MultiUserPosture::Undeclared => eprintln!("{NOTICE_MULTI_USER_DEFAULT}"),
        MultiUserPosture::AuthDisabled => eprintln!("{NOTICE_AUTH_DISABLED}"),
        MultiUserPosture::AlreadyDeclared => tracing::info!("{NOTICE_ALREADY_CONFIGURED}"),
    }
    Ok(())
}

// ── 4.0.0 migration: breaking-change notice ───────────────────────────────────
// The items live in `upgrade_notice_items.rs`; this prints them once.

/// Emit the one-time 4.0.0 notice.
///
/// Reads nothing: no item depends on the config. It marks the webhook item as
/// delivered so a later start does not repeat it. The `Result` is dictated by
/// `Migration::apply`, not by anything this can fail at.
#[allow(clippy::unnecessary_wraps)]
fn migrate_4_0_0_release_notice(data_dir: &Path) -> std::io::Result<()> {
    let body = NOTICE_4_0_0_ITEMS
        .iter()
        .enumerate()
        .map(|(i, item)| format!("    {}. {item}", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    // Printed to stderr, not logged: `--log-level error` or a RUST_LOG filter
    // would swallow a warn event while the version stamp advances, and the
    // notice fires exactly once. stderr so `--quiet` can suppress progress
    // chatter on stdout without suppressing the warning itself.
    // Count read from the list, never spelled out: a hand-written number drifts
    // the moment an item is appended, and the header then contradicts the body.
    eprintln!(
        "v4.0.0: {} changes need your attention. No config was changed automatically.\n{body}",
        NOTICE_4_0_0_ITEMS.len()
    );
    // A marker that fails to write costs one repeated notice, not the upgrade.
    let _ = webhook_notice::mark(data_dir);
    Ok(())
}

// ── Version stamp I/O ─────────────────────────────────────────────────────────

/// Path of the version stamp file.
pub fn stamp_path(data_dir: &Path) -> PathBuf {
    data_dir.join("version.stamp")
}

/// Read the stamp file; returns `None` when the file does not exist.
fn read_stamp(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.trim().to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Atomically write `version` to `path` via a sibling temp file.
fn write_stamp(path: &Path, version: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("stamp.tmp");
    std::fs::write(&tmp, version)?;
    std::fs::rename(tmp, path)
}

// ── Config backup ─────────────────────────────────────────────────────────────

/// Copy `gateway.yaml` to `gateway.yaml.bak.<old_version>` before migrations.
///
/// Only looks inside `config_dir` (`~/.mcp-gateway/gateway.yaml`).
/// Returns `Ok(None)` when the file does not exist there (nothing to back up).
fn backup_config(config_dir: &Path, old_version: &str) -> std::io::Result<Option<PathBuf>> {
    let src = config_dir.join("gateway.yaml");
    if !src.exists() {
        return Ok(None);
    }
    let dst = src.with_extension(format!("yaml.bak.{old_version}"));
    std::fs::copy(&src, &dst)?;
    Ok(Some(dst))
}

// ── What's new ────────────────────────────────────────────────────────────────

/// A "what's new" entry shown when upgrading past a given version.
struct WhatsNew {
    /// Version that introduced these changes.
    version: &'static str,
    /// Bullet points shown to the user.
    items: &'static [&'static str],
}

/// Registry of user-visible changes, sorted ascending by version.
///
/// Add entries here when a release ships noteworthy features.
static WHATS_NEW: &[WhatsNew] = &[
    WhatsNew {
        version: "2.9.1",
        items: &[
            "OWASP Agentic AI Top 10: 8/10 covered (destructive confirmation, message signing, anomaly blocking)",
            "New `upgrade` command with version stamp and migration framework",
            "New `gateway_reload_capabilities` agent-callable meta-tool",
        ],
    },
    WhatsNew {
        version: "2.10.0",
        items: &[
            "A2A transport adapter — proxy Google Agent2Agent agents as MCP backends",
            "Security hardening: HMAC signing (ASI07), destructive confirmation (ASI09), anomaly blocking (ASI10)",
            "FSM state-gated tool visibility for multi-step workflows",
            "Structured self-healing error responses with recovery hints",
        ],
    },
    WhatsNew {
        version: "3.0.0",
        items: &[
            "Per-user OAuth isolation is now the default for auth-enabled gateways (ADR-008 INV-2, fail-closed)",
            "Backends requiring per-user identity now refuse calls lacking a verified end-user identity",
            "Declare `auth.single_user: true` (personal gateway) or `oauth.shared_account: true` (per backend) to opt in to shared-credential behavior",
        ],
    },
    WhatsNew {
        version: "3.1.0",
        items: &[
            "New opt-in `strategy: token_exchange` for `identity_propagation`: RFC 8693 token exchange with a backend's token endpoint, stores no credential",
            "Standards fix: the key server's dormant, opt-in `POST /auth/token` endpoint now uses standard OAuth 2.0 / RFC 8693 form-encoding instead of JSON",
        ],
    },
];

/// Print "What's new" items for all versions strictly after `from` and up to `current`.
///
/// Skipped on fresh install (nobody needs a changelog on first run).
fn print_whats_new(from: &SemVer, current: &SemVer) {
    let items: Vec<&str> = WHATS_NEW
        .iter()
        .filter(|w| SemVer::parse(w.version).is_some_and(|v| &v > from && v <= current.release()))
        .flat_map(|w| w.items.iter().copied())
        .collect();

    if items.is_empty() {
        return;
    }

    println!("What's new in v{current}:");
    for item in &items {
        println!("  - {item}");
    }
}

// ── Migration engine ──────────────────────────────────────────────────────────

/// Context for a single upgrade run.
struct UpgradeContext<'a> {
    data_dir: &'a Path,
    old_ver: SemVer,
    new_ver: SemVer,
    dry_run: bool,
    quiet: bool,
}

impl UpgradeContext<'_> {
    fn applicable_migrations(&self) -> Vec<&'static Migration> {
        MIGRATIONS
            .iter()
            .filter(|m| {
                SemVer::parse(m.applies_below).is_some_and(|ceiling| self.old_ver < ceiling)
            })
            .collect()
    }

    fn run(&self) -> std::io::Result<usize> {
        if !self.quiet {
            print_whats_new(&self.old_ver, &self.new_ver);
        }

        let migrations = self.applicable_migrations();
        let count = migrations.len();

        // A notice writes nothing, so backing the config up would leave an
        // unexplained gateway.yaml.bak.<version> behind for an upgrade that
        // touched only the version stamp.
        if !self.dry_run && migrations.iter().any(|m| !m.notice) {
            backup_config(self.data_dir, &self.old_ver.to_string())?;
        }

        for m in &migrations {
            if !self.quiet {
                let prefix = if self.dry_run { "[dry-run] " } else { "" };
                println!("  {prefix}Applying: {}", m.description);
            }
            if !self.dry_run {
                (m.apply)(self.data_dir)?;
            }
        }

        if !self.dry_run {
            let stamp = stamp_path(self.data_dir);
            write_stamp(&stamp, &self.new_ver.to_string())?;
        }

        Ok(count)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Data directory for the gateway (`~/.mcp-gateway/` or `$MCP_GATEWAY_CONFIG_DIR`).
pub fn data_dir() -> PathBuf {
    mcp_gateway::config_persistence::gateway_data_dir()
}

/// Called early in `serve` startup to apply any pending migrations silently.
///
/// Behaviour:
/// - Stamp missing → fresh install: write current version, return `Ok(())`.
/// - Stamp == current → no-op.
/// - Stamp < current → run migrations, update stamp, log what ran.
/// - Stamp > current → warn about downgrade; do **not** touch stamp.
pub fn check_upgrade(data_dir: &Path) -> std::io::Result<()> {
    check_upgrade_with(data_dir, &mut std::io::stderr())
}

/// [`check_upgrade`], writing the once-only webhook notice to `notices`.
fn check_upgrade_with(data_dir: &Path, notices: &mut impl std::io::Write) -> std::io::Result<()> {
    let current_str = env!("CARGO_PKG_VERSION");
    let current = SemVer::parse(current_str).expect("CARGO_PKG_VERSION is always valid semver");

    std::fs::create_dir_all(data_dir)?;
    let stamp = stamp_path(data_dir);

    let Some(raw) = read_stamp(&stamp)? else {
        // Fresh install — write stamp and return.
        write_stamp(&stamp, current_str)?;
        return webhook_notice::mark(data_dir);
    };

    let Some(installed) = SemVer::parse(&raw) else {
        eprintln!("Warning: unreadable version stamp '{raw}'; treating as fresh install.");
        write_stamp(&stamp, current_str)?;
        return webhook_notice::mark(data_dir);
    };

    match installed.cmp(&current) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Less => {
            let ctx = UpgradeContext {
                data_dir,
                old_ver: installed.clone(),
                new_ver: current.clone(),
                dry_run: false,
                quiet: true,
            };
            let n = ctx.run()?;
            if n > 0 {
                tracing::info!(
                    old = %installed,
                    new = %current,
                    migrations = n,
                    "Upgrade migrations applied"
                );
            }
        }
        std::cmp::Ordering::Greater => {
            tracing::warn!(
                installed = %installed,
                binary = %current,
                "Downgrade detected: running an older binary against a newer data directory"
            );
        }
    }

    // Keyed on a marker, not the stamp: an install already stamped at this
    // version ran no migration above and would otherwise never hear it.
    webhook_notice::show_once(data_dir, notices)?;
    Ok(())
}

/// Run `mcp-gateway upgrade`.
///
/// Mirrors the logic of `check_upgrade` but with user-visible output, dry-run
/// support, and a structured summary.
pub fn run_upgrade_command(dry_run: bool, quiet: bool, config_dir: Option<&Path>) -> ExitCode {
    let dir = config_dir.map_or_else(data_dir, Path::to_path_buf);

    let current_str = env!("CARGO_PKG_VERSION");
    let current = SemVer::parse(current_str).expect("CARGO_PKG_VERSION is always valid semver");

    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("Error: cannot create data directory {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }

    let stamp = stamp_path(&dir);

    let raw_stamp = match read_stamp(&stamp) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: cannot read stamp file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let Some(raw) = raw_stamp else {
        // Fresh install path.
        if !quiet {
            println!("Fresh install detected — writing version stamp {current_str}.");
        }
        if !dry_run && let Err(e) = write_stamp(&stamp, current_str) {
            eprintln!("Error: failed to write stamp: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    };

    let Some(installed) = SemVer::parse(&raw) else {
        eprintln!("Error: unreadable version stamp '{raw}'.");
        return ExitCode::FAILURE;
    };

    match installed.cmp(&current) {
        std::cmp::Ordering::Equal => {
            if !quiet {
                println!("Already at version {current_str} — nothing to do.");
            }
            ExitCode::SUCCESS
        }
        std::cmp::Ordering::Greater => {
            eprintln!(
                "Warning: stamp version {installed} is newer than binary {current}. \
                 Downgrade detected; stamp left unchanged."
            );
            ExitCode::SUCCESS
        }
        std::cmp::Ordering::Less => {
            let ctx = UpgradeContext {
                data_dir: &dir,
                old_ver: installed.clone(),
                new_ver: current.clone(),
                dry_run,
                quiet,
            };
            match ctx.run() {
                Ok(n) => {
                    print_upgrade_summary(&installed, &current, n, dry_run, quiet);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error: upgrade failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn print_upgrade_summary(
    old: &SemVer,
    new: &SemVer,
    _migrations: usize,
    dry_run: bool,
    quiet: bool,
) {
    if quiet {
        return;
    }
    let prefix = if dry_run { "[dry-run] " } else { "" };
    println!("{prefix}mcp-gateway upgraded v{old} \u{2192} v{new}");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "upgrade_notice_tests.rs"]
mod upgrade_notice_tests;

#[cfg(test)]
#[path = "upgrade_webhook_notice_tests.rs"]
mod upgrade_webhook_notice_tests;

#[cfg(test)]
#[path = "upgrade_prerelease_tests.rs"]
mod prerelease_tests;

#[cfg(test)]
mod tests;
