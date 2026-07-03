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

// ── Semver comparison ─────────────────────────────────────────────────────────

/// A parsed semantic version triple `(major, minor, patch)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    major: u32,
    minor: u32,
    patch: u32,
}

impl SemVer {
    /// Parse a semver string of the form `"MAJOR.MINOR.PATCH"`.
    ///
    /// Pre-release suffixes (e.g. `"-alpha.1"`) are stripped before parsing so
    /// that `"3.0.0-alpha.1"` is treated as `"3.0.0"`.
    pub fn parse(s: &str) -> Option<Self> {
        let base = s.split('-').next().unwrap_or(s);
        let mut parts = base.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

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
static MIGRATIONS: &[Migration] = &[Migration {
    applies_below: "3.0.0",
    description: "v3.0.0: informational per-user OAuth isolation notice (config unchanged)",
    apply: migrate_3_0_0_multi_user_notice,
}];

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
        MultiUserPosture::Undeclared => tracing::warn!("{NOTICE_MULTI_USER_DEFAULT}"),
        MultiUserPosture::AuthDisabled => tracing::warn!("{NOTICE_AUTH_DISABLED}"),
        MultiUserPosture::AlreadyDeclared => tracing::info!("{NOTICE_ALREADY_CONFIGURED}"),
    }
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
];

/// Print "What's new" items for all versions strictly after `from` and up to `current`.
///
/// Skipped on fresh install (nobody needs a changelog on first run).
fn print_whats_new(from: SemVer, current: SemVer) {
    let items: Vec<&str> = WHATS_NEW
        .iter()
        .filter(|w| SemVer::parse(w.version).is_some_and(|v| v > from && v <= current))
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
            print_whats_new(self.old_ver, self.new_ver);
        }

        let migrations = self.applicable_migrations();
        let count = migrations.len();

        if !self.dry_run && count > 0 {
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
    std::env::var("MCP_GATEWAY_CONFIG_DIR").map_or_else(
        |_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".mcp-gateway")
        },
        PathBuf::from,
    )
}

/// Called early in `serve` startup to apply any pending migrations silently.
///
/// Behaviour:
/// - Stamp missing → fresh install: write current version, return `Ok(())`.
/// - Stamp == current → no-op.
/// - Stamp < current → run migrations, update stamp, log what ran.
/// - Stamp > current → warn about downgrade; do **not** touch stamp.
pub fn check_upgrade(data_dir: &Path) -> std::io::Result<()> {
    let current_str = env!("CARGO_PKG_VERSION");
    let current = SemVer::parse(current_str).expect("CARGO_PKG_VERSION is always valid semver");

    std::fs::create_dir_all(data_dir)?;
    let stamp = stamp_path(data_dir);

    let Some(raw) = read_stamp(&stamp)? else {
        // Fresh install — write stamp and return.
        write_stamp(&stamp, current_str)?;
        return Ok(());
    };

    let Some(installed) = SemVer::parse(&raw) else {
        eprintln!("Warning: unreadable version stamp '{raw}'; treating as fresh install.");
        write_stamp(&stamp, current_str)?;
        return Ok(());
    };

    match installed.cmp(&current) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Less => {
            let ctx = UpgradeContext {
                data_dir,
                old_ver: installed,
                new_ver: current,
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
                old_ver: installed,
                new_ver: current,
                dry_run,
                quiet,
            };
            match ctx.run() {
                Ok(n) => {
                    print_upgrade_summary(installed, current, n, dry_run, quiet);
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

fn print_upgrade_summary(old: SemVer, new: SemVer, _migrations: usize, dry_run: bool, quiet: bool) {
    if quiet {
        return;
    }
    let prefix = if dry_run { "[dry-run] " } else { "" };
    println!("{prefix}mcp-gateway upgraded v{old} \u{2192} v{new}");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── SemVer::parse ─────────────────────────────────────────────────────────

    #[test]
    fn semver_parse_valid_triple_succeeds() {
        // GIVEN: a valid semver string
        // WHEN: parsed
        // THEN: all three fields are populated
        let v = SemVer::parse("2.9.1").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 2,
                minor: 9,
                patch: 1
            }
        );
    }

    #[test]
    fn semver_parse_strips_prerelease_suffix() {
        let v = SemVer::parse("3.0.0-alpha.1").unwrap();
        assert_eq!(
            v,
            SemVer {
                major: 3,
                minor: 0,
                patch: 0
            }
        );
    }

    #[test]
    fn semver_parse_invalid_returns_none() {
        assert!(SemVer::parse("not-a-version").is_none());
        assert!(SemVer::parse("1.2").is_none());
        assert!(SemVer::parse("").is_none());
    }

    #[test]
    fn semver_ordering_is_correct() {
        let v1 = SemVer::parse("1.0.0").unwrap();
        let v2 = SemVer::parse("2.0.0").unwrap();
        let v3 = SemVer::parse("2.1.0").unwrap();
        let v4 = SemVer::parse("2.1.1").unwrap();

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v3 < v4);
        assert_eq!(v1, SemVer::parse("1.0.0").unwrap());
    }

    // ── stamp read/write ──────────────────────────────────────────────────────

    #[test]
    fn stamp_missing_read_returns_none() {
        // GIVEN: a temp dir with no stamp file
        let dir = TempDir::new().unwrap();
        let path = stamp_path(dir.path());
        // WHEN: reading the missing stamp
        let result = read_stamp(&path).unwrap();
        // THEN: None is returned
        assert!(result.is_none());
    }

    #[test]
    fn stamp_write_then_read_round_trips_version() {
        // GIVEN: a temp dir
        let dir = TempDir::new().unwrap();
        let path = stamp_path(dir.path());
        // WHEN: version is written
        write_stamp(&path, "2.9.1").unwrap();
        // THEN: reading it back returns the same string
        assert_eq!(read_stamp(&path).unwrap().as_deref(), Some("2.9.1"));
    }

    #[test]
    fn stamp_write_trims_on_read() {
        // GIVEN: a stamp file with trailing newline
        let dir = TempDir::new().unwrap();
        let path = stamp_path(dir.path());
        std::fs::write(&path, "2.9.1\n").unwrap();
        // WHEN: read back
        let v = read_stamp(&path).unwrap().unwrap();
        // THEN: whitespace is trimmed
        assert_eq!(v, "2.9.1");
    }

    // ── check_upgrade ─────────────────────────────────────────────────────────

    #[test]
    fn check_upgrade_fresh_install_writes_stamp() {
        // GIVEN: a data dir with no stamp file
        let dir = TempDir::new().unwrap();
        // WHEN: check_upgrade is called
        check_upgrade(dir.path()).unwrap();
        // THEN: the stamp now contains the current version
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn check_upgrade_same_version_is_noop() {
        // GIVEN: a stamp at the current version
        let dir = TempDir::new().unwrap();
        let current = env!("CARGO_PKG_VERSION");
        write_stamp(&stamp_path(dir.path()), current).unwrap();
        // WHEN: check_upgrade is called (noop: stamp == current binary version)
        check_upgrade(dir.path()).unwrap();
        // THEN: stamp content is unchanged — check_upgrade must not re-write the stamp
        // when installed == current; we verify by reading back and comparing the value.
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, current);
        // Note: mtime comparison is platform-specific, so we only check content above.
    }

    #[test]
    fn check_upgrade_older_stamp_updates_to_current() {
        // GIVEN: a stamp at a very old version
        let dir = TempDir::new().unwrap();
        write_stamp(&stamp_path(dir.path()), "0.1.0").unwrap();
        // WHEN: check_upgrade is called
        check_upgrade(dir.path()).unwrap();
        // THEN: stamp is updated to current version (no migrations, so direct update)
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn check_upgrade_downgrade_does_not_touch_stamp() {
        // GIVEN: a stamp at a future version (simulates downgrade)
        let dir = TempDir::new().unwrap();
        write_stamp(&stamp_path(dir.path()), "99.0.0").unwrap();
        // WHEN: check_upgrade is called
        check_upgrade(dir.path()).unwrap();
        // THEN: stamp is left at 99.0.0 (downgrade protection)
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, "99.0.0");
    }

    // ── run_upgrade_command ───────────────────────────────────────────────────

    #[test]
    fn upgrade_command_fresh_install_returns_success() {
        // GIVEN: an empty data dir
        let dir = TempDir::new().unwrap();
        // WHEN: upgrade command runs
        let code = run_upgrade_command(false, true, Some(dir.path()));
        // THEN: exits successfully and writes stamp
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(stamp_path(dir.path()).exists());
    }

    #[test]
    fn upgrade_command_dry_run_does_not_write_stamp() {
        // GIVEN: an empty data dir and dry-run mode
        let dir = TempDir::new().unwrap();
        // WHEN: upgrade command runs in dry-run mode
        let code = run_upgrade_command(true, true, Some(dir.path()));
        // THEN: exits successfully but stamp is NOT written (fresh install dry-run)
        assert_eq!(code, ExitCode::SUCCESS);
        // Dry-run on fresh install: stamp is not created
        assert!(!stamp_path(dir.path()).exists());
    }

    #[test]
    fn upgrade_command_same_version_is_noop() {
        // GIVEN: stamp at current version
        let dir = TempDir::new().unwrap();
        let current = env!("CARGO_PKG_VERSION");
        write_stamp(&stamp_path(dir.path()), current).unwrap();
        // WHEN: upgrade command runs
        let code = run_upgrade_command(false, true, Some(dir.path()));
        // THEN: success, stamp unchanged
        assert_eq!(code, ExitCode::SUCCESS);
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, current);
    }

    #[test]
    fn upgrade_command_old_stamp_updates_to_current() {
        // GIVEN: stamp at 0.1.0
        let dir = TempDir::new().unwrap();
        write_stamp(&stamp_path(dir.path()), "0.1.0").unwrap();
        // WHEN: upgrade runs (quiet so no stdout noise in test)
        let code = run_upgrade_command(false, true, Some(dir.path()));
        // THEN: stamp updated, exit SUCCESS
        assert_eq!(code, ExitCode::SUCCESS);
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn upgrade_command_downgrade_returns_success_stamp_unchanged() {
        // GIVEN: stamp at 99.0.0
        let dir = TempDir::new().unwrap();
        write_stamp(&stamp_path(dir.path()), "99.0.0").unwrap();
        // WHEN: upgrade runs
        let code = run_upgrade_command(false, true, Some(dir.path()));
        // THEN: success, stamp untouched
        assert_eq!(code, ExitCode::SUCCESS);
        let v = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(v, "99.0.0");
    }

    // ── backup_config ─────────────────────────────────────────────────────────

    #[test]
    fn backup_config_missing_returns_none() {
        // GIVEN: a dir with no gateway.yaml
        let dir = TempDir::new().unwrap();
        // WHEN: backup is attempted
        let result = backup_config(dir.path(), "1.0.0").unwrap();
        // THEN: None (nothing to back up)
        assert!(result.is_none());
    }

    #[test]
    fn backup_config_creates_versioned_bak_file() {
        // GIVEN: a dir with gateway.yaml
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        std::fs::write(&yaml, "server:\n  port: 39400\n").unwrap();
        // WHEN: backup is called
        let bak = backup_config(dir.path(), "1.2.3").unwrap().unwrap();
        // THEN: backup file exists with correct name
        assert_eq!(bak.file_name().unwrap(), "gateway.yaml.bak.1.2.3");
        assert!(bak.exists());
    }

    #[test]
    fn backup_config_preserves_content() {
        // GIVEN: a gateway.yaml with known content
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        std::fs::write(&yaml, "content: preserved\n").unwrap();
        // WHEN: backup is made
        let bak = backup_config(dir.path(), "2.0.0").unwrap().unwrap();
        // THEN: backup has the same content
        let content = std::fs::read_to_string(bak).unwrap();
        assert_eq!(content, "content: preserved\n");
    }

    // ── applicable_migrations ─────────────────────────────────────────────────

    #[test]
    fn migrations_registry_has_exactly_one_3_0_0_entry() {
        // GIVEN: the MIGRATIONS registry
        // WHEN/THEN: it carries exactly the 3.0.0 multi-user notice migration
        assert_eq!(MIGRATIONS.len(), 1);
        assert_eq!(MIGRATIONS[0].applies_below, "3.0.0");
    }

    #[test]
    fn pre_3_0_0_stamp_has_one_applicable_migration() {
        // GIVEN: an install stamped below 3.0.0
        let dir = TempDir::new().unwrap();
        let ctx = UpgradeContext {
            data_dir: dir.path(),
            old_ver: SemVer::parse("1.0.0").unwrap(),
            new_ver: SemVer::parse("2.10.0").unwrap(),
            dry_run: false,
            quiet: true,
        };
        // WHEN: applicable migrations are collected
        // THEN: the 3.0.0 notice migration applies
        assert_eq!(ctx.applicable_migrations().len(), 1);
    }

    #[test]
    fn stamp_already_at_3_0_0_has_zero_applicable_migrations() {
        // GIVEN: an install already stamped at 3.0.0 (the migration's own ceiling)
        let dir = TempDir::new().unwrap();
        let ctx = UpgradeContext {
            data_dir: dir.path(),
            old_ver: SemVer::parse("3.0.0").unwrap(),
            new_ver: SemVer::parse("3.0.0").unwrap(),
            dry_run: false,
            quiet: true,
        };
        // WHEN: applicable migrations are collected
        // THEN: none — `applies_below` is a strict upper bound (idempotency guard)
        assert_eq!(ctx.applicable_migrations().len(), 0);
    }

    // ── what's new ───────────────────────────────────────────────────────────

    #[test]
    fn whats_new_registry_has_entries_for_current_version() {
        // GIVEN: the WHATS_NEW registry
        // WHEN: we look for entries at 2.10.0
        let v2100 = SemVer::parse("2.10.0").unwrap();
        let has_entries = WHATS_NEW
            .iter()
            .any(|w| SemVer::parse(w.version) == Some(v2100));
        // THEN: at least one entry exists
        assert!(has_entries, "WHATS_NEW should have entries for v2.10.0");
    }

    #[test]
    fn whats_new_items_shown_when_upgrading_past_version() {
        // GIVEN: upgrading from 2.9.1 to 2.10.0
        let from = SemVer::parse("2.9.1").unwrap();
        let to = SemVer::parse("2.10.0").unwrap();
        // WHEN: collecting what's-new items
        let items: Vec<&str> = WHATS_NEW
            .iter()
            .filter(|w| SemVer::parse(w.version).is_some_and(|v| v > from && v <= to))
            .flat_map(|w| w.items.iter().copied())
            .collect();
        // THEN: items are not empty (v2.10.0 entries should match)
        assert!(
            !items.is_empty(),
            "Should have what's-new items for 2.9.1 -> 2.10.0"
        );
    }

    #[test]
    fn whats_new_items_not_shown_for_same_version() {
        // GIVEN: no version change (already at 2.10.0)
        let from = SemVer::parse("2.10.0").unwrap();
        let to = SemVer::parse("2.10.0").unwrap();
        // WHEN: collecting what's-new items
        let items: Vec<&str> = WHATS_NEW
            .iter()
            .filter(|w| SemVer::parse(w.version).is_some_and(|v| v > from && v <= to))
            .flat_map(|w| w.items.iter().copied())
            .collect();
        // THEN: no items (version > from is false when from == to)
        assert!(items.is_empty());
    }

    // ── backup during migration ──────────────────────────────────────────────

    #[test]
    fn backup_called_when_migrations_apply() {
        // GIVEN: a data dir with gateway.yaml and an UpgradeContext that has a
        // migration (we simulate by directly calling backup_config, since the
        // static MIGRATIONS slice cannot be mutated in tests)
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        let config_content = "server:\n  port: 39400\n  host: 0.0.0.0\n";
        std::fs::write(&yaml, config_content).unwrap();

        // WHEN: backup_config is called as the migration engine would
        let bak = backup_config(dir.path(), "2.8.0").unwrap();

        // THEN: backup file exists and preserves content
        let bak_path = bak.expect("backup should be created when gateway.yaml exists");
        assert_eq!(bak_path.file_name().unwrap(), "gateway.yaml.bak.2.8.0");
        let backed_up = std::fs::read_to_string(&bak_path).unwrap();
        assert_eq!(backed_up, config_content);
        // Original is untouched
        let original = std::fs::read_to_string(&yaml).unwrap();
        assert_eq!(original, config_content);
    }

    #[test]
    fn no_backup_when_zero_migrations() {
        // GIVEN: a data dir with gateway.yaml already stamped at 3.0.0, so the
        // registered 3.0.0 migration's `applies_below` ceiling no longer matches.
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        std::fs::write(&yaml, "server:\n  port: 39400\n").unwrap();
        write_stamp(&stamp_path(dir.path()), "3.0.0").unwrap();

        // WHEN: upgrade runs (stamp already satisfies every registered migration)
        let ctx = UpgradeContext {
            data_dir: dir.path(),
            old_ver: SemVer::parse("3.0.0").unwrap(),
            new_ver: SemVer::parse("3.0.1").unwrap(),
            dry_run: false,
            quiet: true,
        };
        let n = ctx.run().unwrap();

        // THEN: no migrations applied, no backup file created
        assert_eq!(n, 0);
        let bak = dir.path().join("gateway.yaml.bak.3.0.0");
        assert!(
            !bak.exists(),
            "backup should NOT be created when 0 migrations apply"
        );
    }

    // ── 3.0.0 multi-user posture notice migration ────────────────────────────

    #[test]
    fn posture_auth_disabled_when_auth_section_absent() {
        // GIVEN: a config with no `auth` section at all
        let yaml: serde_yaml::Value = serde_yaml::from_str("server:\n  port: 39400\n").unwrap();
        // WHEN/THEN: treated as auth-disabled (default `auth.enabled` is false)
        assert_eq!(
            detect_multi_user_posture(&yaml),
            MultiUserPosture::AuthDisabled
        );
    }

    #[test]
    fn posture_auth_disabled_when_enabled_false() {
        // GIVEN: auth explicitly disabled
        let yaml: serde_yaml::Value = serde_yaml::from_str("auth:\n  enabled: false\n").unwrap();
        // WHEN/THEN
        assert_eq!(
            detect_multi_user_posture(&yaml),
            MultiUserPosture::AuthDisabled
        );
    }

    #[test]
    fn posture_undeclared_when_auth_enabled_without_single_user_or_shared_account() {
        // GIVEN: auth enabled, no single_user flag, no backend shared_account
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      enabled: true\n",
        )
        .unwrap();
        // WHEN/THEN: this is exactly the silent-behavior-change case
        assert_eq!(
            detect_multi_user_posture(&yaml),
            MultiUserPosture::Undeclared
        );
    }

    #[test]
    fn posture_already_declared_when_single_user_true() {
        // GIVEN: auth enabled and single_user explicitly declared
        let yaml: serde_yaml::Value =
            serde_yaml::from_str("auth:\n  enabled: true\n  single_user: true\n").unwrap();
        // WHEN/THEN
        assert_eq!(
            detect_multi_user_posture(&yaml),
            MultiUserPosture::AlreadyDeclared
        );
    }

    #[test]
    fn posture_already_declared_when_backend_shared_account_true() {
        // GIVEN: auth enabled, single_user unset, but one backend opts in to shared_account
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      enabled: true\n      shared_account: true\n",
        )
        .unwrap();
        // WHEN/THEN
        assert_eq!(
            detect_multi_user_posture(&yaml),
            MultiUserPosture::AlreadyDeclared
        );
    }

    #[test]
    fn posture_undeclared_ignores_shared_account_false() {
        // GIVEN: a backend that explicitly sets shared_account: false (still fail-closed)
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      shared_account: false\n",
        )
        .unwrap();
        // WHEN/THEN: an explicit `false` must not be mistaken for an opt-in
        assert_eq!(
            detect_multi_user_posture(&yaml),
            MultiUserPosture::Undeclared
        );
    }

    #[test]
    fn migration_apply_is_a_noop_when_config_file_missing() {
        // GIVEN: a data dir with no gateway.yaml at all
        let dir = TempDir::new().unwrap();
        // WHEN: the migration runs
        let result = migrate_3_0_0_multi_user_notice(dir.path());
        // THEN: it succeeds without creating any file
        assert!(result.is_ok());
        assert!(!dir.path().join("gateway.yaml").exists());
    }

    #[test]
    fn migration_apply_is_a_noop_on_unparseable_yaml() {
        // GIVEN: a gateway.yaml that is not valid YAML
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        std::fs::write(&yaml, "not: [valid: yaml").unwrap();
        // WHEN: the migration runs
        let result = migrate_3_0_0_multi_user_notice(dir.path());
        // THEN: it succeeds (never fails the upgrade over a notice) and leaves
        // the unparseable file untouched.
        assert!(result.is_ok());
        assert_eq!(std::fs::read_to_string(&yaml).unwrap(), "not: [valid: yaml");
    }

    #[test]
    fn migration_apply_never_mutates_the_config_file() {
        // GIVEN: a config that would trigger the "undeclared" notice branch
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        let original =
            "auth:\n  enabled: true\nbackends:\n  jira:\n    oauth:\n      enabled: true\n";
        std::fs::write(&yaml, original).unwrap();

        // WHEN: the migration runs (potentially twice, simulating a re-run)
        migrate_3_0_0_multi_user_notice(dir.path()).unwrap();
        migrate_3_0_0_multi_user_notice(dir.path()).unwrap();

        // THEN: the file is byte-for-byte unchanged — no `single_user` or
        // `shared_account` was injected, no security posture was altered.
        assert_eq!(std::fs::read_to_string(&yaml).unwrap(), original);
    }

    #[test]
    fn migration_apply_is_idempotent_via_check_upgrade_version_stamp() {
        // GIVEN: a v2.x install with an auth-enabled, undeclared-posture config
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        let original = "auth:\n  enabled: true\n";
        std::fs::write(&yaml, original).unwrap();
        write_stamp(&stamp_path(dir.path()), "2.10.0").unwrap();

        // WHEN: check_upgrade runs once — the migration applies and the stamp
        // advances to the current binary version
        check_upgrade(dir.path()).unwrap();
        let stamp_after_first = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(stamp_after_first, env!("CARGO_PKG_VERSION"));
        let content_after_first = std::fs::read_to_string(&yaml).unwrap();
        assert_eq!(content_after_first, original);

        // AND WHEN: check_upgrade runs again (simulating the next process start)
        check_upgrade(dir.path()).unwrap();

        // THEN: the stamp and config are unchanged — the migration did not
        // re-run because `installed == current` short-circuits to the no-op
        // branch (idempotency guaranteed by the version stamp, not by the
        // migration's own logic).
        let stamp_after_second = read_stamp(&stamp_path(dir.path())).unwrap().unwrap();
        assert_eq!(stamp_after_second, env!("CARGO_PKG_VERSION"));
        let content_after_second = std::fs::read_to_string(&yaml).unwrap();
        assert_eq!(content_after_second, original);
    }

    #[test]
    fn migration_registered_for_3_0_0_triggers_config_backup() {
        // GIVEN: a pre-3.0.0 install with a gateway.yaml present
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        std::fs::write(&yaml, "auth:\n  enabled: true\n  single_user: true\n").unwrap();
        write_stamp(&stamp_path(dir.path()), "2.10.0").unwrap();

        // WHEN: check_upgrade runs, triggering the registered 3.0.0 migration
        check_upgrade(dir.path()).unwrap();

        // THEN: the existing backup path fired because >=1 migration applied
        let bak = dir.path().join("gateway.yaml.bak.2.10.0");
        assert!(
            bak.exists(),
            "backup should be created once a real migration is registered and applies"
        );
    }
}
