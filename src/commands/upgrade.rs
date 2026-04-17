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
static MIGRATIONS: &[Migration] = &[
    // No migrations registered yet — the framework is the deliverable.
    // Future migrations go here, sorted by applies_below ascending.
];

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

    // ── applicable_migrations (empty registry) ────────────────────────────────

    #[test]
    fn no_migrations_registered_returns_zero() {
        // GIVEN: the empty MIGRATIONS registry
        let dir = TempDir::new().unwrap();
        let ctx = UpgradeContext {
            data_dir: dir.path(),
            old_ver: SemVer::parse("1.0.0").unwrap(),
            new_ver: SemVer::parse("2.10.0").unwrap(),
            dry_run: false,
            quiet: true,
        };
        // WHEN: applicable migrations are collected
        // THEN: none (registry is empty)
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
        // GIVEN: a data dir with gateway.yaml but no applicable migrations
        let dir = TempDir::new().unwrap();
        let yaml = dir.path().join("gateway.yaml");
        std::fs::write(&yaml, "server:\n  port: 39400\n").unwrap();
        write_stamp(&stamp_path(dir.path()), "0.1.0").unwrap();

        // WHEN: upgrade runs (no migrations in the registry)
        let ctx = UpgradeContext {
            data_dir: dir.path(),
            old_ver: SemVer::parse("0.1.0").unwrap(),
            new_ver: SemVer::parse("2.10.0").unwrap(),
            dry_run: false,
            quiet: true,
        };
        let n = ctx.run().unwrap();

        // THEN: no migrations applied, no backup file created
        assert_eq!(n, 0);
        let bak = dir.path().join("gateway.yaml.bak.0.1.0");
        assert!(
            !bak.exists(),
            "backup should NOT be created when 0 migrations apply"
        );
    }
}
