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
        let migrations = self.applicable_migrations();
        let count = migrations.len();

        if count == 0 && !self.quiet {
            println!("No migrations to apply.");
        }

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

fn print_upgrade_summary(old: SemVer, new: SemVer, migrations: usize, dry_run: bool, quiet: bool) {
    if quiet {
        return;
    }
    let prefix = if dry_run { "[dry-run] " } else { "" };
    println!();
    println!(
        "{prefix}Upgraded from {old} to {new}. \
         {migrations} migration{} applied.",
        if migrations == 1 { "" } else { "s" }
    );
    println!("Run `mcp-gateway doctor` to verify.");
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
            new_ver: SemVer::parse("2.9.1").unwrap(),
            dry_run: false,
            quiet: true,
        };
        // WHEN: applicable migrations are collected
        // THEN: none (registry is empty)
        assert_eq!(ctx.applicable_migrations().len(), 0);
    }
}
