// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared helpers for mutating and persisting gateway config files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::Config;
use crate::config_reload::{ReloadContext, ReloadOutcome};

/// Load config from `path`, returning `Config::default()` when the file is absent
/// or cannot be parsed.
#[must_use]
pub fn load_config_or_default(path: &Path) -> Config {
    if path.exists() {
        Config::load(Some(path)).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Could not load config, using defaults");
            Config::default()
        })
    } else {
        Config::default()
    }
}

/// Load config from `path`, returning `Config::default()` when the file is absent.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be parsed.
pub fn load_existing_or_default(path: &Path) -> crate::Result<Config> {
    if path.exists() {
        Config::load(Some(path))
    } else {
        Ok(Config::default())
    }
}

/// Serialize `config` as YAML and write it to `path`.
///
/// # Errors
///
/// Returns `Err` on validation, serialisation, or I/O failure.
pub fn write_config(path: &Path, config: &Config) -> Result<(), String> {
    config
        .validate()
        .map_err(|e| format!("Failed to validate config: {e}"))?;
    let yaml =
        serde_yaml::to_string(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    write_yaml(path, &yaml)
}

/// Serialize `config`, write it atomically, then trigger hot-reload when a
/// reload context is available.
///
/// Persistence is always authoritative for the on-disk file. Hot-reload then
/// applies only the subset of changes supported by [`ReloadContext`] (for
/// example, backend changes); server listener changes remain on disk until the
/// process is restarted.
///
/// # Errors
///
/// Returns an error string on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> Result<(), String> {
    write_config_and_reload_outcome(path, config, reload_context)
        .await
        .map(|_| ())
}

/// Serialize `config`, write it atomically, then return any hot-reload outcome.
///
/// # Errors
///
/// Returns an error string on serialization, write, rename, or reload failure.
pub async fn write_config_and_reload_outcome(
    path: &Path,
    config: &Config,
    reload_context: Option<&ReloadContext>,
) -> Result<Option<ReloadOutcome>, String> {
    if let Some(ctx) = reload_context {
        // Write and reload share one lock inside the context. Writing here
        // first would reopen the race the lock exists to close.
        return ctx.write_and_reload_outcome(path, config).await.map(Some);
    }

    write_config(path, config)?;
    Ok(None)
}

/// What a guarded read-modify-write did: either the change was applied and
/// persisted, or the caller's own check rejected it and nothing was written.
pub enum ConfigMutation<T, E> {
    /// The change was applied, persisted, and (when a reload context exists)
    /// reloaded.
    Applied(T, Option<ReloadOutcome>),
    /// The caller's closure refused the change. The file is untouched.
    Rejected(E),
}

/// Read the config, apply `mutate` to it, and persist the result without
/// letting another writer slip in between the read and the write.
///
/// Reading outside the lock is what makes edits vanish: two requests each read
/// the same starting file, each apply their own change to that stale copy, and
/// the second write erases the first change while reporting success. Doing the
/// read inside the same critical section as the write is what stops it.
///
/// # Errors
///
/// Returns an error string on validation, write, rename, or reload failure. A
/// refusal from `mutate` is not an error; it comes back as
/// [`ConfigMutation::Rejected`] with the file untouched.
pub async fn mutate_config_and_reload<T, E, F>(
    path: &Path,
    reload_context: Option<&ReloadContext>,
    mutate: F,
) -> Result<ConfigMutation<T, E>, String>
where
    F: FnOnce(&mut Config) -> Result<T, E>,
{
    if let Some(ctx) = reload_context {
        return ctx.mutate_and_reload_outcome(path, mutate).await;
    }

    // No live gateway to reload, so no reload lock exists to hold. This path is
    // the CLI acting on a config file nothing else is serving.
    let mut config = load_config_or_default(path);
    match mutate(&mut config) {
        Ok(value) => {
            write_config(path, &config)?;
            Ok(ConfigMutation::Applied(value, None))
        }
        Err(rejection) => Ok(ConfigMutation::Rejected(rejection)),
    }
}

/// How many times a rename is retried before the write is reported failed.
///
/// Windows can refuse a rename that Unix would complete: another process
/// holding the destination open produces a sharing violation, which is
/// transient rather than fatal. Retrying a bounded number of times rides that
/// out; giving up after it leaves the previous config in place.
const RENAME_ATTEMPTS: u32 = 8;

/// Pause between rename attempts. Eight attempts cost at most ~35ms, and only
/// on the failure path.
const RENAME_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

/// How many scratch names are tried before a write gives up.
///
/// Each name is probed with an exclusive create, so a collision means some
/// other writer owns that name right now. A handful of probes clears any
/// realistic amount of concurrency; past that, failing is more honest than
/// reusing a name whose owner is still writing to it.
const SCRATCH_ATTEMPTS: u64 = 8;

/// Write `yaml` to a scratch file next to `path`, then rename it over `path`.
///
/// The rename is what makes the write atomic: a reader sees either the old
/// file or the new one, never a half-written one. Writing in place instead
/// would leave the config truncated if the process died mid-write, which is
/// exactly the config a restart needs to be intact.
///
/// This path is deliberately not platform-gated. An earlier version wrote in
/// place on Windows, so the one platform without a crash-safe write was also
/// the one no test covered.
fn write_yaml(path: &Path, yaml: &str) -> Result<(), String> {
    let (mut file, tmp_path) = create_scratch_exclusive(path, next_scratch_seed())?;

    // Leave no debris behind on any failure. The scratch name is unique per
    // call, so without cleanup each failure would strand one more file next to
    // the config instead of reusing a single stale one.
    let cleanup = |e: &std::io::Error, what: &str| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("Failed to {what} config: {e}")
    };

    // Write through the handle the exclusive create returned. Reopening by
    // path would reopen the gap the exclusive create just closed.
    file.write_all(yaml.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| cleanup(&e, "write temp"))?;
    drop(file);

    rename_with_retry(&tmp_path, path).map_err(|e| cleanup(&e, "replace"))
}

/// Claim a scratch file next to `path` that no other writer holds.
///
/// The create is exclusive, so a name already in use is refused rather than
/// truncated. A refused name belongs to another live writer, so it is left
/// alone and the next name is tried.
///
/// # Errors
///
/// Returns an error when every candidate name is taken, or on any I/O failure
/// other than a collision.
fn create_scratch_exclusive(path: &Path, first: u64) -> Result<(std::fs::File, PathBuf), String> {
    for seed in first..first.wrapping_add(SCRATCH_ATTEMPTS) {
        let candidate = scratch_candidate(path, seed);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, candidate)),
            // Someone else's scratch file. Not ours to write to, and not ours
            // to delete either.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("Failed to create temp config: {e}")),
        }
    }
    Err(format!(
        "Failed to create temp config: {SCRATCH_ATTEMPTS} scratch names next to the config were all in use"
    ))
}

/// Rename `from` over `to`, retrying while the OS reports a transient refusal.
fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..RENAME_ATTEMPTS {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if is_transient(&e) => {
                if attempt + 1 < RENAME_ATTEMPTS {
                    std::thread::sleep(RENAME_RETRY_DELAY);
                }
                last = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename exhausted its retries")))
}

/// Whether an error is the kind another process can stop causing.
///
/// A Windows sharing violation surfaces as `PermissionDenied` or, on older
/// mappings, uncategorised. On Unix neither classification is reachable from a
/// rename inside a directory the process just wrote to, so the retry loop
/// costs nothing there.
fn is_transient(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::PermissionDenied) || e.raw_os_error() == Some(32)
}

/// The next scratch seed no other writer in this process will pick.
fn next_scratch_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The scratch path for a given seed.
///
/// Split from the counter so a test can name a candidate deterministically.
/// Probing the shared counter to predict the next name is flaky: tests run in
/// parallel threads of one binary and any other write moves it.
fn scratch_candidate(path: &Path, seed: u64) -> PathBuf {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(".tmp.{}.{seed}", std::process::id()));
    PathBuf::from(tmp_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_existing_or_default_returns_default_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.yaml");

        let config = load_existing_or_default(&path).unwrap();

        assert!(config.backends.is_empty());
    }

    #[test]
    fn write_config_persists_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let config = Config::default();

        write_config(&path, &config).unwrap();

        assert!(path.exists());
        let loaded = Config::load(Some(&path)).unwrap();
        assert_eq!(loaded.backends.len(), config.backends.len());
    }

    /// The temp file used by an atomic config write must be unique per call.
    /// A shared `<config>.tmp` lets two concurrent writers clobber each other:
    /// one renames the other's bytes into place and reports its own edit saved.
    /// Every platform writes through a scratch file and renames it into place.
    ///
    /// Windows used to write the config in place, so a crash mid-write left a
    /// truncated config behind — on the one platform no test covered. This
    /// asserts the observable half of the unified path: the scratch file is
    /// gone, the config parses, and nothing extra is left in the directory.
    #[test]
    fn a_config_write_leaves_no_scratch_file_on_any_platform() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");

        write_config(&path, &Config::default()).unwrap();

        assert!(Config::load(Some(&path)).is_ok(), "config is not parseable");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok().map(|e| e.file_name()))
            .filter(|name| name != "gateway.yaml")
            .collect();
        assert!(
            leftovers.is_empty(),
            "the write left scratch files next to the config: {leftovers:?}"
        );
    }

    /// A rename that fails for a reason another process can stop causing is
    /// retried; one that cannot succeed is reported immediately.
    #[test]
    fn only_transient_rename_errors_are_retried() {
        assert!(
            is_transient(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            "a sharing violation would be reported as a permanent failure"
        );
        assert!(
            !is_transient(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            "a missing scratch file would be retried until the attempts ran out"
        );
    }

    /// A scratch name already in use belongs to another live writer. Claiming
    /// it truncates bytes that writer is about to rename over the config, so
    /// its edit ships half-written or vanishes entirely.
    #[test]
    fn a_scratch_name_already_in_use_is_never_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let taken = scratch_candidate(&path, 7);
        std::fs::write(&taken, b"another writer's bytes").unwrap();

        let (_file, chosen) = create_scratch_exclusive(&path, 7).unwrap();

        assert_ne!(
            chosen, taken,
            "the write claimed a scratch file another writer already held"
        );
        assert_eq!(
            std::fs::read(&taken).unwrap(),
            b"another writer's bytes",
            "the write truncated another writer's scratch file"
        );
    }

    /// Exhausting every candidate must fail rather than reuse a live name.
    #[test]
    fn a_write_fails_when_every_scratch_name_is_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        for seed in 0..SCRATCH_ATTEMPTS {
            std::fs::write(scratch_candidate(&path, seed), b"held").unwrap();
        }

        let error = create_scratch_exclusive(&path, 0).unwrap_err();

        assert!(
            error.contains("were all in use"),
            "exhaustion is not distinguishable from an I/O failure: {error}"
        );
    }

    #[test]
    fn each_config_write_gets_its_own_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");

        let (_first_handle, first) = create_scratch_exclusive(&path, next_scratch_seed()).unwrap();
        let (_second_handle, second) =
            create_scratch_exclusive(&path, next_scratch_seed()).unwrap();

        assert_ne!(
            first, second,
            "two writers shared one temp path, so either can overwrite the other"
        );
        for tmp in [&first, &second] {
            assert_eq!(tmp.parent(), path.parent(), "temp file left its directory");
        }
    }

    /// Concurrent writers must each either persist their own bytes or fail
    /// honestly, and the file left behind must be exactly one writer's config.
    /// Against a shared scratch path one writer's rename finds the file already
    /// renamed away and fails with "Failed to replace config file", and the
    /// bytes that land can belong to a writer that reported success elsewhere.
    #[test]
    fn concurrent_config_writes_do_not_lose_the_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");

        // Each writer's config is distinguishable, so the assertion below can
        // tell "one writer won" from "the file is a mix of two writers".
        let config_for = |writer: usize| {
            let mut config = Config::default();
            config.backends.insert(
                format!("writer-{writer}"),
                crate::config::BackendConfig {
                    transport: crate::config::TransportConfig::Http {
                        http_url: "http://127.0.0.1:9/mcp".to_string(),
                        streamable_http: false,
                        protocol_version: None,
                    },
                    ..crate::config::BackendConfig::default()
                },
            );
            config
        };

        for _ in 0..40 {
            let errors: Vec<String> = std::thread::scope(|scope| {
                let path = &path;
                let config_for = &config_for;
                let handles: Vec<_> = (0..8)
                    .map(|writer| scope.spawn(move || write_config(path, &config_for(writer))))
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|h| h.join().unwrap().err())
                    .collect()
            });

            assert!(
                errors.is_empty(),
                "concurrent writers collided on the scratch file: {errors:?}"
            );

            let loaded = Config::load(Some(&path)).expect("config left unparseable");
            let names: Vec<&String> = loaded.backends.keys().collect();
            assert_eq!(
                names.len(),
                1,
                "persisted config is not any single writer's: {names:?}"
            );
            assert!(
                names[0].starts_with("writer-"),
                "persisted config is not any single writer's: {names:?}"
            );
        }

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|name| name != "gateway.yaml")
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch files were left next to the config: {leftovers:?}"
        );
    }

    #[test]
    fn write_config_rejects_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let mut config = Config::default();
        config.backends.insert(
            "invalid_backend".to_string(),
            crate::config::BackendConfig {
                transport: crate::config::TransportConfig::Http {
                    http_url: "not a url".to_string(),
                    streamable_http: false,
                    protocol_version: None,
                },
                ..crate::config::BackendConfig::default()
            },
        );

        let result = write_config(&path, &config);

        assert!(matches!(result, Err(msg) if msg.contains("Failed to validate config")));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn write_config_and_reload_without_context_persists_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let config = Config::default();

        write_config_and_reload(&path, &config, None).await.unwrap();

        assert!(path.exists());
        let loaded = Config::load(Some(&path)).unwrap();
        assert_eq!(loaded.backends.len(), config.backends.len());
    }

    #[tokio::test]
    async fn write_config_and_reload_outcome_without_context_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gateway.yaml");
        let config = Config::default();

        let outcome = write_config_and_reload_outcome(&path, &config, None)
            .await
            .unwrap();

        assert!(outcome.is_none());
    }
}
