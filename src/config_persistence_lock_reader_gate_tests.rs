// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The reload gate: a reload may load only after the abandoned file and the retired manifest are
//! proven absent, on every outcome that permits a load (lock held, deferred or recovering; or no
//! lock in a folder no writer can use). Otherwise it skips and writes nothing. Every reload takes
//! its lock through these two functions (pinned by
//! `every_in_gateway_reload_takes_the_lock_through_reload_outcome`), so the rows call them directly.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{ReaderLock, reader_lock, reader_lock_deferred};
use crate::gateway::test_helpers::write_owner_only;

const CONFIG: &str = "server:\n  port: 7\n";
const EDITED: &str = "server:\n  port: 8\n";
const LOCK_SIDECAR: &str = ".gateway.yaml.lock";
const ABANDONED: &str = "gateway.yaml.abandoned";
const RETIRED: &str = "gateway.yaml.abandoned.retired";
const JOURNAL: &str = ".gateway.yaml.replace-journal";

// A phrase from the abandoned-file class's sentence, and the new manifest sentence in full.
const ABANDONED_PHRASE: &str = "holds audit records this gateway cannot deliver";
const MANIFEST_UNREAD: &str = concat!(
    "This build cannot read the retired config-write manifest beside the config. It stays as ",
    "evidence: move it aside by hand, or use a build that reads it."
);

#[derive(Clone, Copy, Debug)]
enum Route {
    /// An audited gateway's reload: the journal is left for the holder.
    Deferred,
    /// An unaudited reload: a pending journal is recovered while the lock is taken.
    Recovering,
    /// A folder no writer can use: no lock and no sidecar.
    #[cfg(unix)]
    Unlocked,
}

type Listing = Vec<(OsString, Option<Vec<u8>>)>;

fn listing(dir: &Path) -> Listing {
    let mut found: Listing = std::fs::read_dir(dir)
        .expect("list the config directory")
        .map(|entry| {
            let entry = entry.expect("directory entry");
            // The lock sidecar is never read: Windows refuses a read of a range a held lock
            // covers, and every comparison drops the sidecar anyway.
            let plain = entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry.file_name() != LOCK_SIDECAR;
            let bytes = plain.then(|| std::fs::read(entry.path()).expect("read an entry"));
            (entry.file_name(), bytes)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

fn without_sidecar(list: Listing) -> Listing {
    list.into_iter()
        .filter(|(name, _)| name != LOCK_SIDECAR)
        .collect()
}

/// Search and read only (no write), or full owner access again.
#[cfg(unix)]
fn sealed(dir: &Path, seal: bool) {
    let mut access = std::fs::metadata(dir)
        .expect("stat the folder")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut access, if seal { 0o555 } else { 0o755 });
    std::fs::set_permissions(dir, access).expect("chmod the folder");
}

/// Unseals on drop, so the temporary folder can be removed.
#[cfg(unix)]
struct Unseal<'a>(&'a Path);

#[cfg(unix)]
impl Drop for Unseal<'_> {
    fn drop(&mut self) {
        sealed(self.0, false);
    }
}

async fn take(route: Route, config: &Path) -> ReaderLock {
    let deadline = Instant::now() + Duration::from_secs(5);
    match route {
        Route::Deferred => reader_lock_deferred(config, deadline).await,
        Route::Recovering => reader_lock(config, deadline).await,
        #[cfg(unix)]
        Route::Unlocked => reader_lock(config, deadline).await,
    }
}

fn outcome_name(outcome: &ReaderLock) -> String {
    match outcome {
        ReaderLock::Held(_) => "Held".to_owned(),
        ReaderLock::Unlocked(path) => format!("Unlocked({})", path.display()),
        ReaderLock::Skip(why) => format!("Skip({why})"),
    }
}

/// One matrix cell: `artifact` beside the config (or nothing), the config edited, then a reload's
/// lock taken on `route`. Returns the outcome with the folder's listing before and after.
async fn cell(route: Route, artifact: Option<(&str, &str)>) -> (ReaderLock, Listing, Listing) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, CONFIG).expect("config");
    #[cfg(unix)]
    let _unseal = Unseal(dir.path());
    #[cfg(unix)]
    if matches!(route, Route::Unlocked) {
        // Started where it could not write, so nothing made a sidecar; another account that can
        // write there opens it briefly to leave an artifact and the edit.
        sealed(dir.path(), true);
        sealed(dir.path(), false);
    }
    if let Some((name, body)) = artifact {
        write_owner_only(dir.path().join(name), body).expect("artifact");
    }
    write_owner_only(&config, EDITED).expect("the edit a reload would pick up");
    #[cfg(unix)]
    if matches!(route, Route::Unlocked) {
        sealed(dir.path(), true);
        assert!(
            !dir.path().join(LOCK_SIDECAR).exists(),
            "premise: no sidecar, so the reload reaches the no-writer branch"
        );
    }
    let before = listing(dir.path());
    let outcome = take(route, &config).await;
    let after = listing(dir.path());
    (outcome, before, after)
}

fn routes() -> Vec<Route> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut all = vec![Route::Deferred, Route::Recovering];
    #[cfg(unix)]
    if !rustix::process::geteuid().is_root() {
        all.push(Route::Unlocked);
    }
    all
}

/// WIRE.8: every route by which a reload may load skips when an artifact sits beside the config,
/// with that artifact's class, and leaves every file as it was.
#[tokio::test]
async fn reload_gate_matrix() {
    const ROW: &str = "reload_gate_matrix";
    let artifacts = [
        (ABANDONED, "left by a dead writer", ABANDONED_PHRASE),
        (RETIRED, "kept as settled history", MANIFEST_UNREAD),
    ];
    for route in routes() {
        for (name, body, phrase) in artifacts {
            let (outcome, before, after) = cell(route, Some((name, body))).await;
            match &outcome {
                ReaderLock::Skip(why) => assert!(
                    why.contains(phrase),
                    "{ROW} {route:?} {name}: the skip names the artifact's class {phrase:?}: {why}"
                ),
                other => panic!(
                    "{ROW} {route:?} {name}: must skip, got {}",
                    outcome_name(other)
                ),
            }
            assert_eq!(
                without_sidecar(after),
                without_sidecar(before),
                "{ROW} {route:?} {name}: config and artifact unchanged"
            );
        }
    }
}

/// WIRE.8 control: with no artifact each route still permits its load.
#[tokio::test]
async fn reload_gate_matrix_controls() {
    const ROW: &str = "reload_gate_matrix_controls";
    for route in routes() {
        let (outcome, _, _) = cell(route, None).await;
        let loads = match (&outcome, route) {
            (ReaderLock::Held(_), Route::Deferred | Route::Recovering) => true,
            #[cfg(unix)]
            (ReaderLock::Unlocked(_), Route::Unlocked) => true,
            _ => false,
        };
        assert!(
            loads,
            "{ROW} {route:?}: no artifact, so the reload may load; got {}",
            outcome_name(&outcome)
        );
    }
}

/// The disk after a writer died between its rename and its journal's removal: the edit in
/// place, the old bytes staged, the journal naming them.
fn pending_v1(config: &Path) {
    use crate::config_persistence::journal;
    journal::stage_original(config, CONFIG.as_bytes()).expect("stage");
    journal::begin(config, crate::hashing::sha256_hex(CONFIG.as_bytes())).expect("journal");
    write_owner_only(config, EDITED).expect("the renamed-in edit");
}

/// WIRE.8 (gpt r2): the artifact check comes before any journal recovery, on both locked routes:
/// with a pending v1 journal and an artifact, the reload skips and the journal and config stay.
/// Control: the journal alone is recovered on the recovering route, so the fixture is live.
#[tokio::test]
async fn reload_skips_before_recovery() {
    const ROW: &str = "reload_skips_before_recovery";
    for route in [Route::Deferred, Route::Recovering] {
        for (name, body) in [
            (ABANDONED, "left by a dead writer"),
            (RETIRED, "kept as history"),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let config = dir.path().join("gateway.yaml");
            write_owner_only(&config, CONFIG).expect("config");
            pending_v1(&config);
            write_owner_only(dir.path().join(name), body).expect("artifact");
            let before = without_sidecar(listing(dir.path()));
            let outcome = take(route, &config).await;
            assert!(
                matches!(outcome, ReaderLock::Skip(_)),
                "{ROW} {route:?} {name}: skipped, got {}",
                outcome_name(&outcome)
            );
            drop(outcome);
            assert_eq!(
                without_sidecar(listing(dir.path())),
                before,
                "{ROW} {route:?} {name}: journal, staged original and config untouched"
            );
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let config = dir.path().join("gateway.yaml");
    write_owner_only(&config, CONFIG).expect("config");
    pending_v1(&config);
    let outcome = take(Route::Recovering, &config).await;
    assert!(
        matches!(outcome, ReaderLock::Held(_)),
        "{ROW} control: the journal alone is recovered under the lock, got {}",
        outcome_name(&outcome)
    );
    drop(outcome);
    assert!(
        !dir.path().join(JOURNAL).exists(),
        "{ROW} control: recovery removed the journal"
    );
    assert_eq!(
        std::fs::read_to_string(&config).expect("config"),
        CONFIG,
        "{ROW} control: the original is back"
    );
}

/// WIRE.8 (#5202 seats): an artifact that cannot be proven absent blocks like one that is there.
/// A 238-byte config name keeps the lock sidecar (244 bytes), the journal (255) and the abandoned
/// file (248) inside the usual 255-byte name limit, but the retired manifest's name is 256 bytes,
/// so its stat fails as too long instead of not found.
#[cfg(unix)]
#[tokio::test]
async fn reload_skips_an_unprovable_artifact() {
    const ROW: &str = "reload_skips_an_unprovable_artifact";
    let name = format!("{}.yaml", "g".repeat(233));
    for route in [Route::Deferred, Route::Recovering] {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join(&name);
        write_owner_only(&config, CONFIG).expect("config");
        let manifest = dir.path().join(format!("{name}.abandoned.retired"));
        let stat =
            std::fs::symlink_metadata(&manifest).expect_err("premise: no such name can exist");
        assert_ne!(
            stat.kind(),
            std::io::ErrorKind::NotFound,
            "{ROW}: premise: the manifest's stat fails for a reason other than absence"
        );
        let sidecar = OsString::from(format!(".{name}.lock"));
        let unlocked = |list: Listing| -> Listing {
            list.into_iter()
                .filter(|(entry, _)| *entry != sidecar)
                .collect()
        };
        let before = unlocked(listing(dir.path()));
        let outcome = take(route, &config).await;
        match &outcome {
            ReaderLock::Skip(why) => assert!(
                why.contains("could not be checked"),
                "{ROW} {route:?}: the skip says the check failed: {why}"
            ),
            other => panic!("{ROW} {route:?}: must skip, got {}", outcome_name(other)),
        }
        drop(outcome);
        assert_eq!(
            unlocked(listing(dir.path())),
            before,
            "{ROW} {route:?}: config unchanged, nothing written"
        );
    }
}
