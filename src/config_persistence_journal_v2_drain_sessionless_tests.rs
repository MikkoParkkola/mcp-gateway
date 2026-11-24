// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway built from a config path with no startup session behind it runs the startup gate
//! itself: it refuses while a config-write artifact sits beside the config, writes nothing while
//! refusing, and goes ahead on the caller's config when none is there.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use super::fixtures::{Live, replace_bytes, state};
use crate::config::Config;
use crate::config_persistence::lock;
use crate::gateway::Gateway;
use crate::gateway::test_helpers::write_owner_only;

use super::super::fixtures::{NEW, OLD};

const LOCK_SIDECAR: &str = ".gateway.yaml.lock";
const ABANDONED: &str = "gateway.yaml.abandoned";
const RETIRED: &str = "gateway.yaml.abandoned.retired";

// One phrase per refusal class, each found in that class's sentence and in no other; the full
// sentences of the existing classes are pinned by the gate's own rows.
const JOURNAL_PENDING: &str = "journal beside the config still owes audit records";
const ABANDONED_PENDING: &str = "holds audit records this gateway cannot deliver";
const BUSY: &str = "past the 30-second wait";
// The two new classes: their whole sentences are written here first.
const RECOVERY_PENDING: &str = concat!(
    "An interrupted config write needs recovering before this config is used. Call ",
    "mcp_gateway::config_reload::recover_before_start on it, or start the gateway once with ",
    "serve, then build again."
);
const MANIFEST_UNREAD: &str = concat!(
    "This build cannot read the retired config-write manifest beside the config. It stays as ",
    "evidence: move it aside by hand, or use a build that reads it."
);

type Listing = Vec<(OsString, Option<Vec<u8>>)>;

/// Every entry beside the config, name then bytes (`None` for anything not a plain file).
fn listing(dir: &Path) -> Listing {
    let mut found: Listing = std::fs::read_dir(dir)
        .expect("list the config directory")
        .map(|entry| {
            let entry = entry.expect("directory entry");
            let plain = entry.file_type().is_ok_and(|kind| kind.is_file());
            let bytes = plain.then(|| std::fs::read(entry.path()).expect("read an entry"));
            (entry.file_name(), bytes)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// `after` equals `before`, apart from the config lock's sidecar, which taking the lock creates
/// and every start keeps.
fn unchanged_but_sidecar(row: &str, before: &Listing, after: &Listing) {
    let without = |list: &Listing| -> Listing {
        list.iter()
            .filter(|(name, _)| name != LOCK_SIDECAR)
            .cloned()
            .collect()
    };
    assert_eq!(
        without(after),
        without(before),
        "{row}: no file changed or appeared beside the config, except the lock sidecar"
    );
}

/// The caller's config, loaded before any artifact is planted.
fn caller_config(live: &Live) -> Config {
    Config::load(Some(&live.path)).expect("the fixture config loads")
}

/// A v1 replace journal left by a writer killed after its rename: the new bytes in place, the
/// old ones staged.
fn plant_v1_journal(live: &Live) {
    use crate::config_persistence::journal;
    journal::stage_original(&live.path, OLD).expect("stage the original");
    journal::begin(&live.path, crate::hashing::sha256_hex(OLD)).expect("journal");
    replace_bytes(&live.path, NEW);
}

async fn refused(row: &str, case: &str, live: &Live, config: Config, phrase: &str) {
    let before = listing(&live.resolved);
    let built = Gateway::new_with_path(config, Some(live.path.clone())).await;
    let after = listing(&live.resolved);
    let message = match built {
        Ok(_) => panic!("{row} {case}: the constructor must refuse, it built a gateway"),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains(phrase),
        "{row} {case}: the refusal carries {phrase:?}, got {message:?}"
    );
    unchanged_but_sidecar(&format!("{row} {case}"), &before, &after);
}

/// WIRE.2: each artifact alone refuses a sessionless path-backed construction, with its own
/// refusal class, and nothing beside the config changes.
#[tokio::test]
async fn sessionless_artifact_refused() {
    const ROW: &str = "sessionless_artifact_refused";

    let live = Live::new();
    let config = caller_config(&live);
    plant_v1_journal(&live);
    refused(ROW, "pending v1 journal", &live, config, RECOVERY_PENDING).await;

    let live = Live::new();
    let config = caller_config(&live);
    drop(live.seed(state(&live.resolved), ROW));
    refused(ROW, "pending v2 journal", &live, config, JOURNAL_PENDING).await;

    let live = Live::new();
    let config = caller_config(&live);
    write_owner_only(live.resolved.join(ABANDONED), "left by a dead writer").expect("plant");
    refused(
        ROW,
        "abandoned file alone",
        &live,
        config,
        ABANDONED_PENDING,
    )
    .await;

    let live = Live::new();
    let config = caller_config(&live);
    write_owner_only(live.resolved.join(RETIRED), "kept as settled history").expect("plant");
    refused(
        ROW,
        "retired manifest alone",
        &live,
        config,
        MANIFEST_UNREAD,
    )
    .await;
}

/// WIRE.2 control: with no artifact the constructor builds on the caller's config, leaves the
/// config's bytes alone, and does not keep the lock.
#[tokio::test]
async fn sessionless_clean_proceeds() {
    const ROW: &str = "sessionless_clean_proceeds";
    let live = Live::new();
    let config = caller_config(&live);
    let before = listing(&live.resolved);
    let gateway = Gateway::new_with_path(config, Some(live.path.clone()))
        .await
        .unwrap_or_else(|error| panic!("{ROW}: no artifact, so it builds: {error}"));
    unchanged_but_sidecar(ROW, &before, &listing(&live.resolved));
    let again = lock::lock_config_deferred(&live.path, Instant::now()).await;
    assert!(again.is_ok(), "{ROW}: construction let the lock go");
    drop(gateway);
}

/// WIRE.2: a lock someone else holds past the wait refuses with the Busy class, after the full
/// wait and not before.
#[tokio::test]
async fn sessionless_busy() {
    const ROW: &str = "sessionless_busy";
    let live = Live::new();
    let config = caller_config(&live);
    let Ok(held) = lock::lock_config_deferred(&live.path, Instant::now()).await else {
        panic!("{ROW}: nothing else holds the fixture's lock yet");
    };
    let started = Instant::now();
    let built = Gateway::new_with_path(config, Some(live.path.clone())).await;
    let waited = started.elapsed();
    drop(held);
    let message = match built {
        Ok(_) => panic!("{ROW}: a held lock must refuse the build, it built after {waited:?}"),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains(BUSY),
        "{ROW}: the Busy class, got {message:?}"
    );
    assert!(
        (Duration::from_secs(30)..Duration::from_secs(35)).contains(&waited),
        "{ROW}: refused after the 30 s wait, took {waited:?}"
    );
}
