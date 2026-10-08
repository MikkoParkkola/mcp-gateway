// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture and filesystem oracles; no replacement production behavior.
use super::*;
use crate::gateway::task_service::record::{TARGET_VERSION, Target};
use chrono::{DateTime, Utc};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub(super) fn at(second: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-09-07T00:00:{second:02}Z"))
        .unwrap()
        .with_timezone(&Utc)
}

pub(super) fn task() -> Task {
    Task::create_at(
        "private-tool",
        at(0),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    )
}

pub(super) fn files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                read_bytes(&entry.path()).expect("no held scratch record"),
            )
        })
        .collect()
}

/// An empty file's bytes are known without a read. On Windows the empty lease
/// file sits under a whole-file byte-range lock while the store is open, and
/// that lock refuses even a read of an empty file (`ERROR_LOCK_VIOLATION`).
/// `None` only on Windows, for a scratch record the store still holds with no
/// sharing (`ERROR_SHARING_VIOLATION`): its bytes are unobservable by design.
fn read_bytes(path: &Path) -> Option<Vec<u8>> {
    if fs::metadata(path).unwrap().len() == 0 {
        return Some(Vec::new());
    }
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if cfg!(windows) && error.raw_os_error() == Some(32) => None,
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}

pub(super) async fn open(path: &Path) -> TaskStore {
    TaskStore::open(path, StoreLimits::default())
        .await
        .expect("clean store must be ready")
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Artifact {
    pub(super) kind: &'static str,
    pub(super) mode: Option<u32>,
    pub(super) inode: Option<(u64, u64)>,
    pub(super) bytes: Option<Vec<u8>>,
    pub(super) target: Option<PathBuf>,
}
pub(super) type Manifest = BTreeMap<PathBuf, Artifact>;

pub(super) fn manifest(root: &Path) -> Manifest {
    fn visit(root: &Path, path: &Path, result: &mut Manifest) {
        let meta = fs::symlink_metadata(path).unwrap();
        let kind = meta.file_type();
        // Unix-only: compares (dev, ino) file identity via MetadataExt, which Windows std metadata does not expose.
        #[cfg(unix)]
        let (mode, inode) = {
            use std::os::unix::fs::MetadataExt;
            (Some(meta.mode() & 0o7777), Some((meta.dev(), meta.ino())))
        };
        #[cfg(not(unix))]
        let (mode, inode) = (None, None);
        result.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            Artifact {
                kind: if kind.is_symlink() {
                    "link"
                } else if kind.is_dir() {
                    "dir"
                } else if kind.is_file() {
                    "file"
                } else {
                    "other"
                },
                mode,
                inode,
                bytes: kind.is_file().then(|| read_bytes(path)).flatten(),
                target: kind.is_symlink().then(|| fs::read_link(path).unwrap()),
            },
        );
        if kind.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), result);
            }
        }
    }
    let mut result = Manifest::new();
    visit(root, root, &mut result);
    result
}

pub(super) fn created_sidecar(root: &Path) -> std::path::PathBuf {
    let initial: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(
        initial.len(),
        1,
        "fresh store creates its one custody sidecar, no task yet"
    );
    // Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&initial[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    initial[0].clone()
}

pub(super) fn assert_stage_layout(
    image: &Manifest,
    lease: &Path,
    id: &str,
    stage: CommitStage,
    expected: &Value,
) {
    let lease_name = Path::new(lease.file_name().unwrap());
    let lease = image.get(lease_name).expect("same lease remains present");
    assert_eq!(lease.kind, "file");
    // Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
    #[cfg(unix)]
    assert_eq!(lease.mode, Some(0o600));
    let final_name = PathBuf::from(format!("{id}.json"));
    let data: Vec<_> = image
        .iter()
        .filter(|(name, _)| !name.as_os_str().is_empty())
        .filter(|(name, _)| name.as_path() != lease_name)
        .collect();
    assert_eq!(data.len(), 1, "one candidate file at each writer boundary");
    let (name, entry) = data[0];
    assert_eq!(entry.kind, "file");
    // Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
    #[cfg(unix)]
    assert_eq!(
        entry.mode,
        Some(0o600),
        "temporary and final records are private"
    );
    if stage == CommitStage::DirectorySync {
        assert_eq!(name, &final_name);
    } else {
        assert_ne!(name, &final_name);
        assert!(!image.contains_key(&final_name));
    }
    let Some(bytes) = entry.bytes.as_ref() else {
        // Windows holds the scratch record share-0 until it closes it before
        // the rename; name, count and layout above are still checked.
        assert!(
            cfg!(windows) && matches!(stage, CommitStage::Flush | CommitStage::FileSync),
            "candidate bytes unreadable at {stage:?}"
        );
        return;
    };
    if stage == CommitStage::Write {
        assert!(
            bytes.is_empty(),
            "write seam is after private temp creation, before payload write"
        );
    } else {
        let record: Value =
            serde_json::from_slice(bytes).expect("complete candidate before flush/fsync/rename");
        assert_eq!(
            &record, expected,
            "complete proposed record at every post-write boundary"
        );
    }
}

pub(super) fn seed_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    // Unix-only: asserts POSIX mode bits; Windows has no mode bits (owner-only comes from DACLs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Poison `store` as a failed final directory sync does: the record is renamed
/// into place, durability is uncertain, and the store stops serving, with every
/// row still held in memory. Unlike `close`, nothing is cleared, so a readiness
/// guard removed from a read or write path shows as an answer instead of an
/// absence.
pub(super) async fn poison(store: &TaskStore, owner: &str, id: &str, revision: u64) {
    store
        .set_hook(Some(Arc::new(|stage| {
            if stage == CommitStage::DirectorySync {
                Err(std::io::Error::other("injected poison"))
            } else {
                Ok(())
            }
        })))
        .await;
    assert_eq!(
        store
            .mark_dispatched(owner, id, revision)
            .await
            .unwrap_err(),
        StoreError::Storage
    );
    store.set_hook(None).await;
    assert!(!store.ready(), "the store is poisoned, not closed");
}

pub(super) fn record_file(path: &Path, id: &str) -> Value {
    serde_json::from_slice(&fs::read(path.join(format!("{id}.json"))).unwrap()).unwrap()
}

pub(super) fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value).unwrap().len()
}

/// An outcome no record under `limit` can hold, so settling it takes the
/// bounded fallback.
pub(super) fn oversize(limit: usize) -> TaskTransition {
    TaskTransition::Complete(json!({ "content": [{ "type": "text", "text": "q".repeat(limit) }] }))
}

/// A target the bounded fallback drops (MIK-7651): a live row carrying it is
/// larger than its own widest fallback, so an exact-cap case lands on the size
/// check it names rather than on the fallback-room check.
pub(super) fn padding() -> Vec<Target> {
    vec![Target {
        server: "padding".repeat(64),
        tool: "t".to_owned(),
    }]
}

/// [`PreparedTask::for_test`] carrying [`padding`].
pub(super) fn padded(task: &Task, owner: &str, identity: u64) -> PreparedTask {
    let mut prepared = PreparedTask::for_test(task, owner, identity);
    prepared.record.targets = padding();
    prepared.record.version = prepared.record.version.max(TARGET_VERSION);
    prepared
}

/// The bytes of `task`'s freshly created record, and of the bounded failure it
/// settles as straight after, at its natural revision and settle instant. Both
/// measured in a store with room for them.
pub(super) async fn created_and_fallback(task: &Task) -> (usize, Value) {
    created_and_fallback_of(task, PreparedTask::for_test(task, OWNER, 1)).await
}

/// [`created_and_fallback`] for a row `prepared` by the caller.
pub(super) async fn created_and_fallback_of(task: &Task, prepared: PreparedTask) -> (usize, Value) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let room = StoreLimits {
        record_bytes: 4 * 1024,
        ..StoreLimits::default()
    };
    let store = TaskStore::open(&path, room).await.unwrap();
    store.create(prepared).await.unwrap();
    let created = fs::read(path.join(format!("{}.json", task.id())))
        .unwrap()
        .len();
    let settled = store
        .settle_bounded(
            OWNER,
            task.id(),
            1,
            (oversize(4 * 1024), Some(Vec::new())),
            at(1),
        )
        .await
        .unwrap();
    assert!(
        settled.output_free,
        "the fixture outcome takes the fallback"
    );
    let fallback = record_file(&path, task.id());
    store.close().await.unwrap();
    (created, fallback)
}

/// `fallback` re-encoded at its widest: the largest revision and a settle
/// instant printed with all nine fractional digits.
pub(super) fn widest(mut fallback: Value) -> usize {
    fallback["revision"] = json!(u64::MAX);
    let updated = &mut fallback["model"]["task"]["lastUpdatedAt"];
    assert!(
        updated.is_string(),
        "the record keeps its update instant: {fallback}"
    );
    *updated = json!("2026-09-07T00:00:01.999999999Z");
    encoded_len(&fallback)
}
