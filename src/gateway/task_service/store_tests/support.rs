// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixture and filesystem oracles; no replacement production behavior.
use super::*;
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
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
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
                bytes: kind.is_file().then(|| fs::read(path).unwrap()),
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
    let bytes = entry.bytes.as_ref().unwrap();
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
