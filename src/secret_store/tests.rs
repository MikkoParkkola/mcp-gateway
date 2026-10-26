// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The store core (ADR-028 rules 1-6, ADR-024's sequence) over the files
//! store and an in-memory fake. Rows are the test plan's B ids.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::index::sync_seam;
use super::{
    FilesStore, NewSecret, SaveError, SecretStore, StoreError, StoreKind, Vault, choose_store,
    fresh_name, random_suffix, save_secrets, unused_entries,
};
use crate::config::{Config, SecretStoreChoice};

const SENTINEL: &[u8] = b"kc-sentinel-7f3a";

/// A temporary config dir and a vault whose lock lives in it.
pub(super) fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::with_lock(dir.path(), dir.path().join("vault.lock"));
    (dir, vault)
}

pub(super) fn index_text(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("secrets-index.jsonl")).unwrap_or_default()
}

/// An in-memory store that records every call, can fail its Nth create, and
/// checks at each create that the name is already durable in the index.
pub(super) struct Fake {
    entries: Mutex<BTreeMap<String, Vec<u8>>>,
    calls: Mutex<Vec<String>>,
    pub(super) fail_create: Option<usize>,
    creates: Mutex<usize>,
    limit: usize,
    pub(super) probe: Result<(), StoreError>,
    index: Option<PathBuf>,
    /// Every delete fails, leaving the entry.
    pub(super) fail_delete: bool,
    /// The first name asked about is taken by an entry this save did not make.
    collide: bool,
}

impl Fake {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::default(),
            calls: Mutex::default(),
            fail_create: None,
            creates: Mutex::new(0),
            limit: 64,
            probe: Ok(()),
            index: None,
            collide: false,
            fail_delete: false,
        }
    }

    pub(super) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub(super) fn names(&self) -> Vec<String> {
        self.entries.lock().unwrap().keys().cloned().collect()
    }

    fn call(&self, what: &str, name: &str) {
        self.calls.lock().unwrap().push(format!("{what} {name}"));
    }
}

impl SecretStore for Fake {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }
    fn limit(&self) -> usize {
        self.limit
    }
    fn probe(&self) -> Result<(), StoreError> {
        self.calls.lock().unwrap().push("probe".to_owned());
        self.probe.clone()
    }
    fn exists(&self, name: &str) -> Result<bool, StoreError> {
        self.call("exists", name);
        let mut entries = self.entries.lock().unwrap();
        if self.collide && entries.is_empty() {
            entries.insert(name.to_owned(), b"foreign".to_vec());
        }
        Ok(entries.contains_key(name))
    }
    fn create(&self, name: &str, value: &[u8]) -> Result<String, StoreError> {
        self.call("create", name);
        if let Some(index) = &self.index {
            let text = std::fs::read_to_string(index).unwrap_or_default();
            assert!(
                text.contains(name),
                "created before its index line was written"
            );
            let synced = sync_seam::SYNCED.with(|s| s.borrow().clone());
            assert!(
                synced.ends_with(&["index", "index dir"]),
                "created before the index and its directory were synced: {synced:?}"
            );
        }
        let mut creates = self.creates.lock().unwrap();
        *creates += 1;
        if self.fail_create == Some(*creates) {
            return Err(StoreError::Failed("injected create failure".to_owned()));
        }
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(name) {
            return Err(StoreError::Exists);
        }
        entries.insert(name.to_owned(), value.to_vec());
        Ok(format!("keychain:{name}"))
    }
    fn delete(&self, name: &str) -> Result<(), StoreError> {
        self.call("delete", name);
        if self.fail_delete {
            return Err(StoreError::Failed("injected delete failure".to_owned()));
        }
        self.entries.lock().unwrap().remove(name);
        Ok(())
    }
}

pub(super) fn three() -> [NewSecret<'static>; 3] {
    [
        NewSecret {
            field: "auth.bearer_token",
            value: b"one",
        },
        NewSecret {
            field: "key_server.admin_token",
            value: b"two",
        },
        NewSecret {
            field: "security.message_signing.shared_secret",
            value: b"three",
        },
    ]
}

pub(super) fn count(calls: &[String], what: &str) -> usize {
    calls.iter().filter(|c| c.starts_with(what)).count()
}

#[test]
fn b1_secrets_store_parses_and_defaults_to_auto() {
    let parse = |yaml: &str| crate::yaml::from_str::<Config>(yaml);
    assert_eq!(
        parse("{}").expect("empty").secrets.store,
        SecretStoreChoice::Auto
    );
    for (text, want) in [
        ("auto", SecretStoreChoice::Auto),
        ("keychain", SecretStoreChoice::Keychain),
        ("files", SecretStoreChoice::Files),
    ] {
        let config = parse(&format!("secrets:\n  store: {text}\n")).expect(text);
        assert_eq!(config.secrets.store, want);
    }
    let error = parse("secrets:\n  store: vault\n").expect_err("an invalid value");
    let shown = error.to_string();
    assert!(shown.contains("store"), "{shown}");
}

#[test]
fn b1_keychain_is_refused_by_name_until_its_writers_land_and_auto_is_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let refused = choose_store(SecretStoreChoice::Keychain, dir.path())
        .err()
        .expect("keychain refused");
    assert_eq!(refused, StoreError::NotYetAvailable);
    assert!(
        refused.reason().contains("not yet available on this build"),
        "{}",
        refused.reason()
    );
    assert!(refused.reason().contains("secrets.store: files"));
    for choice in [SecretStoreChoice::Auto, SecretStoreChoice::Files] {
        let store = choose_store(choice, dir.path()).expect("files");
        assert_eq!(store.kind(), StoreKind::Files);
    }
}

#[test]
fn b3_b23_a_failed_second_create_leaves_nothing_and_never_commits() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.fail_create = Some(2);
    let mut committed = false;
    let result = save_secrets(&vault, &store, &three(), |_| {
        committed = true;
        Ok::<_, ()>(())
    });
    assert!(
        matches!(result, Err(SaveError::Store(StoreError::Failed(_)))),
        "{result:?}"
    );
    assert!(!committed, "the config was committed after a failed create");
    let calls = store.calls();
    assert_eq!(count(&calls, "create"), 2, "{calls:?}");
    assert_eq!(
        count(&calls, "delete"),
        1,
        "only the first entry is removed: {calls:?}"
    );
    assert!(store.names().is_empty(), "{:?}", store.names());
    assert!(
        super::index::Index::at(dir.path())
            .live()
            .unwrap()
            .is_empty(),
        "the index still lists rolled-back names:\n{}",
        index_text(dir.path())
    );
}

#[test]
fn b3_a_failed_commit_removes_every_new_entry() {
    let (_dir, vault) = vault();
    let store = Fake::new();
    let result = save_secrets(&vault, &store, &three(), |_| Err::<(), _>("disk full"));
    assert!(
        matches!(result, Err(SaveError::Commit("disk full"))),
        "{result:?}"
    );
    assert!(store.names().is_empty(), "{:?}", store.names());
    assert_eq!(count(&store.calls(), "delete"), 3);
}

#[test]
fn b4_old_entries_stay_and_only_unreferenced_ones_are_unused() {
    let (dir, vault) = vault();
    let store = FilesStore::new(dir.path());
    let save = |value: &'static [u8]| {
        save_secrets(
            &vault,
            &store,
            &[NewSecret {
                field: "auth.bearer_token",
                value,
            }],
            |refs| Ok::<_, ()>(refs[0].clone()),
        )
        .expect("saved")
    };
    let first = save(b"first");
    let second = save(b"second");
    let name = |reference: &str| {
        Path::new(reference)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    assert!(Path::new(first.strip_prefix("file:").unwrap()).exists());
    assert!(Path::new(second.strip_prefix("file:").unwrap()).exists());
    let referenced = BTreeSet::from([name(&second)]);
    let unused = unused_entries(&vault, &[&store], &referenced).expect("listed");
    let names: Vec<String> = unused.into_iter().map(|entry| entry.name).collect();
    assert_eq!(names, vec![name(&first)]);
}

#[test]
fn b5_the_index_is_owner_only_outside_secrets_and_survives_a_torn_line() {
    let (dir, vault) = vault();
    let store = FilesStore::new(dir.path());
    let secret = [NewSecret {
        field: "auth.bearer_token",
        value: b"v",
    }];
    save_secrets(&vault, &store, &secret, |_| Ok::<_, ()>(())).expect("saved");
    let index = dir.path().join("secrets-index.jsonl");
    assert!(index.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&index).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    // A crash mid-append leaves a torn last line; the next save closes it.
    let mut text = index_text(dir.path());
    text.push_str("{\"name\":\"mcp-gateway.torn");
    std::fs::write(&index, &text).unwrap();
    save_secrets(&vault, &store, &secret, |_| Ok::<_, ()>(())).expect("saved again");
    let live = super::index::Index::at(dir.path()).live().unwrap();
    assert_eq!(live.len(), 2, "{live:?}");
    assert!(live.iter().all(|entry| {
        entry.name.starts_with("mcp-gateway.auth-bearer-token.") && entry.store == "files"
    }));
}

#[test]
fn b5_b20_each_create_follows_its_synced_index_line() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.index = Some(dir.path().join("secrets-index.jsonl"));
    save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(())).expect("saved");
    assert_eq!(count(&store.calls(), "create"), 3);
}

#[test]
fn b20_a_failed_index_sync_means_no_create() {
    let (_dir, vault) = vault();
    let store = Fake::new();
    sync_seam::FAIL.with(|f| f.set(true));
    let result = save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(()));
    sync_seam::FAIL.with(|f| f.set(false));
    assert!(
        matches!(result, Err(SaveError::Store(StoreError::Failed(_)))),
        "{result:?}"
    );
    assert_eq!(count(&store.calls(), "create"), 0, "{:?}", store.calls());
}

#[test]
fn b6_two_saves_on_one_vault_lock_take_turns() {
    let (dir, _vault) = vault();
    let lock = dir.path().join("vault.lock");
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let first = {
        let (config, lock) = (dir.path().join("a"), lock.clone());
        std::thread::spawn(move || {
            std::fs::create_dir_all(&config).unwrap();
            let vault = Vault::with_lock(&config, lock);
            let store = Fake::new();
            let secret = [NewSecret {
                field: "a",
                value: b"a",
            }];
            save_secrets(&vault, &store, &secret, |_| {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, ()>(())
            })
            .expect("first saved");
        })
    };
    held_rx.recv().expect("the first save holds the lock");
    // While the first save is inside its commit, the lock cannot be taken.
    let contended = crate::fs_lock::ExclusiveFileLock::try_acquire(&lock);
    assert!(
        matches!(&contended, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the vault lock was free during a save: {:?}",
        contended.as_ref().err()
    );
    release_tx.send(()).unwrap();
    first.join().unwrap();
    assert!(crate::fs_lock::ExclusiveFileLock::try_acquire(&lock).is_ok());
}

#[test]
fn b7_b21_bad_values_are_refused_before_anything_is_written() {
    let at_limit = [b'x'; 64];
    let over = [b'x'; 65];
    for (label, value, want) in [
        ("empty", &b""[..], StoreError::Empty),
        (
            "over",
            &over[..],
            StoreError::TooLarge {
                limit: 64,
                store: StoreKind::Keychain,
            },
        ),
        ("not utf-8", &b"\xff\xfe"[..], StoreError::NotUtf8),
    ] {
        let (dir, vault) = vault();
        let store = Fake::new();
        // The bad value is last: nothing before it may be written either.
        let mut secrets = three().to_vec();
        secrets.push(NewSecret {
            field: "auth.bearer_token",
            value,
        });
        let result = save_secrets(&vault, &store, &secrets, |_| Ok::<_, ()>(()));
        match result {
            Err(SaveError::Refused(got)) => assert_eq!(got, want, "{label}"),
            other => panic!("{label}: {other:?}"),
        }
        assert!(store.calls().is_empty(), "{label}: {:?}", store.calls());
        assert!(index_text(dir.path()).is_empty(), "{label}: indexed");
    }
    let (_dir, vault) = vault();
    let store = Fake::new();
    let secret = [NewSecret {
        field: "f",
        value: &at_limit,
    }];
    save_secrets(&vault, &store, &secret, |_| Ok::<_, ()>(())).expect("a value at the limit");
    let refused = StoreError::TooLarge {
        limit: 64,
        store: StoreKind::Keychain,
    }
    .reason();
    assert!(refused.contains("64 bytes") && refused.contains("secrets.store: files"));
    // Files is already the switch: its refusal does not offer it again.
    let files = StoreError::TooLarge {
        limit: 65_535,
        store: StoreKind::Files,
    }
    .reason();
    assert!(!files.contains("secrets.store"), "{files}");
}

#[test]
fn b8_b25_fresh_names_fit_the_grammar_and_never_repeat() {
    let name = fresh_name(
        "auth.bearer_token",
        1_761_418_800_123,
        0x9f3a_1c2e_04b7_d815,
    );
    assert_eq!(
        name,
        "mcp-gateway.auth-bearer-token.1761418800123.9f3a1c2e04b7d815"
    );
    let odd = fresh_name("auth.api_keys['a b/c']", 1, 2);
    assert_eq!(odd, "mcp-gateway.auth-api-keys-a-b-c-.1.0000000000000002");
    let long = fresh_name(&"x".repeat(100), 1, 2);
    assert_eq!(long.split('.').nth(1).unwrap().len(), 40);
    let mut seen = BTreeSet::new();
    for _ in 0..1_000 {
        // The same millisecond for all: only the random part tells them apart.
        let name = fresh_name("auth.bearer_token", 7, random_suffix().expect("random"));
        assert!(crate::config::is_keychain_name(&name), "{name}");
        assert!(seen.insert(name), "a repeated name");
    }
    // One random source, the OS one (ADR-028 rule 1).
    let source = include_str!("mod.rs");
    assert!(source.contains("ring::rand::SystemRandom::new()"));
    for file in [
        include_str!("mod.rs"),
        include_str!("save.rs"),
        include_str!("files.rs"),
        include_str!("index.rs"),
    ] {
        assert!(!file.contains("rand::rng") && !file.contains("thread_rng"));
    }
}

#[test]
fn b9_a_failed_probe_refuses_with_the_switch_and_writes_nothing() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.probe = Err(StoreError::Unavailable(
        "no Secret Service on the session bus".to_owned(),
    ));
    let result = save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(()));
    let Err(SaveError::Refused(error)) = result else {
        panic!("{result:?}");
    };
    assert!(
        error.reason().contains("no Secret Service"),
        "{}",
        error.reason()
    );
    assert!(error.reason().contains("secrets.store: files"));
    assert_eq!(store.calls(), vec!["probe"]);
    assert!(index_text(dir.path()).is_empty());
}

#[test]
fn b13_no_refusal_or_index_line_carries_a_value() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.fail_create = Some(1);
    let secret = [NewSecret {
        field: "auth.bearer_token",
        value: SENTINEL,
    }];
    let result = save_secrets(&vault, &store, &secret, |_| Ok::<_, ()>(()));
    let shown = format!("{result:?}");
    assert!(!shown.contains("kc-sentinel-7f3a"), "{shown}");
    assert!(!index_text(dir.path()).contains("kc-sentinel-7f3a"));
}

#[test]
fn b19_the_vault_lock_is_per_user_whatever_the_config_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = Vault::for_config_dir(&dir.path().join("a")).expect("home");
    let b = Vault::for_config_dir(&dir.path().join("b")).expect("home");
    let home = crate::home_dir::home_dir().expect("home");
    for vault in [&a, &b] {
        assert_eq!(vault.lock_path(), home.join(".mcp-gateway-secrets.lock"));
        assert!(!vault.lock_path().starts_with(dir.path()));
    }
}

/// Set in the child [`vault_lock_child`] runs in: the lock path to hold.
const LOCK_CHILD: &str = "MCP_GW_TEST_VAULT_LOCK_CHILD";

#[test]
#[ignore = "run by b19_a_second_process_meets_the_vault_lock, in a child"]
fn vault_lock_child() {
    let Some(path) = std::env::var_os(LOCK_CHILD) else {
        return;
    };
    let _held = crate::fs_lock::ExclusiveFileLock::try_acquire(Path::new(&path)).expect("lock");
    println!("vault lock held");
    // Held until the parent closes stdin.
    let mut rest = String::new();
    let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut rest);
}

#[test]
fn b19_a_second_process_meets_the_vault_lock() {
    use std::io::BufRead as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let lock = dir.path().join("vault.lock");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "secret_store::tests::vault_lock_child",
            "--ignored",
            "--nocapture",
        ])
        .env(LOCK_CHILD, &lock)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("run the child");
    // Kept open to the end: a closed pipe would fail the child's last write.
    let mut lines = std::io::BufReader::new(child.stdout.take().expect("stdout")).lines();
    let held = lines
        .by_ref()
        .map_while(Result::ok)
        .any(|line| line.contains("vault lock held"));
    assert!(held, "the child never took the lock");
    let contended = crate::fs_lock::ExclusiveFileLock::try_acquire(&lock);
    assert!(
        matches!(&contended, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "a second process took the vault lock while the first held it: {:?}",
        contended.as_ref().err()
    );
    drop(child.stdin.take());
    let rest: Vec<String> = lines.map_while(Result::ok).collect();
    assert!(child.wait().expect("child exit").success(), "{rest:?}");
    assert!(crate::fs_lock::ExclusiveFileLock::try_acquire(&lock).is_ok());
}

#[test]
fn b15_a_collision_is_not_retried_and_the_foreign_entry_stays_listed() {
    let (dir, vault) = vault();
    let mut store = Fake::new();
    store.collide = true;
    let result = save_secrets(&vault, &store, &three(), |_| Ok::<_, ()>(()));
    assert!(
        matches!(result, Err(SaveError::Store(StoreError::Exists))),
        "{result:?}"
    );
    let calls = store.calls();
    assert_eq!(count(&calls, "create"), 0, "{calls:?}");
    assert_eq!(
        count(&calls, "delete"),
        0,
        "a foreign entry was deleted: {calls:?}"
    );
    assert_eq!(store.names().len(), 1, "the foreign entry is gone");
    // Still live in the index: the unused listing can find it.
    let live = super::index::Index::at(dir.path()).live().unwrap();
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(live[0].name, store.names()[0]);
}
