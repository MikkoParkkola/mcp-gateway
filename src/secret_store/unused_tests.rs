// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unused entries: which sources name an entry, the index's store-scoped lines, and name shapes (ADR-028 rule 6).

use super::{Naming, NamingSources, is_generated_name, naming, suffix_of};
use crate::gateway::test_helpers::write_owner_only;
use crate::secret_store::index::Index;
use crate::secret_store::{
    FilesStore, NewSecret, SecretStore, StoreKind, UnusedEntry, Vault, fresh_name, save_secrets,
    unused_entries,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(super) fn rig() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::with_lock(dir.path(), dir.path().join("vault.lock"));
    (dir, vault)
}

pub(super) fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

pub(super) fn sources(dir: &Path) -> NamingSources {
    NamingSources {
        config: dir.join("gateway.yaml"),
        env_files: Vec::new(),
        env_values: Vec::new(),
        process_env: Vec::new(),
        capability_dirs: Vec::new(),
        entries_dir: FilesStore::new(dir).entries_dir().to_path_buf(),
    }
}

/// A readable config that does not name any entry.
pub(super) fn quiet(dir: &Path) -> NamingSources {
    let config = dir.join("gateway.yaml");
    if !config.is_file() {
        write_owner_only(&config, b"k: clean\n").expect("yaml");
    }
    sources(dir)
}

pub(super) fn save_field(vault: &Vault, dir: &Path, field: &str, value: &'static [u8]) -> String {
    let store = FilesStore::new(dir);
    let reference = save_secrets(vault, &store, &[NewSecret { field, value }], |refs| {
        Ok::<_, &str>(refs[0].clone())
    })
    .expect("save");
    reference
        .strip_prefix("file:")
        .and_then(|path| Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .expect("file reference")
        .to_owned()
}

pub(super) fn saved() -> (tempfile::TempDir, Vault, String) {
    let (dir, vault) = rig();
    let name = save_field(&vault, dir.path(), "f", b"v");
    (dir, vault, name)
}

/// One saved entry whose suffix contains a hex letter, so an upper-case
/// spelling is not the same bytes.
fn one_entry() -> (tempfile::TempDir, Vault, String) {
    let (dir, vault) = rig();
    for _ in 0..40 {
        let name = save_field(&vault, dir.path(), "f", b"v");
        let letter = name
            .rsplit('.')
            .next()
            .is_some_and(|suffix| suffix.bytes().any(|byte| matches!(byte, b'a'..=b'f')));
        if letter {
            return (dir, vault, name);
        }
    }
    panic!("fixture: no generated suffix contained a hex letter");
}

pub(super) fn secret_path(dir: &Path, name: &str) -> PathBuf {
    dir.join("secrets").join(name)
}

pub(super) fn index_bytes(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("secrets-index.jsonl")).unwrap_or_default()
}

pub(super) fn list(vault: &Vault, stores: &[&dyn SecretStore]) -> Vec<UnusedEntry> {
    unused_entries(vault, stores, &BTreeSet::new()).expect("list unused")
}

/// Each hex digit as a YAML `\x3N` / `\x6N` escape (`0` is `\x30`, `a` is `\x61`).
fn hex_escapes(suffix: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(suffix.len() * 4);
    for byte in suffix.bytes() {
        // Writing into a String cannot fail.
        let _ = write!(out, "\\x{byte:02x}");
    }
    out
}

#[cfg(unix)]
fn link_file(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("symlink");
}

fn deny_read(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(path, mode).expect("mode 0o000");
    }
    #[cfg(not(unix))]
    {
        std::fs::remove_file(path).expect("replace");
        std::fs::create_dir(path).expect("unreadable stand-in");
    }
}

fn collect_case(
    failures: &mut Vec<String>,
    row: &str,
    case: &str,
    run: impl FnOnce() -> Result<(), String>,
) {
    let detail = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(())) => return,
        Ok(Err(detail)) => detail,
        Err(panic) => panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("panic")
            .to_owned(),
    };
    failures.push(format!("{row} {case}: {detail}"));
}

fn plant_env(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let env = dir.join("overlay.env");
    let line = format!("K=keychain:mcp-gateway.x.1.{suffix}\n");
    std::fs::write(&env, line).expect("env");
    let mut sources = quiet(dir);
    sources.env_files.push(env);
    sources
}

fn plant_process(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let mut sources = quiet(dir);
    sources
        .process_env
        .push(OsString::from(format!("pre-{suffix}-post")));
    sources
}

fn plant_values(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let mut sources = quiet(dir);
    sources.env_values.push(suffix.to_owned());
    sources
}

fn plant_cap(dir: &Path, name: &str, _suffix: &str) -> NamingSources {
    let cap = dir.join("caps");
    std::fs::create_dir_all(&cap).expect("caps");
    std::fs::write(cap.join("a.yaml"), format!("ref: {name}\n")).expect("cap");
    let mut sources = quiet(dir);
    sources.capability_dirs.push(cap);
    sources
}

fn plant_nested(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let cap = dir.join("caps");
    std::fs::create_dir_all(cap.join("deep")).expect("caps");
    std::fs::write(cap.join("deep").join("b.txt"), suffix).expect("cap");
    let mut sources = quiet(dir);
    sources.capability_dirs.push(cap);
    sources
}

fn plant_escape(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let body = format!("ref: \"{}\"\n", hex_escapes(suffix));
    write_owner_only(dir.join("gateway.yaml"), body).expect("yaml");
    sources(dir)
}

fn plant_yaml_key(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let body = format!("\"{}\": clean\n", hex_escapes(suffix));
    write_owner_only(dir.join("gateway.yaml"), body).expect("yaml");
    sources(dir)
}

fn plant_upper(dir: &Path, _name: &str, suffix: &str) -> NamingSources {
    let upper = suffix.to_ascii_uppercase();
    write_owner_only(dir.join("gateway.yaml"), format!("k: {upper}\n")).expect("yaml");
    sources(dir)
}

#[cfg(unix)]
fn plant_symlink(dir: &Path, name: &str, _suffix: &str) -> NamingSources {
    let link = dir.join("current");
    link_file(&secret_path(dir, name), &link);
    let yaml = format!("k: \"file:{}\"\n", link.display());
    write_owner_only(dir.join("gateway.yaml"), yaml).expect("yaml");
    sources(dir)
}

#[cfg(unix)]
fn plant_link(dir: &Path, name: &str, _suffix: &str) -> NamingSources {
    std::fs::hard_link(secret_path(dir, name), dir.join("also")).expect("hard link");
    quiet(dir)
}

fn plant_env_dir(dir: &Path) -> NamingSources {
    let env = dir.join("env.d");
    std::fs::create_dir(&env).expect("env dir");
    let mut sources = quiet(dir);
    sources.env_files.push(env);
    sources
}

fn plant_env_mode(dir: &Path) -> NamingSources {
    let env = dir.join("hidden.env");
    std::fs::write(&env, b"K=other\n").expect("env");
    deny_read(&env);
    let mut sources = quiet(dir);
    sources.env_files.push(env);
    sources
}

#[cfg(unix)]
fn plant_cap_mode(dir: &Path) -> NamingSources {
    let cap = dir.join("caps");
    std::fs::create_dir_all(&cap).expect("caps");
    let file = cap.join("sealed.yaml");
    std::fs::write(&file, b"k: clean\n").expect("cap");
    deny_read(&file);
    let mut sources = quiet(dir);
    sources.capability_dirs.push(cap);
    sources
}

fn plant_bad_yaml(dir: &Path) -> NamingSources {
    write_owner_only(dir.join("gateway.yaml"), b"[\n").expect("yaml");
    sources(dir)
}

fn plant_env_missing(dir: &Path) -> NamingSources {
    let mut sources = quiet(dir);
    sources.env_files.push(dir.join("missing.env"));
    sources
}

#[cfg(unix)]
pub(super) fn scoped_removal(text: &str, name: &str) -> bool {
    text.lines().any(|line| {
        line.contains(name) && line.contains("removed_at") && line.contains("\"store\":\"files\"")
    })
}

#[test]
fn generated_name_shape() {
    const ROW: &str = "generated_name_shape";
    let fresh = fresh_name("f", 1, 0xabc);
    assert!(
        is_generated_name(&fresh),
        "{ROW}: a fresh name was refused: {fresh}"
    );
    let long = "n".repeat(300);
    for bad in [
        "../gateway.yaml",
        "a/b",
        "x\u{0}y",
        long.as_str(),
        "mcp-gateway.x.1.XYZ",
        "mcp-gateway.x.1.0123",
    ] {
        assert!(!is_generated_name(bad), "{ROW}: accepted {bad:?}");
    }
    assert_eq!(
        suffix_of(&fresh),
        Some("0000000000000abc"),
        "{ROW}: suffix of {fresh}"
    );
}

#[test]
fn named_by_every_source() {
    const ROW: &str = "named_by_every_source";
    let mut bad = Vec::new();
    let cases = vec![
        (
            "env file",
            plant_env as fn(&Path, &str, &str) -> NamingSources,
        ),
        ("process env", plant_process),
        ("env values", plant_values),
        ("capability", plant_cap),
        ("nested capability", plant_nested),
        ("yaml escape", plant_escape),
        ("yaml key", plant_yaml_key),
        ("upper case", plant_upper),
    ];
    // Same-file identity is readable only on Unix, so these two name a file there alone.
    #[cfg(unix)]
    let cases = {
        let mut cases = cases;
        cases.push(("symlink", plant_symlink));
        cases.push(("hard link", plant_link));
        cases
    };
    for (case, plant) in cases {
        collect_case(&mut bad, ROW, case, || {
            let (dir, _vault, name) = one_entry();
            let suffix = name.rsplit('.').next().expect("suffix");
            let sources = plant(dir.path(), &name, suffix);
            match naming(&sources, &name) {
                Ok(Naming::Named) => Ok(()),
                other => Err(format!("expected Named, got {other:?}")),
            }
        });
    }
    collect_case(&mut bad, ROW, "control", || {
        let (dir, _vault, name) = one_entry();
        match naming(&quiet(dir.path()), &name) {
            Ok(Naming::NotNamed { .. }) => Ok(()),
            other => Err(format!("expected NotNamed, got {other:?}")),
        }
    });
    assert!(bad.is_empty(), "{ROW}:\n{}", bad.join("\n"));
}

#[test]
fn unreadable_source_refuses() {
    const ROW: &str = "unreadable_source_refuses";
    let mut bad = Vec::new();
    for (case, plant) in [
        ("env directory", plant_env_dir as fn(&Path) -> NamingSources),
        ("env mode", plant_env_mode),
        // Unix only: off Unix the unreadable stand-in is a directory, which the capability
        // walk skips as not a file, so the case would not reach an unreadable read.
        #[cfg(unix)]
        ("capability mode", plant_cap_mode),
        ("bad yaml", plant_bad_yaml),
        ("env missing", plant_env_missing),
    ] {
        collect_case(&mut bad, ROW, case, || {
            let (dir, _vault, name) = saved();
            match naming(&plant(dir.path()), &name) {
                Err(_) => Ok(()),
                other => Err(format!("expected Err, got {other:?}")),
            }
        });
    }
    assert!(bad.is_empty(), "{ROW}:\n{}", bad.join("\n"));
}

#[test]
fn remove_then_recreate() {
    const ROW: &str = "remove_then_recreate";
    let (dir, _vault) = rig();
    let index = Index::at(dir.path());
    let n = fresh_name("f", 1, 0xabc);
    index.append_created(&n, StoreKind::Files).expect("create");
    index
        .append_removed_in(&n, StoreKind::Files)
        .expect("remove");
    let text = std::fs::read_to_string(dir.path().join("secrets-index.jsonl")).expect("index");
    let last = text.lines().last().unwrap_or("");
    let parsed: serde_json::Value = serde_json::from_str(last).expect("json");
    assert_eq!(parsed["store"].as_str(), Some("files"), "{ROW}: {last}");
    index
        .append_created(&n, StoreKind::Files)
        .expect("recreate");
    let live = index.live().expect("live");
    let hits = live.iter().filter(|entry| entry.name == n).count();
    assert_eq!(hits, 1, "{ROW}: {live:?}");
}

#[test]
fn scoped_line_golden() {
    const ROW: &str = "scoped_line_golden";
    let (dir, _vault) = rig();
    let index = Index::at(dir.path());
    let n = fresh_name("n", 3, 0x11);
    index
        .append_created(&n, StoreKind::Keychain)
        .expect("keychain");
    index.append_created(&n, StoreKind::Files).expect("files");
    index
        .append_removed_in(&n, StoreKind::Files)
        .expect("remove");
    let text = std::fs::read_to_string(dir.path().join("secrets-index.jsonl")).expect("index");
    let removals: Vec<_> = text
        .lines()
        .filter(|line| line.contains("removed_at"))
        .collect();
    assert_eq!(removals.len(), 1, "{ROW}: {text}");
    let parsed: serde_json::Value = serde_json::from_str(removals[0]).expect("json");
    assert_eq!(parsed["name"].as_str(), Some(n.as_str()), "{ROW}: {text}");
    assert_eq!(parsed["store"].as_str(), Some("files"), "{ROW}: {text}");
    assert!(parsed["removed_at"].is_number(), "{ROW}: {text}");
    let live = index.live().expect("live");
    let kept: Vec<&str> = live
        .iter()
        .filter(|entry| entry.name == n)
        .map(|entry| entry.store.as_str())
        .collect();
    assert_eq!(kept.len(), 1, "{ROW}: {live:?}");
    assert_eq!(kept[0], "keychain", "{ROW}: {live:?}");
}

/// Seventeen nested directories put a readable file past the walk. That source
/// was not read, so the check refuses.
#[test]
fn capability_walk_refuses_past_the_depth_bound() {
    const ROW: &str = "capability_walk_refuses_past_the_depth_bound";
    let (dir, _vault, name) = saved();
    let cap = dir.path().join("caps");
    let mut bottom = cap.clone();
    for level in 1..=17 {
        bottom.push(level.to_string());
    }
    std::fs::create_dir_all(&bottom).unwrap_or_else(|error| panic!("{ROW}: caps: {error}"));
    std::fs::write(bottom.join("bottom.yaml"), b"k: clean")
        .unwrap_or_else(|error| panic!("{ROW}: cap: {error}"));
    let mut sources = quiet(dir.path());
    sources.capability_dirs.push(cap);
    let got = naming(&sources, &name);
    assert_eq!(got, Err(super::CAP_TOO_DEEP.to_owned()), "{ROW}");
}

/// A capability directory that links back to itself was not read. The check
/// refuses.
#[cfg(unix)]
#[test]
fn capability_symlink_loop_refuses() {
    const ROW: &str = "capability_symlink_loop_refuses";
    let (dir, _vault, name) = saved();
    let cap = dir.path().join("caps");
    std::fs::create_dir_all(&cap).unwrap_or_else(|error| panic!("{ROW}: caps: {error}"));
    std::fs::write(cap.join("a.yaml"), b"k: clean")
        .unwrap_or_else(|error| panic!("{ROW}: cap: {error}"));
    link_file(&cap, &cap.join("loop"));
    let mut sources = quiet(dir.path());
    sources.capability_dirs.push(cap);
    let got = naming(&sources, &name);
    assert_eq!(got, Err(super::CAP_UNREAD.to_owned()), "{ROW}");
}

/// The keychain guard's force switch exists only in test builds: the production text of
/// `unused.rs` (every test-only item blanked by the shared reader) never names it, so no
/// release build can force the macOS and Windows keychain guard off.
#[test]
fn keychain_guard_seam_is_test_only() {
    const ROW: &str = "keychain_guard_seam_is_test_only";
    let text = include_str!("unused.rs");
    // The switch and its one read are in this file, so a scan that finds nothing proves something.
    assert!(
        text.matches("GUARD_KEYCHAIN").count() >= 2,
        "{ROW}: the switch and its read are in unused.rs"
    );
    let production = crate::test_source_text::production_text(text);
    for (i, line) in production.lines().enumerate() {
        assert!(
            !line.contains("GUARD_KEYCHAIN"),
            "{ROW}: unused.rs:{} names the switch outside cfg(test): {}",
            i + 1,
            line.trim()
        );
    }
}
