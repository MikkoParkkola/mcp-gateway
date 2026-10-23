// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8697 slice 1b: the record key's resolution, rows K1-K7 and D2.

use std::path::Path;

use super::*;
use crate::config::EnvOverlay;

const KEY_A5: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a55a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn fallback(dir: &Path) -> crate::Result<RecordPrincipalKey> {
    resolve_key(None, &EnvOverlay::none(), dir)
}

fn temps(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != KEY_FILE)
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

// K1: an empty data dir gets a 64-hex key file, owner-only, and the same key
// on the next start.
#[test]
fn k1_an_empty_data_dir_gets_an_owner_only_hex_key_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = fallback(dir.path()).expect("created");
    let path = dir.path().join(KEY_FILE);
    let text = std::fs::read_to_string(&path).expect("key file");
    let hex = text.strip_suffix('\n').expect("one trailing newline");
    assert_eq!(hex.len(), 64, "{text:?}");
    assert!(
        hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "{text:?}"
    );
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    let again = fallback(dir.path()).expect("read back");
    assert_eq!(first.identity(), again.identity());
    assert_eq!(
        first.identity(),
        RecordPrincipalKey::from_text(hex).expect("key").identity()
    );
    assert!(temps(dir.path()).is_empty(), "{:?}", temps(dir.path()));
}

// K2: an existing valid file is read, never rewritten, and is the key in use.
#[test]
fn k2_an_existing_key_file_is_read_and_never_rewritten() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(KEY_FILE);
    crate::gateway::test_helpers::write_owner_only(&path, format!("{KEY_A5}\n").as_bytes())
        .expect("fixture");
    let before = std::fs::metadata(&path).expect("metadata");
    let key = fallback(dir.path()).expect("read");
    let after = std::fs::metadata(&path).expect("metadata");
    assert_eq!(before.modified().ok(), after.modified().ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(before.ino(), after.ino());
    }
    assert_eq!(
        std::fs::read_to_string(&path).expect("key"),
        format!("{KEY_A5}\n")
    );
    assert_eq!(
        key.identity(),
        RecordPrincipalKey::from_text(KEY_A5)
            .expect("key")
            .identity()
    );
}

// K3b: a malformed file is refused, naming its path, never replaced.
#[test]
fn k3b_a_malformed_key_file_is_refused_naming_its_path() {
    for bad in [
        &KEY_A5[..63],
        "A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A55A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A",
        &"zz".repeat(32),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEY_FILE);
        crate::gateway::test_helpers::write_owner_only(&path, format!("{bad}\n").as_bytes())
            .expect("fixture");
        let Err(err) = fallback(dir.path()) else {
            panic!("{bad:?} was accepted as a key file");
        };
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("kept"),
            format!("{bad}\n")
        );
    }
}

// K3a, K3c: an unreadable or group/world-readable file is refused, naming it.
#[cfg(unix)]
#[test]
fn k3ac_an_unreadable_or_shared_key_file_is_refused() {
    for m in [0o000, 0o640, 0o604] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KEY_FILE);
        crate::gateway::test_helpers::write_owner_only(&path, format!("{KEY_A5}\n").as_bytes())
            .expect("fixture");
        set_mode(&path, m);
        let Err(err) = fallback(dir.path()) else {
            panic!("mode {m:o} was accepted");
        };
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{m:o}: {err}"
        );
    }
}

// K4: a data dir that cannot be written, with no key file, stops startup.
#[cfg(unix)]
#[test]
fn k4_an_unwritable_data_dir_without_a_key_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    set_mode(dir.path(), 0o500);
    let result = fallback(dir.path());
    set_mode(dir.path(), 0o700);
    let Err(err) = result else {
        panic!("a key was produced without a file");
    };
    assert!(
        err.to_string()
            .contains(&dir.path().join(KEY_FILE).display().to_string()),
        "{err}"
    );
}

// K5: two first starts on one empty dir agree on one key and leave one file.
#[test]
fn k5_racing_first_starts_agree_on_one_key() {
    for _ in 0..20 {
        let dir = tempfile::tempdir().expect("tempdir");
        let barrier = std::sync::Barrier::new(2);
        let ids: Vec<String> = std::thread::scope(|s| {
            let racers: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        fallback(dir.path()).expect("resolved").identity()
                    })
                })
                .collect();
            racers
                .into_iter()
                .map(|r| r.join().expect("racer"))
                .collect()
        });
        assert_eq!(ids[0], ids[1]);
        assert!(temps(dir.path()).is_empty(), "{:?}", temps(dir.path()));
    }
}

// K6: a temp left by a crash before publishing is ignored.
#[test]
fn k6_a_stray_temp_from_a_crash_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stray = dir.path().join(format!("{KEY_FILE}.1234.deadbeef.tmp"));
    crate::gateway::test_helpers::write_owner_only(&stray, b"a5a5").expect("fixture");
    let key = fallback(dir.path()).expect("created");
    let text = std::fs::read_to_string(dir.path().join(KEY_FILE)).expect("key file");
    assert_eq!(text.len(), 65, "{text:?}");
    assert_eq!(
        key.identity(),
        RecordPrincipalKey::from_text(text.trim_end())
            .expect("key")
            .identity()
    );
}

// K7: a configured key is used and no file is created; a short or
// unresolvable one stops startup, naming the field.
#[test]
fn k7_a_configured_key_is_used_and_no_file_is_created() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = resolve_key(Some(KEY_A5), &EnvOverlay::none(), dir.path()).expect("literal");
    assert_eq!(
        key.identity(),
        RecordPrincipalKey::from_text(KEY_A5)
            .expect("key")
            .identity()
    );
    assert!(!dir.path().join(KEY_FILE).exists());
    for bad in ["short", "env:MIK_8697_UNSET_RECORD_KEY_VARIABLE"] {
        let Err(err) = resolve_key(Some(bad), &EnvOverlay::none(), dir.path()) else {
            panic!("{bad} was accepted");
        };
        assert!(err.to_string().contains(KEY_FIELD), "{bad}: {err}");
    }
    assert!(!dir.path().join(KEY_FILE).exists());
}

// D2: the fallback file and the same file named as a SecretRef are one key.
#[test]
fn d2_the_key_file_promoted_to_a_secret_ref_keeps_every_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from_file = fallback(dir.path()).expect("created");
    let reference = format!("file:{}", dir.path().join(KEY_FILE).display());
    let other = tempfile::tempdir().expect("tempdir");
    let from_ref = resolve_key(Some(&reference), &EnvOverlay::none(), other.path()).expect("ref");
    assert_eq!(from_file.identity(), from_ref.identity());
    let p = InternalPrincipal::new("3f2a9c0d1e7b".to_owned());
    assert_eq!(p.record_form(&from_file), p.record_form(&from_ref));
}
