// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the fetch's CA bundle choice and snapshot (FETCH.2b-1).

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use super::{DISTRO_BUNDLES, HostBundle, MAX_BUNDLE, ambient_ca_bundle};

/// One freshly made certificate, PEM-encoded.
fn pem() -> String {
    rcgen::generate_simple_self_signed(vec!["ca.test".into()])
        .expect("certificate")
        .cert
        .pem()
}

/// `path` under `root` (a distro path inside a fake root).
fn under(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(path, bytes).expect("write");
}

/// A fake root holding a valid bundle at the first distro path.
fn root_with_distro_bundle() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("root");
    write(&under(root.path(), DISTRO_BUNDLES[0]), pem().as_bytes());
    root
}

/// Kills "the ambient value is dropped" and "a value that is not UTF-8 is
/// treated as unset".
#[test]
fn ambient_passes_the_value_through() {
    let odd = OsString::from(OsStr::from_bytes(b"/etc/\xffbundle.pem"));
    let given = odd.clone();
    assert_eq!(
        ambient_ca_bundle(move |name| (name == "SSL_CERT_FILE").then(|| given.clone())),
        Some(odd)
    );
    assert_eq!(ambient_ca_bundle(|_| None), None);
}

/// Kills "`SSL_CERT_FILE` is ignored".
#[test]
fn a_valid_ssl_cert_file_is_chosen() {
    let root = root_with_distro_bundle();
    let own = tempfile::tempdir().expect("own");
    let path = own.path().join("bundle.pem");
    let bytes = pem();
    write(&path, bytes.as_bytes());
    let chosen = HostBundle::choose(Some(path.as_os_str()), root.path()).expect("chosen");
    assert_eq!(chosen.bytes, bytes.as_bytes());
    assert_eq!(chosen.source, path.canonicalize().expect("canonical"));
}

/// Kills "a bad `SSL_CERT_FILE` falls through to a distro path": each bad
/// value refuses although a valid distro bundle exists.
#[test]
fn a_bad_ssl_cert_file_refuses_with_no_fall_through() {
    let root = root_with_distro_bundle();
    let own = tempfile::tempdir().expect("own");
    let empty = own.path().join("empty.pem");
    write(&empty, b"");
    let not_pem = own.path().join("not.pem");
    write(&not_pem, b"just text\n");
    let big = own.path().join("big.pem");
    let mut over = pem().into_bytes();
    over.resize(MAX_BUNDLE + 1, b'\n');
    write(&big, &over);
    let dangling = own.path().join("dangling.pem");
    std::os::unix::fs::symlink(own.path().join("nowhere"), &dangling).expect("symlink");
    let values: Vec<OsString> = vec![
        "relative/bundle.pem".into(),
        own.path().join("missing.pem").into(),
        own.path().into(),
        empty.into(),
        not_pem.into(),
        big.into(),
        OsString::new(),
        dangling.into(),
    ];
    for value in values {
        let chosen = HostBundle::choose(Some(value.as_os_str()), root.path());
        assert!(chosen.is_err(), "{value:?} was accepted");
    }
}

/// Kills "the size cap is off by one": exactly 4 MiB is accepted.
#[test]
fn a_bundle_of_exactly_four_mib_is_accepted() {
    let root = tempfile::tempdir().expect("root");
    let mut bytes = pem().into_bytes();
    bytes.resize(MAX_BUNDLE, b'\n');
    write(&under(root.path(), DISTRO_BUNDLES[0]), &bytes);
    assert_eq!(
        HostBundle::choose(None, root.path())
            .expect("chosen")
            .bytes
            .len(),
        MAX_BUNDLE
    );
}

/// Kills "an existing but invalid distro bundle falls through to the next".
#[test]
fn an_invalid_first_distro_bundle_refuses() {
    let root = tempfile::tempdir().expect("root");
    write(&under(root.path(), DISTRO_BUNDLES[0]), b"");
    write(&under(root.path(), DISTRO_BUNDLES[1]), pem().as_bytes());
    assert!(HostBundle::choose(None, root.path()).is_err());
}

/// Kills "an absent candidate refuses" and "a later candidate wins".
#[test]
fn the_first_existing_distro_bundle_wins() {
    let root = tempfile::tempdir().expect("root");
    let second = pem();
    write(&under(root.path(), DISTRO_BUNDLES[1]), second.as_bytes());
    assert_eq!(
        HostBundle::choose(None, root.path()).expect("second").bytes,
        second.as_bytes()
    );
    let first = pem();
    write(&under(root.path(), DISTRO_BUNDLES[0]), first.as_bytes());
    assert_eq!(
        HostBundle::choose(None, root.path()).expect("first").bytes,
        first.as_bytes()
    );
}

/// Kills "the reported source is the symlink": a symlinked distro layout
/// reports the real path it read.
#[test]
fn a_symlinked_distro_layout_reports_its_real_path() {
    let root = tempfile::tempdir().expect("root");
    let real = root.path().join("var/lib/ca-certificates/ca-bundle.pem");
    write(&real, pem().as_bytes());
    let link = under(root.path(), DISTRO_BUNDLES[2]);
    std::fs::create_dir_all(link.parent().expect("parent")).expect("dirs");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let chosen = HostBundle::choose(None, root.path()).expect("chosen");
    assert_eq!(chosen.source, real.canonicalize().expect("canonical"));
}

/// Kills "a built-in list is used when no bundle exists".
#[test]
fn no_bundle_refuses() {
    let root = tempfile::tempdir().expect("root");
    assert!(HostBundle::choose(None, root.path()).is_err());
}

/// Kills "a FIFO candidate blocks the choice": it is refused at once.
#[test]
fn a_fifo_candidate_is_refused_without_blocking() {
    let own = tempfile::tempdir().expect("own");
    let fifo = own.path().join("bundle.pem");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .expect("mkfifo");
    let root = root_with_distro_bundle();
    let (tx, rx) = std::sync::mpsc::channel();
    let root_path = root.path().to_owned();
    std::thread::spawn(move || {
        let _ = tx.send(HostBundle::choose(Some(fifo.as_os_str()), &root_path).is_err());
    });
    let refused = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the choice did not return within the guard");
    assert!(refused);
}

/// Kills "any lstat error means absent": a candidate the gateway cannot stat
/// (its directory has no search permission) refuses. Skipped as root.
#[test]
fn an_lstat_error_other_than_absence_refuses() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let root = tempfile::tempdir().expect("root");
    let bundle = under(root.path(), DISTRO_BUNDLES[0]);
    write(&bundle, pem().as_bytes());
    let dir = bundle.parent().expect("parent").to_owned();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    let chosen = HostBundle::choose(None, root.path());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod back");
    assert!(chosen.is_err());
}

/// Kills "the snapshot re-reads its source": it holds the validated bytes
/// even after the source is replaced.
#[test]
fn the_snapshot_holds_the_validated_bytes() {
    let root = tempfile::tempdir().expect("root");
    let source = under(root.path(), DISTRO_BUNDLES[0]);
    let original = pem();
    write(&source, original.as_bytes());
    let chosen = HostBundle::choose(None, root.path()).expect("chosen");
    write(&source, pem().as_bytes());
    let dir = tempfile::tempdir().expect("dir");
    let snapshot = chosen.snapshot(dir.path()).expect("snapshot");
    assert_eq!(std::fs::read(&snapshot).expect("read"), original.as_bytes());
}

/// Kills "the snapshot is writable" and "an existing snapshot is overwritten".
#[test]
fn the_snapshot_is_read_only_and_exclusive() {
    let dir = tempfile::tempdir().expect("dir");
    let bundle = HostBundle {
        bytes: pem().into_bytes(),
        source: PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
    };
    let snapshot = bundle.snapshot(dir.path()).expect("snapshot");
    let mode = std::fs::metadata(&snapshot)
        .expect("meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o444);
    assert!(bundle.snapshot(dir.path()).is_err());
}
