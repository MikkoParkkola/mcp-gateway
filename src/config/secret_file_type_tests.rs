// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F18 A2: a path that is not a regular file is refused, and a FIFO is refused
//! without blocking the reader.

use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use super::{SecretFile, read_secret_file};

/// Longer than any honest read of an empty FIFO, far shorter than a hang.
const BOUND: Duration = Duration::from_secs(5);

fn fifo(dir: &Path) -> PathBuf {
    let path = dir.join("secret.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .expect("create FIFO fixture");
    path
}

/// Runs `op` on its own thread and waits at most [`BOUND`]. On a timeout the
/// FIFO's write end is opened and dropped, so a reader blocked in `open` gets
/// EOF and exits on its own (it is not joined: a failed unblock would then hang
/// the test); the timeout is still reported as `None`.
fn bounded<T: Send + 'static>(fifo: &Path, op: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = tx.send(op());
    });
    if let Ok(out) = rx.recv_timeout(BOUND) {
        reader.join().expect("reader thread");
        return Some(out);
    }
    // The blocked reader holds the read end, so a non-blocking write-end open
    // succeeds and its drop delivers EOF.
    let _writer = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits().cast_signed())
        .open(fifo);
    None
}

#[test]
fn fifo_is_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let path = fifo(dir.path());
    let reading = path.clone();
    let result = bounded(&path, move || {
        read_secret_file(&reading, SecretFile::Config).map_err(|e| e.to_string())
    })
    .expect("reading a FIFO blocked: the open must not wait for a writer");
    let err = result.expect_err("a FIFO is not a config file");
    assert!(
        err.contains("FIFO") && err.contains("not a regular file"),
        "{err}"
    );
}

#[test]
fn directory_is_refused_as_not_regular() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env.d");
    std::fs::create_dir(&path).unwrap();
    // Owner-only, so only the type can be what is refused, whatever the umask.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let err = read_secret_file(&path, SecretFile::EnvFile)
        .expect_err("a directory is not an env file")
        .to_string();
    assert!(err.contains("directory, not a regular file"), "{err}");
}

#[test]
fn tls_key_fifo_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = fifo(dir.path());
    let reading = path.to_str().unwrap().to_string();
    let result = bounded(&path, move || {
        crate::mtls::cert_manager::load_private_key(&reading).map_err(|e| e.to_string())
    })
    .expect("loading a FIFO key blocked: the open must not wait for a writer");
    let err = result.expect_err("a FIFO is not a TLS key");
    assert!(
        err.contains("TLS private key") && err.contains("FIFO"),
        "{err}"
    );
}

#[test]
fn symlink_to_fifo_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = fifo(dir.path());
    let link = dir.path().join("secret.link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let reading = link.clone();
    let result = bounded(&target, move || {
        read_secret_file(&reading, SecretFile::Reference).map_err(|e| e.to_string())
    })
    .expect("reading through a symlink to a FIFO blocked");
    let err = result.expect_err("a symlink to a FIFO is not a secret file");
    assert!(err.contains("FIFO"), "{err}");
}

/// Type before mode: `/dev/null` is 0666, and must be named as a device, not
/// reported as a loose mode that `chmod` could fix.
#[test]
fn dev_null_is_refused_as_a_device() {
    let err = read_secret_file(Path::new("/dev/null"), SecretFile::Config)
        .expect_err("a device is not a config file")
        .to_string();
    assert!(
        err.contains("character device, not a regular file"),
        "{err}"
    );
    assert!(!err.contains("chmod"), "{err}");
}
