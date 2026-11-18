// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one CA bundle a preview's package fetch trusts (the CA amendment to
//! ADR-027's fetch step): chosen on the gateway's side, read once from one
//! descriptor, and snapshotted by its bytes into the preview's private
//! directory, which the helper binds read-only into the sandbox root.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use super::super::Refusal;

/// The largest bundle accepted, in bytes.
pub(super) const MAX_BUNDLE: usize = 4 << 20;

/// The distros' bundle files, in the order tried when `SSL_CERT_FILE` is unset.
pub(super) const DISTRO_BUNDLES: [&str; 3] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// The chosen bundle: the bytes read and validated, and where they came from.
#[derive(Debug)]
pub(super) struct HostBundle {
    pub(super) bytes: Vec<u8>,
    pub(super) source: PathBuf,
}

impl HostBundle {
    /// Choose the bundle: `ca_bundle` (the `SSL_CERT_FILE` value) when set,
    /// else the first distro path whose entry exists under `root` (`/` in
    /// production). An existing candidate that fails any check refuses: there
    /// is no fall-through, and no built-in list.
    pub(super) fn choose(ca_bundle: Option<&OsStr>, root: &Path) -> Result<Self, Refusal> {
        if let Some(value) = ca_bundle {
            let path = Path::new(value);
            // An empty value is not absolute either: set but empty refuses.
            if !path.is_absolute() {
                return Err(Refusal::Step(format!(
                    "SSL_CERT_FILE is not an absolute path ({})",
                    path.display()
                )));
            }
            return Self::read(path);
        }
        for candidate in DISTRO_BUNDLES {
            let path = root.join(candidate.trim_start_matches('/'));
            match rustix::fs::lstat(&path) {
                Ok(_) => return Self::read(&path),
                Err(rustix::io::Errno::NOENT) => {}
                Err(e) => {
                    return Err(Refusal::Step(format!(
                        "the CA bundle {} cannot be checked ({e})",
                        path.display()
                    )));
                }
            }
        }
        Err(Refusal::Step("no CA bundle on this host".into()))
    }

    /// Open `path` once and judge only what that descriptor reads: a regular
    /// file (a FIFO cannot block the non-blocking open), not empty, at most
    /// [`MAX_BUNDLE`] bytes, every PEM section well formed and at least one
    /// certificate. The source reported is the file the descriptor opened.
    fn read(path: &Path) -> Result<Self, Refusal> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject as _;
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        let fail = |why: &str| Refusal::Step(format!("the CA bundle {} {why}", path.display()));
        let flags =
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK;
        let fd = rustix::fs::open(path, flags, rustix::fs::Mode::empty())
            .map_err(|e| fail(&format!("cannot be opened ({e})")))?;
        let stat = rustix::fs::fstat(&fd).map_err(|e| fail(&format!("cannot be checked ({e})")))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(fail("is not a regular file"));
        }
        let source = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .map_err(|e| fail(&format!("cannot be located ({e})")))?;
        let mut bytes = Vec::new();
        let limit = u64::try_from(MAX_BUNDLE + 1).unwrap_or(u64::MAX);
        std::fs::File::from(fd)
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| fail(&format!("cannot be read ({e})")))?;
        if bytes.is_empty() {
            return Err(fail("is empty"));
        }
        if bytes.len() > MAX_BUNDLE {
            return Err(fail("is over 4 MiB"));
        }
        let mut certificates = 0_usize;
        for item in CertificateDer::pem_slice_iter(&bytes) {
            item.map_err(|_| fail("holds a malformed PEM section"))?;
            certificates += 1;
        }
        if certificates == 0 {
            return Err(fail("holds no PEM certificate"));
        }
        Ok(Self { bytes, source })
    }

    /// Write the validated bytes, never the source again, as `ca.pem` in
    /// `dir` (the preview's private directory): created exclusively with mode
    /// 0444 requested. The umask may clear the group and other bits; the
    /// dropped fetch child still reads it as its owner, since it keeps the
    /// namespace's uid 0, mapped to the gateway's uid.
    pub(super) fn snapshot(&self, dir: &Path) -> io::Result<PathBuf> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = dir.join("ca.pem");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&path)?;
        file.write_all(&self.bytes)?;
        Ok(path)
    }
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "ca_bundle_tests.rs"]
mod tests;
