// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A fake npm registry for the fetch rows: TLS on 127.0.0.1 under a leaf for
//! `registry.npmjs.org` signed by a test CA, serving packuments and tarballs.
//! The rows' dial adapter sends the proxy's registry connections here.

use std::io::Write as _;
use std::sync::Arc;

use base64::Engine as _;
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// One package version the registry serves.
pub(super) struct Package {
    /// `name` or `@scope/name`.
    pub(super) name: &'static str,
    pub(super) version: &'static str,
    /// package.json fields beyond name and version (bin, scripts, dependencies).
    pub(super) manifest: serde_json::Value,
    /// Files under `package/`, each with its mode.
    pub(super) files: Vec<(&'static str, Vec<u8>, u32)>,
}

impl Package {
    fn manifest(&self) -> serde_json::Value {
        let mut manifest = self.manifest.clone();
        manifest["name"] = self.name.into();
        manifest["version"] = self.version.into();
        manifest
    }

    /// The package's tarball: a ustar archive of `package/...`, gzipped.
    fn tarball(&self) -> Vec<u8> {
        let mut tar = Vec::new();
        let json = serde_json::to_vec(&self.manifest()).expect("manifest");
        let mut entries = vec![("package.json", json, 0o644)];
        entries.extend(self.files.iter().map(|(p, b, m)| (*p, b.clone(), *m)));
        for (path, bytes, mode) in entries {
            tar.extend_from_slice(&ustar_header(&format!("package/{path}"), bytes.len(), mode));
            tar.extend_from_slice(&bytes);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).expect("gzip");
        gz.finish().expect("gzip")
    }

    fn tarball_name(&self) -> String {
        let base = self.name.rsplit('/').next().unwrap_or(self.name);
        format!("{base}-{}.tgz", self.version)
    }

    /// The packument npm reads: one version, its tarball URL and integrity.
    fn packument(&self, tarball: &[u8]) -> Vec<u8> {
        let digest = sha2::Sha512::digest(tarball);
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        );
        let mut version = self.manifest();
        version["dist"] = serde_json::json!({
            "tarball": format!("https://registry.npmjs.org/{}/-/{}", self.name, self.tarball_name()),
            "integrity": integrity,
        });
        serde_json::to_vec(&serde_json::json!({
            "name": self.name,
            "dist-tags": {"latest": self.version},
            "versions": {(self.version): version},
        }))
        .expect("packument")
    }
}

/// A ustar header for a regular file.
pub(super) fn ustar_header(path: &str, size: usize, mode: u32) -> [u8; 512] {
    let mut h = [0u8; 512];
    let put = |h: &mut [u8; 512], at: usize, text: &str| {
        h[at..at + text.len()].copy_from_slice(text.as_bytes());
    };
    put(&mut h, 0, path);
    put(&mut h, 100, &format!("{mode:07o}\0"));
    put(&mut h, 108, "0000000\0");
    put(&mut h, 116, "0000000\0");
    put(&mut h, 124, &format!("{size:011o}\0"));
    put(&mut h, 136, "00000000000\0");
    h[148..156].fill(b' ');
    h[156] = b'0';
    put(&mut h, 257, "ustar\0");
    put(&mut h, 263, "00");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    put(&mut h, 148, &format!("{sum:06o}\0 "));
    h
}

/// A running fake registry: its loopback port, the CA its leaf chains to, how
/// many connections are open, and a signal on the first request.
pub(super) struct Registry {
    pub(super) port: u16,
    pub(super) ca_pem: String,
    open: Arc<std::sync::atomic::AtomicUsize>,
    first: Arc<tokio::sync::Notify>,
    _serve: tokio::task::JoinHandle<()>,
}

/// One accepted connection, counted open until its handler ends.
struct Open(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Open {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Registry {
    /// Serve `packages` under a leaf for `registry.npmjs.org`, signed by a
    /// fresh test CA named `ca_name`.
    pub(super) async fn start(packages: Vec<Package>, ca_name: &str) -> Self {
        let pki = crate::test_fixture_host::test_pki("registry.npmjs.org", ca_name);
        let chain = vec![
            rustls::pki_types::CertificateDer::from(pki.leaf.der().to_vec()),
            rustls::pki_types::CertificateDer::from(pki.ca.der().to_vec()),
        ];
        let key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(pki.leaf_key.serialize_der()),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("leaf");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let routes: Arc<Vec<(String, String, Vec<u8>)>> = Arc::new(
            packages
                .iter()
                .flat_map(|p| {
                    let tarball = p.tarball();
                    let packument = p.packument(&tarball);
                    let base = format!("/{}", p.name.replace('/', "%2f"));
                    [
                        (base.clone(), "application/json".to_owned(), packument),
                        (
                            format!("/{}/-/{}", p.name, p.tarball_name()),
                            "application/octet-stream".to_owned(),
                            tarball,
                        ),
                    ]
                })
                .collect(),
        );
        let open = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first = Arc::new(tokio::sync::Notify::new());
        let (count, signal) = (Arc::clone(&open), Arc::clone(&first));
        let serve = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, routes) = (acceptor.clone(), Arc::clone(&routes));
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let open = Open(Arc::clone(&count));
                let signal = Arc::clone(&signal);
                tokio::spawn(async move {
                    let _open = open;
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
                        match tls.read(&mut byte).await {
                            Ok(1) => head.push(byte[0]),
                            _ => return,
                        }
                    }
                    // A stored permit: a row that waits after the request still sees it.
                    signal.notify_one();
                    let line = String::from_utf8_lossy(&head);
                    let path = line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let found = routes
                        .iter()
                        .find(|(p, _, _)| p.to_ascii_lowercase() == path);
                    let (status, kind, body) = found
                        .map_or(("404 Not Found", "text/plain", &b""[..]), |(_, k, b)| {
                            ("200 OK", k.as_str(), b.as_slice())
                        });
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(reply.as_bytes()).await;
                    let _ = tls.write_all(body).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Self {
            port,
            ca_pem: pki.ca.pem(),
            open,
            first,
            _serve: serve,
        }
    }

    /// Connections accepted and not yet ended.
    pub(super) fn open_connections(&self) -> usize {
        self.open.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Returns once the registry has read its first request's head.
    pub(super) async fn first_request(&self) {
        self.first.notified().await;
    }
}
