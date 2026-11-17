// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A fake PyPI for the uv fetch rows: TLS on 127.0.0.1 under one leaf naming
//! `pypi.org` and `files.pythonhosted.org`, signed by a fresh test CA,
//! serving the PEP 691 JSON simple API and the files, wheels and sdists
//! built here. Every request is logged as `host path`, so a row can name
//! what uv asked for.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// One file the index serves on `files.pythonhosted.org` at `path`, listed
/// on the simple page of `project` (`None`: reachable by URL only).
pub(super) struct IndexFile {
    pub(super) project: Option<&'static str>,
    pub(super) filename: String,
    pub(super) path: String,
    pub(super) bytes: Vec<u8>,
}

impl IndexFile {
    /// The same file, unlisted, at `path` instead.
    pub(super) fn at(mut self, path: &str) -> Self {
        self.project = None;
        self.path = path.to_owned();
        self
    }
}

/// `entries` as a zip archive, every entry stored (no compression).
fn zip(entries: &[(String, Vec<u8>, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, mode) in entries {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let crc = crc.sum();
        let offset = u32::try_from(out.len()).expect("small archive");
        let size = u32::try_from(data.len()).expect("small entry");
        let name_len = u16::try_from(name.len()).expect("short name");
        let head = |buf: &mut Vec<u8>, signature: u32, central: bool| {
            buf.extend(signature.to_le_bytes());
            if central {
                buf.extend((0x0314_u16).to_le_bytes()); // made by: Unix, 2.0
            }
            buf.extend(20_u16.to_le_bytes()); // needed: 2.0
            buf.extend(0_u16.to_le_bytes()); // flags
            buf.extend(0_u16.to_le_bytes()); // stored
            buf.extend(0_u16.to_le_bytes()); // time
            buf.extend(0x0021_u16.to_le_bytes()); // 1980-01-01
            buf.extend(crc.to_le_bytes());
            buf.extend(size.to_le_bytes());
            buf.extend(size.to_le_bytes());
            buf.extend(name_len.to_le_bytes());
            buf.extend(0_u16.to_le_bytes()); // extra
        };
        head(&mut out, 0x0403_4b50, false);
        out.extend(name.as_bytes());
        out.extend(data);
        head(&mut central, 0x0201_4b50, true);
        central.extend(0_u16.to_le_bytes()); // comment
        central.extend(0_u16.to_le_bytes()); // disk
        central.extend(0_u16.to_le_bytes()); // internal attributes
        central.extend(((0o100_000 | mode) << 16).to_le_bytes());
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let count = u16::try_from(entries.len()).expect("few entries");
    let cd_offset = u32::try_from(out.len()).expect("small archive");
    let cd_size = u32::try_from(central.len()).expect("small directory");
    out.extend(central);
    out.extend(0x0605_4b50_u32.to_le_bytes());
    out.extend(0_u16.to_le_bytes());
    out.extend(0_u16.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend(cd_size.to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0_u16.to_le_bytes());
    out
}

/// A pure-Python wheel of `name` (as its METADATA says it) 1.0, file names
/// built from `dist` (the name with `-` and `.` as `_`): `files` (path,
/// text), its console scripts, and `requires` as `Requires-Dist` lines.
pub(super) fn wheel(
    project: &'static str,
    name: &str,
    dist: &str,
    files: &[(&str, &str)],
    scripts: &[(&str, &str)],
    requires: &[&str],
) -> IndexFile {
    let info = format!("{dist}-1.0.dist-info");
    let mut metadata = format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n");
    for r in requires {
        metadata.push_str(&format!("Requires-Dist: {r}\n"));
    }
    let mut entries: Vec<(String, Vec<u8>, u32)> = files
        .iter()
        .map(|(p, text)| {
            let mode = if p.contains(".data/scripts/") {
                0o755
            } else {
                0o644
            };
            ((*p).to_owned(), text.as_bytes().to_vec(), mode)
        })
        .collect();
    entries.push((format!("{info}/METADATA"), metadata.into_bytes(), 0o644));
    entries.push((
        format!("{info}/WHEEL"),
        b"Wheel-Version: 1.0\nGenerator: preview-rows\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            .to_vec(),
        0o644,
    ));
    if !scripts.is_empty() {
        let mut text = String::from("[console_scripts]\n");
        for (script, target) in scripts {
            text.push_str(&format!("{script} = {target}\n"));
        }
        entries.push((format!("{info}/entry_points.txt"), text.into_bytes(), 0o644));
    }
    let mut record = String::new();
    for (path, data, _) in &entries {
        let digest =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(data));
        record.push_str(&format!("{path},sha256={digest},{}\n", data.len()));
    }
    record.push_str(&format!("{info}/RECORD,,\n"));
    entries.push((format!("{info}/RECORD"), record.into_bytes(), 0o644));
    let filename = format!("{dist}-1.0-py3-none-any.whl");
    IndexFile {
        project: Some(project),
        path: format!("/packages/{filename}"),
        filename,
        bytes: zip(&entries),
    }
}

/// An sdist `<dist>-1.0.tar.gz` holding `files` (path under the top
/// directory, text), as a gzipped ustar archive.
pub(super) fn sdist(project: &'static str, dist: &str, files: &[(&str, &str)]) -> IndexFile {
    let top = format!("{dist}-1.0");
    let mut tar = Vec::new();
    for (path, text) in files {
        let full = format!("{top}/{path}");
        tar.extend(super::fetch_registry::ustar_header(
            &full,
            text.len(),
            0o644,
        ));
        tar.extend(text.as_bytes());
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.extend([0_u8; 1024]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &tar).expect("gzip");
    let filename = format!("{top}.tar.gz");
    IndexFile {
        project: Some(project),
        path: format!("/packages/{filename}"),
        filename,
        bytes: gz.finish().expect("gzip"),
    }
}

/// A running fake PyPI: its loopback port, the CA its leaf chains to, and
/// every request it read, as `host path`.
pub(super) struct Index {
    pub(super) port: u16,
    pub(super) ca_pem: String,
    requests: Arc<Mutex<Vec<String>>>,
    _serve: tokio::task::JoinHandle<()>,
}

/// The PEP 691 JSON page of `project`: every listed file, its URL and hash.
fn simple_page(project: &str, files: &[IndexFile]) -> Vec<u8> {
    let listed: Vec<serde_json::Value> = files
        .iter()
        .filter(|f| f.project == Some(project))
        .map(|f| {
            serde_json::json!({
                "filename": f.filename,
                "url": format!("https://files.pythonhosted.org{}", f.path),
                "hashes": {"sha256": hex::encode(sha2::Sha256::digest(&f.bytes))},
            })
        })
        .collect();
    serde_json::json!({
        "meta": {"api-version": "1.1"},
        "name": project,
        "files": listed,
        "versions": ["1.0"],
    })
    .to_string()
    .into_bytes()
}

impl Index {
    /// Serve `files` under a leaf for both PyPI names, signed by a fresh test
    /// CA named `ca_name`.
    pub(super) async fn start(files: Vec<IndexFile>, ca_name: &str) -> Self {
        let pki = crate::test_fixture_host::test_pki_names(
            &["pypi.org", "files.pythonhosted.org"],
            ca_name,
        );
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
        let mut routes: Vec<(String, &'static str, Vec<u8>)> = Vec::new();
        let mut projects: Vec<&'static str> = files.iter().filter_map(|f| f.project).collect();
        projects.sort_unstable();
        projects.dedup();
        for project in projects {
            routes.push((
                format!("pypi.org /simple/{project}/"),
                "application/vnd.pypi.simple.v1+json",
                simple_page(project, &files),
            ));
        }
        for f in files {
            routes.push((
                format!("files.pythonhosted.org {}", f.path),
                "application/octet-stream",
                f.bytes,
            ));
        }
        let routes = Arc::new(routes);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        let serve = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, routes, log) =
                    (acceptor.clone(), Arc::clone(&routes), Arc::clone(&log));
                tokio::spawn(async move {
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
                    let text = String::from_utf8_lossy(&head);
                    let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
                    let host = text
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("host").then(|| v.trim().to_owned())
                        })
                        .unwrap_or_default();
                    let host = host.split(':').next().unwrap_or_default().to_owned();
                    let key = format!("{host} {path}");
                    log.lock().expect("log").push(key.clone());
                    let found = routes.iter().find(|(k, _, _)| *k == key);
                    let (status, kind, body) = found
                        .map_or(("404 Not Found", "text/plain", &b""[..]), |(_, k, b)| {
                            ("200 OK", *k, b.as_slice())
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
            requests,
            _serve: serve,
        }
    }

    /// Every request read so far, as `host path`, in arrival order.
    pub(super) fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("log").clone()
    }
}
