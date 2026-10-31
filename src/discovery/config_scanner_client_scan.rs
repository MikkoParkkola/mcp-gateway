// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The client config files discovery reads, as one list: it drives both the
//! fingerprint the discovery cache keys on and the per-file reads, so a file
//! the cache watches is always a file the scan read, and the reverse.
//!
//! Environment variables and running processes are not client config files
//! (ADR-021) and are never part of this scan.

use std::path::PathBuf;
use std::time::SystemTime;

use tracing::debug;

use super::{ConfigScanner, DiscoveredServer, DiscoverySource};

/// How a client file is laid out, so the right parser reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    /// `mcpServers` keyed by name (Claude, Cursor, Windsurf, Codex, generic).
    Claude,
    /// VS Code `settings.json` with `mcp.servers`.
    VsCode,
    /// Zed `settings.json` with `context_servers`.
    Zed,
    /// Continue's `mcpServers`, an array or an object.
    Continue,
}

/// One client config file discovery may read.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub(crate) path: PathBuf,
    pub(crate) source: DiscoverySource,
    pub(crate) format: Format,
}

/// A client file larger than this is not parsed: no MCP client config is
/// this big, and a scan holds the discovery cache while it reads.
const MAX_CLIENT_FILE: u64 = 1024 * 1024;

/// A hash over every candidate path with its size, modified time and (on
/// Unix) inode, absent ones included: equal fingerprints mean no client file
/// was created, deleted or changed between them. Only the hash is kept, so a
/// cached listing holds no path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fingerprint(String);

/// One scan of the client config files.
#[derive(Debug)]
pub(crate) struct ClientScan {
    pub(crate) finds: Vec<DiscoveredServer>,
    /// Taken before the reads, from the same candidate list.
    pub(crate) fingerprint: Fingerprint,
    /// Files that exist but could not be read, with their full paths: kept
    /// only for this scan, never cached (the cache keeps a keyed digest).
    pub(crate) unreadable: Vec<UnreadableClientFile>,
}

/// A client config file that exists but could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnreadableClientFile {
    pub(crate) source: DiscoverySource,
    pub(crate) path: PathBuf,
    pub(crate) reason: crate::decisions::UnreadableReason,
}

impl UnreadableClientFile {
    /// The file's name alone, which is all that may be shown.
    pub(crate) fn file_name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// A digest of the full path under `key`: tells two files with one name
    /// apart without holding the path, and without letting anyone test a
    /// guess at it.
    pub(crate) fn path_digest(&self, key: &[u8; 32]) -> String {
        crate::hashing::hmac_sha256_hex(key, self.path.as_os_str().as_encoded_bytes())
    }
}

#[cfg(test)]
impl ClientScan {
    /// Each unreadable file as its file name, reason class and path digest
    /// under a fixed test key.
    pub(crate) fn unreadable_rows(
        &self,
    ) -> Vec<(String, crate::decisions::UnreadableReason, String)> {
        self.unreadable
            .iter()
            .map(|file| (file.file_name(), file.reason, file.path_digest(&[3; 32])))
            .collect()
    }
}

/// One line per candidate: its path, then its stamp or `absent`.
fn stamp_line(path: &std::path::Path) -> String {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        // A file the gateway may not reach is not absent: when it becomes
        // reachable, or unreachable, the fingerprint changes and the cache
        // rescans (R13).
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return format!("{}\0denied\n", path.display());
        }
        Err(_) => return format!("{}\0absent\n", path.display()),
    };
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    format!("{}\0{}\0{modified}\0{inode}\n", path.display(), meta.len())
}

impl ConfigScanner {
    /// Every client config file a scan reads, in `scan_all`'s order. The
    /// generic MCP directory is listed now, so a file added there becomes a
    /// new candidate and changes the fingerprint.
    pub(crate) fn candidates() -> Vec<Candidate> {
        let fixed = [
            (
                Self::claude_desktop_config_path(),
                DiscoverySource::ClaudeDesktop,
                Format::Claude,
            ),
            (
                Self::claude_code_config_path(),
                DiscoverySource::ClaudeCode,
                Format::Claude,
            ),
            (
                Self::vscode_config_path(),
                DiscoverySource::VsCode,
                Format::VsCode,
            ),
            (
                Self::cursor_config_path(),
                DiscoverySource::VsCode,
                Format::VsCode,
            ),
            (
                Self::cursor_mcp_json_path(),
                DiscoverySource::Cursor,
                Format::Claude,
            ),
            (
                Self::windsurf_config_path(),
                DiscoverySource::Windsurf,
                Format::Claude,
            ),
            (Self::zed_config_path(), DiscoverySource::Zed, Format::Zed),
            (
                Self::continue_config_path(),
                DiscoverySource::Continue,
                Format::Continue,
            ),
            (
                Self::codex_config_path(),
                DiscoverySource::Codex,
                Format::Claude,
            ),
        ];
        let mut candidates: Vec<Candidate> = fixed
            .into_iter()
            .filter_map(|(path, source, format)| {
                path.ok().map(|path| Candidate {
                    path,
                    source,
                    format,
                })
            })
            .collect();
        if let Ok(dir) = Self::mcp_config_dir()
            && let Ok(entries) = std::fs::read_dir(&dir)
        {
            let mut generic: Vec<PathBuf> = entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
                .collect();
            generic.sort();
            candidates.extend(generic.into_iter().map(|path| Candidate {
                path,
                source: DiscoverySource::McpConfig,
                format: Format::Claude,
            }));
        }
        candidates
    }

    /// Stat every candidate: no read, no parse.
    pub(crate) fn fingerprint(candidates: &[Candidate]) -> Fingerprint {
        let lines: String = candidates.iter().map(|c| stamp_line(&c.path)).collect();
        Fingerprint(crate::hashing::sha256_hex(lines.as_bytes()))
    }

    /// Read every client config file once, through its own parser.
    pub(crate) async fn scan_client_configs(&self) -> ClientScan {
        self.scan_candidates(&Self::candidates()).await
    }

    /// Read `candidates` in order. An absent file adds nothing; one that
    /// exists but does not read or parse is named in `unreadable`.
    pub(crate) async fn scan_candidates(&self, candidates: &[Candidate]) -> ClientScan {
        // Taken before the reads: a file edited during the scan then differs
        // from it, and the next read rescans.
        let fingerprint = Self::fingerprint(candidates);
        let mut finds = Vec::new();
        let mut unreadable = Vec::new();
        for candidate in candidates {
            use crate::decisions::UnreadableReason;
            let path = &candidate.path;
            let mut unread = |reason| {
                unreadable.push(UnreadableClientFile {
                    source: candidate.source.clone(),
                    path: path.clone(),
                    reason,
                });
            };
            // Not `exists()`: it reads any metadata error as absence, so a
            // file the gateway may not reach vanished without a word.
            let meta = match std::fs::metadata(path) {
                Ok(meta) => meta,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    unread(UnreadableReason::NoPermission);
                    continue;
                }
                Err(_) => {
                    unread(UnreadableReason::NotAReadableFile);
                    continue;
                }
            };
            debug!("Scanning client config at {}", path.display());
            // A FIFO, a device or a huge file never reaches a parser.
            if !(meta.is_file() && meta.len() <= MAX_CLIENT_FILE) {
                unread(UnreadableReason::NotAReadableFile);
                continue;
            }
            // Judged by the open's error kind, never by a parser's message:
            // every parser maps its read error to text.
            if let Err(e) = std::fs::File::open(path)
                && e.kind() == std::io::ErrorKind::PermissionDenied
            {
                unread(UnreadableReason::NoPermission);
                continue;
            }
            let read = match candidate.format {
                Format::Claude => {
                    self.parse_claude_config(path, candidate.source.clone())
                        .await
                }
                Format::VsCode => {
                    self.parse_vscode_config(path, candidate.source.clone())
                        .await
                }
                Format::Zed => self.parse_zed_config(path).await,
                Format::Continue => self.parse_continue_config(path).await,
            };
            match read {
                Ok(mut servers) => finds.append(&mut servers),
                Err(_) => unread(UnreadableReason::DidNotParse),
            }
        }
        ClientScan {
            finds,
            fingerprint,
            unreadable,
        }
    }
}

#[cfg(test)]
#[path = "config_scanner_client_scan_tests.rs"]
mod tests;
