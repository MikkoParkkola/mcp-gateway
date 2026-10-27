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

/// What a file looked like when it was stamped; `None` when it was absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    /// The inode on Unix, so a same-size replacement in the same second is
    /// still seen; 0 elsewhere.
    inode: u64,
}

/// Every candidate path with its stamp: equal fingerprints mean no client
/// file was created, deleted or changed between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fingerprint(Vec<(PathBuf, Option<Stamp>)>);

/// One scan of the client config files.
#[derive(Debug)]
pub(crate) struct ClientScan {
    pub(crate) finds: Vec<DiscoveredServer>,
    /// Taken after the reads, from the same candidate list.
    pub(crate) fingerprint: Fingerprint,
    /// Files that exist but did not read or parse: their app and file name.
    pub(crate) unreadable: Vec<(DiscoverySource, String)>,
}

fn stamp(path: &std::path::Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    Some(Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        inode,
    })
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
        Fingerprint(
            candidates
                .iter()
                .map(|c| (c.path.clone(), stamp(&c.path)))
                .collect(),
        )
    }

    /// Read every client config file once, through its own parser.
    pub(crate) async fn scan_client_configs(&self) -> ClientScan {
        self.scan_candidates(&Self::candidates()).await
    }

    /// Read `candidates` in order. An absent file adds nothing; one that
    /// exists but does not read or parse is named in `unreadable`.
    pub(crate) async fn scan_candidates(&self, candidates: &[Candidate]) -> ClientScan {
        let mut finds = Vec::new();
        let mut unreadable = Vec::new();
        for candidate in candidates {
            if !candidate.path.exists() {
                continue;
            }
            debug!("Scanning client config at {}", candidate.path.display());
            let path = &candidate.path;
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
                Err(_) => unreadable.push((
                    candidate.source.clone(),
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )),
            }
        }
        ClientScan {
            finds,
            fingerprint: Self::fingerprint(candidates),
            unreadable,
        }
    }
}

#[cfg(test)]
#[path = "config_scanner_client_scan_tests.rs"]
mod tests;
