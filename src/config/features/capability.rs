// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability configuration for direct REST API integration.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ── Capability ─────────────────────────────────────────────────────────────────

/// Capability configuration for direct REST API integration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CapabilityConfig {
    /// Enable capability system.
    pub enabled: bool,
    /// Backend name for capabilities (shown in `gateway_list_servers`).
    pub name: String,
    /// Directories to load capability definitions from.
    pub directories: Vec<String>,
    /// HTTP(S) proxy for capability calls, e.g. `http://proxy.internal:3128`.
    ///
    /// Capability calls never follow `HTTP_PROXY`/`HTTPS_PROXY` from the
    /// environment (#1881); this key is the only way to proxy them. With it
    /// set, the proxy resolves each destination, so the gateway's DNS pinning
    /// cannot see where a name leads: private-range enforcement for names is
    /// then the proxy's job. IP-literal destinations are still refused. A plain
    /// `http://` destination sends its URL and headers, credentials included,
    /// to the proxy. Restart-only.
    pub egress_proxy: Option<String>,
    /// Whether `service: cli` and `service: mcp` capabilities may run a local
    /// process at all (MIK-7782). Restart-only; the per-capability kill switch
    /// is the hot stop.
    pub process_execution: ProcessExecution,
    /// What a process-running capability may run: each entry is matched
    /// EXACTLY against the pinned definition's `command` and leading static
    /// `args`. `None` means the shipped catalogue's list
    /// ([`ProcessCommand::shipped`]).
    pub process_commands: Option<Vec<ProcessCommand>>,
    /// Directories capability file parameters are confined to (MIK-7782).
    pub files: FileRoots,
}

/// Named directories a capability's path parameters must resolve inside.
///
/// None has a default: a capability whose parameter names an unset root
/// refuses the call and names the key, rather than reading or writing
/// anywhere the gateway user can.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileRoots {
    /// Files a capability may read and send elsewhere (uploads, analysis).
    pub uploads: Option<std::path::PathBuf>,
    /// Project directories a capability may read (design files, contracts).
    pub projects: Option<std::path::PathBuf>,
    /// Where a capability may write files it fetched.
    pub downloads: Option<std::path::PathBuf>,
    /// Most bytes the downloads directory may hold.
    pub downloads_quota_bytes: u64,
}

/// Default ceiling for the downloads directory (1 GiB).
pub const DEFAULT_DOWNLOADS_QUOTA_BYTES: u64 = 1024 * 1024 * 1024;

impl Default for FileRoots {
    fn default() -> Self {
        Self {
            uploads: None,
            projects: None,
            downloads: None,
            downloads_quota_bytes: DEFAULT_DOWNLOADS_QUOTA_BYTES,
        }
    }
}

impl FileRoots {
    /// The configured root a schema's `path_root` names.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&std::path::Path> {
        match name {
            "uploads" => self.uploads.as_deref(),
            "projects" => self.projects.as_deref(),
            "downloads" => self.downloads.as_deref(),
            _ => None,
        }
    }
}

/// The global switch for process-running capabilities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessExecution {
    /// Pinned, allowlisted `cli`/`mcp` capabilities may run.
    #[default]
    Enabled,
    /// Every `cli`/`mcp` call is refused before anything is spawned.
    Disabled,
}

/// One allowed invocation: the definition's `command`, spelled exactly as
/// here (a bare name or an absolute path, never a prefix of either), whose
/// static leading args start with `args_prefix`, element by element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessCommand {
    /// The command string as the capability definition writes it.
    pub command: String,
    /// Leading static arguments the definition must start with.
    #[serde(default)]
    pub args_prefix: Vec<String>,
}

impl ProcessCommand {
    fn new(command: &str, args_prefix: &[&str]) -> Self {
        Self {
            command: command.to_string(),
            args_prefix: args_prefix.iter().map(ToString::to_string).collect(),
        }
    }

    /// The commands the shipped catalogue runs.
    #[must_use]
    pub fn shipped() -> Vec<Self> {
        vec![
            Self::new("gws", &[]),
            // Not `trawl` and not `mcp-scanner remote`: both are held until
            // they refuse private addresses at dial time (MIK-7788); an
            // operator accepting that lists them.
            Self::new("openpencil-mcp", &[]),
            Self::new("pact-mcp", &[]),
            Self::new("pyghidra-mcp", &[]),
            Self::new("mcp-scanner", &["--analyzers", "yara", "remote"]),
            // Static analyzers only: nothing leaves this machine.
            Self::new("skill-scanner", &["scan"]),
        ]
    }

    /// Whether a definition's `command` and static leading args match.
    #[must_use]
    pub fn admits(&self, command: &str, static_args: &[&str]) -> bool {
        self.command == command
            && static_args.len() >= self.args_prefix.len()
            && self
                .args_prefix
                .iter()
                .zip(static_args)
                .all(|(want, got)| want == got)
    }
}

// Manual `Debug` (CWE-532): `egress_proxy` may carry `user:password@` in its
// URL, and a derived `Debug` would print it with any config dump. Only the
// scheme, host and port are shown.
impl std::fmt::Debug for CapabilityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proxy = self.egress_proxy.as_deref().map(|raw| {
            url::Url::parse(raw).map_or_else(
                |_| "<unparseable>".to_string(),
                |url| Self::egress_proxy_for_log(&url),
            )
        });
        f.debug_struct("CapabilityConfig")
            .field("enabled", &self.enabled)
            .field("name", &self.name)
            .field("directories", &self.directories)
            .field("egress_proxy", &proxy)
            .field("process_execution", &self.process_execution)
            .field("process_commands", &self.process_commands)
            .field("files", &self.files)
            .finish()
    }
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "gateway".to_string(),
            // Only the bundled catalogue. Any other source is named in config.
            directories: vec!["capabilities".to_string()],
            egress_proxy: None,
            process_execution: ProcessExecution::Enabled,
            process_commands: None,
            files: FileRoots::default(),
        }
    }
}

impl CapabilityConfig {
    /// The configured egress proxy, parsed.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigValidation`] unless the value is an absolute `http://`
    /// or `https://` URL with a host. A bad value is refused, never ignored:
    /// ignoring it would silently send the calls direct.
    pub(crate) fn egress_proxy_url(&self) -> Result<Option<url::Url>> {
        let Some(raw) = self.egress_proxy.as_deref() else {
            return Ok(None);
        };
        let refuse = |why: &str| {
            Error::ConfigValidation(format!(
                "capabilities.egress_proxy {why}; expected http(s)://[user:pass@]host[:port]"
            ))
        };
        let parsed = url::Url::parse(raw).map_err(|_| refuse("is not a URL"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(refuse("must use http or https"));
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(refuse("has no host"));
        }
        Ok(Some(parsed))
    }

    /// `scheme://host:port` of the egress proxy, for logs: never its userinfo.
    #[must_use]
    pub(crate) fn egress_proxy_for_log(url: &url::Url) -> String {
        let host = url.host_str().unwrap_or_default();
        match url.port_or_known_default() {
            Some(port) => format!("{}://{host}:{port}", url.scheme()),
            None => format!("{}://{host}", url.scheme()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(proxy: &str) -> CapabilityConfig {
        CapabilityConfig {
            egress_proxy: Some(proxy.to_string()),
            ..CapabilityConfig::default()
        }
    }

    #[test]
    fn egress_proxy_accepts_http_and_https_urls() {
        assert!(
            CapabilityConfig::default()
                .egress_proxy_url()
                .unwrap()
                .is_none()
        );
        for ok in [
            "http://127.0.0.1:3128",
            "https://proxy.internal",
            "http://u:p@proxy:8080",
        ] {
            assert!(with(ok).egress_proxy_url().unwrap().is_some(), "{ok}");
        }
    }

    #[test]
    fn egress_proxy_refuses_what_it_cannot_use() {
        for bad in [
            "not a url",
            "ftp://proxy:21",
            "proxy.internal:3128",
            "file:///tmp/p",
        ] {
            let err = with(bad).egress_proxy_url().unwrap_err().to_string();
            assert!(err.contains("capabilities.egress_proxy"), "{bad}: {err}");
        }
    }

    // CWE-532: a derived `Debug` would print the proxy's password with the
    // whole config.
    #[test]
    fn debug_redacts_egress_proxy_credentials() {
        let sentinel = "SENTINEL_PW_9f3a";
        let dbg = format!(
            "{:?}",
            with(&format!("http://probe-user:{sentinel}@proxy.internal:8080"))
        );
        assert!(!dbg.contains(sentinel), "leaked proxy password: {dbg}");
        assert!(!dbg.contains("probe-user"), "leaked proxy userinfo: {dbg}");
        assert!(
            dbg.contains("proxy.internal:8080"),
            "proxy host missing: {dbg}"
        );
    }

    #[test]
    fn egress_proxy_log_form_drops_credentials() {
        let url = with("http://user:secret@proxy.internal:8080/")
            .egress_proxy_url()
            .unwrap()
            .unwrap();
        assert_eq!(
            CapabilityConfig::egress_proxy_for_log(&url),
            "http://proxy.internal:8080"
        );
    }
}
