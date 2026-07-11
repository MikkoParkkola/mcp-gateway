//! Plugin marketplace registry
//!
//! Provides discovery, installation, and lifecycle management of gateway plugins.
//! Plugins extend the gateway with additional capabilities sourced from a remote
//! marketplace registry.
//!
//! # Security
//!
//! Every downloaded plugin manifest carries a SHA-256 checksum and an optional
//! Ed25519 signature.  The signature is stored as a 128-character lowercase hex
//! string (64 raw bytes) and must be verified against a trusted publisher public
//! key before installation.
//!
//! # Example
//!
//! ```rust,no_run
//! use mcp_gateway::registry::marketplace::{MarketplaceClient, PluginRegistry};
//! use std::path::PathBuf;
//!
//! # async fn run() -> mcp_gateway::Result<()> {
//! let client = MarketplaceClient::new("https://marketplace.example.com", PathBuf::from("/tmp/cache"))?;
//! let results = client.search("stripe").await?;
//! for m in &results {
//!     println!("{} v{}", m.name, m.version);
//! }
//! # Ok(())
//! # }
//! ```

mod crypto;

pub use crypto::{
    Ed25519PublicKey, Ed25519Signature, InstalledPlugin, PluginManifest, verify_signature,
};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, Utc};

use crate::{Error, Result};

// ── Plugin registry (local state) ────────────────────────────────────────────

/// Local plugin registry tracking all installed plugins.
///
/// Persisted as a JSON file (`registry.json`) inside `plugin_dir`.
#[derive(Debug)]
pub struct PluginRegistry {
    /// Installed plugins keyed by name
    installed: HashMap<String, InstalledPlugin>,
    /// Root directory for all plugin installations
    plugin_dir: PathBuf,
}

impl PluginRegistry {
    /// Open (or create) a plugin registry rooted at `plugin_dir`.
    ///
    /// If a `registry.json` file already exists in `plugin_dir` it is loaded;
    /// otherwise an empty registry is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Json`] if the registry file exists but
    /// cannot be read or parsed.
    pub fn open<P: AsRef<Path>>(plugin_dir: P) -> Result<Self> {
        let plugin_dir = plugin_dir.as_ref().to_path_buf();
        let registry_path = plugin_dir.join("registry.json");

        let installed = if registry_path.exists() {
            let content = std::fs::read_to_string(&registry_path)?;
            serde_json::from_str(&content)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            installed,
            plugin_dir,
        })
    }

    /// List all installed plugins.
    #[must_use]
    pub fn list_installed(&self) -> Vec<&InstalledPlugin> {
        let mut plugins: Vec<_> = self.installed.values().collect();
        // Stable ordering for deterministic output / tests.
        plugins.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        plugins
    }

    /// Look up an installed plugin by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&InstalledPlugin> {
        self.installed.get(name)
    }

    /// Register a newly installed plugin and persist the registry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Json`] if the registry file cannot be
    /// written.
    pub fn register(&mut self, plugin: InstalledPlugin) -> Result<()> {
        self.installed.insert(plugin.manifest.name.clone(), plugin);
        self.persist()
    }

    /// Remove an installed plugin from the registry and persist.
    ///
    /// Returns `true` if a plugin with that name was registered, `false`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] or [`Error::Json`] if the registry file cannot be
    /// written.
    pub fn deregister(&mut self, name: &str) -> Result<bool> {
        let existed = self.installed.remove(name).is_some();
        self.persist()?;
        Ok(existed)
    }

    /// Number of installed plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.installed.len()
    }

    /// Returns `true` when no plugins are installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.installed.is_empty()
    }

    /// Root directory of this registry.
    #[must_use]
    pub fn plugin_dir(&self) -> &Path {
        &self.plugin_dir
    }

    /// Write registry state to `<plugin_dir>/registry.json`.
    fn persist(&self) -> Result<()> {
        std::fs::create_dir_all(&self.plugin_dir)?;
        let path = self.plugin_dir.join("registry.json");
        let json = serde_json::to_string_pretty(&self.installed)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

// ── Marketplace client ───────────────────────────────────────────────────────

/// HTTP client for interacting with a remote plugin marketplace.
pub struct MarketplaceClient {
    base_url: String,
    client: reqwest::Client,
    cache_dir: PathBuf,
}

impl MarketplaceClient {
    /// Create a new marketplace client.
    ///
    /// # Arguments
    ///
    /// * `base_url` -- Root URL of the marketplace API (no trailing slash).
    /// * `cache_dir` -- Local directory for caching downloaded manifests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the URL is empty or the HTTP client cannot
    /// be constructed.
    pub fn new<P: AsRef<Path>>(base_url: &str, cache_dir: P) -> Result<Self> {
        if base_url.is_empty() {
            return Err(Error::Config(
                "marketplace base_url must not be empty".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .user_agent(concat!("mcp-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            cache_dir: cache_dir.as_ref().to_path_buf(),
        })
    }

    /// Search the marketplace for plugins matching `query`.
    ///
    /// Queries `GET /api/v1/plugins?q=<query>` and returns the deserialised
    /// manifest list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] on HTTP failure or [`Error::Json`] on a
    /// malformed response body.
    pub async fn search(&self, query: &str) -> Result<Vec<PluginManifest>> {
        let url = format!("{}/api/v1/plugins?q={}", self.base_url, urlencoding(query));
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Transport(format!("marketplace search failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "marketplace returned HTTP {}: {}",
                response.status(),
                url
            )));
        }

        let manifests: Vec<PluginManifest> = response
            .json()
            .await
            .map_err(|e| Error::Transport(format!("failed to parse search response: {e}")))?;

        Ok(manifests)
    }

    /// Install a plugin by name into `plugin_dir`.
    ///
    /// 1. Downloads the manifest from `GET /api/v1/plugins/<name>`.
    /// 2. Verifies the SHA-256 checksum.
    /// 3. Writes the manifest to `<plugin_dir>/<name>/manifest.json`.
    /// 4. Returns the [`InstalledPlugin`] record (caller should call
    ///    [`PluginRegistry::register`] to persist it).
    ///
    /// # Errors
    ///
    /// Returns an error on network failure, checksum mismatch, or filesystem
    /// problems.
    pub async fn install(&self, name: &str, plugin_dir: &Path) -> Result<InstalledPlugin> {
        let manifest = self.fetch_manifest(name).await?;
        manifest.verify_checksum()?;

        let install_path = plugin_dir.join(name);
        std::fs::create_dir_all(&install_path)?;

        let manifest_path = install_path.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        std::fs::write(&manifest_path, manifest_json)?;

        Ok(InstalledPlugin {
            manifest,
            install_path,
            installed_at: Utc::now(),
        })
    }

    /// Uninstall a plugin: removes its directory from `plugin_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when the plugin is not found, or [`Error::Io`]
    /// when the directory cannot be removed.
    pub fn uninstall(name: &str, plugin_dir: &Path) -> Result<()> {
        let plugin_path = plugin_dir.join(name);
        if !plugin_path.exists() {
            return Err(Error::Config(format!(
                "plugin '{name}' is not installed at {}",
                plugin_dir.display()
            )));
        }
        std::fs::remove_dir_all(&plugin_path)?;
        Ok(())
    }

    /// List plugins currently installed in `plugin_dir`.
    ///
    /// Reads `manifest.json` from every immediate subdirectory of `plugin_dir`.
    /// Entries that fail to parse are silently skipped with a warning.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if `plugin_dir` cannot be read.
    pub fn list_installed(plugin_dir: &Path) -> Result<Vec<InstalledPlugin>> {
        if !plugin_dir.exists() {
            return Ok(Vec::new());
        }

        let mut plugins = Vec::new();

        for entry in std::fs::read_dir(plugin_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_dir() {
                continue;
            }

            let manifest_path = path.join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }

            match read_installed_from_dir(&path) {
                Ok(plugin) => plugins.push(plugin),
                Err(e) => eprintln!(
                    "Warning: skipping malformed plugin at {}: {e}",
                    path.display()
                ),
            }
        }

        plugins.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        Ok(plugins)
    }

    /// Fetch a manifest from the marketplace API without installing.
    ///
    /// # Errors
    ///
    /// Returns an error on network or parsing failure.
    pub async fn fetch_manifest(&self, name: &str) -> Result<PluginManifest> {
        let url = format!("{}/api/v1/plugins/{}", self.base_url, name);
        let response =
            self.client.get(&url).send().await.map_err(|e| {
                Error::Transport(format!("failed to fetch manifest for '{name}': {e}"))
            })?;

        if !response.status().is_success() {
            return Err(Error::Transport(format!(
                "plugin '{name}' not found in marketplace (HTTP {})",
                response.status()
            )));
        }

        let manifest: PluginManifest = response
            .json()
            .await
            .map_err(|e| Error::Transport(format!("failed to parse manifest for '{name}': {e}")))?;

        Ok(manifest)
    }

    /// Return the base URL this client is configured with.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the cache directory path.
    #[must_use]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Read an [`InstalledPlugin`] from its installation directory.
fn read_installed_from_dir(dir: &Path) -> Result<InstalledPlugin> {
    let manifest_path = dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path)?;
    let manifest: PluginManifest = serde_json::from_str(&content)?;

    // Derive installed_at from manifest.json mtime; fall back to epoch.
    let installed_at = std::fs::metadata(&manifest_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|d| {
            let secs = i64::try_from(d.as_secs()).ok()?;
            DateTime::from_timestamp(secs, d.subsec_nanos())
        })
        .unwrap_or_else(Utc::now);

    Ok(InstalledPlugin {
        manifest,
        install_path: dir.to_path_buf(),
        installed_at,
    })
}

/// Percent-encode a query string value for use in a URL.
fn urlencoding(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                vec![c]
            }
            ' ' => vec!['+'],
            c => format!("%{:02X}", c as u32).chars().collect(),
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_manifest_with_checksum(name: &str) -> PluginManifest {
        let mut m = PluginManifest {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: format!("Plugin {name}"),
            author: "test-author".to_string(),
            capabilities: vec!["cap_a".to_string(), "cap_b".to_string()],
            checksum: String::new(),
            signature: None,
        };
        m.checksum = m.compute_checksum().unwrap();
        m
    }

    // ── PluginRegistry ───────────────────────────────────────────────────────

    #[test]
    fn registry_open_empty_dir_creates_empty_registry() {
        let tmp = TempDir::new().unwrap();
        let reg = PluginRegistry::open(tmp.path()).unwrap();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_register_then_get_returns_plugin() {
        let tmp = TempDir::new().unwrap();
        let mut reg = PluginRegistry::open(tmp.path()).unwrap();

        let plugin = InstalledPlugin {
            manifest: make_manifest_with_checksum("my-plugin"),
            install_path: tmp.path().join("my-plugin"),
            installed_at: Utc::now(),
        };

        reg.register(plugin).unwrap();
        assert!(reg.get("my-plugin").is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_deregister_removes_plugin() {
        let tmp = TempDir::new().unwrap();
        let mut reg = PluginRegistry::open(tmp.path()).unwrap();
        let plugin = InstalledPlugin {
            manifest: make_manifest_with_checksum("removable"),
            install_path: tmp.path().join("removable"),
            installed_at: Utc::now(),
        };
        reg.register(plugin).unwrap();

        let existed = reg.deregister("removable").unwrap();
        assert!(existed);
        assert!(reg.get("removable").is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_deregister_nonexistent_returns_false() {
        let tmp = TempDir::new().unwrap();
        let mut reg = PluginRegistry::open(tmp.path()).unwrap();
        let existed = reg.deregister("ghost").unwrap();
        assert!(!existed);
    }

    #[test]
    fn registry_persists_and_reloads_correctly() {
        let tmp = TempDir::new().unwrap();
        {
            let mut reg = PluginRegistry::open(tmp.path()).unwrap();
            let plugin = InstalledPlugin {
                manifest: make_manifest_with_checksum("persistent"),
                install_path: tmp.path().join("persistent"),
                installed_at: Utc::now(),
            };
            reg.register(plugin).unwrap();
        }

        let reg2 = PluginRegistry::open(tmp.path()).unwrap();
        assert!(reg2.get("persistent").is_some());
        assert_eq!(reg2.len(), 1);
    }

    #[test]
    fn registry_list_installed_returns_sorted_by_name() {
        let tmp = TempDir::new().unwrap();
        let mut reg = PluginRegistry::open(tmp.path()).unwrap();

        for name in ["zebra", "alpha", "mango"] {
            reg.register(InstalledPlugin {
                manifest: make_manifest_with_checksum(name),
                install_path: tmp.path().join(name),
                installed_at: Utc::now(),
            })
            .unwrap();
        }

        let list = reg.list_installed();
        let names: Vec<_> = list.iter().map(|p| p.manifest.name.as_str()).collect();
        assert_eq!(names, ["alpha", "mango", "zebra"]);
    }

    // ── MarketplaceClient construction ──────────────────────────────────────

    #[test]
    fn client_new_rejects_empty_base_url() {
        let result = MarketplaceClient::new("", std::path::Path::new("/tmp"));
        assert!(result.is_err());
    }

    #[test]
    fn client_new_strips_trailing_slash_from_base_url() {
        let client =
            MarketplaceClient::new("https://example.com/", std::path::Path::new("/tmp")).unwrap();
        assert_eq!(client.base_url(), "https://example.com");
    }

    #[test]
    fn client_returns_configured_cache_dir() {
        let client =
            MarketplaceClient::new("https://example.com", std::path::Path::new("/cache")).unwrap();
        assert_eq!(client.cache_dir(), std::path::Path::new("/cache"));
    }

    // ── install / uninstall (filesystem) ─────────────────────────────────────

    #[tokio::test]
    async fn install_writes_manifest_json_to_plugin_dir() {
        let tmp = TempDir::new().unwrap();
        let manifest = make_manifest_with_checksum("test-plugin");

        let install_path = tmp.path().join(&manifest.name);
        std::fs::create_dir_all(&install_path).unwrap();
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(install_path.join("manifest.json"), &manifest_json).unwrap();

        let manifest_path = install_path.join("manifest.json");
        let loaded: PluginManifest =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
        assert_eq!(loaded.name, "test-plugin");
    }

    #[tokio::test]
    async fn uninstall_removes_plugin_directory() {
        let tmp = TempDir::new().unwrap();
        let plugin_path = tmp.path().join("to-remove");
        std::fs::create_dir_all(&plugin_path).unwrap();
        std::fs::write(
            plugin_path.join("manifest.json"),
            serde_json::to_string(&make_manifest_with_checksum("to-remove")).unwrap(),
        )
        .unwrap();

        MarketplaceClient::uninstall("to-remove", tmp.path()).unwrap();
        assert!(!plugin_path.exists());
    }

    #[tokio::test]
    async fn uninstall_returns_error_for_unknown_plugin() {
        let tmp = TempDir::new().unwrap();
        let result = MarketplaceClient::uninstall("ghost", tmp.path());
        assert!(result.is_err());
    }

    // ── list_installed (filesystem scan) ─────────────────────────────────────

    #[test]
    fn list_installed_returns_empty_for_missing_dir() {
        let result = MarketplaceClient::list_installed(Path::new("/nonexistent/path/xyz"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn list_installed_reads_all_plugin_dirs() {
        let tmp = TempDir::new().unwrap();

        for name in ["plugin-x", "plugin-y"] {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let m = make_manifest_with_checksum(name);
            std::fs::write(
                dir.join("manifest.json"),
                serde_json::to_string(&m).unwrap(),
            )
            .unwrap();
        }

        let plugins = MarketplaceClient::list_installed(tmp.path()).unwrap();
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0].manifest.name, "plugin-x");
        assert_eq!(plugins[1].manifest.name, "plugin-y");
    }

    #[test]
    fn list_installed_skips_dirs_without_manifest_json() {
        let tmp = TempDir::new().unwrap();

        let valid = tmp.path().join("valid-plugin");
        std::fs::create_dir_all(&valid).unwrap();
        let m = make_manifest_with_checksum("valid-plugin");
        std::fs::write(
            valid.join("manifest.json"),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();

        std::fs::create_dir_all(tmp.path().join("no-manifest")).unwrap();

        let plugins = MarketplaceClient::list_installed(tmp.path()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].manifest.name, "valid-plugin");
    }

    // ── urlencoding helper ──────────────────────────────────────────────────

    #[test]
    fn urlencoding_leaves_safe_chars_unchanged() {
        assert_eq!(urlencoding("stripe"), "stripe");
        assert_eq!(urlencoding("abc-123_x.y~z"), "abc-123_x.y~z");
    }

    #[test]
    fn urlencoding_encodes_space_as_plus() {
        assert_eq!(urlencoding("hello world"), "hello+world");
    }

    #[test]
    fn urlencoding_percent_encodes_special_chars() {
        let encoded = urlencoding("a&b=c");
        assert!(encoded.contains('%'));
        assert!(!encoded.contains('&'));
    }
}
