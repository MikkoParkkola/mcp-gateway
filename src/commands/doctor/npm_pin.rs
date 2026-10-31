// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `doctor` row `<backend>: npm pin` (MIK-8512): a stdio backend that pins a
//! registry package to a version npm marks deprecated.
//!
//! The first `doctor` call to a third-party host, safe by construction:
//! - only packages the bundled server registry names are ever asked about,
//!   and only the package name is sent (the version stays local);
//! - the proxy is chosen here from one environment snapshot, never by
//!   reqwest, so a configured proxy is never bypassed and its credentials are
//!   never sent;
//! - every failure is silent, the whole check sits under one budget, and it
//!   never fails `doctor`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use futures::StreamExt as _;
use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
use url::Url;

use super::CheckResult;

mod helpers;

use helpers::{fetch_doc, has_absolute_memory_path, is_exact_version, strip_escapes, usable_proxy};
use mcp_gateway::cli_support::is_format_char;

/// The one registry this check reads.
pub(super) const REGISTRY_BASE: &str = "https://registry.npmjs.org/";
/// The fixed `User-Agent`: no gateway version, no host identifiers.
pub(super) const USER_AGENT: &str = "mcp-gateway-doctor";
/// npm's abbreviated package document.
pub(super) const ACCEPT: &str = "application/vnd.npm.install-v1+json";
/// The whole check, every request included.
pub(super) const BUDGET: Duration = Duration::from_secs(4);
/// One request's connect bound.
pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// One request's whole bound.
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
/// Requests in flight at once.
pub(super) const CONCURRENCY: usize = 4;
/// The largest decoded document read; past it the answer is no answer.
pub(super) const MAX_DOC_BYTES: usize = 1024 * 1024;
/// The most characters of npm's text printed.
pub(super) const MESSAGE_CAP: usize = 200;
/// The row label when the lookup does not run.
pub(super) const SKIPPED_LABEL: &str = "npm registry check";
/// The package whose old graph a pin change leaves behind.
pub(super) const MEMORY_PACKAGE: &str = "@modelcontextprotocol/server-memory";

/// Whether this run looks anything up, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lookup {
    On,
    /// `--no-registry-check` or `MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK`.
    OffByFlag,
    /// `security.posture: hardened`.
    OffByPosture,
}

/// The run's lookup: on by default (operator ruling 2026-10-22), off by the
/// switch or the hardened posture.
pub(super) fn decide(switch_off: bool, hardened: bool) -> Lookup {
    // The switch wins the reason when both apply: it is what the user typed.
    if switch_off {
        Lookup::OffByFlag
    } else if hardened {
        Lookup::OffByPosture
    } else {
        Lookup::On
    }
}

/// [`decide`] for a loaded config: hardened is `security.posture: hardened`.
pub(super) fn lookup_of(config: &Config, switch_off: bool) -> Lookup {
    decide(
        switch_off,
        config.security.posture == mcp_gateway::security::SecurityPosture::Hardened,
    )
}

/// A pinned registry package: `name@version` from an `npx` command.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Pin {
    pub(super) name: String,
    pub(super) version: String,
}

/// The pin in `command`, when it is `npx`, `npx.cmd` or a path ending in
/// either, followed only by `-y`/`--yes` flags, then `<name>@<exact semver>`
/// (`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`, at most 64 characters). Anything
/// else is no pin.
pub(super) fn npx_pin(command: &str) -> Option<Pin> {
    // The host's own splitter, so this reads the command the way spawn will.
    let argv = mcp_gateway::transport::split_command(command)?;
    let program = argv.first()?;
    // The last path segment, on either separator, so a full path to npx
    // counts and a lookalike program name does not.
    let bin = program.rsplit(['/', '\\']).next()?;
    if bin != "npx" && bin != "npx.cmd" {
        return None;
    }
    let mut index = 1;
    while matches!(argv.get(index).map(String::as_str), Some("-y" | "--yes")) {
        index += 1;
    }
    let spec = argv.get(index)?;
    // Any other flag before the package changes what npx would install
    // (another registry, an extra package), so it is not a plain pin.
    if spec.starts_with('-') {
        return None;
    }
    // The last '@' splits name from version; a scoped name's leading '@'
    // sits at index 0 and does not split.
    let at = spec.rfind('@')?;
    if at == 0 {
        return None;
    }
    let (name, version) = (&spec[..at], &spec[at + 1..]);
    if name.is_empty() || !is_exact_version(version) {
        return None;
    }
    // Tokens after the spec are the server's own arguments, not part of it.
    Some(Pin {
        name: name.to_string(),
        version: version.to_string(),
    })
}

/// Every package name the bundled registry pins through `npx`.
pub(super) fn allowlist() -> BTreeSet<String> {
    mcp_gateway::registry::server_registry::all()
        .iter()
        .filter_map(|entry| npx_pin(entry.command))
        .map(|pin| pin.name)
        .collect()
}

/// The registry's own current version of `name`, when it pins one.
pub(super) fn current_version(name: &str) -> Option<String> {
    mcp_gateway::registry::server_registry::all()
        .iter()
        .filter_map(|entry| npx_pin(entry.command))
        .find(|pin| pin.name == name)
        .map(|pin| pin.version)
}

/// The package document's URL: `/<name>`, a scoped name's `/` encoded as `%2F`.
pub(super) fn package_url(base: &Url, name: &str) -> Url {
    // Only a scoped name's first '/' is encoded; the rest of the name is
    // already a single path segment. A join error cannot happen for an
    // allowlisted name, so the base itself is the inert fallback.
    match base.join(&name.replacen('/', "%2F", 1)) {
        Ok(url) => url,
        Err(_) => base.clone(),
    }
}

/// The proxy variables, read once: `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`
/// and `NO_PROXY`, in both cases. Nothing else in the environment is read.
/// A variable whose value is not valid UTF-8 is not stored, and marks the
/// snapshot unreadable: [`route`] skips the lookup then, never reads the
/// variable as unset.
#[derive(Clone, Debug, Default)]
pub(super) struct ProxyEnv {
    pairs: Vec<(String, String)>,
    unreadable: bool,
}

/// The only environment names a snapshot holds, in both cases.
const PROXY_NAMES: [&str; 8] = [
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

impl ProxyEnv {
    /// The process environment's proxy variables.
    pub(super) fn from_process() -> Self {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// A snapshot from explicit pairs (tests; unrelated names are dropped).
    #[cfg(test)]
    pub(super) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self {
            pairs: pairs
                .iter()
                .filter(|(name, _)| PROXY_NAMES.contains(name))
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
            unreadable: false,
        }
    }

    /// The proxy variables read through `lookup`; `from_process` is this
    /// with `std::env::var_os`. A value that is not valid UTF-8 is not
    /// stored, and marks the snapshot unreadable: [`route`] skips the
    /// lookup then.
    pub(super) fn from_lookup(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
        let mut unreadable = false;
        let pairs = PROXY_NAMES
            .iter()
            .filter_map(|name| {
                let value = lookup(name)?;
                if let Ok(value) = value.into_string() {
                    Some(((*name).to_string(), value))
                } else {
                    unreadable = true;
                    None
                }
            })
            .collect();
        Self { pairs, unreadable }
    }

    /// The value of `name`, when set; an empty value is unset, the way the
    /// tools that read these variables treat it.
    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty())
    }
}

/// How the lookup reaches `https://` hosts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Route {
    /// No proxy applies.
    Direct,
    /// Through this credential-free `http`/`https` proxy, except for hosts
    /// the snapshot's `NO_PROXY` covers.
    Proxy { url: Url, no_proxy: Option<String> },
    /// A proxy is set that this check will not use (another scheme,
    /// credentials, unparseable): no lookup at all, never direct.
    Skip,
}

/// The route from the snapshot: `HTTPS_PROXY`, else `ALL_PROXY`; lowercase
/// before uppercase; an empty value is unset; `HTTP_PROXY` is for `http://`
/// targets only. A snapshot holding an unreadable value skips outright.
pub(super) fn route(env: &ProxyEnv) -> Route {
    // Any unreadable variable fails the lookup closed, NO_PROXY included:
    // an exclusion list that cannot be read must not widen where a proxy
    // is used, and Skip is the existing fail-closed answer.
    if env.unreadable {
        return Route::Skip;
    }
    // One group at a time, https before all. A group that is set but
    // unusable skips the lookup outright: falling back to the other group,
    // or going direct, would send the request by a route nobody chose.
    // Within a group every set value must be usable, so a broken spelling
    // in either case cannot hide behind the working one; the lowercase
    // value is the one used when both are set.
    for (lower, upper) in [("https_proxy", "HTTPS_PROXY"), ("all_proxy", "ALL_PROXY")] {
        let values = [env.get(lower), env.get(upper)];
        if values.iter().all(Option::is_none) {
            continue;
        }
        let mut chosen: Option<Url> = None;
        for value in values.into_iter().flatten() {
            match usable_proxy(value) {
                Some(url) => {
                    if chosen.is_none() {
                        chosen = Some(url);
                    }
                }
                None => return Route::Skip,
            }
        }
        return match chosen {
            Some(url) => Route::Proxy {
                url,
                no_proxy: env
                    .get("no_proxy")
                    .or_else(|| env.get("NO_PROXY"))
                    .map(ToString::to_string),
            },
            // The group is set, so the loop produced a URL or returned
            // already; this arm only closes the match.
            None => Route::Skip,
        };
    }
    Route::Direct
}

/// Everything the one client builder takes, as data. Production and tests
/// build through the same [`client`].
pub(super) struct ClientCfg {
    pub(super) base: Url,
    pub(super) roots: rustls::RootCertStore,
    pub(super) proxy: ProxyEnv,
    /// A test-only replacement for both request bounds ([`CONNECT_TIMEOUT`]
    /// and [`REQUEST_TIMEOUT`]); `None` in production. Tests that prove the
    /// [`BUDGET`] set it past the budget, so nothing else can end a stalled
    /// lookup.
    pub(super) bounds_override: Option<Duration>,
}

impl ClientCfg {
    /// npm, the bundled `webpki-roots`, the process proxy variables.
    pub(super) fn production() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            // The one `expect` in this module: a compile-time literal,
            // pinned by a test, not operator input.
            base: Url::parse(REGISTRY_BASE).expect("REGISTRY_BASE is a valid URL literal"),
            roots,
            proxy: ProxyEnv::from_process(),
            bounds_override: None,
        }
    }
}

/// The client, or `None` when the route is `Skip` or the builder fails.
/// Never reads proxies itself (`no_proxy()`), never follows a redirect,
/// never retries, never consults the platform verifier.
pub(super) fn client(cfg: &ClientCfg) -> Option<reqwest::Client> {
    let route = route(&cfg.proxy);
    if matches!(route, Route::Skip) {
        return None;
    }
    // The injected roots are the only roots: a preconfigured TLS backend
    // built from them alone, never the platform verifier. HTTP/1.1 is the
    // only ALPN on offer, matching `http1_only` below.
    let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(cfg.roots.clone())
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    // `no_proxy()` stops the builder reading proxy variables itself, so
    // the route chosen from the snapshot above is the only proxy decision.
    // No redirects and no retries: one request, one answer, or silence.
    let mut builder = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(cfg.bounds_override.unwrap_or(CONNECT_TIMEOUT))
        .timeout(cfg.bounds_override.unwrap_or(REQUEST_TIMEOUT))
        .user_agent(USER_AGENT)
        .http1_only();
    if let Route::Proxy { url, no_proxy } = route {
        let proxy = reqwest::Proxy::https(url.as_str())
            .ok()?
            .no_proxy(no_proxy.as_deref().and_then(reqwest::NoProxy::from_string));
        builder = builder.proxy(proxy);
    }
    builder.build().ok()
}

/// npm's `deprecated` text for `version` in an abbreviated document, when it
/// is a non-empty string after trimming. Any parse failure is `None`.
pub(super) fn deprecation(doc: &[u8], version: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(doc).ok()?;
    let text = value
        .get("versions")?
        .get(version)?
        .get("deprecated")?
        .as_str()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// npm's text made safe for a terminal: ANSI escapes and Unicode `Cc`/`Cf`
/// characters removed, whitespace runs collapsed to one space, cut to
/// [`MESSAGE_CAP`] characters.
pub(super) fn npm_text(raw: &str) -> String {
    // Escapes first: a sequence can hide characters the filters below
    // would otherwise keep, and its own bytes must not survive either.
    let mut kept = String::new();
    for c in strip_escapes(raw).chars() {
        if is_format_char(c) {
            continue;
        }
        if c.is_control() {
            // Line breaks and tabs only separate words; every other
            // control (a bell, a backspace over printed text) is dropped.
            if matches!(c, '\n' | '\r' | '\t') {
                kept.push(' ');
            }
            continue;
        }
        kept.push(c);
    }
    // One space between words, nothing at the ends, capped by characters
    // so the cut never splits one.
    kept.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MESSAGE_CAP)
        .collect()
}

/// The hint for a deprecated pin. For [`MEMORY_PACKAGE`] with no absolute
/// `MEMORY_FILE_PATH` in the backend's env, the copy-first steps that keep
/// the graph; otherwise "edit the pin".
pub(super) fn hint(backend: &str, pin: &Pin, config: &BackendConfig) -> String {
    let target = match current_version(&pin.name) {
        Some(current) => format!("{}@{current}", pin.name),
        None => "the registry's current version".to_string(),
    };
    // server-memory keeps its graph next to the installed package unless
    // MEMORY_FILE_PATH names an absolute path, and a new pin installs into
    // a new directory: the graph must be copied out before the pin moves.
    if pin.name == MEMORY_PACKAGE && !has_absolute_memory_path(config) {
        // The npm cache the backend's child actually uses: the
        // gateway-assigned directory, or the operator's own when they set
        // npm_config_cache in the backend's env.
        let cache = match &config.transport {
            TransportConfig::Stdio { command, .. } => {
                mcp_gateway::transport::isolated_package_manager_env(
                    backend,
                    command,
                    config.env.clone(),
                )
                .remove("npm_config_cache")
            }
            _ => None,
        };
        let place = match cache.as_deref() {
            Some(dir) => format!(
                "in the {MEMORY_PACKAGE} package under {}",
                std::path::Path::new(dir).join("_npx").display()
            ),
            None => format!(
                "in the {MEMORY_PACKAGE} package under the npm cache this backend uses, \
                 in its _npx directory"
            ),
        };
        format!(
            "First copy the existing memory.jsonl ({place}) to an absolute path and set \
             MEMORY_FILE_PATH to it in backends.{backend}.env, then edit \
             the pin in backends.{backend}.command to {target}"
        )
    } else {
        format!("edit the pin in backends.{backend}.command to {target}")
    }
}

/// The rows: one `Pass` skipped row when the lookup is off; otherwise one
/// `Warn` per enabled stdio backend whose pin npm marks deprecated, in backend
/// order, and nothing at all on any failure. Completed rows survive the
/// budget running out.
pub(super) async fn check(config: &Config, cfg: &ClientCfg, lookup: Lookup) -> Vec<CheckResult> {
    let skipped = match lookup {
        Lookup::On => None,
        Lookup::OffByFlag => Some("skipped (--no-registry-check)"),
        Lookup::OffByPosture => Some("skipped (security.posture: hardened)"),
    };
    if let Some(detail) = skipped {
        return vec![CheckResult::pass(SKIPPED_LABEL, detail).with_category("backend_stdio")];
    }

    // Only registry packages are ever asked about: a pin outside the
    // allowlist is not collected, so its name never leaves the machine.
    let allowed = allowlist();
    let mut pins: Vec<(String, Pin, &BackendConfig)> = Vec::new();
    for (name, backend) in config.enabled_backends() {
        let TransportConfig::Stdio { command, .. } = &backend.transport else {
            continue;
        };
        let Some(pin) = npx_pin(command) else {
            continue;
        };
        if allowed.contains(&pin.name) {
            pins.push((name.clone(), pin, backend));
        }
    }
    // Backend-name order, whatever order the config map yields.
    pins.sort_by(|a, b| a.0.cmp(&b.0));
    if pins.is_empty() {
        return Vec::new();
    }
    let Some(http) = client(cfg) else {
        return Vec::new();
    };

    // One request per distinct package, however many backends pin it,
    // started in sorted order with at most CONCURRENCY in flight, and
    // collected as they arrive, so a finished answer is never held behind
    // a stalled earlier one.
    let names: BTreeSet<String> = pins.iter().map(|(_, pin, _)| pin.name.clone()).collect();
    // Documents land in a map outside the timed future, so a finished
    // answer survives the budget running out under slower ones.
    let mut docs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let _ = tokio::time::timeout(BUDGET, async {
        let http = &http;
        let mut stream = futures::stream::iter(names.into_iter().map(|name| async move {
            let doc = fetch_doc(http, cfg, &name).await;
            (name, doc)
        }))
        .buffer_unordered(CONCURRENCY);
        while let Some((name, doc)) = stream.next().await {
            if let Some(doc) = doc {
                docs.insert(name, doc);
            }
        }
    })
    .await;

    let mut rows = Vec::new();
    for (backend, pin, backend_cfg) in &pins {
        let Some(doc) = docs.get(&pin.name) else {
            continue;
        };
        let Some(text) = deprecation(doc, &pin.version) else {
            continue;
        };
        rows.push(
            CheckResult::warn(
                format!("{backend}: npm pin"),
                format!(
                    "{}@{} is deprecated on npm. npm says: \"{}\"",
                    pin.name,
                    pin.version,
                    npm_text(&text)
                ),
            )
            .with_category("backend_stdio")
            .with_hint(hint(backend, pin, backend_cfg)),
        );
    }
    rows
}

#[cfg(test)]
#[path = "npm_pin_tests.rs"]
mod tests;
