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

use std::collections::BTreeSet;
use std::time::Duration;

use mcp_gateway::config::{BackendConfig, Config};
use url::Url;

use super::CheckResult;

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

/// Whether the lookup runs when nothing turns it off. Held as one value until
/// the operator rules on the default (lead, 2026-10-22); `decide` is tested
/// under both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Default {
    On,
    Off,
}

/// The shipped default.
pub(super) const DEFAULT: Default = Default::On;

/// Whether this run looks anything up, and if not, why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lookup {
    On,
    /// `--no-registry-check` or `MCP_GATEWAY_DOCTOR_NO_REGISTRY_CHECK`.
    OffByFlag,
    /// `security.posture: hardened`.
    OffByPosture,
    /// The default is off and nothing turned it on.
    OffByDefault,
}

/// The run's lookup from the default, the off switch and the posture.
pub(super) fn decide(default: Default, switch_off: bool, hardened: bool) -> Lookup {
    let _ = (default, switch_off, hardened);
    unimplemented!("MIK-8512")
}

/// [`decide`] for a loaded config: hardened is `security.posture: hardened`.
pub(super) fn lookup_of(config: &Config, default: Default, switch_off: bool) -> Lookup {
    let _ = (config, default, switch_off);
    unimplemented!("MIK-8512")
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
    let _ = command;
    unimplemented!("MIK-8512")
}

/// Every package name the bundled registry pins through `npx`.
pub(super) fn allowlist() -> BTreeSet<String> {
    unimplemented!("MIK-8512")
}

/// The registry's own current version of `name`, when it pins one.
pub(super) fn current_version(name: &str) -> Option<String> {
    let _ = name;
    unimplemented!("MIK-8512")
}

/// The package document's URL: `/<name>`, a scoped name's `/` encoded as `%2F`.
pub(super) fn package_url(base: &Url, name: &str) -> Url {
    let _ = (base, name);
    unimplemented!("MIK-8512")
}

/// The proxy variables, read once: `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`
/// and `NO_PROXY`, in both cases. Nothing else in the environment is read.
#[derive(Clone, Debug, Default)]
pub(super) struct ProxyEnv {
    pairs: Vec<(String, String)>,
}

impl ProxyEnv {
    /// The process environment's proxy variables.
    pub(super) fn from_process() -> Self {
        unimplemented!("MIK-8512")
    }

    /// A snapshot from explicit pairs (tests; unrelated names are dropped).
    pub(super) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let _ = pairs;
        unimplemented!("MIK-8512")
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
/// targets only.
pub(super) fn route(env: &ProxyEnv) -> Route {
    let _ = env;
    unimplemented!("MIK-8512")
}

/// Everything the one client builder takes, as data. Production and tests
/// build through the same [`client`].
pub(super) struct ClientCfg {
    pub(super) base: Url,
    pub(super) roots: rustls::RootCertStore,
    pub(super) proxy: ProxyEnv,
}

impl ClientCfg {
    /// npm, the bundled `webpki-roots`, the process proxy variables.
    pub(super) fn production() -> Self {
        unimplemented!("MIK-8512")
    }
}

/// The client, or `None` when the route is `Skip` or the builder fails.
/// Never reads proxies itself (`no_proxy()`), never follows a redirect,
/// never retries, never consults the platform verifier.
pub(super) fn client(cfg: &ClientCfg) -> Option<reqwest::Client> {
    let _ = cfg;
    unimplemented!("MIK-8512")
}

/// npm's `deprecated` text for `version` in an abbreviated document, when it
/// is a non-empty string after trimming. Any parse failure is `None`.
pub(super) fn deprecation(doc: &[u8], version: &str) -> Option<String> {
    let _ = (doc, version);
    unimplemented!("MIK-8512")
}

/// npm's text made safe for a terminal: ANSI escapes and Unicode `Cc`/`Cf`
/// characters removed, whitespace runs collapsed to one space, cut to
/// [`MESSAGE_CAP`] characters.
pub(super) fn npm_text(raw: &str) -> String {
    let _ = raw;
    unimplemented!("MIK-8512")
}

/// The hint for a deprecated pin. For [`MEMORY_PACKAGE`] with no absolute
/// `MEMORY_FILE_PATH` in the backend's env, the copy-first steps that keep
/// the graph; otherwise "edit the pin".
pub(super) fn hint(backend: &str, pin: &Pin, config: &BackendConfig) -> String {
    let _ = (backend, pin, config);
    unimplemented!("MIK-8512")
}

/// The rows: one `Pass` skipped row when the lookup is off; otherwise one
/// `Warn` per enabled stdio backend whose pin npm marks deprecated, in backend
/// order, and nothing at all on any failure. Completed rows survive the
/// budget running out.
pub(super) async fn check(config: &Config, cfg: &ClientCfg, lookup: Lookup) -> Vec<CheckResult> {
    let _ = (config, cfg, lookup);
    unimplemented!("MIK-8512")
}

#[cfg(test)]
#[path = "npm_pin_tests.rs"]
mod tests;
