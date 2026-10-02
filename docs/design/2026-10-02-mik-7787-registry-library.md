# MIK-7787: the built-in catalogue as a library

Status: decisions recorded (lead, 2026-10-02: D4 servers and capabilities ACCEPTED; D5 operator-confirmed); for seat review. Ticket: MIK-7787 (ACs MIK-REG.FIX.1, ADD.1, AUTH.1, SAFE.1, DOC.1).

## Problem

- `mcp-gateway add <name>` writes what `src/registry/server_registry.rs` says. On 2026-10-02, of its 45
  npm packages 30 were 404 and 7 deprecated; none of the 45 was pinned to a version
  (`scripts/dev/check-registry-packages.py`: 1 of 46 entries passes, the hosted context7).
- `add` of a stdio entry writes no `env:`. The child environment is cleared and rebuilt from PATH, HOME,
  TMPDIR and the backend's own `env:` (`src/transport/stdio.rs`, `configure_child_environment`), so
  `add tavily` yields a backend without its key while `add` prints `TAVILY_API_KEY set`.
- A registry entry can say "stdio command" or "HTTP URL", nothing else. Vendor-hosted servers need an
  OAuth login (Notion, Atlassian, Sentry, Supabase, GitLab, Linear, Asana, Cloudflare) or a bearer
  header (GitHub, HubSpot, Stripe). The gateway already does both for a hand-written backend:
  `headers:` with `${VAR}` expansion (`src/config/mod.rs`, `expand_env_vars`) and the backend OAuth
  client, created only when the backend has an enabled `oauth:` stanza (`src/backend/lifecycle.rs`,
  `create_oauth_client`), which follows protected-resource metadata and tries dynamic client
  registration when no `client_id` is set (`src/oauth/client/mod.rs:325-333`).
- Operator direction (2026-10-02): the catalogue (servers and capability YAMLs) is an extensive
  library. Entries that need a login are available but off until the user turns them on; entries that
  work without a login are on by default. No-login servers that can reach arbitrary addresses
  (Playwright, Chrome DevTools, fetch) go to the operator; until then they are off, with the reason,
  behind a one-line switch.

## What exists today (reused, not rebuilt)

| Need | Existing mechanism |
|---|---|
| Server library | `server_registry::all()/search()/lookup()`; web UI `GET /ui/api/registry`, `/ui/api/registry/search` |
| Turn a server on | `mcp-gateway add <name>` (CLI) and `POST /ui/api/backends` (UI); both go through `backend_ops::resolve_transport` + `add_backend` |
| Turn a server off/on again | `enabled:` on the backend; UI `PATCH` via `BackendUpdate.enabled`; `mcp-gateway remove` |
| See configured servers | `mcp-gateway list`, `get` |
| Login for a hosted server | `oauth:` stanza -> existing OAuth client, DCR, token store under `~/.mcp-gateway/oauth/` |
| Stdio secret | `env:` with `${VAR}`; same expansion and C4 rule as `headers:` |
| Bearer header | `headers:` with `${VAR}`; an unset `${VAR}` on an enabled backend refuses the config load (C4), a disabled backend keeps it verbatim |
| Capability needs a login | `auth.required: true` + `auth.key` in the YAML (`src/capability/definition/mod.rs` `AuthConfig`) |

Missing: (1) a registry entry cannot carry `oauth`/`headers`; (2) `add` ignores everything but the
transport; (3) no CLI way to browse the library; (4) nothing decides on/off per entry; (5) capabilities
load whether or not their credential exists.

## Design

### D1 Registry entry fields (enums, no booleans)

```rust
pub enum Auth {
    None,                                   // works with no login
    EnvVars,                                // stdio server reads required_env
    OAuth,                                  // hosted, existing OAuth flow (DCR)
    Header { name: &'static str, value: &'static str }, // e.g. ("Authorization", "Bearer ${GITHUB_TOKEN}")
}
pub enum Reach {
    Bounded,                                // talks to its own vendor or local resource
    Arbitrary { reason: &'static str },     // can be pointed at any address (browser, fetch)
}
pub enum Setup {
    Ready,                                  // starts with no arguments and no other service
    NeedsArgs { hint: &'static str },       // e.g. filesystem: allowed directories; git: --repository
    NeedsService { hint: &'static str },    // e.g. redis, postgres: a running server to point at
}
pub struct RegistryEntry { /* existing fields */, auth: Auth, reach: Reach, setup: Setup }
impl RegistryEntry {
    pub fn needs_login(&self) -> bool { !matches!(self.auth, Auth::None) }
    /// The one product switch for arbitrary-reach servers; `add` and `init` both read it.
    pub fn reach_allows_on(&self) -> bool { matches!(self.reach, Reach::Bounded) }
    /// The starter set `init` writes enabled.
    pub fn default_enabled(&self) -> bool {
        !self.needs_login() && self.reach_allows_on() && matches!(self.setup, Setup::Ready)
    }
}
```

A test pins the starter set exactly. With the repointed catalogue (D6) it is {memory,
sequential-thinking, context7}; the additions PR (top-15: `time`, `git`, `chrome-devtools`, ...)
adds `time` and updates the pinned sets in the same change. semgrep is not in it: the gateway
warm-starts every configured backend at boot to prefetch tools (`src/gateway/server/warmstart.rs`), so
its ~100 MB engine would download at start, not on first use (lead, 2026-10-02).

A unit test fails when `Auth::EnvVars` has an empty `required_env`, when `Auth::None` has a non-empty
one, or when a `Header` value names a `${VAR}` that is not in `required_env`.

### D2 `add` writes the whole backend (one path for CLI and UI)

`resolve_transport` returns a `BackendConfig` seed instead of `(TransportConfig, String)`, so CLI and UI
keep sharing it. For a registry entry it fills:

- `Auth::OAuth` -> `oauth: Some(OAuthConfig { enabled: true, ..defaults })` (add `impl Default for
  OAuthConfig` matching the serde defaults). The first connection runs the existing flow. No second
  OAuth path.
- `Auth::Header` -> `headers: { name: value }`, the `${VAR}` template written verbatim; expansion stays
  in `expand_env_vars`. If the user passed `-e VAR=value` for a variable the header names, the value is
  substituted into the header instead (an `env:` entry cannot feed a header: `expand_env_vars` reads the
  overlay, not `backend.env`), and VAR is not also written to `env:` for an HTTP backend.
- Every `required_env` name of a stdio entry -> `env: { NAME: "${NAME}" }`, unless `-e NAME=...`
  supplied a value. This fixes the scrubbed-environment bug above with the existing expansion.
- HTTP entries: `Transport::Http { default_url, flavor: HttpFlavor }` with `enum HttpFlavor { Streamable, Sse }`
  is stored on the entry (Asana is `Sse`, every other hosted entry `Streamable`), not inferred from the
  URL. `Sse` means the legacy SSE handshake (`src/transport/http/mod.rs`).
- `enabled`: `true`, except (a) `Reach::Arbitrary` -> `false`, printed with its reason and the switch
  (`enabled: true` in gateway.yaml, or the UI toggle); (b) any `${VAR}` left in the written
  `headers`/`env` that the loader would refuse -> `false`, printed with the variable name. Readiness
  is decided by the loader's own rule, not by `std::env`: the `EnvOverlay` built for the target config
  (env_files included) and the non-empty test in `secret_ref::expand_field`, so an empty value counts as
  unset. Rule (b) exists because an enabled backend with an unresolved `${VAR}` makes the next load fail
  (C4). As the final guard, the persistence path (`config_persistence::write_config`, which already
  validates and writes through an exclusive scratch file and a rename) refuses when the backend being
  added or enabled carries an unresolved reference, using the loader's own `expand_field` rule; the
  check is scoped to that backend, so a reference only the running gateway can resolve in another
  backend does not block an unrelated `add`: `add` never writes a
  config the gateway refuses.

Explicit `--command`/`--url` keep today's behaviour (enabled, no auth fields). `add_backend` takes the
seed `BackendConfig` and inserts it as is, instead of rebuilding it from transport and env and forcing
`enabled: true`.

Turning a backend on later (UI `PATCH` with `enabled: true`, `update_backend`) runs the same
temporary-load guard and refuses, naming the variable, while a `${VAR}` in that backend is unresolved,
instead of writing a config the next reload rejects.

### D3 Browsing the library

- CLI: `mcp-gateway list --available [--json]` prints the registry: name, category, transport, login
  (`none` / `env: X, Y` / `oauth` / `header: X`), and `default on` / `off: <reason>`. A flag on the
  existing `list`, not a new verb.
- UI: `RegistryEntryJson` gains `auth`, `needs_login`, `default_enabled`, `reach_reason`, `setup` and its hint; the registry
  tab shows them. No new endpoint.

### D4 "No-login entries on by default" (ACCEPTED by the lead, 2026-10-02)

"Stay enabled" describes capabilities (keyless ones are served today). No server was enabled by default
before; the lead accepted the server reading below.

- Servers: `mcp-gateway init --profile local` (the default profile) writes every `default_enabled()`
  registry entry into the starter config, enabled, generated by iterating `all()` rather than a
  hand-kept YAML snippet. `--profile minimal` stays a skeleton. Today that is memory, sequential-thinking, context7 (verified keyless 2026-10-02: `initialize` and
  `tools/list` answer without a key) and time (git and filesystem need a path
  argument, so they are not zero-configuration and stay `add`-only). Login-needing entries are not
  copied into the config: the registry is the library, `add` turns one on. Existing configs are not
  touched (no upgrade migration adds backends to a user's file).
- Capabilities (shared with MIK-7782 / CAP-EXEC): a capability is served only when its requirements are
  met. For `auth.required: true` the requirement is that an environment-backed `auth.key` resolves
  to a non-empty value. "Environment-backed" uses the executor's own spellings
  (`src/capability/executor/credentials.rs`, `fetch_credential`): `env:NAME`, `{env.NAME}` and a bare
  `NAME` that `looks_like_env_var_name` (e.g. `WOLFRAM_APPID`, `capabilities/knowledge/wolfram_llm.yaml`).
  That key-to-variable mapping is extracted into one function both the executor and the gate call, and
  the lookup uses the same live `EnvOverlay` the executor resolves with. The gate is evaluated when
  tools are listed, searched or invoked, not cached at file load, so adding or removing a credential in
  the process env or an env_file takes effect on the same schedule the executor already sees it.
  `keychain:`, `file:` and `oauth:` keys are not decided by the gate (R2); CAP-EXEC adds the
  "binary present" requirement for `cli` capabilities through the same predicate. An unmet capability is
  listed by `mcp-gateway cap list` as `off: needs <X>` and is not exposed to clients. The user turns it
  on by providing the credential. Keyless capabilities stay on. An upgrade sees no change for any
  capability whose credential is set today.

  Alternative (not chosen): an explicit `capabilities.enable: [names]` list. It matches "choose" more
  literally but switches off every credentialed capability an existing user has working, which needs
  an upgrade migration to undo; and a capability without its key cannot run anyway.

### D5 Arbitrary-reach servers (operator-confirmed default off, chat 2026-10-02)

Classified by rule, not by name: a no-login server whose tools take a URL or drive a browser is
`Reach::Arbitrary`. Playwright and fetch today, Chrome DevTools with the additions PR (puppeteer is removed by D6).
A registry test lists the Arbitrary set exactly, so a new browser/fetch entry must be classified on
purpose.

Playwright, Chrome DevTools and fetch are `Reach::Arbitrary`. The private-network egress guard
(`validate_url_not_ssrf`) runs only on REST capability calls; a stdio backend does its own egress, so
the gateway cannot stop it reaching localhost, the LAN or cloud metadata. Default: off, with that
reason printed by `add` and shown by `list --available`. The switches are one line each:
- per user: `enabled: true` under the backend in gateway.yaml (or the UI toggle);
- for the product, if the operator rules them on: the body of `RegistryEntry::reach_allows_on` becomes
  `true`. `add` (rule (a)) and `init` both read it; `reach` stays recorded on each entry.

User-facing reason (docs and `add` output): "This server can open any address it is given. A prompt
injection in a page or a tool result can steer it to your local network or a cloud metadata address. The
gateway's private-network guard covers REST capabilities only, not this server. Turn it on with
`enabled: true` if you accept that."

### D7 Where the live check runs (lead, 2026-10-02)

- Live npm/PyPI/HTTP lookups (`.github/workflows/registry-packages.yml`): pull requests that touch
  `src/registry/**` or the check scripts, pushes to the release line and `main`, and a daily schedule
  (GitHub fires schedules from the default branch's copy). No workflow holds Linear credentials, so a
  scheduled failure fails that run loudly instead of filing an issue.
- For `Auth::OAuth` entries the live check also requires that the endpoint advertises dynamic client
  registration (protected-resource metadata -> authorization-server metadata with a
  `registration_endpoint`), because the registry writes no `client_id`. `Auth::Header` entries must
  answer an unauthenticated request with 401 or 403.
- Every PR (`ci.yml`): the offline self-test plus `check-registry-packages.py --offline`, which parses the
  registry and enforces the pin and launcher rules without network.

### D6 Removals and repoints

Every dead entry is repointed to the vendor's current package at a pinned version or hosted URL, or
removed when no maintained server exists. Each removal is listed in UPGRADING-4.0 with the reason. The
CI job `registry-packages` keeps the list honest; README and docs counts are generated from
`server_registry::all().len()` and checked by a test.

## Risks

- R1 `init` now launches third-party packages (pinned) on first use. Mitigation: only no-login,
  bounded entries; pinned versions; listed in the generated file so the user sees them.
- R2 Capability gating hides a capability whose key comes from a source resolved only at call time
  (keychain prompt, file). Falsifier: a test with `auth.key: keychain:` must stay listed when the
  resolver cannot decide at load without prompting; only a definitely-absent `env:` key hides it.
- R3 Multi-user gateways: a registry OAuth backend stores one gateway-held token; ADR-008 INV-2 already
  refuses serving it to several users unless `shared_account: true`. `add` prints that.
- R4 Hosted endpoints change; the CI probe catches a 404/410 but not a semantic change.

## Tests (red first)

1. Registry invariants (D1) over `all()`.
2. `resolve_transport("notion")` -> HTTP, `oauth.enabled`, streamable; `("github")` -> header template.
3. `add playwright` -> written `enabled: false`, output names the reason.
4. `add github` with `GITHUB_TOKEN` unset -> written `enabled: false` and the config still loads.
5. `init` output contains exactly {memory, sequential-thinking, context7, time}, enabled.
6. Capability with `auth.required: true` and an unset key is not exposed, for each spelling (`env:X`,
   `{env.X}`, bare `X`); set non-empty -> exposed; set empty -> not exposed; `keychain:` -> exposed.
7. `add github -e GITHUB_TOKEN=t` writes the token into the header and the config loads; `add github`
   with the token only in an env_file -> enabled; empty -> disabled; the temporary-load guard refuses a
   seeded unloadable config and leaves the target file byte-identical.
8. README/docs count equals `all().len()`.
