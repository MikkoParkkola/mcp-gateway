# Contributing to MCP Gateway

## Development Setup

### Prerequisites

- **Rust 1.95+** (edition 2024): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js** (only for testing stdio backends that use `npx`)

### Build and Test

```bash
git clone https://github.com/YOUR_USERNAME/mcp-gateway
cd mcp-gateway
cargo build
cargo test --all-features   # full suite, all must pass
cargo run -- init    # Generate a starter config
cargo run -- serve --config gateway.yaml --log-level debug
```

### Full CI Check (Run Before Pushing)

```bash
cargo fmt --all -- --check && \
scripts/dev/check-public-repo-hygiene.sh && \
cargo clippy --all-features -- -D warnings && \
cargo test --all-features && \
python3 benchmarks/token_savings.py --scenario readme --json
```

### Formal Verification (Kani)

`mcp-gateway` also has targeted Kani proofs for small safety-critical helpers:
circuit-breaker transitions, idempotency decisions, kill-switch budget decisions,
and firewall action resolution.

```bash
cargo install --locked kani-verifier
cargo kani setup
cargo kani --output-format=terse
```

### Windows test coverage

The `Windows check` job runs `cargo test --all-features --tests --no-fail-fast`: the
library, the binary and every integration target under `tests/`, with no `--skip`
filters. It also runs the privileged owner-only rows (`win_privileged::`, `--ignored`).
Nothing else is counted as Windows coverage, and no met release criterion cites Windows
execution evidence (`scripts/release/test_windows_job_scope.py`).

Every test that does not run on Windows is in one of three classes, and Windows
failures are fixed in that order of preference:

1. A test assumption: the fixture is fixed so the test runs on Windows.
2. A product defect: fixed in 4.0, with the failing test first on the `Windows check` job.
3. Unix-only by design: the behavior has no Windows equivalent. The test carries a
   `#[cfg(unix)]`, `#[cfg(not(windows))]` or `#[cfg(target_os = ...)]` gate with a comment
   stating the reason, and the limitation is listed below.

Give a child process a home directory with `MCP_GATEWAY_TEST_HOME_DIR` (debug builds
only, `src/home_dir.rs`; the release job fails if the release binary carries the name).
On Windows `dirs::home_dir()` ignores `HOME` and `USERPROFILE`, so `HOME` alone cannot do it.
Give a child process a clock that reads before 1970 with `MCP_GATEWAY_TEST_CLOCK=before-epoch`
(debug builds only, `src/clock.rs`; the release job fails if the release binary carries the
name). In-process tests use `crate::clock::test_clock` instead.
Create a test symlink with `crate::test_symlink::symlink`: the `Windows check` job enables
Developer Mode (`ci.yml`, "Allow symlink creation"), so symlink creation needs no gate.

### Windows limitations

Each entry is a Unix behavior the gateway or its test fixtures rely on that Windows does
not provide. The test gates for it state the same reason in a comment.

- **W-L1 POSIX mode bits, umask and `chmod`.** Windows has no mode bits. Owner-only files
  and directories are enforced through DACLs (ADR-016, `docs/UPGRADING-4.0.md` items 68
  and 99) and tested in `win_acl`, `windows_tests.rs` and the privileged rows. Tests that
  assert `0600`/`0700`, build a group-readable fixture, or inject a failure with
  `chmod 0` (or a read-only directory) stay Unix-only.
- **W-L2 File ownership by uid.** Windows ownership is an ACL owner, not a uid.
- **W-L3 File identity and allocation.** `(dev, ino)` from `MetadataExt` and `st_blocks`
  are not exposed by stable Windows std metadata.
- **W-L4 Process table, pid liveness and zombie reaping.** Windows has no zombie state,
  `kill(0)` or `ps` state column. Tests that prove a child was reaped by reading the
  process table stay Unix-only.
- **W-L5 POSIX shell fixtures.** Fake MCP servers and launchers written as `sh` scripts,
  `rlimit`, and `umask` inside `sh -c`. Windows provides none of them.
- **W-L6 Signals and inherited descriptors.** Windows has no `SIGTERM` or `SIGKILL`
  death-by-signal, and no `fd` duplication across `fork`.
- **W-L7 Non-UTF-8 environment values.** Windows environment strings are UTF-16, so a
  raw-bytes value cannot be built; a test that moves `HOME` and restores it is also
  Unix-only, because Windows resolves the home from the Known Folder API.
- **W-L8 FIFOs.** `mkfifo` named pipes have no Windows counterpart; the refusal of a FIFO
  where a file is expected is asserted on Unix.
- **W-L9 Platform-specific facilities.** Linux `inotify` watcher rows, the `SSL_CERT_FILE`
  trust path on Unix outside Apple platforms, the per-platform runtime substrate and
  resident-set measurement, and the macOS keychain. Windows takes the fallback path.
- **W-L10 Trailing dots in path components.** Windows strips a trailing dot from a path
  component, so a directory named `task-..` cannot be created (one case of the malformed-id
  store test is Unix-only).

Fix a Windows failure in the test or the product before reaching for a gate. Add a gate only
for a genuine Unix-only behavior, with a comment naming which limitation above it is.
User-facing limits: see `docs/UPGRADING-4.0.md` (items 68 and 99) and the README.

## Code Organization

Source in `src/`, each module kept to **800 lines or fewer**. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full diagram.

```
src/
  main.rs              Entry point, CLI dispatch
  lib.rs               Library root, module declarations
  error.rs             Unified error types (thiserror)
  cli/                 CLI parsing (clap derive): Cli, Command, CapCommand, ToolCommand
  config/              Configuration (figment: YAML + env vars)
    mod.rs               Config, ServerConfig, BackendConfig, TransportConfig
    features.rs          Auth, cache, security, key server, streaming configs
  gateway/             Core server
    server.rs            Gateway struct, startup, shutdown
    router/              Axum router and request handlers
    auth.rs              Bearer token / API key auth
    proxy.rs             Backend proxy manager
    streaming.rs         SSE notification multiplexer
    meta_mcp/            Meta-MCP tool implementations (search, invoke, list)
    oauth/               OAuth 2.0 (agent auth, OIDC JWT) — see [docs/OAUTH_CONFIG.md](docs/OAUTH_CONFIG.md)
    ui/                  Embedded web dashboard (feature: webui)
    webhooks/            Webhook receiver
  backend/             Backend lifecycle (spawn, connect, health, tool cache)
  transport/           Wire protocols
    mod.rs               Transport trait
    stdio.rs             Subprocess I/O (stdin/stdout JSON-RPC)
    http/                HTTP client (Streamable HTTP + SSE)
    websocket.rs         WebSocket client (no backend config selects it)
  protocol/            MCP JSON-RPC types, version negotiation
  capability/          REST-to-MCP bridge (YAML defs, executor, hot-reload)
  failsafe/            Circuit breaker, retry, rate limiter, health checks
  security/            Tool policy engine, input sanitization
  cache.rs             Response cache with TTL
  secrets.rs           Keychain/env credential resolution
  validator/           Capability YAML linter (agent-UX rules)
  mtls/                Mutual TLS authentication
  key_server/          OIDC identity to scoped API key exchange
```

## Adding a New Capability (YAML)

The easiest way to contribute. No Rust needed.

**1. Create** a YAML file in the appropriate `capabilities/` subdirectory:

```yaml
fulcrum: "1.0"
name: my_api_tool
description: One sentence -- what it does, what API it uses.
schema:
  input:
    type: object
    properties:
      query:
        type: string
        description: Search query
    required: [query]
providers:
  primary:
    service: rest
    cost_per_call: 0
    timeout: 10
    config:
      base_url: https://api.example.com
      path: /v1/search
      method: GET
      params:
        q: "{query}"
cache:
  strategy: exact
  ttl: 300
auth:
  required: false
  type: none
metadata:
  category: knowledge
  tags: [search, free]
  cost_category: free
  read_only: true
  rate_limit: 1000 req/day
  docs: https://api.example.com/docs
```

**2. Validate and test:**

```bash
cargo run -- cap validate capabilities/knowledge/my_api_tool.yaml
cargo run -- cap test capabilities/knowledge/my_api_tool.yaml --args '{"query": "test"}'
cargo run -- validate capabilities/knowledge/my_api_tool.yaml
```

**Guidelines:**
- Zero-config (no API key) capabilities are preferred.
- Use `env:VAR_NAME` or `keychain:name` for credentials. Never hardcode secrets.
- Write a clear, specific `description` -- the AI reads it to decide tool selection.
- Set `read_only: true` for GET-only endpoints.
- Document rate limits in `metadata.rate_limit`.
- Place files in the correct category subdirectory.

## Adding a New Transport

**1. Implement the `Transport` trait** in `src/transport/`:

```rust
#[async_trait]
impl Transport for MyTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()>;
    fn is_connected(&self) -> bool;
    async fn close(&self) -> Result<()>;
}
```

**2. Add config variant** to `TransportConfig` in `src/config/mod.rs`, update `transport_type()`.

**3. Wire into** `src/backend/mod.rs` for config-based selection.

**4. Add tests** -- unit tests in the transport module, integration tests in `tests/`.

## Code Style

- **Formatting:** `cargo fmt` before every commit. CI rejects unformatted code.
- **Linting:** `cargo clippy --all-features -- -D warnings`. Pedantic warnings are promoted to errors in CI.
- **Feature sets:** test targets are supported with the default feature set only; builds without default features are covered for the library and binary alone (the *Feature combination* job in `.github/workflows/ci.yml`).
- **Safety:** `unsafe` code is denied at the crate level. No exceptions.
- **Errors:** `thiserror` for typed errors, `anyhow` for application-level.
- **Logging:** `tracing` macros (`info!`, `debug!`, `warn!`), never `println!`.
- **Concurrency:** `Arc` for shared state, `dashmap`/`parking_lot` for concurrent maps.
- **Config structs:** derive `Serialize`, `Deserialize`, use `#[serde(default)]`.

Allowed clippy exceptions (in `Cargo.toml`): `module_name_repetitions`, `must_use_candidate`, `missing_errors_doc`.

## Pull Request Process

1. **Branch** from `main`: `git checkout -b feature/your-feature`
2. **Verify:** `cargo fmt --all -- --check && cargo clippy --all-features -- -D warnings && cargo test --all-features && python3 benchmarks/token_savings.py --scenario readme --json`
3. **Document:** Update README.md for user-facing features. Add a changelog fragment (below).
4. **Open PR** with a clear description of what changed and why.
5. **CI must pass.** Formatting, clippy pedantic, and the full test suite.

Smaller PRs are reviewed faster. For large changes, open an issue first.

**What runs where.** Every pull request runs the CI workflow. The container image build and
CodeQL code scanning run once per merge, on the push to the release branch (and on `main` and
tags), not on each pull-request push; a pull request into the release branch still builds the
image when it changes `Dockerfile`, `.dockerignore`, `Cargo.toml`, `Cargo.lock`,
`deploy/helm/`, the smoke scripts or `docker.yml`. Pull requests into `main` run everything,
except that a docs-only one skips the image build.
A **docs-only** pull request (every changed file under `docs/`, or a Markdown or text file at
the repository root, with no root file deleted; `scripts/ci/changed-scope.sh`) skips clippy, feature combinations, Kani,
formatting, audit, Helm/kind, the upgrade rehearsal and the smoke jobs. Every job that runs tests
still runs (tests read the docs), as do hygiene, the secret scans, public claims, the release
ledger and the file-size check. If that decision fails, everything runs.
Maintainer `throwaway/` branches (red-first and mutation-proof runs, never merged) run only the
test suite (`Tests (throwaway)`), on a hosted runner until the project's own arm64 runner is
registered, then on that runner; see `scripts/ci/trusted-runner/`.
Mutation proofs are batched: push `throwaway/mutants-<pr>` as the pull request's head plus one
commit adding `.mutants/manifest.tsv` and the patches; one run of the Mutants workflow classifies
every mutant (format and rules in `scripts/ci/mutants/run_mutants.py`).
The batch must carry the harness (`run_mutants.py`, `mutants.yml`) byte-identical to the release
branch, or the run aborts: after a harness change merges, re-copy both files into every open
`throwaway/mutants-*` branch before pushing it again.

## Architecture Decisions

Changes affecting public API, config schema, new dependencies, transport protocols, or security features should be discussed in a GitHub issue before implementation. Design docs live in `docs/design/`.

## Public Repo Hygiene

Public docs should explain install, operation, architecture, security, compliance, and user-facing comparisons. Internal strategy, competitive intelligence, product positioning, roadmap reasoning, launch OPSEC, patent strategy, and build-vs-integrate licensing analysis must stay outside tracked public paths.

Use ignored local paths for private strategy work: `docs/strategy/`, `docs/competitive/`, `docs/competitive-intelligence/`, or `docs/positioning/`. Before pushing, run `scripts/dev/check-public-repo-hygiene.sh`; CI runs the same check and fails if tracked public docs contain high-confidence internal strategy markers.

## Commit Messages

Every message in this repository is world-readable. Write each one as if a stranger were reading it, because one will.

- Subject: `type(scope): summary` in the imperative, 72 characters or fewer, no trailing period.
- Body: bullets only, one idea each, at most six. The message is an index of what changed.
- State facts about the code. Evidence, measurements and reasoning belong in the pull request body, the issue, or a code comment.
- No first person, no apology, no account of how the change was found, no naming the tool or model that wrote it. Attribution goes in a trailer.

`scripts/dev/check-commit-message-hygiene.sh` enforces this over the commits your branch adds; the pre-push hook and CI both run it. Rewrite a flagged message with `git commit --amend` or `git rebase -i` rather than bypassing the hook.

## Good First Issues

Look for [`good first issue`](https://github.com/MikkoParkkola/mcp-gateway/labels/good%20first%20issue) or [`help wanted`](https://github.com/MikkoParkkola/mcp-gateway/labels/help%20wanted). Good starters: adding a zero-config capability, improving error messages, adding edge-case tests, documentation.

## Contributor License Agreement

Contributing to this repository is acceptance of the
**[Contributor License Agreement](CLA.md)** — it binds on submission, so
there is nothing to sign and nothing is requested before a merge. It lets the maintainer offer
commercial licenses for the Noncommercial-licensed code (which a bare
inbound=outbound or DCO cannot do): you keep your copyright, and you grant a
broad, sublicensable, **relicensable** copyright and patent license, plus
represent that you have the right to contribute the work. To record the
acceptance explicitly, `CLA.md` gives a one-line statement you can add to your
first PR; it is optional.

## License

Contributions are licensed under **PolyForm Noncommercial 1.0.0**, the single
license for the whole repository as of v4.0.0 (see `LICENSES.md`):

- **Every source file carries an affirmative header** — a copyright line plus an
  explicit `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`. New files
  are **not** exempt: run `bash scripts/ci/apply-license-headers.sh --apply` (or
  add the two-line header by hand) so the file declares its license. The CI guard
  (`scripts/ci/check-license-headers.sh`) fails on any file missing the copyright
  line or carrying a different identifier.
- There is no second license and no allowlist. A first-party file carrying any
  other identifier is an error, not a carve-out.
- Third-party or generated material is out of scope and belongs in
  `.license-scope-exclude`, which is where its own terms are recorded.

Existing MIT releases and the MIT-headered files in the 3.x line are not
retroactively relicensed; see `NOTICE.md`.

## Contributor Checklist

We want your PR to merge fast. Here is what helps.

### Required (these block merge)

- [ ] **Tests for new behavior**, not just regression. If your change adds a config field, add a test that exercises it. If it adds a branch, add a test that hits it.
- [ ] **CI green on Linux**. We ignore known-flaky checks labelled `flaky-ci`, but Linux must pass.
- [ ] **`cargo fmt --all && cargo clippy --all-features -- -D warnings`** clean on your branch.
- [ ] **A test that reads a repository file** (`include_str!`, or a path under `CARGO_MANIFEST_DIR`) has that exact path in `Cargo.toml` `include`. The published crate carries only that list; the `package-tests` job builds the tests from it and fails otherwise.
- [ ] **Threat-model note for security-sensitive code** (auth, OAuth, URL handling, path handling, secrets, deserialization of untrusted input): a short note in the PR description covering what inputs come from untrusted sources, what validation you run, what you chose not to validate and why.

### Strongly encouraged

- [ ] **Changelog fragment** if the change is user-visible: add `changelog.d/<number>.<type>.md`,
  where `<number>` is the PR (or issue) number and `<type>` is one of `added`, `changed`,
  `removed`, `fixed`, `security`. It holds your bullet(s) exactly as they should read in
  CHANGELOG.md, for example `- doctor: report why a stdio backend died (#526)`. Do not edit
  CHANGELOG.md itself: a shared section makes every open PR conflict whenever one merges.
  A PR that changes a shipped file without a fragment, or edits CHANGELOG.md
  by hand, fails the *Changelog fragment* check; a maintainer can apply the `no-changelog`
  label when no entry is warranted. Shipped files are `src/`, `crates/*/src/`, `Dockerfile*`,
  `.github/workflows/docker*.yml` (or `.yaml`), `capabilities/`, `server.json` and `npm/`.
  Each bullet of a `security` fragment also needs a two-space-indented line naming who is
  affected and what an operator must do, for example
  `  Affects: 3.0.0 up to 3.5.1. Operator action: none.`; the same check runs
  `scripts/release/check_security_fragments.py` over `changelog.d/` and fails without it.
- [ ] **UPGRADING entry** if the change breaks or changes something an operator upgrading
  from 3.5.x must act on: add `upgrading.d/<number>.md` (several: `<number>-1.md`, ...).
  Do not number it or edit the numbered list in `docs/UPGRADING-4.0.md`: two open PRs
  would take the same number. Release preparation numbers the fragments in file-name order.
  A fragment is a front-matter block, then the section:

  ```markdown
  ---
  change: <the summary row's Change cell, one line, no `|`>
  action: <the summary row's Action needed cell, one line, no `|`>
  notice: <only if the marker says `prints a notice`: a phrase the notice item contains>
  ---
  ## <Title, no number>

  **Startup:** <marker, same grammar as the numbered items>

  <body>
  ```

  To point an older item at a pending one, write `> Superseded in part by <Title>:`.
  `python3 scripts/release/upgrading_fragments.py check` validates the fragments.
- [ ] **PR description** answers: what problem this solves, the shape of the fix, anything you are unsure about.
- [ ] **Prefer a config struct** over 5+ function arguments. Keeps future extensions clean.
- [ ] **Doc comments on user-facing config fields**. They surface in `cargo doc` and in downstream IDE tooltips.

### What we handle, so do not block on these

- Release versioning, crates.io publishing, compiled CHANGELOG at release time. Maintainer tasks.
- Lint drift on `main` that pre-dates your branch. Our responsibility. If clippy was green on your branch base, we fix main and rebase your PR.
- Security review beyond the threat-model note. We do the deep dive.
- Windows CI flakes and other known-environmental failures. We label the PR `flaky-ci` and treat Linux as the source of truth.

### If you get stuck

- Open a draft PR early. We would rather help you finish than review a polished PR that missed the target.
- Leave a comment and tag `@MikkoParkkola`. No minimum response-time promise, usually within 24h on weekdays.
- First PR? Say so in the description. We will be patient.

The external SDK recovery test is gated by its own required CI job. See
[the SDK runner instructions](docs/tests/task-sdk-recovery.md) for the two-step
all-feature suite and Linux/Redis prerequisites; ordinary `cargo test` needs
no external SDK services.
