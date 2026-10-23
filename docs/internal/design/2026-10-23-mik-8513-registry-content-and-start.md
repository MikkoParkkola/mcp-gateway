# MIK-8513: the registry check verifies content and that entries start

Status: draft for review (r1). Scope: `scripts/dev/check-registry-packages.py`,
its self-test, its testdata, `.github/workflows/registry-packages.yml`. No
product code, no user-visible change.

## Problem

The live check proves an exact pin exists and is not deprecated or yanked. Two
gaps remain:

1. **Content.** A re-published or tampered artifact under the same version
   passes.
2. **Start.** A pin can resolve and still fail to start, for example when a
   transitive range no longer resolves or bootstrap fails.

## CONTENT.1: expected digests, compared live

**Where the digests live.** A sidecar file sits next to the source the checker
reads: `src/registry/server_registry_entries.integrity.json`. The checker finds
it by convention: the source path with `.rs` replaced by `.integrity.json`. So
the testdata files carry their own sidecars, with no new flag. It is a sidecar
rather than a `RegistryEntry` field because a field would be product code, a
change to a public struct that ships to users; the ticket's impact line rules
that out.

**Keyed by package and version, not by entry name.** A version bump without a
new digest then fails offline:

```json
{
  "npm": {"@modelcontextprotocol/server-memory@1.0.0": "sha512-UDMt…ODw=="},
  "pypi": {"mcp-server-time==2026.8.18": {
    "mcp_server_time-2026.8.18-py3-none-any.whl": "1407583a…",
    "mcp_server_time-2026.8.18.tar.gz": "ec1313fe…"}}
}
```

**Offline rule** (every PR, no network; CONTENT.3):

- every npx or uvx entry's exact pin has a record;
- no record is orphaned, meaning its pin is used by no entry;
- formats hold: `sha512-` plus 88 base64 characters; 64 lowercase hex for sha256;
- the sidecar parses.

These are file reads only.

**Live rule.** It reuses the request the check already makes:

- **npm:** the version document's `dist.integrity` must equal the record.
- **PyPI:** the release's `{filename: digests.sha256}` over `urls` must equal
  the recorded map exactly. A file added later under the same version is a
  FAIL, because it is new content that `uvx` may pick.

The checker never downloads or hashes a tarball, as the fail-fast rule requires.

**Why metadata is enough.**

- npm verifies the tarball against `dist.integrity` at install.
- uv verifies each file against the index's sha256.

So the published digest is a binding statement about the bytes that install.
The check pins that statement to the reviewed value.

**Known ceiling.** Only the top-level artifact is pinned. Transitive
dependencies resolve by range at install time. The start check (CONTENT.2)
catches a transitive break that stops startup, but not silent transitive
content drift. A lockfile per entry would close that gap; it is out of scope.

**Falsifier for CONTENT.1.** New testdata `scripts/dev/testdata/registry-integrity.rs`
holds two live, healthy entries, `memory@1.0.0` and `mcp-server-time@2026.8.18`.
Its sidecar records one correct digest and one deliberately wrong one. The live
workflow step expects:

- exit 1;
- `1/2 registry entries resolve`;
- exactly one `FAIL` line, naming the wrong entry and `integrity`.

The offline self-test covers missing, orphaned and malformed records, and npm
and PyPI mismatches, with the network stubbed as today.

**Seeding the digests.** They are fetched from npm and PyPI once. They are
cross-checked against the MIK-8510 design note for the three npm packages it
recorded: memory's `UDMt…` matches. The PR lists every value with its source URL.

## CONTENT.2: each eligible stdio entry answers `initialize`

**Which entries.** An entry is eligible when it is stdio, `Setup::Ready`, has an
empty `required_env` and has `Auth::None`. On today's line that is `memory`,
`sequential-thinking`, `fetch`, `time` and `playwright`. Every other stdio
entry is printed as `SKIP <name>: <reason>`:

- `needs arguments: <hint>` (filesystem, git);
- `needs a service` (redis, aws, semgrep, chrome-devtools, postgres, mysql,
  mongodb);
- `needs credentials: <ENV>` (the EnvVars entries).

A skip is not a pass. The summary line counts the two separately.

**Parser.** The existing `parse_entries` gains three fields, `setup`,
`required_env` and `hint`, as new `FIELD_RE` entries. There is no second parser.

### Isolation (reviewed before code, per the AC)

**Threat.** Running a third-party package executes its code, including npm
install scripts, on the CI runner. The job has no repository secrets, its token
is `contents: read`, and checkout persists no credentials. That still leaves one
exposure: every step's environment holds `ACTIONS_RUNTIME_TOKEN` and the
cache/results URLs. A hostile package could use them to poison the Actions cache
other workflows restore. The runner is an ephemeral VM, so the host itself is
disposable; the cache is not.

**Control.** Every install and start runs in a Docker container that receives
**no environment from the runner**. Only explicit `-e` values are passed, and
none of them is a token. Each container runs with:

- `--rm --read-only --tmpfs /tmp --tmpfs /work` (an exec-allowed tmpfs for the
  install);
- `--cap-drop ALL --security-opt no-new-privileges --user 1000:1000`;
- `--memory 1g --pids-limit 256 --cpus 1`.

**Images** are pinned by digest from `mirror.gcr.io`, as ci.yml does for
Docker Hub content:

- `node:24-slim` for npm entries;
- `astral-sh/uv` with Python 3.12 for PyPI entries.

**Two phases per entry, in one container**, so that a server that needs the
network at start is visible as a FAIL rather than hidden by an open network:

1. **Install, network on, 180 s cap.**
   - npm: `npm install --no-save --prefix /work <pkg>@<ver>`. Install scripts
     run, because users get them via `npx -y` and skipping them would fail
     packages that need them. The container is the boundary.
   - uvx: `uv tool install <pkg>==<ver>` into /work.
   - The installed top-level artifact's integrity, read from
     `node_modules/.package-lock.json` or uv's install record, must equal the
     sidecar. This ties CONTENT.1 to the bytes that actually ran.
2. **Start, network off, 60 s cap.** The network is dropped with `docker network
   disconnect` before the start command runs. The installed bin is started with
   the entry's own arguments. The driver writes one `initialize` line to stdin
   and needs a JSON-RPC `result` with `protocolVersion` and `serverInfo`
   inside the cap. Then it closes stdin, waits 5 s, and kills the container.

**Verdicts:**

| case | verdict |
|---|---|
| timeout | `FAIL <name>: did not answer initialize within 60 s` |
| exit before a reply | `FAIL <name>: exited <code> before answering initialize` plus the stderr tail |
| install failure | `FAIL <name>: install failed` |
| an error reply | FAIL |

**Not in scope:** `pull_request_target` is never used; fork PRs get the same
token-less job. No `docker` socket or host path is mounted. The driver itself
runs as the step on the host, but it only parses stdout from the container.

**Where it runs.** A new job, `starts`, in `registry-packages.yml`, beside
`resolve`, with `timeout-minutes: 20`. It is not in ci.yml (CONTENT.3).

**Falsifier for CONTENT.2.** New testdata `scripts/dev/testdata/registry-wont-start.rs`
has one eligible entry whose package installs but is not an MCP server: a pinned
npm package with a bin that exits at once. Its sidecar holds the real digest.
The workflow step expects exit 1 and one `FAIL … exited … before answering
initialize`. A second entry, `time`, must start, so the falsifier also proves
that the harness can pass.

## Rollout and rollback

One PR. Revert it to roll back. MIK-8511 (the repin to 2.0.0) updates the
sidecar in its own PR and gets the start check for memory and
sequential-thinking for free.

## Questions for review

1. Sidecar file vs a `RegistryEntry` field. Is the product-code line right?
2. Is an exact PyPI file-set match too strict (late wheel uploads), or correct?
3. Install scripts on inside the container, or `--ignore-scripts`?
4. Is `docker network disconnect` before start sound, or is there a simpler
   way to keep install online and start offline?
