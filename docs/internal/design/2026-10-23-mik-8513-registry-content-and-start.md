# MIK-8513: the registry check verifies content and that entries start

Status: draft for review (r2: r1 seat findings folded, see the end). Scope: `scripts/dev/check-registry-packages.py`,
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

**Where the digests live.** A sidecar file, `scripts/dev/registry-integrity.json`.
It stays out of `src/` so that Cargo's `include = ["src/**"]` does not publish
it. The checker takes `--integrity PATH`, defaulting to that file; the workflow
passes each testdata file's own sidecar. It is a sidecar
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

**Served bytes, not only metadata (r2).** The metadata comparison above catches
a changed digest. It cannot catch bytes that differ from an unchanged digest.
So the live job also has the package manager fetch every pinned top-level
artifact inside the isolated container (below), skipped start entries
included. The package manager checks the actual bytes against the sidecar
value:

- **npm:** `npm pack --json <pkg>@<ver>` reports the `integrity` it computed
  from the downloaded tarball, which must equal the sidecar.
- **PyPI:** `pip download --no-deps --require-hashes` with `<pkg>==<ver>
  --hash=sha256:<v>` for every recorded file. pip refuses a download whose
  bytes match none of them.

The checker itself still hashes nothing (fail-fast).

**Ceiling:** pip verifies the one file it selects. The others are covered only
by the metadata map.

## CONTENT.2: each eligible stdio entry answers `initialize`

**Which entries.** An entry is eligible when it is stdio, `Setup::Ready`, has an
empty `required_env`, has `Auth::None` and is not in the checker's own
`START_SKIP` table. The table today holds one row, `playwright: needs a
browser`; the product's `Setup` stays unchanged. That makes `memory`,
`sequential-thinking`, `fetch` and `time` eligible. Every other stdio entry
prints `SKIP <name>: <reason>`:

- `needs arguments: <hint>`;
- `needs a service`;
- `needs credentials: <ENV>`;
- `needs a browser`.

A skip is not a pass.

**A green run must attempt something.** The workflow asserts:

- `PASS memory`, `PASS sequential-thinking`, `PASS fetch` and `PASS time`;
- `4/4 eligible entries start`.

So a parser miss that makes everything ineligible fails the job.

**Parser.** The existing `parse_entries` gains three fields, `setup`,
`required_env` and `hint`, as new `FIELD_RE` entries. There is no second
parser. The work lands after #4061 renames the struct.

### Isolation (reviewed before code, per the AC)

**Threat.** Running a third-party package executes its code, including npm
install scripts, on the runner. The job has no secrets, a `contents: read`
token, and no persisted credentials. But every host step's environment holds
`ACTIONS_RUNTIME_TOKEN` and the cache URLs, so a hostile package on the host
could poison the Actions cache other workflows restore. A workspace mount
would also expose `GITHUB_ENV`. The runner VM itself is disposable.

**Control.** All package code runs in containers that get no runner
environment and no host path:

- **Spawned by argv lists,** never a shell string. The argv is built from the
  classified `(launcher, pkg, ver, args)`, so a crafted `command` in a fork PR
  cannot inject into the host.
- **Flags:**
  - `--rm --read-only --log-driver none`;
  - `--cap-drop ALL --security-opt no-new-privileges --user 1000:1000`;
  - `--memory 1g --pids-limit 256 --cpus 1`;
  - `--tmpfs /tmp:exec,size=256m,uid=1000,gid=1000,mode=1777`.
- **Per-entry volume:** a fresh named Docker volume mounted at `/work`, prepared
  for uid 1000 and removed afterwards.
- **Environment:** only `-e HOME=/work -e npm_config_cache=/work/.npm
  -e UV_CACHE_DIR=/work/.uv -e UV_TOOL_DIR=/work/tools
  -e XDG_CACHE_HOME=/work/.cache`.
- **No secret** is ever passed.

**Images, pinned by digest:**

- `mirror.gcr.io/library/node:24-slim` for npm;
- `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` for PyPI. That one is
  published on ghcr.io and is not Docker Hub content.

**Three steps per entry.** The first two use the network; the last does not.

1. **Fetch and verify:** `npm pack` or `pip download` as above, 120 s cap. This
   runs for every pinned entry.
2. **Prime the launcher users get,** 180 s cap:
   - npm: `npm exec --yes --package <pkg>@<ver> -- true`. This fills the npx
     cache, runs install scripts as `npx -y` would (the container is the
     boundary), and does not start the server.
   - uvx: `uv tool install <pkg>==<ver>`.
3. **Start,** in a second container on the same volume with `--network none`,
   60 s cap:
   - npm: `npx --offline -y <pkg>@<ver> <args>`;
   - uvx: the installed tool binary `<args>`.

   A server that needs the network to start therefore FAILs.

**The driver** writes one `initialize` request with `id: 1`. It reads stdout
line by line, at most 1 MiB, until a JSON-RPC message with `id: 1` arrives.

- **PASS:** the message has a `result` carrying `protocolVersion` and `serverInfo`.
- **FAIL:**
  - an `error` reply;
  - a reply with the wrong id;
  - malformed JSON;
  - EOF;
  - the time cap.

  The last 4 KiB of stderr is kept for the FAIL line.

**Cleanup:** `docker rm -f` and `docker volume rm` run in `finally`, on every
path, including timeouts.

**Not in scope:** no `pull_request_target`, no Docker socket, no host mount.
The host-side driver only parses bounded container output.

**Where it runs.** A new job, `starts`, in `registry-packages.yml`, with
`timeout-minutes: 25`. Not in ci.yml (CONTENT.3).

### Falsifiers

| AC | how it is shown | where |
|---|---|---|
| CONTENT.1, metadata | `registry-integrity.rs`: two healthy entries, one sidecar value wrong; `1/2 resolve`, exactly one `FAIL … integrity` | live job step |
| CONTENT.1, bytes | the byte step's comparison is unit-tested with a stubbed `npm pack` result whose integrity differs while the metadata matches | offline self-test |
| CONTENT.2 | `registry-wont-start.rs`: `time` must PASS; a pinned npm package whose bin exits at once must FAIL `exited … before answering initialize`; `1/2 eligible entries start` | live job step |
| CONTENT.2, harness | timeout, malformed reply, wrong id, and an error reply, each against a tiny local fake server driven without Docker | offline self-test |
| CONTENT.3 | `--offline` asserted to make no network call: `fetch` is replaced with one that raises | offline self-test |

## Rollout and rollback

One PR, after #4061. Revert it to roll back. MIK-8511's repin updates the
sidecar and gets byte verification and the start check for memory and
sequential-thinking.

## r1 review folded (gpt SWF, grok SWF)

- **Adopted:**
  - the tmpfs/HOME/cache flags;
  - playwright skipped;
  - the uv image from ghcr.io;
  - the uv receipt comparison dropped;
  - output caps and `--log-driver none`;
  - two containers with `--network none` instead of a disconnect;
  - the sidecar moved out of `src/`;
  - the entry's own launcher, offline;
  - exec-form argv;
  - a green run must attempt named entries;
  - harness negative controls;
  - cleanup on every path;
  - a note that a late extra PyPI file is a reviewed digest update.
- **Disagreement settled toward gpt:**
  - **grok:** comparing metadata is enough, since installers verify.
  - **gpt:** bytes must be checked.
  - **Ruling:** the AC says "the served tarball differs", so the installer
    enforces the sidecar hash on the real download in the container. This
    stays inside the fail-fast rule: the checker hashes nothing.
