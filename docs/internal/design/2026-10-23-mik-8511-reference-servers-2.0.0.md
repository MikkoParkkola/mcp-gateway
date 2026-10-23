# MIK-8511: repin filesystem, memory and sequential-thinking to 2.0.0

Status: draft for review (r1). Operator ruling 2026-10-22: repin all three to
2.0.0 in 4.0.0. The code lands after MIK-8513 (its integrity sidecar and checks,
final design at b63ace710), which itself lands after #4061 (the
`RegistryEntry` → `ServerCatalogEntry` rename).

## What changes for a user

`mcp-gateway add filesystem|memory|sequential-thinking` writes `@2.0.0` instead
of `@1.0.0`. **Configs already written keep 1.0.0**, because the registry is
read only at `add` time.

## Facts the design rests on (verified 2026-10-23)

**npm metadata for 2.0.0.** All three are `dist-tags.latest`, not deprecated, and
declare `engines: {node: ">=24"}`. 1.0.0 declared no `engines` field.

| package | bin | dist.integrity |
|---|---|---|
| server-filesystem | `mcp-server-filesystem` | `sha512-JT+bt9wrNIMqhGvOr49vEE9NpbkBxdjQxyLVqh3lYHsB2zGgbzePmDOGrm1glBT1DPR5YvkM6h/NXztWSRhywg==` |
| server-memory | `mcp-server-memory` | `sha512-h+oxQCpK6FOuhlPB9hAcSihAAahcnijuGTZGcXStGOL4UzFYB4ap+pvtSelxchkZlz7tnpY/e0sONaAs24Rurw==` |
| server-sequential-thinking | `mcp-server-sequential-thinking` | `sha512-LAljkLByTHuOOPoQHAGNX5EiUJAvYuuTG7yEvdK5pRg7s7oxchNh8LwSkcuW3Y8bvQk4uZgjbjH3x7rNKpJ3Iw==` |

The only lifecycle script is `prepare: npm run build`, which does not run for a
registry install. Runtime dependencies: `@modelcontextprotocol/server ^2.3.1`
and `zod ^4.2.0` in all three. Package-specific additions:

- filesystem: `diff`, `glob`, `minimatch`;
- sequential-thinking: `chalk`, `yargs`.

**The roots change does not reach gateway users.** The gateway's `initialize`
to a backend declares `"capabilities": {}` (`src/protocol/negotiate.rs:99`
`initialize_params`), so it never offers Roots. In filesystem 2.0.0
`dist/server.js`, `oninitialized` asks for roots only `if
(clientCapabilities?.roots)`. Otherwise it logs "Client does not support MCP
Roots, using allowed directories set from server args" and keeps the
command-line directories. The tightened behaviour (#5095, #5098, #5102)
applies only after a client's roots are in force, which a gateway backend
never reaches.

On 2026-07-28 (modern era) Roots does not exist, and the server serves its
command-line directories. Startup (`dist/index.js`) is unchanged in shape:
missing or non-directory arguments are dropped with a warning, and the server
exits 1 when none remain, as in 1.0.0.

**Node 22 does not hang or refuse at start.** Probe on Spark, 2026-10-23: Docker
`node:22-slim` and `node:24-slim`, `npx -y @modelcontextprotocol/server-memory@2.0.0`,
one `initialize` on stdin. Both returned a `result`. Node 22 printed only `npm
warn EBADENGINE … required: { node: '>=24' }` to stderr. Tool calls on Node 22
are still unverified (see the plan).

**sequential-thinking hints are unchanged.** 2.0.0 `dist/index.js` has
`readOnlyHint: false, idempotentHint: false` (plus `destructiveHint: false,
openWorldHint: false`), the same as 1.0.0. So
`SEQUENTIAL_THINKING_REVIEWED` (`src/registry/server_registry_tests.rs:240`)
moves to `("2.0.0", false, false)` with no visible behaviour change.

**memory keeps its graph next to the package.** In 2.0.0 `defaultMemoryPath` is
still the package directory's `memory.jsonl`, so a new pin installs into a new
npx directory and starts with an empty graph. That matters only to users who
move an existing config, because existing configs keep 1.0.0. `doctor`'s
copy-first steps (`src/commands/doctor/npm_pin.rs` `hint`) already describe the
move for a deprecated pin; the upgrading note reuses them.

## Plan

**One PR, after MIK-8513.**

1. **Pins.** `src/registry/server_registry_entries.rs`: the three `command`
   strings go from `@1.0.0` to `@2.0.0`. Nothing else in the entries changes,
   except the description suffix proposed in question 2.
2. **Digests.** MIK-8513's sidecar `scripts/dev/registry-integrity.json`: the three
   1.0.0 records are replaced by the 2.0.0 values above. Its offline orphan rule
   forces the replacement, its live job verifies the served bytes, and its
   `starts` job proves memory and sequential-thinking answer `initialize`.
   filesystem is skipped there as `needs arguments`.
3. **Reviewed hints.** `SEQUENTIAL_THINKING_REVIEWED` becomes `("2.0.0", false,
   false)`, read from 2.0.0 `dist/index.js` and cited in the PR.
4. **Roots pin (new test).** A unit test asserts that `initialize_params`
   declares no `roots` capability. Its message names the dependency: the
   filesystem server keeps its command-line directories only while the gateway
   does not offer Roots. Declaring Roots later would hand the stricter 2.0.0
   roots semantics to every filesystem backend. Today nothing pins this.
5. **Node 24 floor, where users read requirements:**
   - `docs/DEPLOYMENT.md:14` and `docs/QUICKSTART.md:26` gain "Node.js 24 or
     later for the filesystem, memory and sequential-thinking registry entries";
   - the README registry table row, if it lists them;
   - optionally the entry descriptions (question 2).
6. **Release notes:**
   - `changelog.d/8511.changed.md`;
   - `upgrading.d/8511.md` covering: existing configs keep 1.0.0; moving one
     needs Node 24; the memory graph must be copied first (doctor's copy-first
     steps); the roots change does not apply through the gateway; a copy-paste
     check, `node -e 'process.exit(+process.versions.node.split(".")[0] >= 24 ? 0 : 1)' && echo "Node is new enough for 2.0.0"`.
7. **Revert:** one commit restoring the three `@1.0.0` pins and the three 1.0.0
   sidecar records. The PR states it.

## Behaviour proof on Spark (AC: through the gateway)

The gateway is built from the PR head on Spark, as a release binary. It runs
inside Docker `node:24-slim`, pinned by digest, with the binary and a config
mounted read-only. Containers get no Spark environment. A temporary directory
holds two allowed folders for filesystem.

Config: all three backends exactly as `mcp-gateway add` writes them at 2.0.0;
filesystem gets the two folders as arguments.

For each backend, the proof records:

- `initialize`;
- `tools/list` through `gateway_list_tools(server)`;
- one real call through `gateway_invoke`:
  - filesystem: `list_allowed_directories` returns both folders, and a
    `read_file` inside one succeeds while one outside is refused;
  - memory: `create_entities` then `read_graph` returns it;
  - sequential-thinking: one `sequentialthinking` step.

Everything goes into a log with rc lines. The same run on `node:22-slim`
records what Node 22 users see for each call:

- **if every call works,** the floor is documented and the EBADENGINE warning is
  stated as the only signal;
- **if any call fails,** the failure text the gateway surfaces is quoted;
- **if any call hangs past the gateway's request timeout,** stop and report: a
  hang is the case the AC's "clear message" covers, and it would need its own
  design.

## Acceptance criteria mapping

| AC | how |
|---|---|
| REPLACE.2 digests | fetched from npm (above), recorded in the sidecar, checked by MIK-8513's offline and live jobs |
| REPLACE.2 start proofs | the Spark proof above, all three, Node 24 |
| REPLACE.2 roots | stated: the change does not reach gateway backends (evidence above); pinned by step 4's test and by the filesystem proof (folder arguments in force, outside path refused). See deviation 1 |
| REPLACE.2 Node 24 floor | step 5 docs, plus the Node 22 run. See deviation 2 |
| REPLACE.2 notes | step 6 |
| REPLACE.2 revert | step 7 |
| REPLACE.3 | the due date of 2026-12-01 stays until merge, then is re-graded as answered by the repin |

## Deviations from the AC text, for the lead and the operator

1. **"A config that worked at 1.0.0 and no longer does" (roots).** None exists
   through the gateway. The gateway offers no Roots, so the 2.0.0 roots
   tightening never activates, and the command-line directories behave as at
   1.0.0. Proposed reading: the change is stated, shown not to apply, and
   pinned (step 4). If a breaking config turns up in the Spark proof, it is
   added as the regression instead.
2. **"An older Node gives a clear message rather than a hang".** On Node 22,
   2.0.0 does not hang at start: it answers `initialize`, and npm prints
   `EBADENGINE`. The Node 22 run decides between "documented floor plus that
   warning" and a real failure to quote. No gateway-side Node version check is
   proposed: it would be product code reading `engines` per package, and the
   floor is upstream's.

## Questions for review

1. Is the roots reading (deviation 1) sound, or is there a gateway path where a
   backend does see client Roots? For example, the modern-era input bridge
   relays `roots/list` to a legacy client.
2. Should the three registry descriptions carry "(Node 24+)" so users see the
   floor at `add` time, or are the docs and the upgrading note enough?
3. Does the Spark proof prove enough "through the gateway", or should the
   memory graph location change (a new npx directory) also be shown?
