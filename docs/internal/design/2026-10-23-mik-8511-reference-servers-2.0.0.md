# MIK-8511: repin filesystem, memory and sequential-thinking to 2.0.0

Status: FINAL (r2 confirmation folded; lead ruling: no further design round). Operator ruling 2026-10-22: repin all three to
2.0.0 in 4.0.0. The code lands after MIK-8513 (its integrity sidecar and checks,
final design at b63ace710), which itself lands after #4061 (the
`RegistryEntry` → `ServerCatalogEntry` rename).

## What changes for a user

The registry is read when a config is written, never while the gateway serves.

- `mcp-gateway add filesystem|memory|sequential-thinking` writes `@2.0.0`.
- **`mcp-gateway init` (and the empty-import wizard, which calls it) writes
  memory and sequential-thinking enabled by default**, because `default_enabled` holds: no login, a bounded reach, and
  `Setup::Ready`. So every new init gets those two at 2.0.0.
- filesystem stays add-only (`Setup::NeedsArgs`).
- **Configs already written keep 1.0.0.**

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

The packages ask for roots only from `oninitialized`, and only when
`clientCapabilities.roots` is set. The modern-era input bridge relays
`roots/list` only as a question inside a tool call (multi-round tool results),
a path these servers do not take. stdio refuses an unsolicited
server-to-client request. `initialize_params` takes only the version and no
client input, so a Roots-capable frontend client cannot change what a backend
is offered. (Corrected in r2: "Roots does not exist on 2026-07-28" was wrong.
That revision removed `notifications/roots/list_changed`; `roots/list` remains
capability-gated.) Startup (`dist/index.js`) is unchanged in shape:
missing or non-directory arguments are dropped with a warning, and the server
exits 1 when none remain, as in 1.0.0.

**Node 22 does not hang or refuse at start.** Probe on Spark, 2026-10-23: Docker
`node:22-slim` and `node:24-slim`, `npx -y @modelcontextprotocol/server-memory@2.0.0`,
one `initialize` on stdin. Both returned a `result`. Node 22 printed only `npm
warn EBADENGINE … required: { node: '>=24' }` to stderr. **That warning never
reaches a user through the gateway:** a stdio child's stderr goes to neither
the MCP client nor the gateway log (MIK-7978,
`src/transport/stdio_early_exit.rs:9`). It is only matched against fixed
needles. Tool calls on Node 22
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
3. **Version-dependent tests.**
   - `SEQUENTIAL_THINKING_REVIEWED` becomes `("2.0.0", false, false)`, read from
     2.0.0 `dist/index.js` and cited in the PR.
   - `src/commands/doctor/npm_pin_tests.rs` moves every assertion on the
     registry's current version to 2.0.0: the `current_version` row at :158
     and the copy-first hint assertions at :479, :483, :503 and :525. Only the
     parser fixtures (:67–74, :410–435) keep `1.0.0`.
4. **Roots pin.** The existing `build_init_params_contains_version`
   (`src/transport/stdio_tests.rs:133`) gains an assertion that
   `initialize_params` declares no `roots` capability. Its message names the
   dependency: the filesystem server keeps its command-line directories only
   while the gateway does not offer Roots, and declaring Roots would hand the
   stricter 2.0.0 roots semantics to every filesystem backend. Today nothing
   pins this.
5. **The Node 24 recommendation, where users read requirements** (lead ruling,
   option A):
   - the quick-start wizard path and the manual prerequisites in
     `docs/QUICKSTART.md`, and `docs/DEPLOYMENT.md:14`;
   - the init docs, because `init` (and the empty-import wizard, which calls
     it) enables memory and sequential-thinking by default;
   - the README registry table row, if it lists them;
   - "(Node 24+)" at the end of the three registry descriptions.

   It is worded as a recommendation: Node 22 works, and the gateway shows no
   warning.
6. **Release notes:**
   - `changelog.d/8511.changed.md`;
   - `upgrading.d/8511.md` covering:
     - existing configs keep 1.0.0;
     - Node 24 is recommended for 2.0.0 (Node 22 works, and the gateway shows
       no warning);
     - moving a memory config needs the graph copied first (doctor's
       copy-first steps);
     - the roots change does not apply through the gateway;
     - a copy-paste check, `node -e 'process.exit(+process.versions.node.split(".")[0] >= 24 ? 0 : 1)' && echo "Node 24 or later (recommended for 2.0.0)"`.
7. **Revert:** `git revert -m 1` of the PR's merge commit, which restores the
   pins, the sidecar records and the version-dependent tests together (they
   landed across several commits, so reverting one of them alone leaves tests
   expecting 2.0.0). The PR states it.

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
  - sequential-thinking: one `sequentialthinking` step;
- memory migration, the documented path:
  1. on 1.0.0 with the default path, create an entity;
  2. copy its `memory.jsonl` to a mounted folder;
  3. start 2.0.0 with an absolute `MEMORY_FILE_PATH` pointing at it;
     `read_graph` returns the entity;
  4. write a second entity on 2.0.0;
  5. restart 2.0.0; `read_graph` returns both.

  This proves the upgrading note's steps keep existing data and that 2.0.0
  persists across a restart.

Everything goes into a log with rc lines. **The same run on `node:22-slim`
decides REPLACE.5:**

- **every call works:** REPLACE.5 holds. The PR states that Node 22 works and
  that the gateway shows no warning; the Node 24 floor ships as a
  recommendation;
- **any call fails or hangs:** stop. The original Node clause stands
  (REPLACE.5's own condition), I return to the lead with the quoted failure,
  and the reserve option B (a gateway-owned pre-launch Node check) comes back
  into play.

## Acceptance criteria mapping

| AC | how |
|---|---|
| REPLACE.2 digests | fetched from npm (above), recorded in the sidecar, checked by MIK-8513's offline and live jobs |
| REPLACE.2 start proofs | the Spark proof above, all three, Node 24 |
| REPLACE.2 notes | step 6 |
| REPLACE.2 revert | step 7 |
| REPLACE.3 | the due date of 2026-12-01 stays until merge. After that, the standing reminder is MIK-8513's live job, which runs on every merge and daily and fails on a deprecated or yanked pin or changed bytes |
| REPLACE.4 (supersedes REPLACE.2's roots clause; pending ratify) | step 4's assertion, plus the filesystem proof: folder arguments in force, outside path refused |
| REPLACE.5 (supersedes REPLACE.2's Node clause; pending ratify) | the Node 22 run above, plus step 5's docs as a recommendation; any Node 22 failure restores the original clause |

## Superseded AC text (operator ratify)

1. **Roots** (REPLACE.4 replaces "a config that worked at 1.0.0 and no longer
   does"). No such config exists through the gateway. The gateway offers no
   Roots, so the 2.0.0 roots tightening never activates, and the command-line
   directories behave as at 1.0.0.
2. **Node** (REPLACE.5 replaces "the Node 24 floor is declared … an older Node
   gives a clear message rather than a hang"). On Node 22, 2.0.0 answers
   `initialize`. npm's EBADENGINE warning goes to the child's stderr, which the
   gateway never shows (MIK-7978), so there is no message to give. The floor is
   upstream's and is documented as a recommendation.

## Lead rulings (2026-10-23)

1. **Option A** for the Node floor: docs (including init and quick start), the
   upgrading note, and "(Node 24+)" in the three descriptions. B, a pre-launch
   check, stays in reserve and is triggered only if the Node 22 run fails.
2. **REPLACE.5 reworded** to "works on Node 22; the gateway shows no warning"
   (pending the operator's ratify).
3. **Design rounds:** one review plus one confirmation. This is the final
   design; r2 findings are folded below, with no further round.

## r1 review folded (gpt SWF, grok SWF)

- **Adopted:**
  - EBADENGINE is invisible through the gateway; claims are corrected and the
    floor options are put to the lead;
  - `init` also writes memory and sequential-thinking;
  - the modern-era roots sentence is corrected, and the reasoning folded into
    the step-4 pin;
  - REPLACE.3 maps to MIK-8513's live job after merge;
  - the doctor test that pins `1.0.0` is named;
  - a memory migration proof.
- **Not adopted:** a Roots-capable frontend client run (gpt). The step-4 test
  pins `initialize_params`, which takes no client input, so a frontend's Roots
  cannot reach a backend's `initialize`. The pin covers the regression gpt
  names.
- **Settled:** the reviewers disagreed on a memory demo (grok: none; gpt: a
  migration proof). The migration proof is adopted because it checks the
  upgrading note's own steps.

## r2 confirmation folded (gpt SWF, grok SWF): final

- **Every section now follows REPLACE.5's branch.** Steps 5 and 6, the Node 22
  run and the AC table describe Node 24 as a recommendation. Any Node 22
  failure stops the work, restores the original clause, returns to the lead
  and brings option B back.
- **The doctor hint assertions** at :479, :483, :503 and :525 move with the pin.
- **The revert** is the whole repin commit, tests included.
- **The leftover open sections** are removed.
- **The wizard paths:** the quick-start wizard path carries the Node note, and
  the empty-import wizard (which calls `init`) is named.
- **The roots pin** joins the existing `build_init_params_contains_version`
  test.
- **The migration proof** adds a 2.0.0 write, a restart, and a read.
