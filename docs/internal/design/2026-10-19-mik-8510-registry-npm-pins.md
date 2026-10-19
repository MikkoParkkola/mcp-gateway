# MIK-8510: repin the three deprecated registry npm entries

Status: design v1. Refs MIK-8510, family registry-drift. Ships in 4.0.0.

## Problem

`mcp-gateway add <name>` writes whatever `src/registry/server_registry_entries.rs`
says. The live check (`scripts/dev/check-registry-packages.py`, workflow
"Registry packages") resolves every entry against the outside world and last
passed on 2026-10-09. It now reports `32/35 registry entries resolve` (run
39206164018, job 117909352172): three npm pins are deprecated upstream.

| entry | line | pin today |
|---|---|---|
| filesystem | 66 | `@modelcontextprotocol/server-filesystem@2026.8.31` |
| memory | 260 | `@modelcontextprotocol/server-memory@2026.8.31` |
| sequential-thinking | 320 | `@modelcontextprotocol/server-sequential-thinking@2026.8.31` |

npm's message for each: "Date-based versions are no longer published. This
package has resumed semantic versioning at 1.0.0: install the latest version."
Gate day runs this check, and users who run `add` today get deprecated pins.

Not failing, and not changed: `context7` (`Auth::None`; its open endpoint is
correct) and `hubspot` (stdio `@hubspot/mcp-server@0.4.0` with a token env var).
The `open-header` and `oauth-without-dcr` FAIL lines in the same log are the
checker's negative-control step, run against the synthetic
`scripts/dev/testdata/registry-dead.rs` and asserted by the workflow.

## Decision

Pin each of the three to the exact version `1.0.0`: the `latest` dist-tag, not
deprecated, published 2026-10-11 (upstream release `v1.0.0`, "Final Legacy
Server Release"). Three string edits, nothing else.

Alternatives rejected:

- Keep the date-based pins: they are deprecated, the check stays red.
- An unpinned or `@latest` command: the checker and the supply-chain rule
  require an exact version.
- Drop or replace the entries: these are the reference servers and users rely on
  them; replacing them is a product decision, not drift repair.

## What changed upstream (read, not assumed)

The tarballs of `2026.8.31` and `1.0.0` of each package were downloaded and
compared. Same `bin` names and entry file in all three. The only install-time
script is `prepare: npm run build` in both (it does not run for registry
installs). Runtime dependencies: `@modelcontextprotocol/sdk` `^1.30` to `^1.31`
in all three, and a new `zod ^4.0.0` in all three. New files: `dist/server.js`
and `dist/version.js` (filesystem), `dist/version.js` (memory). A scan of `dist`
for `child_process`, `fetch(`, `eval(`, `new Function` finds nothing new; the new
`http` and `spawn` matches are a JSON-Schema URL string and a comment.
Tarball integrity (npm `dist.integrity`, sha512), so the review is reproducible:

| package | 2026.8.31 | 1.0.0 |
|---|---|---|
| server-filesystem | `kKaFkyAh6oipvc9+EAbJ552JafnMnOq5nzmzWkp1jJdBhTAAGpmIpWihUG1+rfNhmEFM98gUZDdCHCDD4v6a7Q==` | `2fN6qhpsiPSBAe0ev1qDPk4sCWdULCZQTuYc4ZY7+BDWQ1XCxLB+7dqStF2ZflgG4G/9vTwQsjxh7pjFqrrpcg==` |
| server-memory | `ljj/3S4aGjxdNSQWw6gucKKGnTLdBPWxzapyY/MT2tOVyZwvxChvevXSLPwx59nKJAlVpUVW+cOlnVRXRwiqMQ==` | `UDMtMrw2xeI16mcn7O4fesp9Pf3hYh91thuU5KSz0BxKqwnTwEytZKjHfkrqxxmKp0r4QHoiEkMV99UmadmODw==` |
| server-sequential-thinking | `/EMH++1j2e+VmHwpibw1IUPHxA0tcQY09Yo5/OIPwW/8irEKLAufJNGSZQhCK18n8TUvV6WwZyQOuaDKxe/CeQ==` | `ykTmeS4Eejs+FESDrD73mDBNYCkb+cCZJ1MWuv7/vwucbVgGfEbBL5HVt2nVw0/vNF8jz+o9sO/WmxxfXt0J6w==` |

Behaviour changes a gateway user can see (each read in the 1.0.0 `dist`, not
inferred; the first two were missing from the first draft and were found in
review):

- **sequential-thinking:** the tool's annotations change from `readOnlyHint:
  true, idempotentHint: true` to `readOnlyHint: false, idempotentHint: false`.
  The gateway reads `read_only_hint` in role-filtered search
  (`src/gateway/meta_mcp/search.rs`) and in the backend pool, so a read-only
  role no longer surfaces this tool and it is no longer treated as a safe
  read. That is the accurate annotation for a tool that keeps thought-history
  state; it is a change, not a regression.
- **memory:** `createRelations` now throws `Entity with name <x> not found` when
  a relation names an entity that does not exist (1.0 accepted it); reads and
  writes also take a lock, and unreadable lines in the graph file are kept
  rather than dropped. `~` is expanded in `MEMORY_FILE_PATH`.
- **memory, data location:** with no `MEMORY_FILE_PATH`, the graph file lives
  next to the package (`memory.jsonl` beside `dist/`). `npx` installs each
  version into its own cache directory, so a user who re-adds the entry on the
  new pin starts with an empty graph while the old graph stays in the old
  version's cache. Existing configs keep their pin and are not touched. Users
  who need continuity set an absolute `MEMORY_FILE_PATH`. The same held for
  every earlier date-based bump; the release note says so.
- **filesystem:** client-provided roots replace the command-line directories in
  both versions (precedence unchanged). New in 1.0.0: tool calls wait for the
  initial roots, a refresh that arrives out of order is discarded, a client that
  withdraws its roots withdraws the server's access, and a start with no
  directories and no roots fails visibly. The registry entry is
  `Setup::NeedsArgs`, so the user supplies directories as before.

Accepted: an exact pin fixes the top-level package only; its dependency ranges
resolve at install time, as for every other pinned entry in the registry. The
integrity values above would let the offline checker verify content later; that
and the end-of-life question for these three legacy servers are tickets, not
part of this fix.

## Verification

- Red first: the live checker on the unmodified base prints the three FAIL lines
  and `32/35`.
- After the edit: `35/35`; the offline checker (the PR-time rule) still passes.
- The registry unit tests and the full pre-push gate pass.

## Not changed

No checker logic, no workflow. The `check-registry-packages.py` docstring's
file name is corrected (`server_registry_entries.rs`). A changelog fragment tells
users about the pins and the behaviour changes above. Rollback: revert the three
strings.
