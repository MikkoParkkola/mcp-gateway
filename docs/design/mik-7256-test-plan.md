# MIK-7256 test plan

One row per acceptance criterion. An empty evidence cell is a finding, not an
omission. Criteria are in `docs/design/mik-7256-env-files-on-a-failed-load.md`.

| AC | case | level | type | fails before the fix because |
|---|---|---|---|---|
| ENVFILE.1 | reload a candidate whose already-listed env file sets `MIK7256_FAIL_<uniq>`, with a config that fails validation; assert the variable is still absent from the process afterwards | integration (config_reload) | negative | `Config::load` applies the env file before it validates, so the variable is set |
| ENVFILE.1b | same, but the reload is refused by the network posture rather than by validation | integration | negative | the apply happens before the refusal is computed |
| ENVFILE.2 | reload a candidate that SUCCEEDS, its already-listed env file sets `MIK7256_OK_<uniq>`; assert the variable IS readable from the process afterwards, with the file's value | integration | positive | passes before and after — the no-regression pin that keeps every lazy `env:` reader working. It is here because the previous draft asserted the opposite, and reversing an assertion silently is how a requirement gets lost |
| ENVFILE.3 | process holds nothing for `MIK7256_INH_<uniq>`; the already-listed env file now sets it; reload FAILS validation; spawn a backend that does not reference it; assert the child does not see it at all | integration (transport) | negative | today the failed reload has already set the process value; the child still does not inherit it, so the assertion that bites is on the gateway process, and the child half only pins that `env_clear` keeps holding |
| ENVFILE.4 | `Config::load(path)` with two env files, the second overriding the first; assert both variables land in the process and the override order holds | unit (config) | positive | passes before and after — the startup-parity pin |
| ENVFILE.5 | reload a candidate that adds a backend whose `env` map contains `${MIK7256_NEW_<uniq>}`, with an already-listed env file now defining it; assert the resolved backend config carries the value | integration (config_reload) | positive | passes before and after by a different mechanism — pair with .1 over the same fixture, which is what proves the value arrived through the overlay rather than through a mutation |
| ENVFILE.6 | process holds `MCP_GATEWAY_PORT=18081` from startup; the env file's contents change to `18082`; assert the reloaded config's port is `18081`, and that a SECOND reload of the same config yields `18082` | integration (config_reload) | negative + positive | today the candidate file is applied first, so Figment's second extract reads `18082` on the first reload. The second half pins the lag as a lag rather than a loss |
| ENVFILE.6b | same fixture; assert a warn-level log names the `MCP_GATEWAY_PORT` key AND that neither the old nor the new port value appears in the record | integration | positive + negative | no such log exists; the negative half is what keeps it compatible with PR #439's removal of configured values from diagnostic output |
| ENVFILE.7 | `mutate_and_reload_outcome_within` with a closure that REJECTS, over a config whose env file sets `MIK7256_UI_<uniq>`; assert `ConfigMutation::Rejected` and the variable still absent | integration (config_reload) | negative | `load_config_or_default` applies the file before the closure runs, so a rejected edit still mutates the environment |
| ENVFILE.7b | `mutate_and_reload_outcome_within` with a closure that SUCCEEDS, over a config whose already-listed env file sets `MIK7256_UIOK_<uniq>` referenced by a backend it adds; assert `ConfigMutation::Applied`, the file on disk carries the edit, and the resolved backend config carries the value | integration (config_reload) | positive | .7's twin. Without it, .7 passes against a UI path that reads nothing and applies nothing, which is the failure the plan's own pairing rule exists to catch |
| ENVFILE.7c | same path, with the config file made unwritable so `write_config` fails after the closure succeeded; assert the error surfaces and `MIK7256_UIW_<uniq>` is absent | integration (config_reload) | negative | today `load_config_or_default` applies the env file before the write is attempted, so a write failure leaves the process mutated with nothing on disk — the same defect as .7 at a later exit |
| ENVFILE.1c | reload a candidate that is malformed TOML, over a config whose already-listed env file sets `MIK7256_PARSE_<uniq>`; assert the parse error surfaces and the variable is absent | integration (config_reload) | negative | `Config::load` applies env files before it parses far enough to fail, so the earliest failing exit mutates the process too. One case per enumerated exit; this is the first |
| ENVFILE.1d | same, for a config that parses but fails Figment type extraction (a string where a port is expected) | integration (config_reload) | negative | the exit between parse and validation. Named in ENVFILE.1's criterion and previously untested |
| ENVFILE.8 | an already-listed env file rewritten with a `EF BB BF` prefix, first line `MIK7256_BOM_<uniq>=v`; reload a config whose backend env references `${MIK7256_BOM_<uniq>}`; assert it resolves to `v` | integration (config_reload) | negative | there is no overlay yet, so nothing to strip a BOM from — the case exists to pin new code, and MUST be written against the overlay builder before it is called correct |
| ENVFILE.9 | running watcher over a config naming an env file; edit the env file's value for a `${VAR}` a backend uses; assert a reload IS published and the resolved backend config carries the new value | integration (config_reload) | positive + control | passes before and after — the pin that this design did not remove hot-reload of env-file contents |
| ENVFILE.10 | reload a candidate adding `auth.bearer_token: env:MIK7256_TOK_<uniq>`, with the value defined only in an already-listed env file; assert the reload VALIDATES, AND that the outcome reports `restart_required`, AND that the live `ResolvedAuthConfig` still holds the old token | integration (config_reload) | positive + negative | validation resolves `env:` through `std::env` only, and today the file happens to have been applied first — so the validation half passes before the fix and fails against an overlay-only design. It is the case that killed option C. The two added halves pin the narrowing the design now states: `auth` is in `tracked_sections`, so this edit is restart-only, and a test asserting the running token CHANGED would be asserting a feature nobody built |
| ENVFILE.10b | same shape for a capability credential, driven through the live `fetch_credential` rather than a resolution helper: reload succeeds, then invoke a capability whose auth references the rotated name; assert the call carries the NEW value and that a call authorised with the old one is rejected | integration (capability) | positive + negative | this is the only credential a reload actually rotates, so it is the only one whose end-to-end behaviour can be asserted. Driving the helper instead would pass against a design that resolves correctly and never applies |
| ENVFILE.10c | env file ONLY is edited — config bytes byte-identical — watcher fires a reload; assert the reload succeeds with a `no_changes` outcome AND `fetch_credential` returns the new value afterwards | integration (config_reload) | positive | `load_config_patch` returns `Ok(None)` on an empty patch (`src/config_reload/mod.rs:1242-1243`) and `reload_outcome_locked` returns early (`:1442-1450`), so an apply hung off the published branch never runs. This is the change's own success case and the previous draft had no case for it |
| ENVFILE.10d | accepted reload whose `apply_patch` reports not-fully-applied (registry shutdown latch), over a candidate whose already-listed env file sets `MIK7256_ABORT_<uniq>`; assert the error is the shutdown abort AND the variable is absent | integration (config_reload) | negative | pins the apply BELOW the abort check (`:1517-1522`). An apply placed before `apply_patch` — which reads better for restarted backends — passes every other case in this plan and fails only this one |
| ENVFILE.10e | a reload that FOLLOWS a successful path-adding reload: reload 1 adds `extra.env` to `env_files` and is published; reload 2 changes something unrelated; assert `extra.env`'s variables are STILL absent from the process and `restart_required` is still reported | integration (config_reload) | negative | the list must come from `running()` (`:253`), not `get()` (`:276`). Sourcing it from the published snapshot passes ENVFILE.11 — the path-adding reload itself — and activates the file one reload later, before the restart the operator was told to do |
| ENVFILE.11 | candidate ADDS `extra.env` to `env_files`, defining `MIK7256_ADD_<uniq>` and a `${MIK7256_ADD_<uniq>}` reference in a backend; reload succeeds; assert the reference resolves empty, the variable is absent from the process, AND a warn-level log names the key and the unread file without the value | integration (config_reload) | negative + positive | today the candidate's own list drives the apply, so naming a file is enough to activate its contents |

Two rules the design states but no criterion owns, pinned as one case each:

| case | level | type | asserts |
|---|---|---|---|
| env-file `${VAR}`, same file | integration | positive | candidate env file `A=1` then `B=${A}`, with `A` absent from the process; assert `B` resolves to `1`. `dotenvy`'s `apply_substitution` consults `env::var` first and its per-file table second (dotenvy 0.15.7, `parse.rs:260-273`), so the file's own value wins when the process has none — identical to startup |
| env-file `${VAR}`, across files | integration | positive | first file `A=1`, second file `B=${A}`, `A` absent from the process; assert `B` resolves to `1` on the reload path, the same as startup. An earlier draft accepted a divergence here because each file got its own table; the design now builds the overlay cumulatively, so the parity is the requirement and this row is what holds it |
| duplicate key across files | unit (config) | positive | first file `A=1`, second `A=2`; assert the overlay yields `2`, matching `from_path_override`'s later-file-wins precedence |
| the applied bytes are the validated bytes | integration (config_reload) | negative | build the overlay, then rewrite the env file before the commit runs; assert the process receives the value the overlay captured, not the value now on disk. A commit that re-reads the files passes every other case and fails this one |
| overlay precedence | unit (config) | positive | overlay entry wins over a process variable of the same name, matching `from_path_override` |
| no `Config::load` inside a running gateway | compile-time | negative | a source-text scan was the first plan and it is the weaker mechanism: it passes against an alias, a re-export, or a helper that wraps the call. The rule becomes a type instead — the gateway-facing readers take the loader through a `pub(crate)` seam that exposes only `load_with_overlay`, so the mutating startup operation is not nameable from `src/config_reload/`. What remains testable is the seam itself: a `trybuild` or doc-level assertion that the startup loader is not reachable from the runtime module. Cheaper to hold, and it fails at build time rather than at review time |

## Can any of these pass while broken?

- .1, .1b, .3, .7 assert an ABSENCE. An absence passes trivially if the env
  file is never read at all — a fixture that writes it to the wrong path
  passes every one. Each pairs with .2 or .4 over the SAME fixture shape,
  which proves the file is real and its variables land when applied. Without
  that pairing the negative cases are unfalsifiable, and .2's reversal is what
  makes the pairing available at the reload level rather than only at startup.
- .11 is an absence with a positive twin in .5: the same fixture with the file
  already listed must resolve, which is what proves the path list is the only
  difference. Without .5 it passes against code that reads no env file at all.
- .5, .9 and .10 fail if the overlay is never consulted; .6 fails if the
  overlay is wired into Figment after all; .2 and .10 fail if the commit-time
  apply is dropped. The five together fix the boundary from both sides. Any
  one alone can pass with the boundary in the wrong place — which is exactly
  what happened to the previous design, where every case then written passed
  against a design that broke `env:`.
- .8 cannot fail before the fix in a useful way — the code it tests does not
  exist. It is a retrofit against new code, so it needs the falsifier probe:
  build the overlay WITHOUT the BOM strip, run it, and show the assertion
  fails on the variable name. Written and shown failing, not asserted to fail.
- Every negative case asserts ONE absent sentinel, which cannot see a partial
  apply that stopped before that name. The env-file fixtures for `.1`, `.1b`,
  `.1c`, `.1d`, `.7`, `.7c` and `.10d` therefore define three variables, and
  each case compares the full `std::env::vars_os()` set before and after
  against the snapshot taken at case start — equality, not the absence of one
  key. A failed reload that set two of the three passes the sentinel form and
  fails this one.
- The full-environment comparison is only sound if nothing else in the process
  mutates the environment concurrently, and the suite runs tests in parallel
  threads. Every case that asserts on a whole-environment snapshot lives in its
  own integration-test binary (`tests/env_files_on_failed_load.rs`), which
  `cargo test` runs as a separate process. Serialising within the shared unit
  binary would be the alternative and it is weaker: any test added later
  without the marker silently breaks the comparison.
- No test calls `std::env::set_var`, so none needs `#[allow(unsafe_code)]`.
  Where a case needs a value in the real process environment (.2, .4, .6) it
  gets there through `Config::load` on a startup-shaped fixture, which writes
  it inside `dotenvy`. The workspace lint stays intact and the tests exercise
  the real apply path rather than a hand-rolled substitute.
- The suite runs threads in parallel and .2, .4 and .6 mutate the process.
  Unique suffixed names per test, and no test asserts on a variable another
  writes. `MCP_GATEWAY_PORT` in .6 is the exception it cannot avoid: it must
  run serialised.
- .9's positive half passes trivially if filesystem events do not work in the
  test environment at all. The assertion is on the resolved VALUE reaching the
  backend config, not on a reload being published — a published reload that
  changed nothing satisfies the weaker form.

## Seams

`expand_env_vars` is a private method with one call site
(`src/config/mod.rs:313`), so the overlay parameter is compiler-enforced
there — but a compiler guarantee is not a test, which is why .5, .6, .8 and
.10 drive the loader end to end rather than calling `expand_string` directly.
Validation is the second seam: `validate_env_reference`
(`src/config/mod.rs:651`) funnels four call sites and the agent-key path
(`:433`) stands alone, so .10 must cover both — a design that threads the
overlay into the funnel and forgets the inline site passes .10 and fails on
agent secrets in production.
