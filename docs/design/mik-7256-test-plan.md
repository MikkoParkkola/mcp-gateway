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
| ENVFILE.8 | an already-listed env file rewritten with a `EF BB BF` prefix, first line `MIK7256_BOM_<uniq>=v`; reload a config whose backend env references `${MIK7256_BOM_<uniq>}`; assert it resolves to `v` | integration (config_reload) | negative | there is no overlay yet, so nothing to strip a BOM from — the case exists to pin new code, and MUST be written against the overlay builder before it is called correct |
| ENVFILE.9 | running watcher over a config naming an env file; edit the env file's value for a `${VAR}` a backend uses; assert a reload IS published and the resolved backend config carries the new value | integration (config_reload) | positive + control | passes before and after — the pin that this design did not remove hot-reload of env-file contents |
| ENVFILE.10 | reload a candidate adding `auth.bearer_token: env:MIK7256_TOK_<uniq>`, with the value defined only in an already-listed env file; assert the reload VALIDATES, and that the resolved token equals the file's value | integration (config_reload) | positive | validation resolves `env:` through `std::env` only, and today the file happens to have been applied first — so this passes before the fix and fails against an overlay-only design. It is the case that killed option C, and it fails loudly if the overlay is not threaded into validation |
| ENVFILE.10b | same, for a capability credential resolved by `fetch_credential` | integration (capability) | positive | same shape at the other convention — `env:VAR`, `{env.VAR}` and a bare `UPPER_SNAKE` name all read `std::env` at call time |
| ENVFILE.11 | candidate ADDS `extra.env` to `env_files`, defining `MIK7256_ADD_<uniq>` and a `${MIK7256_ADD_<uniq>}` reference in a backend; reload succeeds; assert the reference resolves empty and the variable is absent from the process | integration (config_reload) | negative | today the candidate's own list drives the apply, so naming a file is enough to activate its contents |

Two rules the design states but no criterion owns, pinned as one case each:

| case | level | type | asserts |
|---|---|---|---|
| env-file `${VAR}`, same file | integration | positive | candidate env file `A=1` then `B=${A}`, with `A` absent from the process; assert `B` resolves to `1`. `dotenvy`'s `apply_substitution` consults `env::var` first and its per-file table second (dotenvy 0.15.7, `parse.rs:260-273`), so the file's own value wins when the process has none — identical to startup |
| env-file `${VAR}`, across files | integration | negative | first file `A=1`, second file `B=${A}`, `A` absent from the process; assert `B` resolves to empty on the reload path, where startup resolves it to `1`. Each file gets its own table and the earlier file has not been applied yet — the documented divergence |
| overlay precedence | unit (config) | positive | overlay entry wins over a process variable of the same name, matching `from_path_override` |
| no `Config::load` inside a running gateway | source scan | negative | assert `Config::load(` appears nowhere under `src/config_reload/` or in `src/config_persistence.rs`'s gateway-facing sibling — the design's one rule a compiler cannot hold, pinned the way this repository already pins enforced absences |

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
