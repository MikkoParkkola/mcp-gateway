# MIK-7256 test plan

One row per acceptance criterion. An empty evidence cell is a finding, not an
omission. Criteria are in `docs/design/mik-7256-env-files-on-a-failed-load.md`.

| AC | case | level | type | fails before the fix because |
|---|---|---|---|---|
| ENVFILE.1 | reload a candidate whose env file sets `MIK7256_FAIL_<uniq>`, with a config that fails validation; assert the variable is still absent from the process afterwards | integration (config_reload) | negative | `Config::load` applies the env file before it validates, so the variable is set |
| ENVFILE.1b | same, but the reload is refused by the network posture rather than by validation | integration | negative | the apply happens before the refusal is computed |
| ENVFILE.2 | reload a candidate that SUCCEEDS, env file sets `MIK7256_OK_<uniq>`; assert the variable is still absent from the process | integration | positive | a successful reload applies it |
| ENVFILE.3 | process holds `MIK7256_INH_<uniq>=A`; candidate env file sets it to B; reload succeeds; spawn a backend that does NOT reference it; assert the child sees A | integration (transport) | negative | today the reload overwrites the process value, so the child sees B |
| ENVFILE.4 | `Config::load(path)` with two env files, the second overriding the first; assert both variables land in the process and the override order holds | unit (config) | positive | passes before and after — the no-regression pin, and the ONLY test that mutates the process environment |
| ENVFILE.5 | reload a candidate that adds a backend whose `env` map contains `${MIK7256_NEW_<uniq>}`, with a candidate env file defining it; assert the resolved backend config carries the value AND the process does not | integration (config_reload) | positive | the value lands, but only by mutating the process — the assertion on the process fails |
| ENVFILE.6 | process holds `MCP_GATEWAY_PORT=A` from startup; candidate env file sets it to B; assert the reloaded config's port is A | integration (config_reload) | negative | the candidate file is applied first, so Figment's second extract reads B |
| ENVFILE.7 | `mutate_and_reload_outcome_within` with a closure that REJECTS, over a config whose env file sets `MIK7256_UI_<uniq>`; assert `ConfigMutation::Rejected` and the variable still absent | integration (config_reload) | negative | `load_config_or_default` applies the file before the closure runs, so a rejected edit still mutates the environment |
| ENVFILE.8 | env file written with a `EF BB BF` prefix, first line `MIK7256_BOM_<uniq>=v`; reload a config whose backend env references `${MIK7256_BOM_<uniq>}`; assert it resolves to `v` | integration (config_reload) | negative | there is no overlay yet, so nothing to strip a BOM from — the case exists to pin the new code, and MUST be written against the overlay builder before it is called correct |
| ENVFILE.9 | running watcher over a config naming an env file; edit the env file's value for a `${VAR}` a backend uses; assert a reload IS published and the resolved backend config carries the new value | integration (config_reload) | positive + control | passes before and after — the pin that option C did not remove hot-reload of env-file contents |

Two rules the design states but no criterion owns, pinned as one case each:

| case | level | type | asserts |
|---|---|---|---|
| env-file-internal `${VAR}` | integration | negative | candidate env file `A=1` then `B=${A}`, with `A` absent from the process; assert the reloaded config resolves `B` to empty, not `1` — the stated "env files supply values to the YAML, not to each other" rule |
| overlay precedence | unit (config) | positive | overlay entry wins over a process variable of the same name, matching `from_path_override` |

## Can any of these pass while broken?

- .1, .1b, .2, .3, .6, .7 assert an ABSENCE or a non-change. An absence passes
  trivially if the env file is never read at all — a fixture that writes it to
  the wrong path passes every one. Each pairs with .4 over the SAME fixture
  shape: .4 proves the file is real and its variable lands when applied.
  Without that pairing the negative cases are unfalsifiable.
- .5 and .9 are the cases that fail if the overlay is never consulted, and .6
  is the case that fails if the overlay is wired into Figment after all. The
  three together fix the design's boundary in place from both sides; any one
  alone can pass while the boundary is in the wrong position.
- .8 cannot fail before the fix in a useful way — the code it tests does not
  exist. It is a retrofit against new code, so it needs the falsifier probe:
  build the overlay WITHOUT the BOM strip, run it, and show the assertion
  fails on the variable name. Written and shown failing, not asserted to fail.
- .4 mutates the process environment and the suite runs threads in parallel.
  Unique suffixed names per test, never a shared name, and no test asserts on
  a variable another test writes. `MCP_GATEWAY_PORT` in .6 is the exception it
  cannot avoid: it must run serialised, or set the process value inside the
  test's own guard.
- .9's positive half passes trivially if filesystem events do not work in the
  test environment at all. The assertion is on the resolved VALUE reaching the
  backend config, not on a reload being published — a published reload that
  changed nothing satisfies the weaker form.

## Seams

`expand_env_vars` is a private method with one call site
(`src/config/mod.rs:313`), so the overlay parameter is compiler-enforced at
that site — but a compiler guarantee is not a test, which is why .5, .6 and .8
drive `Config::load_with_overlay` end to end rather than calling
`expand_string` directly. The precedence and internal-`${VAR}` rows are the two
exceptions: those are properties of the overlay builder alone and are tested at
that level.
