# MIK-7256 — a failed reload must not leave the process environment mutated

## Problem

`Config::load` applies every path in `env_files` to the process environment
before it validates anything (`src/config/mod.rs:198`, then `:303`
`dotenvy::from_path_override`). Every reload runs through it via
`load_config_patch` (`src/config_reload/mod.rs:1239`). A reload that fails —
parse error, validation error, shutdown abort, or the posture refusal — has
already overwritten process variables from the candidate file. The reload
reports failure; the environment keeps the new values, and they leak two ways:
a later `${VAR}` expansion resolves against the overridden value, and any
backend spawned afterwards inherits it. `from_path_override` overwrites
existing variables, so this is not additive-only.

## Constraints, measured

Each verified at source.

**This crate cannot write an environment variable.** `std::env::set_var` is
`unsafe` in Rust 2024 and unsafe is denied (`src/lib.rs:25`,
`Cargo.toml:203`). The only writer available is `dotenvy::from_path_override`,
which applies a whole file and reports nothing about what it changed. Nothing
can be restored, and nothing can be applied by halves.

**One config consumer reads the real process environment and takes no
substitute.** `Self::figment` merges `Env::prefixed("MCP_GATEWAY_")`
(`src/config/mod.rs:286`) and `Config::load` extracts it a second time at
`:199`, deliberately after the apply — so an env file setting
`MCP_GATEWAY_PORT` reaches the config through Figment, not through `${VAR}`.
Figment reads the process environment itself and accepts no overlay.

**`${VAR}` expansion, by contrast, is entirely ours.** `expand_env_vars`
(`src/config/mod.rs:313-338`) walks backend headers, backend env and
capability directories, and resolves each `${NAME}` or `${NAME:-default}`
through one function, `expand_string` → `env::var` (`:330`). It is a private
method on `Config` with a single call site. Nothing outside the crate depends
on how it obtains a value.

**Backends do not inherit the gateway's environment.**
`configure_child_environment` calls `cmd.env_clear()` and then sets PATH, HOME,
TMPDIR and the backend's own `env` map (`src/transport/stdio.rs:39-75`). A
backend receives exactly the values the config resolved for it — so a value
that never entered the process environment still reaches the backend.

**Validation is not the point a reload is accepted.** `Config::load` returning
`Ok` only means the file parsed and validated. The posture refusal
(`src/config_reload/mod.rs:1478`) and the shutdown abort run afterwards. Any
fix that applies files "once the config is known good" still mutates before
those two.

## Options

**A. Snapshot the environment, restore it on failure.** Unbuildable, not
merely unattractive: restoring requires writing variables, which requires
`set_var`, which the first constraint forbids.

**B. The reload path stops applying env files, and stops reading them.**
Rejected on the operator's constraint. Hot-adding a backend is a headline
feature of this product, and a hot-added backend usually arrives with a new
credential. `expand_string` returns `""` for a variable that is not set — no
error, no warning (`src/config/mod.rs:330`). So a backend added by reload with
`${NEW_API_KEY}` in its headers would register with a blank credential and
fail at first call, with nothing in the config pointing at why. The narrowing
is not "you must restart to pick up the value"; it is "the gateway silently
accepts a broken backend".

**C. Parse the candidate's env files into a temporary map; overlay it on the
real environment for the length of the evaluation; never write the process
environment.** The map lives on the stack, is threaded into
`expand_env_vars`, and is dropped when the evaluation ends — whether it
succeeded, failed validation, was refused by the posture check, or aborted at
shutdown. There is no path on which anything is left behind, because nothing
is ever applied.

**Chosen: C.** After it the finding cannot be stated: the reload path contains
no code that writes the environment. It is also the only option that keeps
hot-add-with-a-new-secret working, which B does not and A does only by
mutating first and repairing after.

## What C costs

**One kind of variable stops being reloadable: `MCP_GATEWAY_*` set from an env
file.** Those reach the config through Figment's env layer
(`src/config/mod.rs:286`), which reads the process environment directly and
cannot be handed an overlay. Under C a candidate env file that changes
`MCP_GATEWAY_PORT` has no effect until restart. Everything routed through
`${VAR}` — backend headers, backend env, capability directories, which is
where credentials live — reloads normally.

This is a narrowing of user-visible behaviour, put to the operator with that
cost stated, and chosen by them over option B.

The cost is bounded and it is the small half. `MCP_GATEWAY_*` in an env file
duplicates a key the YAML already carries; the YAML is what the reload is
reading. Credentials are the half that must keep working, and they do.

**Env-file values inside env files resolve against the process environment,
not against the candidate.** `dotenvy`'s `apply_substitution` consults
`std::env::var` before its own per-file table (`parse.rs:260-265`), so a
`${VAR}` *inside* an env file cannot see a value the overlay holds — the
overlay is not in the environment, which is the entire point. Consequences,
both stated rather than fixed: a later env file referencing a variable an
earlier one defined resolves to the process value or to empty, and a file that
redefines a variable the process already holds and then references it resolves
to the process value. On startup both resolve to the file's value, because
startup really does apply as it goes.

One rule covers both, and it is the same rule the `MCP_GATEWAY_*` cost states:
**on the reload path the candidate's env files supply values to the YAML, and
not to each other.** Documented, and pinned by a test rather than left as a
surprise.

**The overlay must strip a byte-order mark itself.** `remove_bom` is called
only from `Iter::load` and `Iter::load_override` (`iter.rs:30,48`), not on the
iterator path the overlay uses. A BOM-prefixed file loaded at startup yields
`FIRST_KEY`; parsed through `from_path_iter` it yields `\u{feff}FIRST_KEY`.
Without an explicit strip the overlay would silently disagree with startup
about the first variable of exactly those files. Named here because it is
invisible in every test that does not write a BOM.

**No design event on the watcher.** Under C an edit to a watched env file
genuinely changes the resulting config — the overlay re-reads it — so
`ReloadTrigger::EnvFile` (`src/config_reload/mod.rs:1227`),
`resolve_env_file_paths` (`:941`), `matching_env_file` (`:967`) and their six
tests (`src/config_reload/tests.rs:399,414,485,502,518,533`) all keep doing
what they claim. Nothing is deleted. An earlier draft of this design removed
them; that followed from option B and goes with it.

## Shape

Three changes, no signature churn at 35 call sites.

**`EnvOverlay`** — a newtype over `HashMap<String, String>`, private to
`src/config/mod.rs`, with two constructors and one reader:

- `EnvOverlay::none()` — empty. What startup passes.
- `EnvOverlay::from_paths(&[PathBuf]) -> Result<Self>` — for each existing
  path in order, open the file, strip a leading BOM, `dotenvy::from_read_iter`,
  and insert each pair. Later files overwrite earlier ones, matching
  `from_path_override`'s precedence. A missing path is skipped, exactly as
  `load_env_files_from_paths` skips it today; a parse error is returned, so a
  malformed candidate env file fails the reload instead of half-loading.
- `get(&self, name: &str) -> Option<&str>`.

**`expand_env_vars(&mut self, overlay: &EnvOverlay)`** and
`expand_string(s: &str, overlay: &EnvOverlay)`. The only behavioural line is in
`expand_string`: consult `overlay.get(name)` first, fall back to `env::var`,
then to the `:-` default. Overlay-before-environment mirrors
`from_path_override`, which is what startup does — so a variable present in
both resolves the same way on both paths.

**`Config::load_with_overlay(path: Option<&Path>) -> Result<Config>`**,
`pub(crate)`. Same body as `Config::load` with two lines changed: it builds an
`EnvOverlay` from `env_file_config.env_files` instead of calling
`load_env_files_from_paths`, and passes it to `expand_env_vars`. `Config::load`
keeps its signature, calls `load_env_files_from_paths` exactly as today, and
expands with `EnvOverlay::none()` — byte-for-byte the current behaviour for all
35 call sites, which is why none of them is edited.

The two bodies share a private `load_inner(path, EnvSource)` with
`enum EnvSource { ApplyToProcess, Overlay }` — an enum, not a boolean, so the
call site says which it means without opening the signature.

`load_with_overlay` is `pub(crate)` because `config_persistence` is a different
module and must reach it, and nothing outside the crate should. Its documented
invariant is that it does not mutate the process environment.

**Who calls it: every config read that happens inside a running gateway.** A
rule, not a list, because a list goes stale the moment a reader is added. Two
readers satisfy it today, found by reading every caller of `Config::load`,
`load_config_or_default` and `load_existing_or_default` under `src/gateway/`,
`src/config_reload/` and `src/a2a/`:

- `load_config_patch` (`src/config_reload/mod.rs:1239`) — evaluates a candidate
  before a reload.
- `mutate_and_reload_outcome_within` (`:1405`) — the admin-UI
  read-modify-write path. It reads through
  `config_persistence::load_config_or_default`, which calls `Config::load`
  (`src/config_persistence.rs:16`), so today it applies the candidate's env
  files *before* the mutation closure has run, before the file is written, and
  before the reload that may then be refused. A rejected mutation returns
  `ConfigMutation::Rejected` having changed no file and already changed the
  environment. Found by review; the first draft named only `load_config_patch`.

`load_config_or_default` keeps its signature — five of its seven callers are
CLI commands (`src/commands/setup.rs`, `src/commands/add_remove.rs`) where
applying is correct. It gains one `pub(crate)` sibling that delegates to
`Config::load_with_overlay`. `src/config_reload/mod.rs:1688` is not one of the
two: its own comment says it is the CLI acting on a config file no gateway is
serving, so there is no running process whose environment could be corrupted.

`load_env_files(&self)` (`src/config/mod.rs:276`) is a thin wrapper over
`load_env_files_from_paths` reached only from `src/config/tests.rs`. Already
unwired before this change and not made so by it, so it stays. Recorded as an
observation, not a ticket.

## Acceptance criteria

- **MIK.ENVFILE.1** Given a running gateway, When a reload fails for any reason
  — parse, validation, posture refusal, or shutdown abort — Then process
  environment variables are identical to before the reload.
- **MIK.ENVFILE.2** Given a reload that succeeds, Then process environment
  variables are still identical to before the reload.
- **MIK.ENVFILE.3** Given a reload whose candidate env file sets a variable the
  process already holds, Then a backend spawned afterwards that does not
  reference it receives the original value.
- **MIK.ENVFILE.4** Given startup, Then env files are applied exactly as today
  — same variables, same override order, same final state.
- **MIK.ENVFILE.5** Given a reload that hot-adds a backend whose header or env
  references `${NEW_KEY}`, and a candidate env file defining `NEW_KEY`, Then the
  running backend receives that value, without a restart and without the process
  environment being changed.
- **MIK.ENVFILE.6** Given a candidate env file that changes a `MCP_GATEWAY_*`
  variable, Then the reloaded config keeps the value the process has had since
  startup — the stated narrowing, pinned so it cannot regress silently in
  either direction.
- **MIK.ENVFILE.7** Given an admin-UI config edit against a running gateway,
  When the mutation is rejected or the write fails, Then process environment
  variables are identical to before the edit.
- **MIK.ENVFILE.8** Given a BOM-prefixed env file, Then the reload path
  resolves its first variable to the same name and value startup does.
- **MIK.ENVFILE.9** Given an env file whose contents change under a running
  gateway, Then a reload is triggered and the new `${VAR}` values reach the
  running backends — the behaviour option B would have removed.

An earlier form required the gateway to report `env_files` as restart-required
after a content-only edit. Cut, not weakened: `pending_restart_fields` compares
the `env_files` *path list* (`src/config_reload/mod.rs:552`), which a content
edit does not change, and under C a content edit does not need a restart for
the values that matter.

## Docs corrected here

- `CHANGELOG.md:333` and `docs/DEPLOYMENT.md:596` — both describe a candidate
  config applying its `env_files` before validation. That stops happening.
- `src/config_reload/mod.rs:1485` and `src/config_reload/tests.rs:1271,1295` —
  comments explaining why the reload refusal message may not claim that nothing
  was applied. Correct when written; the reload path applies nothing after this.
- `docs/DEPLOYMENT.md:177` — describes `env_files` without saying what a reload
  can and cannot pick up from one. It now needs both halves: `${VAR}` values
  reload, `MCP_GATEWAY_*` and env-file-internal `${VAR}` do not.

## Out of scope

**Whether the `env_files` list should be reloadable.** Adding a path still
requires a restart. This change is about what a failing reload may do to the
process, and about the contents of paths already listed.

**Making Figment's env layer overlay-aware.** It would close the
`MCP_GATEWAY_*` narrowing, and it is a change to how every configuration key is
resolved, not to how env files are handled. Disposal: recorded as an
observation, not filed — nobody has asked for it.

**Strengthening the reload refusal message.** Once the reload path applies
nothing the gateway can honestly say so, and the message at
`src/config_reload/mod.rs:1478` was deliberately weakened over three review
rounds because it could not. Still out: it changes user-visible security
messaging and the tests guarding it assert the ABSENCE of those phrases, so
they keep passing either way. Disposal: filed as a follow-up.

## Open questions

- *Does the overlay reach the backends, given they do not inherit the gateway's
  environment?* — yes. `configure_child_environment` calls `env_clear` and then
  sets the backend's own resolved `env` map (`src/transport/stdio.rs:39-75`),
  and that map is what `expand_env_vars` writes into. Changed the design: it is
  why C works at all, and why option B's blank credential is silent rather than
  loud.
- *Does `dotenvy`'s iterator behave like `from_path_override` on a candidate
  file?* — no, in two ways, both read at source: no BOM strip
  (`iter.rs:30,48,58`) and `${VAR}` resolving against the real environment
  first (`parse.rs:260-265`). Changed the design: added an explicit BOM strip
  and the "env files supply values to the YAML, not to each other" rule, plus
  MIK.ENVFILE.8.
- *Which behaviour does the operator want to lose — `MCP_GATEWAY_*` on reload,
  or hot-add with a new credential?* — asked, answered: the `MCP_GATEWAY_*`
  narrowing, with hot-add preserved. Changed the design: option B was the
  chosen option before this answer and is now rejected.
