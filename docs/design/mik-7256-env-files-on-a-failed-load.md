# MIK-7256 — a failed reload must not leave the process environment mutated

## Problem

`Config::load` applies every path in `env_files` to the process environment
before it validates anything (`src/config/mod.rs:198`, then `:303`
`dotenvy::from_path_override`). Every reload runs through it via
`load_config_patch` (`src/config_reload/mod.rs:1239`). A reload that fails —
parse error, validation error, shutdown abort, or the posture refusal — has
already overwritten process variables from the candidate file. The reload
reports failure; the environment keeps the new values, and every later reader
sees them — a `${VAR}` expansion resolves against the overridden value, and so
does every lazily-resolved `env:` reference, including capability credentials
read on each call. `from_path_override` overwrites existing variables, so this
is not additive-only. Backends are not among the readers: they are spawned
with a cleared environment (`src/transport/stdio.rs:39-75`) and see only the
values the config resolved for them.

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

**`${VAR}` is not the only convention, and the other one reads the process
environment at call time.** A second spelling, `env:NAME`, is resolved lazily
wherever the value is used, never through `expand_env_vars`:
`fetch_credential` accepts `env:VAR`, `{env.VAR}` and a bare `UPPER_SNAKE`
name for every capability credential and reads `std::env` on each call
(`src/capability/executor/credentials.rs:20-56`); `auth.bearer_token`
(`src/config/features/auth.rs:122`), `auth.api_keys[].key` (`:169`),
`agent_auth.agents[].hs256_secret` (`:267`) and `key_server.admin_token`
(`src/config/features/key_server.rs:139`) each resolve their own. Validation
reads it too, at `validate_env_reference` (`src/config/mod.rs:651`, four call
sites) and inline for agent key material (`:433`).

This constraint was missed in the first draft and it falsifies that draft's
central claim. `${VAR}` is not "where credentials live" — capability
credentials, the bearer token and the admin token all live behind `env:`. An
overlay consulted only by `expand_env_vars` reaches none of them.

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

**C is not sufficient.** It defends a stronger invariant than the ticket asks
for — *never* write the process environment — and that extra strength is what
breaks the `env:` convention. Under C a rotated capability credential
delivered by an env file would not take effect until restart, and a candidate
adding `auth.bearer_token: env:NEW_TOKEN` with the value in its own env file
would be rejected by validation. Both are exactly the hot-add case the
operator's constraint protects.

**D. Overlay for the evaluation; a real apply once the candidate is
accepted.** The env files the running gateway lists are re-read into a
temporary map and consulted by `${VAR}` expansion and by validation, as in C,
so nothing is written while the outcome is still unknown. When the reload is accepted —
after validation, after the posture check, after the shutdown abort could
still have fired — the files are applied for real with
the captured map, with the same later-wins precedence startup gets from
chained `dotenvy::from_path_override` calls. The commit applies what evaluation
read; it does not re-read the files.

**Chosen: D.** The ticket's invariant is that a *failed* reload leaves the
environment untouched, and D holds it: on every failing path the map is
dropped and nothing was written. On the succeeding path the process ends up
where a restart would have put it, so the one reader that resolves lazily —
capability credentials, through `fetch_credential` — keeps working with no
plumbing at all. The auth family resolves once at startup and is restart-only
regardless; the narrowing that follows is stated under Shape. After D the finding cannot be stated: there
is no reload outcome that mutates the environment without proceeding.

## What D costs

**`MCP_GATEWAY_*` set from an env file takes effect at the next config load,
not at this one.** Those reach the config through Figment's env layer
(`src/config/mod.rs:286`), which reads the process environment directly and
accepts no overlay, and the apply now happens after the candidate has been
evaluated. The value is applied, so the following reload or a restart picks it
up; the reload that introduced it does not. Everything else — `${VAR}`
expansion, every `env:` reference, capability credentials — reloads in full.

This is the whole of the narrowing, and it is smaller than the one put to the
operator when C was chosen: that one required a restart, this one does not.
Nothing the operator relies on is removed, so it is a notification rather than
a scope change. It is pinned by a test and logged at warn level when an
env file sets a `MCP_GATEWAY_*` key, so the lag is diagnosable rather than
silent. **The log names the key and never the value** — open PR #439 is
removing configured values from diagnostic output across the CLI and the
transport logs, and a new log that reintroduces one would land on top of that
work.

**A path ADDED to `env_files` still needs a restart.** The overlay and the
apply both use the running gateway's list, so a newly named file is neither
read nor applied until the gateway restarts — the same rule as before this
change, now for a stated reason rather than by accident. Editing the CONTENTS
of a listed file is the hot path and is unaffected. The watcher agrees
independently: `notify` watches are registered once before the event loop
starts and the callback cannot add more (open issue #453), so a newly named
env file would not be watched even if it were read.

**A `${VAR}` inside an env file resolves against the process environment
first, then against the same file.** `dotenvy`'s `apply_substitution` consults
`std::env::var` before its own per-file table (dotenvy 0.15.7,
`parse.rs:260-273`). Two cases, and they differ:

- *Same file*: `A=1` then `B=${A}`, with `A` absent from the process, resolves
  `B` to `1` — the per-file table carries it. Identical to startup. The first
  draft claimed this resolved to empty; that was wrong, and reading the crate
  is what settled it.
- *Across files*: each file gets its own table, so a later file referencing a
  variable an earlier one defined resolves to the process value or to empty.
  On the reload path the earlier file has not been applied yet, so it resolves
  to empty where startup would have resolved it to the earlier file's value.

The rule is therefore narrower than the first draft's: **on the reload path an
env file can reference its own values, but not another file's.** Documented,
and pinned by two cases rather than one.

**The overlay must strip a byte-order mark itself.** `remove_bom` is called
only from `Iter::load` and `Iter::load_override` (`iter.rs:30,48`), not on the
iterator path the overlay uses. A BOM-prefixed file loaded at startup yields
`FIRST_KEY`; parsed through `from_path_iter` it yields `\u{feff}FIRST_KEY`.
Without an explicit strip the overlay would silently disagree with startup
about the first variable of exactly those files. Named here because it is
invisible in every test that does not write a BOM.

**No design event on the watcher.** Under D an edit to a watched env file
genuinely changes the resulting config — the overlay re-reads it — so
`ReloadTrigger::EnvFile` (`src/config_reload/mod.rs:1227`),
`resolve_env_file_paths` (`:941`), `matching_env_file` (`:967`) and their six
tests (`src/config_reload/tests.rs:399,414,485,502,518,533`) all keep doing
what they claim. Nothing is deleted. An earlier draft of this design removed
them; that followed from option B and goes with it.

## Shape

Four changes, no signature churn at 35 call sites.

**`EnvOverlay`** — a newtype over `HashMap<String, String>`, private to
`src/config/mod.rs`, with two constructors and one reader:

- `EnvOverlay::none()` — empty. What startup passes.
- `EnvOverlay::from_paths(&[PathBuf]) -> Self` — **infallible, and that is a
  decision, not an omission.** For each existing path in order it opens the
  file, strips a leading BOM, iterates with `dotenvy::from_read_iter`, and
  inserts each pair; later files overwrite earlier ones, matching
  `from_path_override`'s precedence. A missing path is skipped and a parse
  error is logged at warn level and skipped — byte-for-byte the behaviour of
  `load_env_files_from_paths` today (`src/config/mod.rs:305`). A fallible
  builder would introduce a *new* error class into `Config::load`, and
  `load_config_or_default` turns any `Config::load` error into
  `Config::default()` (`src/config_persistence.rs:14-23`), which the admin-UI
  read-modify-write then writes to disk. A malformed env file would silently
  replace an operator's configuration with defaults. Parity with startup makes
  that unreachable rather than merely unlikely.

**Validation reads the overlay too.** `validate_env_reference`
(`src/config/mod.rs:651`) and the inline agent-key resolution (`:433`) are the
only two validate-time readers of `env:` — the first funnels four call sites
(`auth.bearer_token`, `auth.api_keys[].key`, `agent_auth.agents[].hs256_secret`,
`key_server.admin_token`), the second stands alone. Both take an
`&EnvOverlay`, consult it first and fall back to `env::var_os`, reached
through `validate` on the same parameter. Without this a candidate that adds
`auth.bearer_token: env:NEW_TOKEN` with the value in its own env file fails
validation, because the value is not in the process yet — the hot-add case,
failing at the last gate before it would have worked.

**One reader is lazy, and it is the one that matters.** `fetch_credential`
(`src/capability/executor/credentials.rs:22-56`) reads `std::env::var` on every
call, for all three conventions (`env:VAR`, `{env.VAR}`, a bare `UPPER_SNAKE`
name). It is not touched: by the time it runs on an accepted config the apply
has happened, and the alternative is threading an overlay handle into the
capability executor for a value the process will hold anyway. That is the whole
reason D exists.

`resolve_key`, `resolved_hs256_secret` and `resolve_admin_token` are **not**
lazy, and an earlier draft of this paragraph said they were. They run exactly
once, at startup: `ResolvedAuthConfig::try_from_config` resolves the bearer
token and every API key eagerly (`src/gateway/auth.rs:126-127,148`) and is
constructed once (`src/gateway/server/mod.rs:912`), beside the key-server admin
token (`:957`) and each agent HS256 secret (`:982`). Nothing reconstructs them
on a reload — and nothing should, because `auth`, `key_server` and `agent_auth`
are all in `tracked_sections` (`src/config_reload/mod.rs`), which makes an edit
to any of them restart-only by an older decision than this one.

So the narrowing, stated rather than implied: **a successful reload rotates
capability credentials and nothing else.** An operator who rotates
`auth.bearer_token` gets a reload that validates against the overlay and a
`restart_required` outcome, exactly as they do today for any auth edit. Making
those holders atomically reloadable is a larger change to the restart-only
boundary, it is what the review asked for, and it is OUT of this change's
scope — recorded as an observation, not filed, because nobody has asked for
live auth rotation.

**The apply happens on acceptance — and acceptance, not a non-empty diff, is
what gates it.** `load_config_patch` evaluates the candidate with an overlay and
returns it; the reload path applies at the point the reload is committed, after
validation, after the posture refusal (`src/config_reload/mod.rs:1500`), after
the shutdown abort (`:1517-1522`). Every earlier exit drops the snapshot and
leaves the process untouched.

The word *acceptance* is doing work the first draft left to the diff, and the
review found the gap. `load_config_patch` returns `Ok(None)` when the patch is
empty (`:1242-1243`) and `reload_outcome_locked` turns that into a `no_changes`
outcome and returns (`:1442-1450`) — a successful reload that never reaches the
publish. A pure credential rotation IS that case: the operator edits only the
env file, the watcher fires (`:1225`, "env file changed, triggering reload"),
the config bytes are identical, the patch is empty. Hanging the apply off the
non-empty branch would leave the change's own success case broken — the
rotation would take effect at the next reload that happened to change something
else, or never.

So the apply is a step of the accepted reload, not a step of applying a patch.
Both accepting exits run it: the `no_changes` return and the published one. The
empty patch stops being an early exit from the function and becomes what it
already is, a property of the patch.

**One snapshot, read once.** Evaluation and commit MUST NOT each read the files
from disk. `EnvOverlay::from_paths` produces the map; that same map is what the
commit applies, through a `set_var` loop over its entries rather than a second
`load_env_files_from_paths` call. Two independent reads would leave a window in
which the bytes validated and the bytes applied differ — a rotation landing
between them applies a value nothing checked. The overlay is also what makes
the two agree on *meaning*: it is built cumulatively, each file's `${VAR}`
references resolving against the entries earlier files already contributed and
falling back to the process, which is what the chained `from_path_override`
calls do at startup. A per-file table with no cumulative view resolves a
cross-file reference from the stale process value instead.

**Where the apply sits: after the last abort, immediately before the publish.**
The last way an accepted reload can still fail is the shutdown abort
(`:1517-1522`), which fires after `apply_patch` has already stopped and started
backends. The apply goes below it and above `self.live_config.set(new_config)`
(`:1524`). `set` is a lock write and cannot fail (`:281-283`), and there is no
await between the two, so no reader observes the new environment paired with the
old config, and no failure path exists between mutating the process and
committing the config. Apply-before-`apply_patch` would read better for backends
this reload restarts, and would reopen the ticket's exact defect: a shutdown
abort would leave the environment mutated with nothing published.

Named residual: a backend that this same reload restarts is spawned before the
new values land, so a `${VAR}` in its `env` map that the rotation changed
carries the old value until it next restarts. Bounded, not general — children
get `env_clear()` and only the keys the config names
(`src/transport/stdio.rs:40,71-73`), so nothing leaks in by inheritance, and a
capability credential is unaffected because `fetch_credential` reads per call.
Pinned by a test rather than left as a caveat.

**Both the overlay and the apply read the RUNNING gateway's `env_files` list,
never the candidate's.** A candidate is an unvalidated file on disk, and its
`env_files` list is part of what has not been validated. Building the overlay
from it would let an edited config name any path and have its contents
activated as credentials during evaluation; under D it is sharper still,
because acceptance would then write those contents into the process. So the
path list is an input to the load, not a field read out of the candidate:
`load_with_overlay` takes `&[PathBuf]` from the caller, and the reload path
passes the list the running gateway started with. A path the candidate ADDS is
parsed by nobody and applied by nobody — it takes effect at the next restart,
which is what adding a path already required (below). A path the candidate
REMOVES stays applied until restart, matching the fact that nothing unsets a
variable today either.

That leaves the hot-add workflow silent, and it should not be: an operator who
adds a path, a credential and a backend in one edit gets a reload that succeeds
with the credential resolved to empty. `${VAR}` expansion yields the empty
string rather than failing, so nothing refuses and the backend registers
broken. The design does not change what is applied — the restart-only rule
stands — but it does add a warn-level log when a `${VAR}` resolves empty at
reload while a candidate-added, unread env file defines that name. It names the
key and the file, never the value. The `env:` form needs no such log: it
resolves through `validate_env_reference`, which refuses, so the operator is
told by the refusal.

The same asymmetry answers the admin-UI write path, which revalidates through
`write_config` (`src/config_persistence.rs:42`) against the running
environment: an edit referencing a variable only a candidate-added env file
supplies is rejected in the `env:` form and warned in the `${VAR}` form. That
is the restart-only rule reaching the UI, not a defect. An overlay-aware
write-validation path — resolving a candidate against files the running process
has never read — would let the UI accept exactly the configuration a restart
would need, and it is OUT of scope for the same reason making Figment's env
layer overlay-aware is. This is also why `Config::load` keeps reading the list
out of the file: at startup the config on disk *is* the running config, and
there is no earlier list to prefer.

**`expand_env_vars(&mut self, overlay: &EnvOverlay)`** and
`expand_string(s: &str, overlay: &EnvOverlay)`. The only behavioural line is in
`expand_string`: consult `overlay.get(name)` first, fall back to `env::var`,
then to the `:-` default. Overlay-before-environment mirrors
`from_path_override`, which is what startup does — so a variable present in
both resolves the same way on both paths.

**`Config::load_with_overlay(path: Option<&Path>, env_files: &[PathBuf]) ->
Result<Config>`**, `pub(crate)`. Same body as `Config::load` with two lines
changed: it builds an `EnvOverlay` from the `env_files` ARGUMENT — the running
gateway's list, never the candidate's own `env_file_config.env_files` — instead
of calling `load_env_files_from_paths`, and passes it to `expand_env_vars`. `Config::load`
keeps its signature, calls `load_env_files_from_paths` exactly as today, and
expands with `EnvOverlay::none()` — byte-for-byte the current behaviour for all
35 call sites, which is why none of them is edited.

The two bodies share a private `load_inner(path, EnvSource)` with
`enum EnvSource<'a> { ApplyToProcess, Overlay(&'a [PathBuf]) }` — an enum, not
a boolean, so the call site says which it means without opening the signature,
and the overlay variant cannot be constructed without naming the list it reads.

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

Both supply the path list from **the config the running process actually
applied at startup**, not from the published snapshot and not from the
candidate. `LiveConfig` already keeps that second snapshot beside the published
one — `running`, "what the running process actually applied, fixed at startup"
(`src/config_reload/mod.rs:228-238`), reached through `running()` (`:253`).
`load_config_patch` already takes `&Arc<LiveConfig>` (`:1233-1235`) and
`mutate_and_reload_outcome_within` is a `ReloadContext` method with
`live_config` on `self` (`:1258-1262`), so the list arrives at both sites with
no new plumbing.

`running()` and not `get()`, and the difference is the whole point: the
published snapshot can carry a restart-only edit the process never applied. If
the list came from `get()`, a successful reload that ADDED an env-file path
would leave that path in the published config, and the NEXT reload would parse
and apply its contents — while `pending_restart_fields` was still telling the
operator a restart was required. The file would activate before the restart it
was documented to need, with nobody having validated it. Pinned by a test on
the reload that FOLLOWS a path-adding reload, not just on the path-adding
reload itself.

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
- **MIK.ENVFILE.2** Given a reload that succeeds, Then the running gateway's
  env files are applied to the process, so a variable they define is readable
  afterwards exactly as it would be after a restart.
- **MIK.ENVFILE.3** Given a reload whose candidate env file sets a variable
  that fails validation, When a backend is spawned afterwards, Then the child
  does not receive the candidate's value — it does not receive the variable at
  all, because `configure_child_environment` clears the environment and passes
  only the backend's own resolved `env` map.
- **MIK.ENVFILE.4** Given startup, Then env files are applied exactly as today
  — same variables, same override order, same final state.
- **MIK.ENVFILE.5** Given a reload that hot-adds a backend whose header or env
  references `${NEW_KEY}`, and an already-listed env file whose contents now
  define `NEW_KEY`, Then the running backend receives that value without a
  restart, and the value reaches the resolved config before the process
  environment is touched.
- **MIK.ENVFILE.6** Given an env-file edit that changes a `MCP_GATEWAY_*`
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

- **MIK.ENVFILE.10** Given a reload that adds an `env:` reference — an
  `auth.bearer_token`, an api key, an agent secret, an admin token, or a
  capability credential — whose value is defined only in an already-listed env
  file, Then the reload validates and the value is in use afterwards, with no
  restart. The criterion the first design would have failed.

- **MIK.ENVFILE.11** Given a candidate that ADDS a path to `env_files`, When
  the reload succeeds, Then no variable defined only in that new file is
  readable from the process or resolvable in the reloaded config — an
  unvalidated file cannot activate a credential by being named.

An earlier form required the gateway to report `env_files` as restart-required
after a content-only edit. Cut, not weakened: `pending_restart_fields` compares
the `env_files` *path list* (`src/config_reload/mod.rs:552`), which a content
edit does not change, and under D a content edit does not need a restart for
the values that matter.

## Docs corrected here

- `CHANGELOG.md:333` and `docs/DEPLOYMENT.md:596` — both describe a candidate
  config applying its `env_files` before validation. That stops happening; the
  apply moves to the point the reload is committed.
- `docs/DEPLOYMENT.md:177` — describes `env_files` without saying what a reload
  can and cannot pick up from one. It now needs both halves: `${VAR}` and
  `env:` values reload, a `MCP_GATEWAY_*` value lands one config load later.
- `src/config_reload/mod.rs:1485` and `src/config_reload/tests.rs:1271,1295` —
  comments explaining why the reload refusal message may not claim that nothing
  was applied. Under D a *refused* reload really does apply nothing, so the
  comments become wrong in the direction of understating the guarantee. The
  message itself stays out of scope (below); the comments are corrected.

## Out of scope

**Whether the `env_files` list should be reloadable.** Adding a path still
requires a restart. This change is about what a failing reload may do to the
process, and about the contents of paths already listed.

**Making Figment's env layer overlay-aware.** It would close the
`MCP_GATEWAY_*` lag entirely, and it is a change to how every configuration
key is resolved, not to how env files are handled. Disposal: recorded as an
observation, not filed — nobody has asked for it.

**Strengthening the reload refusal message.** Once a refused reload applies
nothing the gateway can honestly say so, and the message at
`src/config_reload/mod.rs:1478` was deliberately weakened over three review
rounds because it could not. Still out: it changes user-visible security
messaging and the tests guarding it assert the ABSENCE of those phrases, so
they keep passing either way. Disposal: filed as a follow-up, MikkoParkkola/mcp-gateway#463.

**`load_config_or_default` turning a config error into `Config::default()`.**
`src/config_persistence.rs:14-23` logs a warning and returns defaults for any
`Config::load` failure, and the admin-UI read-modify-write then writes that
result to disk — a YAML syntax error in a config an operator is editing can
replace it with defaults. Pre-existing, on a path this change does not create,
and `load_existing_or_default` (`:29-35`) already shows the fallible shape a
fix would take. This change avoids *adding* to it by keeping the overlay
builder infallible. Disposal: filed as a ticket, MikkoParkkola/mcp-gateway#462, because
whether the admin path should refuse rather than default is an operator's call,
not a repair.

## Open questions

- *Does the overlay reach the backends, given they do not inherit the gateway's
  environment?* — yes. `configure_child_environment` calls `env_clear` and then
  sets the backend's own resolved `env` map (`src/transport/stdio.rs:39-75`),
  and that map is what `expand_env_vars` writes into. Changed the design: it is
  why an overlay works at all during evaluation, and why option B's blank
  credential is silent rather than loud.
- *Does `dotenvy`'s iterator behave like `from_path_override` on a candidate
  file?* — no, in two ways, both read at source: no BOM strip
  (`iter.rs:30,48,58`) and `${VAR}` consulting `env::var` before the per-file
  table (dotenvy 0.15.7, `parse.rs:260-273`). Changed the design: added an
  explicit BOM strip, and the same-file/cross-file split above. The first draft
  read the second fact as "an env file cannot reference itself", which the
  crate contradicts — same-file references resolve.
- *Is `${VAR}` the only way a config value reaches the process environment?* —
  no, and this is what broke the first design. `env:` references are resolved
  lazily by six sites and validated by two more, all reading `std::env`
  directly. Found by reading every `env::var` caller under `src/`, prompted by
  a review finding. Changed the design: option C was chosen before this answer
  and is now insufficient; D exists because of it.
- *Which behaviour does the operator want to lose — `MCP_GATEWAY_*` on reload,
  or hot-add with a new credential?* — asked, answered: the `MCP_GATEWAY_*`
  narrowing, with hot-add preserved. Changed the design: option B was the
  chosen option before this answer and is now rejected. D narrows less than the
  option that answer selected, so the answer still holds a fortiori.
