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

**One config consumer reads the real process environment, and the library
offers no way to redirect it.** `Self::figment` merges
`Env::prefixed("MCP_GATEWAY_")` (`src/config/mod.rs:286`) and `Config::load`
extracts it a second time at `:201-203`, deliberately after the apply call at
`:199` — so an env
file setting `MCP_GATEWAY_PORT` reaches the config through Figment, not
through `${VAR}`. `Env` reads `std::env::vars_os()` and takes no substitute.
This is the one constraint that cannot be met by passing an overlay to an
existing function, and it is why `EffectiveEnv` below is a provider of our own
rather than a modified `Env`.

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
sites) and inline for agent key material (`:433`). And `SecretResolver::resolve`
expands `{env.NAME}` in any resolved string on every call
(`src/secrets.rs:82`), reached from webhook signing
(`src/gateway/webhooks/mod.rs:32`), secret injection
(`src/secret_injection.rs:34`) and the capability executor
(`src/capability/executor/mod.rs:44`).

**The rule, so the enumeration cannot go stale silently: every reader that
resolves an operator-declared reference — `${VAR}`, `env:VAR`, `{env.VAR}`, a
bare credential name — takes the overlay and consults it before the process.
Readers of process infrastructure do not.** `PATH`, `HOME`, `TMPDIR`,
and `NO_COLOR` are not declared by a config author and are not env-file
territory; they keep reading `std::env` directly. The `MCP_GATEWAY_*` knobs are
NOT in that set, and an earlier form of this sentence put them there: they are
config-bound, reach the config through `EffectiveEnv`, and where one is read
directly — `MCP_GATEWAY_FIREWALL_SKIP_KEYS` is — the read goes through
`LiveEnv` like any other. A knob an operator sets in an env file and expects a
reload to honour is env-file territory by authorship, whatever its prefix. The
line between the two sets is authorship, not mechanism, and it is what a new
reader has to be placed on. The mechanical half is a test, not a convention:
see the source-scan row in the test plan.

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

**C was rejected, and the rejection is withdrawn.** It read as insufficient
only while the overlay was a stack temporary discarded at the end of the
evaluation. An overlay that SURVIVES acceptance answers both objections, and D
below is that overlay with a publish step. The reasoning is kept because it is
what the publish step exists to defeat: C as originally written defends a
stronger invariant than the ticket asks for — *never* write the process
environment — and that extra strength is what breaks the `env:` convention.
Under C a rotated capability credential delivered by an env file would not
take effect until restart, and a candidate adding `auth.bearer_token:
env:NEW_TOKEN` with the value in its own env file would be rejected by
validation. Both are exactly the hot-add case the operator's constraint
protects.

**D. Overlay for the evaluation; publication once the candidate is
accepted.** The env files the running gateway lists are re-read into a
temporary map and consulted by `${VAR}` expansion and by validation, as in C,
so nothing is written while the outcome is still unknown. When the reload is
accepted — after validation, after the posture check, after the shutdown abort
could still have fired — the captured map is PUBLISHED: it replaces the
overlay every lazy `env:` reader consults, and the process environment is not
touched at all. The commit applies what evaluation read; it does not re-read
the files, and it does not call `set_var`.

An earlier draft committed by writing the process environment, and the review
killed it at source. `std::env::set_var` is `unsafe` under edition 2024
(`Cargo.toml:4`) and this crate carries `#![deny(unsafe_code)]`
(`src/lib.rs`), which `src/config/tests.rs:31` already says in words. There is
no `unsafe` block available to write, so a commit that mutates a running
process is not a design this repository can express. `from_path_override` is
not an escape either: it re-reads the files AND mutates the same live process.
The startup path is safe for the same reason it always was — it runs before
any thread is spawned, and it is the only place that mutation is sound.

**Chosen: D.** The ticket's invariant is that a *failed* reload leaves the
environment untouched, and D holds it: on every failing path the map is
dropped and nothing is published. It holds it structurally rather than
carefully: no reload path writes the process environment, so there is no
ordering to get right and no partial state to reason about. The one reader
that resolves lazily — capability credentials, through `fetch_credential` —
sees the rotation because it consults the published overlay first. The auth
family resolves once at startup and is restart-only regardless; the narrowing
that follows is stated under Shape. After D the finding cannot be stated:
there is no reload outcome that mutates the environment, failing or otherwise.

**Terminology, because the rest of this document uses one word for two
things.** *Apply* means publishing the captured map to the shared `LiveEnv`
cell, which is what every runtime reader consults. The process environment is
written in exactly one place, `Config::load` at startup, before any thread
exists. Where a sentence below says a value is *applied* on the reload path,
it means published.

## What D costs

**Nothing about an env file is restart-only that is not restart-only from the
YAML file too.** `${VAR}` expansion, every `env:` reference, capability
credentials and `MCP_GATEWAY_*` keys all reach the config on a reload:
the first three through the overlay their readers now take, the last through
`EffectiveEnv`. What remains is the ordinary restart-required set, and it is a
property of the FIELD rather than of where the value came from.
`MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND` reaches
`server.allow_unauthenticated_network_bind`, read once inside `run` at bind
time (`src/gateway/server/mod.rs:1266`); a listener is already bound, so no
mechanism short of a restart can move it. Those fields are in
`tracked_sections`, so the reload path already reports them as pending
restart, and it reports an env-file-sourced value on exactly the same terms as
a YAML-sourced one. Two earlier drafts of this section were wrong in opposite
directions — one said "the next reload", true only of the `set_var` commit the
review killed, the other said "the next restart", true only while the Figment
gap was being deferred.

**What D does cost: a reader outside this crate's config path still sees the
startup process environment.** The overlay reaches every reader enumerated
above because each one is ours to change. A dependency that calls
`std::env::var` for itself is not, and would keep a startup value until the
next restart. No such reader is known today — the enumeration is a walk of the
crate, and the source-scan case in the test plan is what keeps it a walk
rather than a memory — but a future dependency could introduce one silently,
which is the residual and is recorded as one.

**No diagnostic names a value.** Where the reload path reports a key — a
restart-required field, a refused reference, an unread candidate file — it
names the key and the file and never the value. Open PR #439 is removing
configured values from diagnostic output across the CLI and the transport
logs, and a new log reintroducing one would land on top of that work.

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

- *Same file, referent absent from the process*: `A=1` then `B=${A}` resolves
  `B` to `1` — the per-file table carries it. Identical to startup. The first
  draft claimed this resolved to empty; that was wrong, and reading the crate
  is what settled it.
- *Referent present in the process*: the process value wins, whichever file
  defines `A`. Startup makes this benign, because startup has just written
  `A` itself. On the reload path nothing writes the process any more, so the
  process still holds the value from STARTUP — and `B` keeps resolving to it
  after every subsequent rotation of `A`, permanently, with nothing said.

The second case is the whole problem, and it is worse than the "documented
divergence" an earlier draft accepted: not a value that resolves empty and is
noticed, but a rotated secret that silently keeps its old value for the life
of the process. Across files it is the common shape; within one file it
appears as soon as the referenced key was applied at startup.

**So a reload REFUSES a config whose env files substitute a key those same env
files define.** Each listed file is read ONCE into a buffer, and both the scan
and `dotenvy` consume that buffer — the parser through `from_read_iter`, never
a second `from_path`. Two reads of the same path are two different files
whenever anything writes between them, and the reload is triggered by a watcher
on exactly those paths, so the interleaving is the expected case rather than an
exotic one: a scan reading a clean file and a parser reading a rewritten one
publishes the substitution the refusal exists to prevent. One scan of that
buffer for a substitution naming a `K` that appears as a key in any of them,
self included; a match ends
the reload with the file and the key named, and neither value. **Both spellings
count.** `dotenvy` substitutes the unbraced `$K` as well as `${K}`: the `{`
merely selects `SubstitutionMode::EscapedBlock` over `Block`, and the unbraced
branch substitutes as soon as a non-name character terminates it
(`dotenvy-0.15.7/src/parse.rs:171-213`). A scan matching only the braced form
would refuse `B=${A}` and accept `B=$A`, which resolves identically and carries
exactly the defect this refusal exists to prevent. The scan reads only tokens
`dotenvy` would itself substitute: either spelling inside a `#` comment, inside
a single-quoted value, or escaped is inert to the parser and so inert here. Matching those would refuse a reload over bytes that change no
value — a refusal keyed on text the parser ignores is a false positive by
construction, and the case is cheap to hold with three fixture lines. Nothing is
published, which is the invariant this change already holds on every other
refusing path.

Classifying which tokens `dotenvy` would substitute is a small piece of that
parser restated in our code, which is the drift this design refuses elsewhere —
so it is not left to a reading. Every fixture in the refusal cases is asserted
against `dotenvy`'s own parse of the same bytes: a fixture the scan refuses must
be one where `dotenvy` substitutes, and a fixture it accepts must be one where
`dotenvy` does not. The library is the oracle for its own lexical rules, and a
rule we get wrong fails a test rather than shipping as a false positive or a
silent miss.

Refusal, not a warn, and not our own expander. A warn leaves a wrong value in
service and asks an operator to read logs to find out; re-implementing
substitution against a cumulative map forks `dotenvy`'s parser, and the BOM
finding below is what that class of divergence costs. Refusing is the only one
of the three after which the finding cannot be restated.

The cost is stated plainly: a config that starts fine can now fail to reload,
because startup applies the files in order and genuinely resolves the chain.
An operator hits this only by using an env-file variable inside another env
file — the fix is to write the literal, and the refusal says so. Startup
behaviour is unchanged.

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
them; that followed from option B and goes with it. `resolve_env_file_paths`
stays the resolver and keeps its behaviour; what moves is WHO calls it and
WHEN — startup only, expanding each entry as it is applied and in that order,
never the whole list up front. Startup ends holding the resulting
`ResolvedEnvFiles`, which the watcher binds instead of resolving the list again
at `:1011-1014`. "Once" describes the number of TIMES the list is resolved, not
a single whole-list pass: per the Shape rule, expansion happens per open,
against the overlay as it stands at that point. One consequence is a seam:
the expansion reaches its home through an injected resolver rather than
calling `dirs::home_dir()` inline as `src/config/mod.rs:291-292` does today.
That is what lets a test install a resolver which fails after startup, so a
second resolution is impossible rather than merely unobserved — an outcome
assertion cannot tell the two apart, because a re-resolving implementation
agrees with itself. `matching_env_file` goes
on matching a changed file against that list, which is the same list it
matched against before.

## Shape

No signature churn at the 35 `Config::load` call sites: everything below is
additive, and the existing entry point keeps today's behaviour exactly.

**`EnvOverlay`** — a `HashMap<String, String>` and the set of keys the env
files own, private to `src/config/mod.rs`, with three constructors and one
reader:

- `EnvOverlay::none()` — empty map, empty owned set. What a gateway with no
  env files configured runs on.
- `EnvOverlay::from_paths_checked(&[PathBuf], previous: &EnvOverlay) ->
  Result<Self, EnvFileError>` — what a RELOAD calls. Same resolution, same
  precedence, same union; but the required set is the set of paths that were
  PRESENT AT THE LAST SUCCESSFUL LOAD, carried by `previous` alongside the owned
  set and the baseline. A path in that set which no longer exists, or which
  exists and fails to open or to parse, is an `Err`; and on `Err` the previous overlay stands unchanged and the
  reload is rejected with a diagnostic naming the file and the line.
  **The asymmetry with `from_paths` is the decision.** At startup a truncated
  file yields the pairs before the bad line and a warning, which is byte-for-byte
  what ships today and what a running operator has already booted on. On a
  reload the same partial read is a silent revocation: a key the previous
  overlay owns and the truncated file no longer supplies is indistinguishable
  from a key the operator deliberately deleted, so one stray character in a
  credential file unsets a live credential for every holder that resolves
  through it. A refused reload changing nothing is the rule the rest of this
  design already runs on; this is that rule reaching the file layer.
  **A file that disappears is the same event as a file that truncates**, and
  checking existence against the previous load rather than against nothing is
  what makes them one case: a path listed but absent at the last load is still
  skipped, exactly as today, so an optional env file that has never existed does
  not break every reload. What cannot happen is revocation by absence.
  Deliberately retiring an env file means removing it from the configuration,
  which is a config edit, which is a reload that carries its own intent.
- `EnvOverlay::from_paths(&[PathBuf], previous: &EnvOverlay) -> Self` — the
  map from the files, and an owned set of its own keys unioned with
  `previous`'s. Startup passes `&EnvOverlay::none()`; a reload does not call
  this constructor at all, it calls `from_paths_checked`. The previous overlay is a parameter rather
  than a field the builder reaches for because the union is the whole of what
  makes a removal durable (below), and a caller that forgets it should not
  compile. **Infallible, and that is a decision, not an omission.** For each existing path in order it opens the
  file, strips a leading BOM, iterates with `dotenvy::from_read_iter`, and
  inserts each pair; later files overwrite earlier ones, matching
  `from_path_override`'s precedence. **The constructor never expands anything.** It receives absolute paths and
  opens them. `~` is resolved ONCE, by startup, in the loop startup already
  has: each path is expanded immediately before startup opens it, so a `HOME`
  an earlier file set still governs a later `~/...` exactly as it does today
  (`src/config/mod.rs:290-306` expands and applies inside one iteration).
  What is new is only that the absolute path is RECORDED as it is opened. That
  recorded sequence is what the watcher binds
  (`src/config_reload/mod.rs:1011-1014`) and what every later reload re-reads.
  Startup's behaviour does not move — resolving the whole list up front WOULD
  move it, and an earlier draft of this paragraph said so, which would have
  changed which file a `~/...` entry after a `HOME`-setting file reads.
  Three consumers, one resolution, and nothing to
  disagree about — the earlier design had the reload re-expand, and the rule
  governing that re-expansion was wrong three times running, each time about a
  platform detail rather than about this change: `dirs` falls back to the
  passwd entry when `HOME` is empty as well as when it is unset
  (`dirs-sys-0.5.0/src/lib.rs:33-37`), Windows reads a known folder and
  consults `HOME` not at all, and startup itself mutates `HOME` between one
  path's expansion and the next because it applies each file inside the same
  loop (`src/config/mod.rs:289-309`). A rule that has to be right about all
  three is a rule this change has no reason to own. Resolving once is right
  about all three by construction, because there is no second resolution to be
  right about.
  The one case this leaves — an env file that now sets a different `HOME`, so
  a restart would resolve a `~/...` entry somewhere else while the running
  gateway keeps its recorded path — is REPORTED rather than accepted, and
  reporting it costs no second resolution. Two facts the reload already holds
  decide it: the raw `env_files` list still carries the `~` spellings even
  though `ResolvedEnvFiles` does not, and the new overlay knows which keys its
  files ASSIGNED. Any `~` entry plus any assignment of `HOME` is
  restart-required — the assignment, not a changed value. Comparing values
  would miss a file that sets `HOME` and a later file that puts it back, which
  leaves the merged value identical while a restart still resolves the entry
  between them somewhere else; a rule that asks only *was `HOME` assigned*
  cannot have an intermediate state to miss, because it never looks at states.
  It over-reports when a file assigns the value `HOME` already had, which
  costs a restart notice nobody needed and is the same trade as the platform
  one below. Reported alongside the added-path case
  (`pending_restart_fields`, `src/config_reload/mod.rs:552`). Deliberately
  unconditional on platform: on Windows `dirs::home_dir()` ignores `HOME` and
  the report is unnecessary, and it is still the right trade — an
  unnecessary restart notice is a nuisance, a silent divergence between a
  running gateway and its own restart is the defect this change exists to
  remove, and conditioning the rule would put back the platform knowledge
  whose absence is the point.

  A missing path is skipped. A parse error
  ENDS that file at the offending line, keeping the pairs before it and taking
  none after it, then moves to the next file with a warning — byte-for-byte the
  behaviour of `load_env_files_from_paths` today, which calls
  `dotenvy::from_path_override` and gets exactly that: the iterator applies each
  pair as it goes and returns `Err` at the first line it cannot parse
  (`src/config/mod.rs:303-306`). Skipping the bad line and continuing would be
  the more obvious reading of "warn and skip", and it would publish assignments
  startup would never have applied — a credential live on a reload and absent
  after the next restart. A fallible
  builder would introduce a *new* error class into `Config::load`, and
  `load_config_or_default` turns any `Config::load` error into
  `Config::default()` (`src/config_persistence.rs:14-23`), which the admin-UI
  read-modify-write then writes to disk. A malformed env file would silently
  replace an operator's configuration with defaults. Parity with startup makes
  that unreachable rather than merely unlikely.

  **The warning is ours, and it never carries `dotenvy`'s message.**
  `Error::LineParse(line, index)` formats as `Error parsing line: '<line>',
  error at line index: <n>` (`dotenvy-0.15.7/src/errors.rs:40-44`) — the whole
  offending line, so a malformed `TOKEN=secret` is a secret in the log. The
  reload logs the file path, the line NUMBER and a category, never the line and
  never `{e}`. This is not only a new requirement: the startup loader already
  logs `Failed to load env file {expanded}: {e}` (`src/config/mod.rs:305`) and
  has the leak today. Fixing it is smaller than a ticket describing it, so it is
  fixed here and the fixture asserting the value never reaches a log covers both
  call sites.

- `EnvOverlay::resolve(&self, name: &str) -> Option<String>` — the single
  reader every overlay-aware site calls. It implements the resolution table
  below and states no semantics of its own. One method rather than a `get()` each caller pairs with
  its own fallback, because the owned-key rule is exactly the part a caller
  would get wrong, and eight sites getting it right by convention is seven
  more chances than the type needs to give them.
- `EnvOverlay::effective_vars(&self) -> BTreeMap<String, String>` — for the
  reader that ITERATES rather than asks. `config_scanner` walks the whole
  environment looking for backend endpoints (`env::vars()`,
  `src/discovery/config_scanner.rs:212`), and a per-key `resolve` gives it
  nothing to walk. Defined BY the table below rather than beside it: the
  process environment, with each owned key's row applied — the overlay's value
  where the row says value, the baseline where it says baseline, absent where
  it says unset. Like `resolve` it states no semantics of its own, which is the
  whole point of naming it here instead of letting the scanner keep reading the
  process directly. ENVFILE.19b asserts the scanner sees a rotated endpoint.

#### What a key resolves to — the one statement

This table is the ONLY definition of a key's value after startup. `resolve`,
`EffectiveEnv`, the child-spawn path, the config provider, the firewall's
free-text list and every acceptance criterion CITE it; none of them restates
it. Owned means the key appears in the cumulative union the overlay carries.

| overlay owns it | present in the current files | baseline captured | resolves to |
|---|---|---|---|
| no | — | — | `std::env::var_os`, the process untouched |
| yes | yes | — | the current file value |
| yes | no | yes | the baseline — the process value from before any env file loaded |
| yes | no | no | unset |

Row three is the one an implementation drops: an owned key that vanishes from
the files restores what the shell exported, and only a key the files
INTRODUCED disappears entirely. An earlier draft had `resolve` answer "absent
means unset" for every owned key, which contradicts the baseline the same
document requires two sections earlier — three reviewers found the collision
independently, each through a different consumer, which is the argument for one
owner rather than four careful readings.

**A third site reads operator-named keys at launch, not per call.**
`StdRuntimeCommandRunner::run` copies each `runtime.profiles.*.env_keys` name
out of `std::env::var_os` into a runtime child
(`src/runtime/provider.rs:651`). The names are operator-supplied, so they may
be env-file keys, and after this change a rotated value is not in the process
for it to find. `run` takes the `&EnvOverlay` alongside the `env_keys` slice
it already receives and resolves through it; a key the operator removed is
then absent from the child rather than present with a stale value. This is the
third reader the enumeration missed — first `SecretResolver::resolve`, now
this — which is the argument for the rule and the source scan over any list.

**The reported set is derived, never a list of four.** An earlier draft named
four eager authentication forms and reported a rotation only when the changed
key was one of them. A fixed list is wrong the moment a consumer is added, and
it was already wrong when written, and the corrected citation shows why a
LIST cannot be the mechanism: `src/attestation/wiring.rs:117-119` reads
the attestation mode, the signing key AND the key id with `std::env::var` at
startup — three reads on consecutive lines, of which an earlier draft named two —
`src/gateway/server/mod.rs:591-592` reads the key id a second time when it
constructs the provenance signer, and
`src/attestation/launcher.rs:86` reads the rollback flag the same way. None is
an authentication form, all three are startup-only, and a rotated signing key
that goes unreported is the exact failure this reporting exists to prevent.
So the reported set is the intersection of the changed keys with the
startup-only consumers the REGISTRY holds — attestation included, and whatever
registers next included without editing this paragraph. The scan's job is to
prove the registry has no gaps, not to be the registry: a set assembled by
grepping at build time cannot be read by the running process that has to
report on it. The list of four is
gone rather than extended: extending it leaves the finding statable one
consumer later.

**And the scan itself missed two, which is the argument for what it matches
on.** `MCP_GATEWAY_FIREWALL_SKIP_KEYS` is read with `std::env::var`
(`src/security/firewall/input_scanner.rs:72`) and keeps its startup value, so
an operator narrowing a firewall exclusion during an incident gets the old set
until a restart. `src/discovery/config_scanner.rs:212` iterates `env::vars()`
through an aliased import, which no scan spelled `std::env::var` can see, and
it discovers backend endpoints — so a rotated endpoint stays at its startup
value with nothing reporting it. Both route through `LiveEnv`, and both get a
behavioural case rather than a scan entry, because the scan is what missed
them. What the scan does and does not reach is stated once, in the test
plan's source-scan row, and not restated here — this paragraph asserted a reach
the plan records as a residual, and two documents describing one mechanism is
how a check acquires a capability nobody built. What belongs to the design is
the consequence: a reader the scan cannot see needs a behavioural case, so the
prefix-wide exemption is replaced by named, reviewed call sites. An exemption
covering a prefix covers every future reader that happens to start with it.

**`EffectiveEnv` — the reload's environment as a Figment provider.** Figment merges
`Env::prefixed("MCP_GATEWAY_").split("__")` over the YAML file
(`src/config/mod.rs:286`), and that provider reads `std::env::vars_os()` with
no way to supply a different source: `Env`'s whole key transformation lives in
a private closure applied inside `iter()`, which is hard-wired to the process
(`figment-0.10.19/src/providers/env.rs:504-520`). So the overlay gets its own
provider rather than a modified `Env`. It is small, because the two pieces that
matter are public: `figment::util::nest` (`src/util.rs:271`) and `Dict::merge`,
which are the entirety of `Env::data()` (`env.rs:614-625`).

**It replaces the `Env` merge on the reload path; it does not join it.** An
earlier form of this section merged `OverlayEnv` alongside the real `Env` and
had to pick an order, which was wrong twice over. It picked the order from a
precedence claim that is false at source — startup calls
`dotenvy::from_path_override` (`src/config/mod.rs:303`), so an env file
OVERRIDES a value already exported into the process, and each listed file
overrides the ones before it. And with no process write on the reload path, the
process still holds the values startup wrote there, so keeping the real `Env`
in the merge at all means a rotated key is overwritten by its own startup value
and a key DELETED from the env file is resurrected from the process. Neither is
a precedence to be tuned; both are the same defect, that a second provider is
reading a snapshot the reload deliberately refuses to update.

So there is one provider, `EffectiveEnv`, computing the environment the process
WOULD have if the accepted env files were loaded into it. That map is
`overlay.effective_vars()` — the same one every iterating reader gets, defined
by the table and nowhere else — and the provider applies the transformation once
over it: strip the prefix case-insensitively, replace `__` with `.`, reject a
key with an empty dot-segment, `nest` each pair, merge.

**Which keys those are is not a question `EffectiveEnv` answers.** It has no owned set, no subtraction and no fallback of its own. An earlier draft had it strip the keys the STARTUP env files owned
while the overlay's owned set was the cumulative union carried forward from the
overlay it replaced. The two agreed on the first reload and diverged on the
next: add a key to a file, remove it again, reload twice, and a variable also
exported into the process is unset to `resolve` and present to `EffectiveEnv` —
the config provider and every credential reader then disagree about the same
name. All three reviewers found it independently, which is the argument for
having one owner rather than two careful implementations. `from_path_override` overwrites, so
the process value for an owned key is the env file's own — but it may have
overwritten a shell-exported value, and that older value is what a restart
would produce. So `EnvOverlay` carries `baseline` as well: the process value of an
owned key as it was BEFORE any env file supplied that key, captured at the
moment the key ENTERS the owned set and carried forward across reloads with the
set itself. At startup that is one snapshot taken before the first file is
read. It cannot be only that snapshot: the owned set grows, and a key first
named by a file on a LATER reload would then have no baseline at all, so
removing it would unset a variable the shell exported rather than restoring it
— the very defect the baseline exists to prevent, one reload later. Capture on
entry is well defined precisely because the reload path writes nothing to the
process: a key not owned at startup still holds whatever the shell exported,
never a file's value, so the value read when it first becomes owned is the
pre-file one. Removing an owned key
restores its baseline value where one exists and unsets it where none does.
Without the snapshot, `FOO=shell` exported into the process, `FOO=file` in an
env file, then the line deleted, leaves `FOO` absent in the running gateway and
`shell` in the next one — the two disagree, and nothing surfaces the
disagreement until something reboots. A key
the operator exported and never wrote in a file keeps working; a key removed
from a file goes away on the reload, as it would across a restart. With one
provider there is no merge order left to get wrong.

Reimplementing a transformation is how two implementations drift, so this one
is pinned by an oracle rather than by care: for a given key set,
`EffectiveEnv`'s `data()` must equal the real `Env` provider's `data()` when
those same keys are in the process environment — the WHOLE return, a
`Map<Profile, Dict>`, not the inner `Dict`. Comparing the full return is what
makes the oracle cover the transformations this prose does not enumerate:
`Env::data()` ends `self.profile.collect(dict)` (`env.rs:624`) and `iter()`
lowercases each key on the way through (`env.rs:513-516`), so a provider that
emitted the wrong profile, or skipped the lowercasing and left
`MCP_GATEWAY_SERVER__PORT` nesting as `SERVER.PORT` onto nothing, fails here
without either being named as a rule to follow. The oracle is the library itself, so the test
cannot pass by agreeing with the thing it is checking.

**Validation reads the overlay too.** `validate_env_reference`
(`src/config/mod.rs:651`) and the inline agent-key resolution (`:433`) are the
only two validate-time readers of `env:` — the first funnels four call sites
(`auth.bearer_token`, `auth.api_keys[].key`,
`agent_auth.agents[].hs256_secret`, `key_server.admin_token`), the second
stands alone. Both take an `&EnvOverlay`, resolve through it — owned keys from
the overlay alone, the rest from `env::var_os` — reached through `validate` on
the same parameter. Without this a candidate that adds `auth.bearer_token:
env:NEW_TOKEN` with the value in its own env file fails validation, because
the value is not in the process yet — the hot-add case, failing at the last
gate before it would have worked.

**Two readers are lazy, and they are the ones that matter.** `fetch_credential`
(`src/capability/executor/credentials.rs:22-56`) reads `std::env::var` on
every call, for all three conventions (`env:VAR`, `{env.VAR}`, a bare
`UPPER_SNAKE` name). It resolves through the published overlay on the same
terms as every other overlay-aware reader — an owned key answers from the
overlay, anything else from `std::env::var` — unchanged in every other
respect. An earlier draft left it untouched on the grounds that the process
would hold the value by then; nothing writes the process any more, so the
overlay is where the value lives. `SecretResolver::resolve`
(`src/secrets.rs:82`) is the second, on the same terms; between them they are
the runtime readers that have to see a rotation.

**The executor holds a handle, not a snapshot, and that is forced.**
`CapabilityExecutor` is constructed at exactly two production sites, both
startup entry points — `run` (`src/gateway/server/mod.rs:813`) and `run_stdio`
(`:1468`) — and the reload path never reconstructs it: `ReloadContext` carries
`Arc<LiveConfig>` and patches the registry, nothing more. A plain
`Arc<EnvOverlay>` field would therefore be captured once and go stale at the
first rotation, which is the failure this change exists to prevent. So the
shared cell is `LiveEnv`, the same shape as `LiveConfig` and for the same
reason: `RwLock<Arc<EnvOverlay>>`, `get()` cheap on the request path, `set()`
called once by an accepted reload.

**Startup publishes the overlay its own load returned, never a second read of
the same paths.** The gateway's own startup calls `Config::load_evaluated`,
which applies the env files to the process exactly as today AND returns the map
it applied, as the same `Evaluated { config, overlay, env_paths }` the reload path
produces. **`env_paths` is the third field, and it is what stops the one
resolution becoming two.** It is a `ResolvedEnvFiles` — an opaque wrapper over
the absolute paths startup recorded as it opened them, constructible ONLY by
the resolver and carrying no `~` spelling to expand a second time. The watcher
and every reload take it from the startup result instead of calling
`resolve_env_file_paths(&config.env_files)` themselves
(`src/config_reload/mod.rs:1011-1014` is the call that changes), and
`load_with_overlay`'s `env_files: &[PathBuf]` argument is fed from it. Without
a named owner every consumer has `Config.env_files` in reach and rebuilding
the list from it is the obvious thing to write — which is the divergence this
rule exists to remove, arriving through the back door. A type that cannot be
built from raw strings is the mechanism; a paragraph asking implementers not
to is not. `LiveEnv` is seeded from that value and handed to the reload context
and the executor. `Config::load` is a thin wrapper that calls it and drops the
overlay, so its signature and behaviour are unchanged for all 35 call sites,
and the CLI paths that hold only a `Config` still have no overlay to pass —
both of which the shape section below relies on.

Re-parsing the configured paths to build the overlay would open the same window
at boot that *One snapshot, read once* closes at reload: a file edited between
the two reads gives a process holding one set of values and an overlay serving
another, with the second parse's validation the only one anything sees. It
would also duplicate the ordering, BOM and malformed-line rules, and a
duplicated rule is one that gets fixed in one copy.

**One read of the bytes, not one call.** `dotenvy::from_path_override` opens
the file itself, so calling it and then building the map would be two reads
however it is phrased. So the apply reads each file once into memory, parses
that buffer TWICE and applies nothing itself: `dotenvy::from_read_iter`
(`dotenvy-0.15.7/src/lib.rs:303`) yields the pairs for the overlay's map and the
baseline snapshot, and `dotenvy::from_read_override`
(`dotenvy-0.15.7/src/lib.rs:278`) applies the same buffer to the process with
override semantics in file order. A DESIGN DECISION, named: startup stops
delegating to `from_path_override`, which opens the file itself and would make
that two reads however it is phrased, and delegates to the reader-taking
override instead. Performing the write in our own code is NOT available and
saying so is the point: `std::env::set_var` is `unsafe` in edition 2024 and
this crate is `#![deny(unsafe_code)]`, so the write stays inside `dotenvy`
where the unsafety already lives. Two parses of one buffer is the price, and it
is not the race the single read exists to close: both parses see identical
bytes. What is preserved is every observable — same order, same override
precedence, same skip-if-absent, same warn on a failed file — and what is
gained is that the process and the overlay cannot disagree, because they came
from one buffer. `ENVFILE.6d` is the case that fails if this is implemented as
two reads.

**The overlay owns a key domain, or removal cannot work.** Startup applies the
env files to the process, so a key deleted from a file at reload time is still
sitting in the process from the previous boot: an overlay consulted first and
then falling through would keep serving the deleted secret, silently, forever.
That is what the owned set in the constructor above is for — the keys of the
overlay's own map, unioned with the owned set of the overlay it replaces — and
the resolution table governs what an owned key answers: the file value, else
the baseline, else unset. A reader that requires a key which resolves to unset
fails closed rather than resolving a value the operator has removed. Keys
outside the owned set are not the overlay's business at all, which is what
keeps `PATH` and the `MCP_GATEWAY_*` knobs working.
The union is what makes the removal durable across a second reload; it grows
only with keys the operator's own files have named.

**The two publishes are ordered, and the order is the argument.** Config and
overlay live in separate cells, so a request in flight can see one before the
other. Overlay first, then the config: a request in that window resolves the
new credential against the old spec, which is what a rotation means and is
harmless. The reverse order would give the new spec the old credential — a
generation mismatch that looks exactly like the bug this change exists to
remove. A key removed rather than rotated resolves as unset in the same window
and the reader fails closed. Fusing both into one snapshot would remove the
window entirely and is the better shape if the config cell is ever
reconstructed on reload; today the reload patches `LiveConfig` in place and
the executor holds handles, so fusing them means reconstructing the executor,
which the change explicitly does not do.

The executor gains `with_env(Arc<LiveEnv>)` and keeps `new()` meaning
"process environment only". Two production call sites change; the ten test
constructions do not. `SecretResolver` takes the same handle on the same terms,
and its `new()` keeps the same meaning. Its two executor constructions
(`src/capability/executor/mod.rs:189`, `:218`) inherit the handle the executor
now holds. The other two production sites do not have one in scope today —
secret injection (`src/secret_injection.rs:160`, `:169`) and webhook signing
(`src/gateway/webhooks/mod.rs:427`) — so the handle is threaded to them from
their own construction sites. Open until the first patch: whether either of
those is built before startup publishes the first overlay. Resolved by reading
their construction order at implementation time; if one is, it takes the
`LiveEnv` cell rather than an `Arc<EnvOverlay>`, which is why the cell exists
and costs nothing to pass early.

`resolve_key`, `resolved_hs256_secret` and `resolve_admin_token` are **not**
lazy, and an earlier draft of this paragraph said they were. They run exactly
once, at startup: `ResolvedAuthConfig::try_from_config` resolves the bearer
token and every API key eagerly (`src/gateway/auth.rs:126-127,148`) and is
constructed once (`src/gateway/server/mod.rs:912`), beside the key-server admin
token (`:957`) and each agent HS256 secret (`:982`). Nothing reconstructs them
on a reload — and nothing should, because `auth`, `key_server` and `agent_auth`
are all in `tracked_sections` (`src/config_reload/mod.rs`), which makes an edit
to any of them restart-only by an older decision than this one.

So the narrowing, stated rather than implied: **a successful reload rebuilds no
holder that a tracked section owns.** It does NOT say the reload changes nothing
else, and an earlier draft that wrote it as *rotates capability credentials and
nothing else* was falsified by this design's own live readers: `EffectiveEnv`,
the firewall's exclusion set, discovery's scanner and every runtime child read
the new overlay live, and ENVFILE.19b asserts two of them. An operator who
rotates `auth.bearer_token` gets a reload that validates against the overlay and
a `restart_required` outcome, exactly as they do today for any auth edit.

**A live value can outlive its binding, and that is the boundary rather than a
window.** The ordering argument above — overlay first, config second — bounds
the mismatch to one request only when the config catches up on the same reload.
For a tracked section it never does: rotate a credential and its destination in
one edit and the credential is live while the destination stays as it was until
a restart. What keeps this visible rather than silent is the outcome itself,
which reports `restart_required` and names the changed section (ENVFILE.10c);
what remains is that the new credential is in use against the old binding for as
long as the operator leaves the gateway running. Stated because the ordering
paragraph reads as though every mismatch were bounded by a request. Making
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

**And once it runs there, `no_changes` is the wrong thing to say.** The patch
is empty, so nothing about the CONFIG changed; the overlay is not the config,
and a rotation that replaced a live credential is not a no-op. Two corrections,
both on every accepting exit, not on the empty-patch one. Scoping them there
would have reproduced the defect they exist to close, one reload over: an
operator who rotates a compromised credential in an env file AND edits anything
else in the same reload produces a NON-empty patch, and reporting keyed on
patch-emptiness goes quiet on precisely that reload. The overlay diff is
computed once per accepted reload and reported the same way whatever the patch
contains:

- The outcome names the rotation. An accepted reload whose overlay differs from
  the one it replaces reports the keys that changed, alongside whatever the
  config patch reports — added, changed, removed,
  by name, never by value — instead of `no_changes`. An operator who rotates a
  secret and is told nothing happened cannot distinguish a rotation that took
  from a watcher that fired on the wrong file.
- The outcome reports `restart_required` when a changed key is referenced by a
  restart-only holder. `EnvOverlay` knows which keys changed; the keys a
  startup-only consumer holds come from a REGISTRATION, not from an inference.
  Each such consumer resolves through `startup_env::read(key, holder)` rather
  than `std::env::var` — same value, plus a `(key, holder)` pair recorded in a
  process-wide registry that is written during startup and read-only after it.
  The report is the intersection of the changed keys with that registry. An
  earlier draft said the running config "knows" which keys those consumers
  resolved, and nothing in the process computed it: the config records the
  references it was handed, not the environment reads a module makes on its own,
  so attestation — three reads the config never names — would have been reported
  as unchanged forever. The source scan does not produce this set, it VERIFIES
  it: a `std::env::var` or `env::vars` call site outside the registry and the
  named allowlist fails the scan. Without this the worst
  case is silent and security-shaped: an operator rotates a compromised
  `auth.bearer_token` through the env file alone, sees a successful reload, and
  the old token stays valid until a restart nobody knew to perform. The value is
  not logged; the key and the holder are.
- **Live or startup-only is a property of the CALL SITE, never of the key.** A
  site that resolves per use is a live reader and answers from the resolution
  table; a site that resolves once and keeps the value registers. The same key
  may legitimately have one of each — a live reader then sees the rotation
  immediately AND the report names the key for the holder that cached it, which
  is two true statements rather than a contradiction. What is NOT permitted is a
  single site claimed as both. `MCP_GATEWAY_FIREWALL_SKIP_KEYS` is the case that
  forced this: an earlier draft had it in the registry while a criterion asserted
  the scanner applies the new exclusion set on the next scan, and only one can
  hold. Source settles it — `free_text_keys` reads the variable inside the
  per-key loop with no caching (`src/security/firewall/input_scanner.rs:71,150`)
  — so it is a live reader with no registry entry, and the criterion asserting
  live application is the correct one.

Both are the same defect seen twice — the reload reporting on the patch when it
should report on what it applied — and one of them decides whether a revoked
credential is believed to be revoked.

**One snapshot, read once.** Evaluation and commit MUST NOT each read the files
from disk. `EnvOverlay::from_paths` produces the map; that same map is what the
commit publishes, through a single `LiveEnv::set` rather than a second
`load_env_files_from_paths` call. Two independent reads would leave a window in
which the bytes validated and the bytes applied differ — a rotation landing
between them publishes a value nothing checked.

What the snapshot does NOT do is change how a `${VAR}` inside an env file
resolves. That stays `dotenvy`'s rule, which prefers the process value — and
the reload refuses any config that depends on it, for the reason given under
*What D costs*.

**Where the apply sits: after the last abort, immediately before the publish.**
The last way an accepted reload can still fail is the shutdown abort
(`:1517-1522`), which fires after `apply_patch` has already stopped and
started backends. The apply goes below it and above
`self.live_config.set(new_config)` (`:1524`). `set` is a lock write and cannot
fail (`:281-283`), so no failure path exists between publishing the overlay
and committing the config. It does NOT make the pair atomic: there is a window
in which a request sees the new overlay under the old config, which is the
window the publish order above argues is the harmless one. An earlier draft of
this paragraph claimed no reader could observe it, which contradicted that
argument two paragraphs earlier and would have been read as licence not to
test the transition. Apply-before-`apply_patch` would read better for backends
this reload restarts, and would reopen the ticket's exact defect: a shutdown
abort would leave the new overlay in force under the old config.

A backend this same reload restarts is spawned before the publish and is
nonetheless correct: `apply_patch` starts it from the CANDIDATE config, whose
`${VAR}` were already expanded against the new overlay during evaluation, so
the new values are baked into its `env` map before the cell is written. An
earlier draft named this as a residual, which was wrong in the direction that
matters — it would have had the implementation and its test agree on stale
values being acceptable. Children get `env_clear()` and only the keys the
config names (`src/transport/stdio.rs:40,71-73`), so nothing stale reaches one
by inheritance either, and a capability credential is unaffected because
`fetch_credential` reads per call. Pinned by a test rather than left as a
claim.

**Both the overlay and the apply read the RUNNING gateway's `env_files` list,
never the candidate's.** A candidate is an unvalidated file on disk, and its
`env_files` list is part of what has not been validated. Building the overlay
from it would let an edited config name any path and have its contents
activated as credentials during evaluation; under D it is sharper still,
because acceptance would then publish those contents to every runtime reader
in the process. So the
path list is an input to the load, not a field read out of the candidate:
`load_with_overlay` takes `&[PathBuf]` from the caller, and the reload path
passes the list the running gateway started with. A path the candidate ADDS
contributes nothing to the load: not to the overlay, not to the process, not to
any reader — it takes effect at the next restart,
which is what adding a path already required (below). A path the candidate
REMOVES stays applied until restart, matching the fact that nothing unsets a
variable today either.

That leaves the hot-add workflow silent, and it should not be: an operator who
adds a path, a credential and a backend in one edit gets a reload that succeeds
with the credential resolved to empty. `${VAR}` expansion yields the empty
string rather than failing, so nothing refuses and the backend registers
broken. The design does not change what is applied — the restart-only rule
stands — but it does add a warn-level log when a `${VAR}` resolves empty at
reload while a candidate-added env file defines that name. It names the key
and the file, never the value.

**That diagnostic opens the file, and saying so is the point.** An earlier
draft claimed a candidate-added path was "parsed by nobody", which cannot be
true of a warn that knows the file supplies the missing name — one of the two
statements had to go, and the one that had to go was the absolute. A DESIGN
DECISION, named here because it moves a security property: the file is read for
its KEY NAMES ONLY, on the failure path, to answer one question — does this
name exist here. Nothing it contains is applied, published, resolvable or
logged; a value never leaves the parse. The path is operator-supplied through
the same config the operator is already editing, so opening it grants no reach
the edit did not already have, and a read that cannot influence a value cannot
activate a credential. The rule that matters is unchanged and is about
APPLYING, not about opening. The `env:` form needs no such log: it
resolves through `validate_env_reference`, which refuses, so the operator is
told by the refusal.

The same asymmetry answers the admin-UI write path, which revalidates through
`write_config` (`src/config_persistence.rs:42`) against the running
environment: an edit referencing a variable only a candidate-added env file
supplies is rejected in the `env:` form and warned in the `${VAR}` form. That is
the unreloadable `env_files` LIST reaching the UI, not a defect: the file
supplying the name has never been read, so no overlay contains it. A
write-validation path that resolved a candidate against files the running
process has never opened would let the UI accept exactly the configuration a
restart would need, and it is OUT of scope for the same reason the list itself
is. This is also why `Config::load` keeps
reading the list out of the file: at startup the config on disk *is* the
running config, and there is no earlier list to prefer.

**`expand_env_vars(&mut self, overlay: &EnvOverlay)`** and
`expand_string(s: &str, overlay: &EnvOverlay)`. The only behavioural line is
in `expand_string`: resolve through `overlay`, which answers owned keys itself
and defers the rest to `env::var`, then to the `:-` default.
Overlay-before-environment mirrors `from_path_override`, which is what startup
does — so a variable present in both resolves the same way on both paths.

**`Config::load_with_overlay(path: Option<&Path>, env_files: &[PathBuf],
previous: &EnvOverlay) -> Result<Evaluated>`**, `pub(crate)`, where
`Evaluated { config: Config, overlay: Arc<EnvOverlay>, env_paths:
ResolvedEnvFiles }`. The third field is the recorded path sequence stated
above, and it is on this signature as well as `load_evaluated`'s so the two
entry points return the same shape. `previous` is the
overlay in force: `&EnvOverlay::none()` at startup, `live_env.get()` on a
reload. It is here for the same reason it is on the constructor — the owned
set has to survive the replacement, and a signature that cannot express that
would silently resurrect a removed key. The return type carries the overlay because the
overlay is what the commit publishes: a function that built it, used it and
dropped it would force the caller to rebuild it from disk at commit time,
which is exactly the two-reads window *One snapshot, read once* forbids. The
evaluation object is the mechanical guarantee that the published map is the
validated map — the caller cannot publish anything else, because it has
nothing else. Same body as `load_evaluated` otherwise, with two lines changed:
it builds an `EnvOverlay` from the `env_files` ARGUMENT and `previous` — the
running gateway's list, never the candidate's own
`env_file_config.env_files` — rather than applying those files to the process,
and passes it to
`expand_env_vars`. `Config::load` is unchanged in signature and behaviour for
all 35 call sites, which is why none of them is edited; it is the thin wrapper
over `load_evaluated` stated above, and nothing here gives it a second
definition.

The two bodies share a private `load_inner(path, EnvSource)` with
`enum EnvSource<'a> { ApplyToProcess, Overlay { paths: &'a [PathBuf],
previous: &'a EnvOverlay } }` — an enum, not a boolean, so the call site says
which it means without opening the signature, and the overlay variant cannot
be constructed without naming both the list it reads and the overlay it
replaces.

`load_with_overlay` is `pub(crate)` because `config_persistence` is a different
module and must reach it, and nothing outside the crate should. Its documented
invariant is that it does not mutate the process environment.

**`write_config` takes the overlay too.** `src/config_persistence.rs:42`
revalidates before writing, and validation is now overlay-aware, so leaving it
on the process alone would reject an admin edit naming a key that an
already-listed env file supplies and a reload has since rotated — a rejection
this change would have caused. It gains an `&EnvOverlay` parameter, supplied
from the `LiveEnv` cell by the in-process admin path. The CLI path passes
`EnvOverlay::none()`: `Config::load` deliberately returns only a `Config`, so
there is no overlay to hand it, and a CLI invocation has no running gateway
whose rotations it could be missing. An earlier draft said the CLI passed what
`Config::load` produced, which could not have been wired as written.

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

Both supply the paths as the `ResolvedEnvFiles` **the running process
actually opened at startup**, not by resolving `running().env_files` again,
not from the published snapshot and not from the candidate. It rides on
`LiveConfig` beside `running`, "what the running process actually applied,
fixed at startup" (`src/config_reload/mod.rs:228-238`, reached through
`running()` at `:253`) — the same lifetime and the same reason. `running()`
keeps supplying the raw list, which is what the restart-required rule reads
for its `~` spellings; what it no longer supplies is anything to resolve.
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
  environment variables are identical to before the reload, AND the published
  overlay is the one that was in force before it. The second half is what has
  content now: the process half holds for every reload, failing or succeeding,
  because no reload path can write the process environment.
- **MIK.ENVFILE.2** Given a reload that succeeds, Then every value its env
  files define is resolvable by the runtime `env:` readers through the
  published overlay, and the process environment is unchanged. An earlier form
  required the value to be readable from the process "exactly as after a
  restart"; that described the `set_var` commit the review killed.
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
  restart, and the value reaches the resolved config from the overlay built
  for the evaluation — before that overlay is published, and without the
  process environment being touched at any point.
- **MIK.ENVFILE.6** Given an env-file edit that changes a `MCP_GATEWAY_*`
  variable, Then the reloaded config carries the new value, and it wins over
  the same variable exported into the process — startup's precedence,
  unchanged by the overlay, because startup calls
  `dotenvy::from_path_override` (`src/config/mod.rs:303`) and the file
  therefore overrides the process. Pinned so it cannot regress in either
  direction: three drafts got this wrong, the last two by asserting the
  process wins.
- **MIK.ENVFILE.7** Given an admin-UI config edit against a running gateway,
  When the mutation is rejected or the write fails, Then process environment
  variables and the published overlay are both identical to before the edit,
  and when the mutation is accepted and written, Then the overlay carries the
  candidate's values.
- **MIK.ENVFILE.8** Given a BOM-prefixed env file, Then the reload path
  resolves its first variable to the same name and value startup does.
- **MIK.ENVFILE.9** Given an env file whose contents change under a running
  gateway, Then a reload is triggered and the new `${VAR}` values reach the
  running backends — the behaviour option B would have removed.

- **MIK.ENVFILE.10a** Given a reload that adds an `env:` reference in ANY of
  the five CALL SITES that validate one — the four `auth.bearer_token`, api
  key, agent secret and admin token references that funnel through
  `validate_env_reference`, plus the inline agent-key resolution that stands
  alone — whose value is defined only in an already-listed env file, Then
  validation passes, because validation reads the overlay. A capability
  credential is not among them: nothing validates it at config load, so
  asserting that its validation passes asserts nothing. Its resolution is
  .10b's subject. The criterion the first design would have failed.
- **MIK.ENVFILE.10b** Given that reload, When the reference is a capability
  credential, Then the value is in use afterwards with no restart — the one
  reader that resolves per call.
- **MIK.ENVFILE.10c** Given that reload, When the reference is one of the four
  auth forms, Then the outcome reports `restart_required` and the holder keeps
  the value it resolved at startup. A single criterion previously asserted 10b
  for all five, which the round-2 source check disproved; the split is what
  keeps the passing case from covering for the restart-only one.
- **MIK.ENVFILE.10.1** Given an edit to an env file only, with the config file
  byte-identical, When the watcher fires, Then the rotated values are in force
  afterwards. The patch is empty and the reload returns early, so this is the
  exit a publish placed on the change-applying branch would miss — and it is
  the change's own headline case, rotation without a config edit.
- **MIK.ENVFILE.10.4** Given an env-file-only edit that rotates a key which the
  running config references from one of the enumerated startup-only consumers, When the
  reload is accepted, Then the outcome names the changed key and reports
  `restart_required`, and the value appears in neither. This holds whatever the
  config patch contains: an empty patch reports it instead of `no_changes`, and
  a non-empty one reports it alongside the patch. The case where believing the
  outcome means believing a revoked credential was revoked.
- **MIK.ENVFILE.10.2** Given an accepted reload whose changes are not fully
  applied — the registry shutdown abort — Then nothing is published, because
  the reload did not commit.
- **MIK.ENVFILE.10.3** Given a reload that follows a successful reload which
  added a path to `env_files`, Then the later reload still reads the path list
  that was in force at startup, not the one the earlier reload accepted. The
  list must come from the running config; taken from the candidate side it
  activates a file whose addition still reports `restart_required`.
- **MIK.ENVFILE.12** Given env files in which a substitution — `${K}` or the
  unbraced `$K` — names a key those same files define, When a reload is
  attempted, Then it is refused with the file and the key named and no value
  logged, and nothing is published. Startup accepts the same files unchanged. A
  token the parser would not substitute — either spelling inside a `#` comment,
  inside a single-quoted value, or escaped — does not refuse.
- **MIK.ENVFILE.13** Given a key removed from an env file whose value was
  applied to the process at startup, When the reload is accepted, Then the key resolves as the
  resolution table says — to its baseline where one was captured, to unset where
  none was — and never to the value the deleted line carried.
- **MIK.ENVFILE.17** Given an env file whose second line cannot be parsed and
  whose third line is a valid assignment, When the overlay is built from it,
  Then the first line's pair is present and the third line's is not — the same
  answer startup gives over the same bytes.
- **MIK.ENVFILE.16** Given a `runtime.profiles.*.env_keys` name supplied by an
  env file, and a reload that rotates its value, When a runtime child is
  launched afterwards, Then it receives the rotated value; and given the key is
  removed instead, Then it receives no value for that name.
- **MIK.ENVFILE.15** Given an admin-UI edit naming a key that an already-listed
  env file supplies, and whose current value reached the gateway through an
  accepted reload rather than through the process, When the edit is written,
  Then validation accepts it.
- **MIK.ENVFILE.14** Given a `{env.NAME}` reference resolved through
  `SecretResolver` on a live request path, When an accepted reload rotates
  `NAME` in an already-listed env file, Then the next resolution returns the new
  value without a restart.

- **MIK.ENVFILE.11** Given a candidate that ADDS a path to `env_files`, When
  the reload succeeds, Then no variable defined only in that new file is
  resolvable in the reloaded config, nor readable from the process — an
  unvalidated file cannot activate a credential by being named.

- **MIK.ENVFILE.11a** Given a running gateway whose `env_files` contains an
  entry spelled `~/...`, When an accepted reload's env files set `HOME` to a
  different value than the running overlay holds, Then the outcome reports
  restart-required and names `HOME`, and the gateway keeps reading the paths
  it recorded at startup.

An earlier form required the gateway to report `env_files` as restart-required
after a content-only edit. Cut, not weakened: `pending_restart_fields` compares
the `env_files` *path list* (`src/config_reload/mod.rs:552`), which a content
edit does not change, and under D a content edit does not need a restart for
the values that matter.

## Docs corrected here

- `CHANGELOG.md:333` and `docs/DEPLOYMENT.md:596` — both describe a candidate
  config applying its `env_files` before validation. That stops happening: a
  reload never writes the process environment, and the values it reads are
  published to the runtime overlay only once the reload is committed.
- `docs/DEPLOYMENT.md:177` — describes `env_files` without saying what a reload
  can and cannot pick up from one. It now needs three statements: `${VAR}` and
  `env:`
  values reload, and so do `MCP_GATEWAY_*` keys; a field the running process
  reads only at startup is reported as pending restart whichever source
  supplies it; a substitution, in either spelling, naming a key the env
  files themselves define is refused on reload and accepted at startup.
- `src/config_reload/mod.rs:1485` and `src/config_reload/tests.rs:1271,1295` —
  comments explaining why the reload refusal message may not claim that nothing
  was applied. Under D a *refused* reload really does apply nothing, so the
  comments become wrong in the direction of understating the guarantee. The
  message itself stays out of scope (below); the comments are corrected.

## Out of scope

**Whether the `env_files` list should be reloadable.** Adding a path still
requires a restart. This change is about what a failing reload may do to the
process, and about the contents of paths already listed.

**Making Figment's env layer overlay-aware was here, and is now IN scope** as
`EffectiveEnv`. It moved when the asked question came back: restart-only was not
acceptable for values that arrive through an env file. The deferral had rested
on the affected keys being startup-shaped anyway, which is true of some of them
and was never true of all of them.

**Putting every process-environment read behind a wrapper, with a lint
forbidding the direct call.** It would close the residual named above — a
dependency, or a later helper, reading `std::env` outside the enumerated set.
It is crate-wide, it is not about env files, and the source scan covers the
omission this change could plausibly cause. Disposal: recorded as an
observation, not filed.

**Strengthening the reload refusal message.** Once a refused reload applies
nothing the gateway can honestly say so, and the message at
`src/config_reload/mod.rs:1478` was deliberately weakened over three review
rounds because it could not. Still out: it changes user-visible security
messaging and the tests guarding it assert the ABSENCE of those phrases, so
they keep passing either way. Disposal: filed as a follow-up,
MikkoParkkola/mcp-gateway#463.

**`load_config_or_default` turning a config error into `Config::default()`.**
`src/config_persistence.rs:14-23` logs a warning and returns defaults for any
`Config::load` failure, and the admin-UI read-modify-write then writes that
result to disk — a YAML syntax error in a config an operator is editing can
replace it with defaults. Pre-existing, on a path this change does not create,
and `load_existing_or_default` (`:29-35`) already shows the fallible shape a
fix would take. This change avoids *adding* to it by keeping the overlay
builder infallible. Disposal: filed as a ticket,
MikkoParkkola/mcp-gateway#462, because whether the admin path should refuse
rather than default is an operator's call, not a repair.

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
  explicit BOM strip, and — once the commit stopped writing the process — the
  refusal above, because a process value that nothing ever refreshes turns the
  second fact into a permanently stale reference. The first draft read that
  fact as "an env file cannot reference itself", which the crate contradicts:
  same-file references resolve, and that is exactly why the refusal keys on
  the defined-here set rather than on file boundaries.
- *Is `${VAR}` the only way a config value reaches the process environment?* —
  no, and this is what broke the first design. `env:` and `{env.VAR}`
  references are resolved lazily by seven sites and validated by two more, all
  reading `std::env` directly. Found by reading every `env::var` caller under
  `src/`, prompted by a review finding. Changed the design: option C was chosen
  before this answer and is now insufficient; D exists because of it. That
  reading missed one — `SecretResolver::resolve` (`src/secrets.rs:82`), the
  `{env.NAME}` form on the webhook, injection and executor paths — which a
  later review found. An enumeration is the wrong instrument for a set that
  grows, so the rule is now authorship-based and the set is held by a source
  scan; the count above is a description, not the mechanism.
- *Which behaviour does the operator want to lose — `MCP_GATEWAY_*` on reload,
  or hot-add with a new credential?* — asked, answered: the `MCP_GATEWAY_*`
  narrowing, with hot-add preserved. **SUPERSEDED by the bullet below, which
  put the same axis back to the operator and got the opposite answer.** The
  record stays because the answer was given and the design moved on it; it is
  the next bullet that governs. Changed the design: option B was the
  chosen option before this answer and is now rejected. The narrowing has since
  DEEPENED: with no process write on the reload path, a `MCP_GATEWAY_*` value
  added while running waits for a restart rather than for the next config load.
  The answer still holds a fortiori — it is the same axis the operator chose to
  give up, and hot-add is still preserved, which is what B could not do — but
  the operator selected a smaller loss than the one now on offer, so it was put
  back to them rather than assumed. The bullet below is that second question,
  and its answer removed the deepening entirely.
- *Is restart-only acceptable for `MCP_GATEWAY_*` values that arrive through an
  env file?* — asked 2026-08-29, offered as restart-only, live-apply, or
  live-now-restart-later; answered: apply live wherever safe. Where a value
  genuinely cannot be applied to a running process, the operator is to be told
  which setting needs a restart rather than left to discover it. Changed the design: the
  Figment item is no longer out of scope and appears below as `EffectiveEnv`, and
  the narrowing this bullet was about no longer exists — an `MCP_GATEWAY_*`
  value in an env file is evaluated on a reload exactly as one in the YAML file
  is. What genuinely cannot be applied to a running process — a listener
  already bound to a port — is reported by the restart-required path the reload
  already has, on the same terms as any other config source. That is the point
  of the answer rather than a caveat on it: an env file stops being a special
  case.

## Two layer changes the reviews proposed, and why neither is this change

Both external reviewers proposed replacing the mechanism rather than repairing
it, in different rounds and different words. Recorded with its reason, because
an unrecorded rejection comes back every round and costs a round every time.

**Overlay-only — never write the process at all, at startup or on reload.**
Declined at source. `reqwest` honours `HTTPS_PROXY` and `NO_PROXY` from the
process environment it reads for itself — documented in the crate
(`reqwest-0.13.2/src/lib.rs`) — and every HTTP client the gateway builds goes
through it (`Cargo.toml:59`). A third-party crate reading the environment is a
reader no overlay can reach and no scan of our source can see, so a gateway
that never wrote the process would silently stop honouring an operator's proxy
settings. Startup therefore keeps applying its files. What this change removes
is the write on the RELOAD path, which is the one that leaks a rejected
candidate's values. The narrowing is forced by a dependency, not chosen.

**One typed, generation-scoped runtime environment service that every
operator-declared lookup goes through.** Declined for scope, not for merit — it
is the right end state, and this design moves toward it deliberately: `resolve`
and `effective_vars` are already the only two places an outcome is written, and
every named reader routes through one of them. What the service would add is
compiler enforcement in place of an AST-aware scan, and atomic
value-with-binding generations in place of two ordered publishes — which is
exactly the residual named above, where a rotated credential outlives its
restart-only binding. It needs every environment read in the crate behind a
wrapper plus a lint forbidding the direct call, crate-wide, across subsystems
this ticket does not open, and it is entangled with the tracked-section
boundary that makes those bindings restart-only in the first place.

So it is a decision rather than a deferral, its TRIGGER is named: the first
defect the scan admits it cannot catch — an aliased environment read that
reaches production, or a second value-with-binding mismatch — promotes the
service from an improvement to the fix, and it gets its own design.
