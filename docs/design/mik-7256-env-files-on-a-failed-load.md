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

Three, each verified at source. Together they leave one buildable shape.

**This crate cannot write an environment variable.** `std::env::set_var` is
`unsafe` in Rust 2024 and unsafe is denied (`src/lib.rs:25`,
`Cargo.toml:203`). The only writer available is `dotenvy::from_path_override`,
which applies a whole file and reports nothing about what it changed.

**A candidate config cannot be evaluated without applying the files first.**
Two consumers read the real process environment and neither takes a
substitute. `Self::figment` merges `Env::prefixed("MCP_GATEWAY_")`
(`src/config/mod.rs:286`) and `Config::load` extracts it a second time at
`:199`, deliberately after the apply — so an env file setting
`MCP_GATEWAY_PORT` feeds the config through Figment, not through `${VAR}` at
all. `dotenvy`'s own `apply_substitution` consults `std::env::var` first
(`parse.rs:265`). Neither accepts an overlay.

**Validation is not the point a reload is accepted.** `Config::load` returning
`Ok` only means the file parsed and validated. The posture refusal
(`src/config_reload/mod.rs:1478`) and the shutdown abort run afterwards.

## Options

**A. Snapshot the environment, restore it on failure.** Unbuildable, not
merely unattractive: restoring requires writing variables, which requires
`set_var`, which the first constraint forbids. Even with unsafe available it
was a patch — the environment *is* mutated, and then put back.

**B. Parse without applying; apply only after validation.** Rejected on two
verified findings from design review. The Figment env layer never sees the
parsed values, so a whole class of settings silently falls back to YAML or a
default — an overlay handed to expansion cannot reach Figment any more than it
can reach dotenvy. And applying inside `Config::load` still mutates before the
posture refusal and the shutdown abort, so it does not deliver the criterion it
exists for. It also needed `set_var`.

**C. The reload path stops applying env files.** `Config::load` gains an
explicit parameter saying whether env files may be applied. Startup passes
`Apply` and is byte-for-byte what it is today. The reload path and the
config-export watcher pass `Skip`: they evaluate a candidate against the
environment as it stands, which is the environment the running process has had
since startup.

**Chosen: C.** After it the finding cannot be stated at all — the reload path
has no code that writes the environment, so no failure mode of any kind can
leave it mutated. It is also what the gateway already reports: `env_files` is
listed restart-required by `pending_restart_fields`
(`src/config_reload/mod.rs:552`) and documented as such at `:669`.

## What C costs

**Editing an env file's contents no longer takes effect until a restart.**
Today a change to a watched env file triggers a reload
(`ReloadTrigger::EnvFile`, `src/config_reload/mod.rs:1227`) and the values flow
into the live config through `Config::load`. Under C that reload would
re-read the YAML and find nothing new: a trigger that cannot change anything.
So the env-file watch goes with it — `resolve_env_file_paths`
(`:1011`), the `ReloadTrigger::EnvFile` variant and its log line are removed
rather than left in place lying about what they do. Adding a *path* to
`env_files` already required a restart; now editing the file behind the path
does too, and the two halves finally agree.

**This is a narrowing of user-visible behaviour and was decided without an
answer.** The choice was put to the operator and went unanswered; C is taken
because it is the only buildable fix and because it matches what the gateway
already tells users about `env_files`. It is cheap to reverse: restoring
today's behaviour means passing `Apply` on the reload path, at the price of
reopening MIK-7256 with no mechanism available to close it.

Startup is untouched. Same `dotenvy::from_path_override` call, same order,
same byte-order-mark handling, same cross-file `${VAR}` substitution, same
Figment layering. None of the semantics that killed option B are in play,
because nothing about how env files are applied changes — only *whether* the
reload path applies them.

## Shape

`Config::load(path)` becomes `Config::load(path, env_files: EnvFiles)` with
`enum EnvFiles { Apply, Skip }` — an enum and not a boolean, so the call site
says which it means without opening the signature. The body's only change is
that `Self::load_env_files_from_paths` runs under `EnvFiles::Apply`.

- `Apply`: the five startup sites in `src/main.rs` and the setup wizard.
- `Skip`: `load_config_patch` (`src/config_reload/mod.rs:1239`) and the
  config-export watcher (`src/commands/config_export/watch.rs:81`), both of
  which evaluate a candidate inside a process that is already running.

`load_env_files(&self)` (`src/config/mod.rs:276`) is unused outside tests and
is deleted with the watch that motivated it.

## Acceptance criteria

- **MIK.ENVFILE.1** Given a running gateway, When a reload fails for any reason
  — parse, validation, posture refusal, or shutdown abort — Then process
  environment variables are identical to before the reload.
- **MIK.ENVFILE.2** Given a reload that succeeds, Then process environment
  variables are still identical to before the reload.
- **MIK.ENVFILE.3** Given a candidate env file that sets a variable the process
  already has, When the reload runs, Then a subsequently spawned backend
  inherits the original value.
- **MIK.ENVFILE.4** Given startup, Then env files are applied exactly as today
  — same variables, same override order, same final state.
- **MIK.ENVFILE.5** Given an env file whose contents change under a running
  gateway, Then no reload is triggered by that change alone, and the config
  reports `env_files` as restart-required.
