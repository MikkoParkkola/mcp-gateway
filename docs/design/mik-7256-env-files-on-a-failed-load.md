# MIK-7256 — a failed reload must not leave the process environment mutated

## Problem

`Config::load` applies every path in `env_files` to the process environment
before it validates anything (`src/config/mod.rs:198`, then `:303`
`dotenvy::from_path_override`). Every reload runs through it via
`load_config_patch`. A reload that fails — parse error, validation error,
shutdown abort, or the posture refusal — has already overwritten process
variables from the candidate file. The reload reports failure; the environment
keeps the new values, and they leak two ways: a later `${VAR}` expansion
resolves against the overridden value, and any backend spawned afterwards
inherits it. `from_path_override` overwrites existing variables, so this is not
additive-only.

## Constraint, measured

The order is not accidental. `config.expand_env_vars()` runs at
`src/config/mod.rs:203` and resolves `${VAR}` from the process environment, so
the file's values must be visible to expansion. Moving the apply after
validation without changing anything else would break every config that
references a variable its own env file defines.

## Options

**A. Snapshot the environment, restore it on failure.** Rejected on three
counts. `from_path_override` reports nothing about which keys it changed, so
the snapshot would have to cover the whole environment or re-parse the file to
learn the key set — and if it re-parses the file, option B is already available
and cheaper. Restoring a variable that did not previously exist means removing
it, and mutating the process environment is unsound in the presence of any
concurrent reader, which is why `std::env::set_var` is `unsafe` from Rust 2024.
Worst of all it is a patch: after it, the finding is still stateable — the
environment *is* mutated, and then put back.

**B. Parse without applying; apply only after validation.** `dotenvy` exposes
`from_path_iter` (0.15.7, `src/lib.rs:130`), which returns the parsed pairs and
touches nothing. Expansion reads an overlay — the process environment with the
parsed pairs laid over it — so it sees exactly what it sees today. The process
environment is written once, after validation succeeds, and never on a failure
path.

**Chosen: B.** After it, the finding cannot be stated: there is no window in
which a failed load has mutated anything.

## Shape

`load_env_files_from_paths` splits into two functions with one side effect
between them:

- `parse_env_files(paths: &[String]) -> Vec<(String, String)>` — pure. Keeps
  today's semantics exactly: `~` expansion, files processed in order, later
  files overriding earlier ones, missing files skipped silently, a parse
  failure logged and skipped.
- `apply_env_vars(vars: &[(String, String)])` — the only writer of the process
  environment, with the same override semantics `from_path_override` had.

`Config::load` becomes: parse → expand against the overlay → validate → apply.
The `&self` variant at `src/config/mod.rs:277` routes through the same two
functions rather than keeping a second copy of the walk; a second copy is how
the two paths drift apart.

## Acceptance criteria

- **MIK.ENVFILE.1** Given a running gateway, When a reload fails for any reason,
  Then process environment variables are identical to before the reload.
- **MIK.ENVFILE.2** Given a reload that succeeds, Then env files are applied
  exactly as today — same variables, same override order, same final state.
- **MIK.ENVFILE.3** Given a candidate env file that sets a variable the process
  already has, When the reload fails, Then a subsequently spawned backend
  inherits the original value.

## Out of scope

Whether `env_files` should be reloadable at all. It is currently reported as
restart-only by `pending_restart_fields` (`src/config_reload/mod.rs:552`), which
is a separate question from whether a failed load may mutate the process.

## Unknowns

- *Does any caller depend on the environment being populated before validation
  returns?* — checked by reading every caller of `Config::load` and
  `load_env_files`; expansion at `:203` is the only reader, and it is inside the
  function. Nothing changed as a result.
- *Does `from_path_iter` apply the same parse rules as `from_path_override`?* —
  both are `dotenvy` 0.15.7 over the same parser; `from_path_override` is
  `from_path_iter` plus `load_override`. Confirmed at
  `~/.cargo/registry/src/index.crates.io-*/dotenvy-0.15.7/src/lib.rs:110,130`.
  Nothing changed as a result.
