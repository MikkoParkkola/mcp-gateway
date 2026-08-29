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

### What option B costs, found at source

Two things `from_path_override` does that iterating `from_path_iter` does not.
Both were found by reading `dotenvy` rather than by assuming the two entry
points were interchangeable, and the second is a real behaviour change.

**The byte-order mark.** `load_override` calls `self.remove_bom()` before it
iterates (`iter.rs:47`); `from_path_iter` hands back the raw `Iter` and
`remove_bom` is private, so a caller cannot invoke it. A UTF-8 BOM at the start
of an env file would therefore become part of the first key. Handled by
trimming a leading `\u{feff}` from the first parsed key — the same correction,
applied where we can apply it. Pinned by a criterion below so it cannot regress
into a silent difference.

**Substitution across files.** `dotenvy` resolves `${VAR}` inside an env file
by consulting the process environment first and only then the keys parsed so far
*from that same file* (`parse.rs:265`, `apply_substitution`). Today the files
are applied one at a time, so file 2's `${FOO}` sees a `FOO` that file 1 has
already written to the process. Under option B nothing is written until every
file is parsed, and the parser's own table is per-file, so that reference
resolves empty instead.

This cannot be preserved: the substitution reads `std::env::var` directly and
`dotenvy` exposes no overlay. Within a single file the behaviour is unchanged —
same `Iter`, same table. Only a reference *across* two env files is affected,
and only when the variable is not already in the process environment.

Taken deliberately, and bounded: `env_files` is documented as loading `.env`
files with `~` expansion (`docs/DEPLOYMENT.md:177`), `gateway.example.yaml`
ships it empty, and nothing in the repository documents or tests a cross-file
reference. A criterion below pins the new behaviour so it is a decision on
record rather than a surprise.

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
- **MIK.ENVFILE.4** Given an env file whose first byte is a UTF-8 byte-order
  mark, When it loads, Then the first key is set under its own name, with no
  mark attached.
- **MIK.ENVFILE.5** Given two env files where the second references a variable
  the first defines and the process does not, When they load, Then the reference
  resolves empty — the recorded consequence of parsing before applying, pinned
  so a later change cannot make it drift unnoticed.

## Documentation this change makes untrue

Three places state the defect as current behaviour and are corrected inside this
change, per the documentation gate:

- `CHANGELOG.md:333` and `docs/DEPLOYMENT.md:596` — both describe a config file
  applying its `env_files` before validation.
- `src/config_reload/mod.rs:1485` and `src/config_reload/tests.rs:1271,1295` —
  comments explaining why the reload refusal message may not claim that nothing
  was applied. The reasoning was correct when written and stops being true here.

## Out of scope

Whether `env_files` should be reloadable at all. It is currently reported as
restart-only by `pending_restart_fields` (`src/config_reload/mod.rs:552`), which
is a separate question from whether a failed load may mutate the process.

**Strengthening the reload refusal message.** Once nothing is applied on a
failure path, the gateway *can* honestly say so, and the message at
`src/config_reload/mod.rs:1478` was deliberately weakened over three review
rounds precisely because it could not. Tempting and still out: it changes
user-visible security messaging, it has its own review history, and the tests
that guard it assert the ABSENCE of those phrases — so they keep passing either
way and would not catch a careless rewrite. Disposal: filed as a follow-up, not
folded in here.

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
