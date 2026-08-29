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
