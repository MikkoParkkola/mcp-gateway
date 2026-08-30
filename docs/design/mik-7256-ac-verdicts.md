# MIK-7256 — acceptance-criterion verdicts

Commit: `51ce1f32`. Suite: `cargo test --quiet` → **4537 passed, 0 failed, 23 ignored**
(E3). `cargo test --all-features` → **1 failure**, `ac_discover_3_initialize_result_is_unchanged`,
a missing `spec_preview` golden fixture that has never existed in this repository. Pre-existing
on this branch's base and out of scope here; disposed as a ticket because the choice between
capturing the fixture and gating the assertion is a product decision.

**Headline: this change does not pass DoD §1.** Of 26 acceptance criteria, 7 are verified by a
test, 7 are partly verified, 11 have no verifying test, and 1 describes behaviour that was never
built.

Verdict vocabulary: PASS = a named test asserts the criterion. PARTIAL = a test asserts part of
it. NO TEST = no case asserts it, confirmed by a search run for this table. FAIL = the criterion
is not implemented. PARTIAL and NO TEST are **not** PASS.

Searches run for this table (cited, not recalled):
- `rg -n 'fn envfile_[a-z0-9_]+' src tests --glob '*.rs'` → 11 functions
- `rg -o 'MIK\.ENVFILE\.[0-9a-z.]+' docs/design/mik-7256-env-files-on-a-failed-load.md | sort -u` → **26** criteria
- `rg -n 'set_var' src --glob '*.rs'` → **zero matches**, whole crate
- `rg -n 'from_path_override' src tests` → **zero matches**
- `rg -n '\.baseline\(' src tests` → **zero callers**
- `rg -n 'ENVFILE\.12|envfile_12' src tests` → design document only

| AC | verdict | evidence | E |
|---|---|---|---|
| ENVFILE.1 | PARTIAL | Process half verified structurally: zero `set_var` in `src/`, so no reload path can write the process environment. Overlay half: `a_refused_reload_applies_nothing_at_all` (`src/config_reload/tests.rs:1299`) asserts `live_config` is not published but never asserts `live_env` is still the pre-reload `Arc` | E2+E3 |
| ENVFILE.2 | PARTIAL | Overlay-read half: `resolve_reads_a_variable_the_env_overlay_assigns` (`src/secrets.rs:235`), `credential_resolves_against_an_env_file_overlay` (`tests/secret_injection_tests.rs:489`). No end-to-end accepted-reload-then-read case | E3 |
| ENVFILE.3 | NO TEST | `configure_child_environment` (`src/transport/stdio.rs:39`) clears the environment by construction, so the criterion holds structurally; no test covers the candidate-value case | E2 |
| ENVFILE.4 | PARTIAL | `envfile_19_the_overlay_opens_the_tilde_path_startup_recorded` (`src/config/tests.rs:1188`). The four `test_load_env_files_*` cases (`src/config/tests.rs:76-138`) exercise `load_env_files`, which the design records as unwired (design line 1037), so they do not verify the startup path | E2+E3 |
| ENVFILE.5 | NO TEST | searched `NEW_KEY`, `hot.?add` across `src` and `tests` | E2 |
| ENVFILE.6 | NO TEST | Direction is correct in source: `EnvOverlay::resolve` (`src/config/env_overlay.rs:105-110`) reads the file's assignment first and falls through to the process environment only when the file has none, so the file wins. No test pins it, and an in-process one is structurally hard: the crate forbids `unsafe`, so a test cannot seed a process variable (`src/config_reload/tests.rs:1876-1879`) | E2 |
| ENVFILE.7 | NO TEST | admin-UI reject-and-accept overlay invariance; searched `write_config_and_reload`, `mutation.*reject` | E2 |
| ENVFILE.8 | NO TEST | searched `BOM`, `feff` | E2 |
| ENVFILE.9 | PASS | `matching_env_file_*` (`src/config_reload/tests.rs:430,447,463,478`) | E3 |
| ENVFILE.10a | NO TEST | `validate_required_env_references` (`src/config/mod.rs:854`) takes the overlay; no case exercises any of the five call sites | E2 |
| ENVFILE.10b | PASS | `credential_resolves_against_an_env_file_overlay` (`tests/secret_injection_tests.rs:489`) | E3 |
| ENVFILE.10c | PASS | `envfile_10c_a_byte_identical_patch_still_reports_the_rotated_startup_only_key` (`src/config_reload/tests.rs:2398`) | E3 |
| ENVFILE.10.1 | PASS | same test (`:2398`) — env-file-only edit, config byte-identical, rotated value published at `:2486` | E3 |
| ENVFILE.10.2 | NO TEST | registry shutdown-abort branch; searched `shutdown.*abort` | E2 |
| ENVFILE.10.3 | NO TEST | a reload following a path-adding reload; searched `env_files.*add` | E2 |
| ENVFILE.10.4 | PARTIAL | `:2398` covers the empty-patch half over the derived holder set; the non-empty-patch repeat the criterion also requires is absent | E3 |
| ENVFILE.11 | NO TEST | an added path must not activate its variables | E2 |
| ENVFILE.11a | PASS | `envfile_19e_*` (`src/config_reload/tests.rs:2095`), `envfile_19f_*` (`:2176`) | E3 |
| ENVFILE.12 | **FAIL** | Not implemented, not merely untested. `dotenvy` performs `${K}` expansion inside `apply_file` (`src/config/env_overlay.rs:184`) and nothing scans for a substitution naming a key the same files define. The identifier appears only in the design document | E2 |
| ENVFILE.13 | PASS | `a_key_deleted_from_an_env_file_stops_resolving_after_a_reload` (`src/config/tests.rs`) asserts the unset half. The baseline half needs no separate capture: `resolve` falls through to the process environment, and nothing in the crate writes it (`rg 'set_var|remove_var' src/` returns nothing), so a key's pre-overlay value is still readable after any number of reloads. The unused `EnvOverlay::baseline` accessor that stored a second copy was removed | E2+E3 |
| ENVFILE.14 | PARTIAL | `resolve_reads_a_variable_the_env_overlay_assigns` (`src/secrets.rs:235`) proves overlay resolution; rotation-without-restart on the live request path is not asserted | E3 |
| ENVFILE.15 | NO TEST | admin-UI edit naming an overlay-supplied key | E2 |
| ENVFILE.16 | NO TEST | `runtime.profiles.*.env_keys` rotation into a child; searched `env_keys` | E2 |
| ENVFILE.17 | PARTIAL | `envfile_6c_a_malformed_line_at_startup_*` (`src/config_reload/tests.rs:2344`) and the reload sibling (`:2357`) pin the diagnostic; the first-line-present, third-line-absent semantics the criterion states are not asserted | E3 |
| ENVFILE.19b | PASS | `free_text_override_from_an_env_file_reaches_the_scanner` (`src/security/firewall/input_scanner.rs:264`), `an_env_file_endpoint_reaches_the_environment_scan` (`src/discovery/config_scanner.rs:758`) | E3 |
| ENVFILE.19c | PASS | `src/config_reload/tests.rs:1983` | E3 |

**Totals over the 26 acceptance criteria: 8 PASS, 6 PARTIAL, 11 NO TEST, 1 FAIL.**

Two rows have been verified at source since the table was drafted: ENVFILE.13, now PASS, and ENVFILE.12, which stays FAIL. The remaining rows were mapped by reading each criterion against the tests that appear to cover it; no test names its criterion, so the mapping is prose matching rather than traceability. `rg 'MIK\.ENVFILE\.' src/ tests/` returns nothing for all 26 identifiers.

## Test-plan cases that are not acceptance criteria

These five identifiers appear in test names and in the test plan but not in the criteria list.
They are recorded separately so they cannot inflate the count above.

| id | verdict | evidence |
|---|---|---|
| ENVFILE.1b | PARTIAL | `a_refused_reload_applies_nothing_at_all` (`src/config_reload/tests.rs:1299`) is the posture-refusal branch. Same gap as ENVFILE.1: it asserts `live_config`, never `live_env` |
| ENVFILE.19 | PASS | `src/config/tests.rs:1188` |
| ENVFILE.19d | PASS | `src/config/tests.rs:1233`, child assertion at `:1270` |
| ENVFILE.19e | PASS | `src/config_reload/tests.rs:2095` |
| ENVFILE.19f | PASS | `src/config_reload/tests.rs:2176` |

## What the operator has to decide

Eleven criteria have no verifying test and one is unbuilt. Writing the missing tests, accepting
them as recorded residual risk, or splitting them out is a scope decision, not an engineering one.
