# MIK-8425 B3: YAML errors never print the offending value

Status: frozen 2026-10-20 (see the end of "Behaviour change"). Refs MIK-8425. Lead ruling 2026-10-20:
approved on both paths (swap in 4.0.0 or the dated extension). Redact
offending values in YAML errors in `src/yaml.rs`, with the G2 sentinel test;
rewrite the exact-text tests it breaks. This is a CWE-532 leak fix.

## Problem

A serde error prints the value that failed, for example
`invalid type: string "sk-...", expected u16` or
`unknown variant `forever`, expected ...`. That value is often a secret typed
into the wrong field, and the error reaches stderr, CI and container logs.

The config load path removes values already: `config/load_error.rs`
(MIK-8375) redacts figment's chain. The direct paths do not. Every other
`crate::yaml::from_str`, `from_value` and `documents` caller formats
serde_yaml's error as is, about 140 call sites, starting with the
capability parser (`capability/parser.rs:16-17`). The MIG.0 baseline
records this as `capability/type-error leaks=true`
(`tests/fixtures/mik_8425_yaml/redaction.txt`, ticket comment ed23a694).
Since MIG.1 every one of those errors is the adapter's `crate::yaml::Error`,
so one type fixes every site.

## Design

1. **One redactor.** `redact_message` and its helpers (`kind_word`,
   `location`, and the constants `EXPECTED` and `VARIANT`) move unchanged
   from `src/config/load_error.rs` into `src/yaml.rs`, as
   `pub(crate) fn redact_message`. `load_error.rs` keeps `from_figment` and
   `redact_kind`, and re-exports the moved function
   (`pub(crate) use crate::yaml::redact_message;`). Its callers
   (`strict_keys.rs:292`, `security/agent_identity.rs:178`,
   `config/tests/load_error.rs`) do not change. Moving the function is
   allowed because it names nothing under `crate::`, and `src/yaml.rs` must
   not.
2. **An adapter-owned error.** `pub(crate) use serde_yaml::Error` becomes
   `pub(crate) struct Error(serde_yaml::Error)`, a private field, with:
   - `Display`: `redact_message` of serde_yaml's message;
   - `Debug`: the same redacted text, as `Error("<redacted message>")`. A
     derived `Debug` would print the value;
   - `std::error::Error`, with no `source()`, so a chain printer cannot
     reach the inner error's text.

   Every adapter function that returns `serde_yaml::Error` wraps it:
   `from_str`, `from_str_loose`, `to_string`, `to_value`, `from_value` and
   `documents`. `figment_data` returns figment's error, which
   `load_error::from_figment` already redacts.

   The newtype forwards `location()` as `Option<Location>`. `Location` is
   the adapter's own small `Copy` struct, with `line()` and `column()`
   only. `commands/config_write.rs:101` (`refuse_unreadable`) compiles
   unchanged, and no serde_yaml type leaks out for MIG.2 to reproduce.
   Every other call site names `crate::yaml::Error` or formats it with
   `{e}`.
3. **Custom messages: fix the source, add no catch-all.** The
   redactor's invariant (MIK-8375) is that the gateway's own refusals name
   keys and never values. A catch-all (every message it does not recognise
   becomes `invalid value`) would erase reviewed fixed messages such as
   `a duration of 0 seconds`.

   All 19 `::custom(` sites in `src/` were audited, and one echoes a value:
   `config/humantime_serde.rs:62`, the duration serializer, writes
   `too_long(&format!("{}s", secs))`. It becomes `too_long("this duration")`,
   which is what the deserializer already writes (`duration_bound.rs:38`).

   The rest are value-free:
   - fixed strings;
   - `parse()`'s messages, which G2 pins;
   - forwarded serde_json errors (`capability/definition/providers.rs`),
     whose `invalid type:` and `invalid value:` markers the redactor cuts;
   - JSON-only protocol paths.

   **Guard (lead condition, 2026-10-20):** a source-scan test,
   `custom_errors_never_format_a_value` in `tests/mik_8425_yaml_redaction.rs`,
   walks `src/` and fails on any `::custom(` call whose argument is a
   `format!(...)` with a `{` placeholder. The allowed forms are a string
   literal, `too_long("...")` with a literal, or forwarding another error
   (`map_err(...::custom)`), which the redactor's markers handle. A future
   site that formats a value fails the test, so the audit stays enforced.
4. **What is kept:** the key path serde_yaml prefixes (`providers.primary:`),
   serde's type words, `expected ...`, the exact ` at line L column C`,
   field and key names (`unknown field`, `duplicate entry with key`), and
   libyaml's fixed syntax messages. That is what `redact_message` keeps today
   on the config path, reviewed under MIK-8375.

## Tests (red first)

- **G2 sentinel**, new file `tests/mik_8425_yaml_redaction.rs` (one crate
  root, `#[path = "common/yaml.rs"] mod yaml;`). The sentinel goes into:
  - a type error (`port: SENTINEL` into a struct with `port: u16`);
  - an invalid value (an integer out of range for `u8`);
  - an unknown variant (`mode: SENTINEL` into an enum);
  - a syntax error (an unterminated quoted scalar holding the sentinel);
  - a duplicate key (the sentinel as the value under a repeated key);
  - a nesting-depth refusal (129 levels with the sentinel at the bottom);
  - an alias-expansion refusal (the level-4 fan-out document with the
    sentinel in its base);
  - a bad duration (`timeout: SENTINEL` into a humantime field), and a
    too-long duration written through `to_string` (the serializer path);
  - a tagged scalar (`agent: !exact SENTINEL` into the grants enum).

  The numeric cases use the number `424242424242` as the sentinel, because
  a string cannot appear in them. It goes in as a value out of range for
  `u8`, and as the wrong type for a `bool`, and each case asserts that the
  number is absent.

  The fixed-text refusals (syntax, duplicate key,
  `recursion limit exceeded`, `repetition limit exceeded`) also pin that
  text, so a vanished refusal goes red.

  `std::error::Error::source(&e)` is `None`.

  Each case runs through every public adapter function that can produce it:
  `from_str` typed and into `Value`, `from_str_loose`, `documents` and
  `from_value`. Each case asserts all of:
  - refused for the right reason (it names the key, `invalid type`, the
    variant word, or ` at line `);
  - the sentinel absent from both `{e}` and `{e:?}`;
  - a control without the sentinel loads.

  Red today: the type error, the invalid value, the numeric cases, the
  variant case and the too-long duration write all show the sentinel.
- **MIG.0 goldens that pin serde_yaml's raw text** are retargeted, not
  dropped:
  - `tests/fixtures/mik_8425_yaml/redaction.txt` row
    `capability/type-error` changes from `leaks=true` to `leaks=false`.
    That is the documented G2 "after";
  - `the_baseline_shows_the_capability_leak_and_a_clean_config_path`
    (`tests/mik_8425_yaml_baseline_redaction.rs:157`) is renamed and
    asserts `leaks=false` on every row, keeping `names=true` and
    `control=loads`. Its header records the close (B3);
  - the `behaviour.txt` ERR rows that quote a value are re-recorded with
    the redacted text;
  - the adapter-test comparisons in `tests/mik_8425_yaml_adapter.rs`
    compare the adapter's output with serde_yaml's output passed through
    `redact_message`. So they still prove "reads like serde_yaml", and now
    also that it redacts.
- **Exact-text tests that break**, rewritten to assert the key, the kind and
  the absence of the value, never weakened to "is an error":
  - `src/personal_accounts/config/journey_tests.rs:530-531` asserts
    ``unknown variant `forever` `` and `` `login` ``. They become
    `unknown variant`, with `forever` and `login` asserted absent;
  - any others the red run shows. The full lib run and CI list them, and
    each one is named in the PR.

## Behaviour change (`changelog.d/8425.security.md` and an `upgrading.d/8425.md` section)

- YAML errors outside the config loader no longer print the offending
  value. That covers capability files, grants, skills, imports, the CLI and
  the other direct readers. They keep the key path, the expected type, and
  the line and column.
- A message that named a wrong enum value now says
  `unknown variant, expected ...`, the same as the config loader has said
  since MIK-8375. The upgrade note warns scripts that match the old
  wording.
- A too-long duration that the gateway writes now reports `this duration`,
  not its seconds. The new wording is `this duration is longer than 100
  years, the most any duration may be`. The old wording was
  `<N>s is longer than 100 years, the most any duration may be`. The
  upgrade note lists both.

Status: frozen 2026-10-20. The lead agreed the design call (fix at the
source, add no catch-all, enforce with the guard), and the hold on the
adapter test is lifted. Re-run the overlap scan at cut time.

## Files (about 12)

- `src/yaml.rs`
- `src/config/load_error.rs`
- `src/config/humantime_serde.rs`
- `tests/mik_8425_yaml_redaction.rs` (new)
- `tests/mik_8425_yaml_baseline_redaction.rs`
- `tests/fixtures/mik_8425_yaml/redaction.txt`
- `tests/fixtures/mik_8425_yaml/behaviour.txt`
- `tests/mik_8425_yaml_adapter.rs`
- `src/personal_accounts/config/journey_tests.rs`
- the changelog and upgrading fragments
- this plan
- whatever the red run lists

Review folds 2026-10-20 (gpt SHIP-WITH-FIXES gpt-20261020T032619Z-67106,
grok SHIP-WITH-FIXES grok-20261020T032620Z-67157):
- `location()` is forwarded;
- the custom-message audit, with the one echoing site fixed at the source.
  A catch-all was declined, for the reason in Design point 3;
- numeric sentinels;
- cases for duration, tags, `source()` and the writers;
- fixed-text pins;
- the MIG.0 goldens are retargeted;
- the upgrade note.
- Second fold (code review): the guard is built on syn (comments, escapes and macro delimiters), the location pin refuses the scalar, the duration writers use assert_redacted with a passing control. Not in scope, noted: a bad duration read names neither its field nor a line, because serde_yaml attaches no path to a custom error (pre-existing).

## Out of scope

- serde_json errors, for example on the JSON grants branch of
  `identity_grants_matching.rs:76`. They are not YAML. A follow-up ticket
  covers them if wanted.
- MIG.2's own error type, which re-implements this `Display`/`Debug`
  contract against the same sentinel test.

## Process

- gpt and grok review this plan.
- muse writes the red tests, then the code, with shell disabled.
- Spark runs the targeted tests, clippy on both feature sets, and the gate.
- The seats review the code. The gap-finder runs, then the brief goes to
  the lead.
- Cut from the line after #3993 (B2) merged (d7a40d52b).
