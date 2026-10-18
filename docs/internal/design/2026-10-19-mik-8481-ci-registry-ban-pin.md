# MIK-8481: pin the Linux CI registry-ban step's `CLIPPY_CONF_DIR`

Status: design v2 (after two design seats). Test-only. Refs MIK-8481, family
boundary-pins (MIK-8387).

## Problem

`t1f_the_ban_config_and_its_wiring_are_pinned`
(`src/gateway/meta_mcp/boundary_pins/allow_pins.rs`) pins the registry-ban
clippy config and asserts `scripts/dev/pre-push.sh` exports
`CLIPPY_CONF_DIR="$REPO_ROOT/scripts/lint/registry-ban"`. It does not read the
Linux CI workflow. Dropping or redirecting `CLIPPY_CONF_DIR` in the CI step
`Registry ban (MIK-8387)` leaves the pin green, and that step is the required
Linux check; pre-push is the weaker wiring (under `spark-cargo` it is vacuous
until the variable is forwarded). MIK-8387 design 4.2 requires both to name the
directory.

## Change

1. `t1f` reads the Linux CI workflow and calls one shared assertion,
   `assert_ci_registry_ban_conf_dir(text)`, which panics unless the step named
   exactly `Registry ban (MIK-8387)` sets `CLIPPY_CONF_DIR` to
   `${{ github.workspace }}/scripts/lint/registry-ban` in its own `env`
   mapping.
2. The workflow is parsed with the repo's adapter,
   `crate::yaml::from_str::<crate::yaml::Value>` (MIK-8425), then walked as
   `jobs.*.steps[]`. No parser is named in the test, so
   `no_new_file_names_a_yaml_parser_directly` stays green, and quoting,
   comments, blank lines and key order are the parser's concern, not a line
   scanner's. Exactly one step with that name must exist anywhere under `jobs`:
   zero (renamed or removed) and two or more both fail.
3. The value must match exactly, and only the step's own `env` counts: the
   variable in another step's `env`, or only inside a `run:` script, fails.

## Falsifiers (AC CLIPPIN.2)

The falsifiers call the same `assert_ci_registry_ban_conf_dir` that `t1f` calls
(one shared path, so a refactor that detaches `t1f` from it is a test failure,
not a silent pass), on text mutated from the checked-in file in memory; no
workflow file is edited. Each is a `catch_unwind` test that must panic, and the
unmodified text must not:

- delete the `CLIPPY_CONF_DIR` line of the step;
- comment it out;
- redirect it (`scripts/lint/registry-ban` -> `scripts/lint/other`);
- rename the step (`Registry ban (MIK-8387)` -> `Registry ban`);
- duplicate the step;
- move the `env:` block to the next step;
- keep the variable only inside a `run:` script.

## Packaged crate (AC CLIPPIN.3)

`Cargo.toml` `include` ships only the release workflow; the CI workflow,
`scripts/dev/pre-push.sh` and `scripts/lint/registry-ban/clippy.toml` are not in
the published crate (and the ruling is not to add repo tooling to it). The
PR-time packaged job only compiles (`--no-run`); the post-merge
`packaged-suite` runs the tests from the unpacked crate, where the existing
`t1f` would panic on the missing config.

One test-only helper, `repo_file(rel) -> Option<String>`:

- file readable: `Some(text)`;
- file missing and `Cargo.toml.orig` exists beside `Cargo.toml` (cargo writes it
  into every packaged crate, never into a checkout): `None`, and `t1f` skips its
  whole file-dependent block with a printed note;
- file missing in a checkout: panic, so deleting or renaming a pinned file
  cannot pass vacuously.

`t1f` uses it for all three reads (config, pre-push, CI workflow). In the
packaged crate the config span comparison and both wiring assertions are
skipped together (the span is extracted from the missing config, so it cannot
run there); only compilation of the embedded snapshot is verified. A companion
test, `t1f_pinned_files_are_read_in_a_checkout`, asserts that outside a
packaged crate all three files are present, so the pin cannot pass vacuously
in both modes.

## Not changed

No product code, no `Cargo.toml`, nothing under the workflows directory.

## Rollback

Revert the commit.
