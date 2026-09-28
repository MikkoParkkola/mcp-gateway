#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Check a Windows CI test log against the owner-only red-first expectations.

Usage: check-windows-red-markers.py LOG

A row counts as red only when its test FAILED and its output carries the
row's own `WT-ASSERT <row>` marker. Any `WT-FIXTURE` line fails the check: a
plant that did not take is not red evidence. The regression guards must pass.
"""

import re
import sys

# Test-name suffix -> row id. A row is red when every listed test failed with
# its own marker.
RED = {
    "wt1_created_objects_carry_only_the_user_ace": "W-T1",
    "wt1_store_objects_are_owner_only": "W-T1",
    "wt1_task_store_objects_are_owner_only": "W-T1",
    "wt1b_objects_are_private_at_the_instant_of_creation": "W-T1b",
    "wt2_foreign_ace_on_store_dir_refuses": "W-T2",
    "wt3_inherited_ace_on_store_dir_refuses": "W-T3",
    "wt4_authority_json": "W-T4",
    "wt4_record": "W-T4",
    "wt4_lock_sidecar": "W-T4",
    "wt4_store_directory": "W-T4",
    "wt4_task_dir": "W-T4",
    "wt4_task_lease": "W-T4",
    "wt4_task_record": "W-T4",
    "wt7_unc": "W-T7",
    "wt7_verbatim_unc": "W-T7",
    "wt7_device": "W-T7",
    "wt7_globalroot": "W-T7",
    "wt8_null_dacl_refuses": "W-T8",
    "wt8b_read_only_ace_refuses": "W-T8b",
    "wt9_custody_is_exclusive_and_released": "W-T9",
    "wt10_legacy_token_inherited_acl_refuses": "W-T10",
    "wt10b_legacy_token_remediation_works": "W-T10b",
    "wt11_foreign_owner_refuses": "W-T11",
    "wt12_mapped_network_drive_refuses": "W-T12",
    "wt13_moved_in_unprotected_file_refuses": "W-T13",
    "wt14_second_user_cannot_read": "W-T14",
    "wt15_fat32_volume_refuses": "W-T15",
    "wt15_exfat_volume_refuses": "W-T15",
    "wt16a_held_directory_blocks_its_own_rename": "W-T16a",
    "wt18_path_swap_between_walk_and_open_refuses": "W-T18",
    "wt19_other_ace_type_refuses": "W-T19",
    "wt20_external_holder_released_after_one_attempt": "W-T20",
    "wt20_external_holder_never_released": "W-T20",
    "wt22_durability_calls_are_made": "W-T22",
    "wt23_directory_at_record_name_refuses": "W-T23",
    "wt24_record_is_judged_on_the_open_handle": "W-T24",
    "wt6_symlink_record_refuses": "W-T6",
}
# Regression guards: already true of the permissive stage, must pass.
GUARDS = {
    "wt7_drive_relative", "wt7_root_relative", "wt7_relative", "wt7_parent_component",
    # The existing symlink walk already refuses junctions, and an open store's
    # own sidecar handles already pin its ancestors (probe E6).
    "wt5_junction_in_store_path_refuses", "wt16_open_store_blocks_ancestor_swap",
    "wt17_reader_closes_before_replace",
    "wt21_foreign_deny_ace_is_accepted", "wt22b_sync_file_really_flushes",
    "wt25_create_refuses_an_existing_name",
}



def main() -> int:
    """`LOG` checks a red run; `LOG --mutant ROW [ROW...]` checks a mutant run:
    the named rows must fail with their marker, every other row and guard pass."""
    args = sys.argv[1:]
    killers = set(args[args.index("--mutant") + 1:]) if "--mutant" in args else None
    text = open(args[0], encoding="utf-8", errors="replace").read()
    status = {}
    for name, result in re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)", text, re.M):
        status[name.rsplit("::", 1)[-1]] = result
    blocks = dict(re.findall(r"^---- (\S+) stdout ----\n(.*?)(?=^---- |\Z)", text, re.M | re.S))
    output = {k.rsplit("::", 1)[-1]: v for k, v in blocks.items()}
    problems = []
    # No row may skip in a red or mutant run: an unexecuted row proves nothing.
    problems += [f"skipped: {l.strip()}" for l in text.splitlines() if "WT-SKIP" in l]
    problems += [f"fixture failure: {l.strip()}" for l in text.splitlines() if "WT-FIXTURE" in l]
    for test, row in RED.items():
        must_fail = killers is None or row in killers
        got = status.get(test)
        if must_fail and got != "FAILED":
            problems.append(f"{row} {test}: expected FAILED, got {got}")
        elif must_fail and f"WT-ASSERT {row}" not in output.get(test, ""):
            problems.append(f"{row} {test}: failed without its WT-ASSERT marker")
        elif not must_fail and got != "ok":
            problems.append(f"{row} {test}: expected ok under this mutant, got {got}")
    for test in GUARDS:
        if status.get(test) != "ok":
            problems.append(f"guard {test}: expected ok, got {status.get(test)}")
    for p in problems:
        print(p)
    print(f"{len(RED)} red tests, {len(GUARDS)} guards, {len(problems)} problems")
    return 1 if problems else 0

if __name__ == "__main__":
    sys.exit(main())
