#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Validate the approved scope; release mode also rejects unresolved acceptance.

Evidence existence is the agreed bar, not automatic proof of a test execution.
Exit 0: valid plan (--check), or accepted release (--release/--publish-check).
Exit 1: valid but incomplete release. Exit 2: invalid/unreadable contract.

A criterion is met, pending, or waived. A waived row ships unmet by operator
ruling: it does not block the tag, it names the resolved decision that
authorised it in ``waived_by``, and it is counted and printed apart from met
and pending so an accepted shortfall cannot read as finished work.

--publish-check runs the same consistency checks as --check on every ref, and
additionally requires completed acceptance when GITHUB_EVENT_NAME/GITHUB_REF
(and, for workflow_dispatch, INPUT_TAG) show a tag push or manual dispatch
(publishing context) whose Cargo.toml [package].version or normalized tag/
input is 4.0.0, with or without a suffix. The one exception is a
4.0.0-beta.N or 4.0.0-rc.N prerelease: by owner decision of 2026-09-25 it
ships to the opt-in channels before acceptance completes, so it gets the
consistency checks only. Both the manifest and the tag must be such a
prerelease; either one naming 4.0.0 otherwise still requires acceptance.
The manifest must exist and parse with a valid version in that context
regardless of which version it names.
"""

import argparse
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
DOCS = pathlib.Path("docs/requirements")
SCOPE = DOCS / "RELEASE-4.0.0-scope-update.md"
STATUS = DOCS / "RELEASE-4.0.0-scope-status.json"
BASELINE = DOCS / "RELEASE-4.0.0-criteria-status.md"
MANIFEST = pathlib.Path("Cargo.toml")
REQUIRED_DECISIONS = {"reference_personal_account_journey"}
ID = re.compile(r"^\| ((?:MIK-\d+|NFR|GH\d+)\.[A-Z0-9]+\.\d+[a-z]?) \|", re.M)
VERSION_400 = re.compile(r"^4\.0\.0([+-].*)?$")
# The two prerelease forms a 4.0.0 beta or candidate takes. Any other suffix
# (4.0.0-hotfix, 4.0.0-beta.1+build) is still held to full acceptance.
PRERELEASE_400 = re.compile(r"^4\.0\.0-(beta|rc)\.\d+$")
VERSION_FORMAT = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")

spec = importlib.util.spec_from_file_location(
    "release_counter", pathlib.Path(__file__).with_name("count-release-criteria.py")
)
counter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(counter)


def unique_object(pairs):
    """Reject duplicate JSON fields instead of accepting the last verdict."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def is_publishing_context(event_name, ref):
    """A published artifact originates from a tag push or a manual dispatch."""
    if event_name == "workflow_dispatch":
        return True
    return event_name == "push" and ref.startswith("refs/tags/")


def requires_400_acceptance(version):
    """4.0.0 in any form except a beta/rc prerelease must be fully accepted."""
    return bool(VERSION_400.match(version)) and not PRERELEASE_400.match(version)


def normalize_ref(value):
    value = value.strip()
    if value.startswith("refs/tags/"):
        value = value[len("refs/tags/") :]
    if value.startswith("v"):
        value = value[1:]
    return value


def manifest_version_errors(root):
    """Read [package].version from the manifest; fail closed on any defect."""
    path = root / MANIFEST
    try:
        text = path.read_text()
    except OSError as error:
        return None, [f"{MANIFEST}: {error}"]
    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return None, [f"{MANIFEST}: invalid TOML: {error}"]
    package = manifest.get("package")
    version = package.get("version") if isinstance(package, dict) else None
    if not isinstance(version, str) or not version.strip():
        return None, [f"{MANIFEST}: [package].version is missing or not a string"]
    if not VERSION_FORMAT.match(version):
        return None, [
            f"{MANIFEST}: [package].version is not a valid version: {version!r}"
        ]
    return version, []


# Ordered delivery stages. A criterion advances left to right; only the last
# one satisfies the tag gate. The intermediate stages exist so that a day of
# real progress is visible in the tracker instead of reading as no movement.
STAGES = ("ungraded", "graded", "built", "on-line", "proven", "met")
BLOCKED_ON = ("none", "operator", "external")
# Anything but "none" is someone else's turn. Deriving the held set keeps a
# blocker category added later from validating but staying invisible.
HELD_ON = tuple(value for value in BLOCKED_ON if value != "none")
# A criterion the operator accepted unmet. It does not block the tag, so the
# two waiver fields are mandatory together and forbidden anywhere else: a row
# that ships unmet has to name the ruling that let it, and say which kind of
# residual it is, so the release record cannot read a measured shortfall and a
# deferred measurement the same way.
CRITERION_KEYS = frozenset(
    {"id", "status", "stage", "blocked_on", "evidence", "note"}
)
WAIVER_KEYS = frozenset({"waived_by", "waiver_kind"})
WAIVER_KINDS = ("measured", "deferred")
# The criteria this release may ship unmet. Membership lives here, in reviewed
# code with a test, so a second waiver cannot be introduced by editing the
# ledger alone: turning a red gate green has to be a diff someone reviews.
# The set is matched exactly against the waived rows, so it also fails when a
# waiver is retired -- a ratchet, not a high-water mark. A stale entry would
# otherwise sit here holding permission for a waiver nobody is taking, ready
# to re-authorise it silently.
APPROVED_WAIVERS = frozenset({"MIK-3274.RANKING.3"})


def stage_burnup(criteria):
    """Render the per-stage counts in stage order, plus what is externally held."""
    counts = {stage: 0 for stage in STAGES}
    for row in criteria:
        if isinstance(row, dict) and row.get("stage") in counts:
            counts[row["stage"]] += 1
    held = [
        f"{row['id']} ({row['blocked_on']})"
        for row in criteria
        if isinstance(row, dict) and row.get("blocked_on") in HELD_ON
    ]
    line = f"{counts['met']}/{len(criteria)} met; " + " | ".join(
        f"{stage} {counts[stage]}" for stage in STAGES
    )
    return line + (f"; held: {', '.join(held)}" if held else "; held: none")


def waiver_errors(row, ident):
    """Check the waiver fields against the row's own status.

    The pair is mandatory on a waived row and forbidden elsewhere, so a stray
    ``waived_by`` cannot sit on a pending row waiting to take effect the day
    someone flips its status, and a waived row cannot ship without naming both
    the ruling behind it and what kind of residual it leaves.
    """
    errors = []
    if row["status"] == "waived":
        if not isinstance(row.get("waived_by"), str) or not row["waived_by"].strip():
            errors.append(
                f"{ident}: a waived criterion needs waived_by naming the"
                " authorising decision"
            )
        if row.get("waiver_kind") not in WAIVER_KINDS:
            errors.append(
                f"{ident}: waiver_kind must be one of {', '.join(WAIVER_KINDS)}"
            )
        return errors
    return [
        f"{ident}: {key} belongs only on a waived criterion"
        for key in sorted(WAIVER_KEYS & set(row))
    ]


def names_criterion(text, ident):
    """Is this criterion named in the text, on its own rather than inside another ID?

    Containment is wrong: a ruling about MIK-3274.RANKING.31 would otherwise
    authorise waiving MIK-3274.RANKING.3. IDs end in digits with an optional
    letter suffix, so a following digit or letter means a different criterion,
    while sentence punctuation after the ID is a genuine mention.
    """
    pattern = rf"(?<![0-9A-Za-z.\-]){re.escape(ident)}(?![0-9A-Za-z])"
    return re.search(pattern, text) is not None


def waiver_authority_errors(waived, decisions):
    """Tie each waiver to a resolved ruling that names the criterion it waives.

    The decision schema has no field for the criterion a ruling governs, nor
    for the release it covers, and its key set is closed, so the operator's
    mandatory ``selection`` text is the only place the link can be read.
    Requiring the criterion to be named there on a token boundary stops a
    waiver borrowing authority off an unrelated resolved decision or off a
    longer ID that merely contains this one. It cannot establish that the
    ruling authorised shipping unmet in this release; that residual is
    printed beside every waiver rather than implied to be verified.
    """
    errors = []
    for ident, authority in waived:
        decision = decisions.get(authority)
        if decision is None:
            errors.append(f"{ident}: waived_by names no decision: {authority}")
        elif decision.get("status") != "resolved":
            errors.append(f"{ident}: waiver authority {authority} is not resolved")
        elif not names_criterion(str(decision.get("selection", "")), ident):
            errors.append(
                f"{ident}: decision {authority} does not name this criterion"
                " in the operator's selection"
            )
    return errors


def waived_burnup(criteria):
    """Split the verdicts three ways so no count hides an accepted shortfall."""
    counts = {status: 0 for status in ("met", "waived", "pending")}
    for row in criteria:
        if isinstance(row, dict) and row.get("status") in counts:
            counts[row["status"]] += 1
    return " / ".join(f"{counts[status]} {status}" for status in counts)


def waiver_lines(criteria):
    """Name every accepted-unmet row with its ruling, so no waiver is silent."""
    return [
        f"  {row['id']} waived by {row.get('waived_by')}"
        f" ({row.get('waiver_kind')})"
        for row in criteria
        if isinstance(row, dict) and row.get("status") == "waived"
    ]


def evidence_errors(root, evidence, label, required):
    if not isinstance(evidence, list):
        return [f"{label}: evidence must be a list of repository file paths"]
    errors = []
    if required and not evidence:
        errors.append(f"{label}: completed verdict needs evidence")
    for item in evidence:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{label}: invalid evidence path")
            continue
        cite, span = split_citation(item)
        if span is None and cite is None:
            errors.append(f"{label}: evidence line citation must be numeric: {item}")
            continue
        path = pathlib.Path(cite)
        resolved = (root / path).resolve()
        if path.is_absolute() or not resolved.is_relative_to(root.resolve()):
            errors.append(
                f"{label}: evidence must remain inside the repository: {item}"
            )
        elif not resolved.is_file():
            errors.append(f"{label}: evidence file does not exist: {item}")
        elif span:
            first, last = span
            if first > last:
                errors.append(f"{label}: evidence range runs backwards: {item}")
                continue
            lines = len(resolved.read_text(errors="replace").splitlines())
            if last > lines:
                errors.append(
                    f"{label}: evidence cites line {last} of a"
                    f" {lines}-line file: {item}"
                )
    return errors


def split_citation(item):
    """Split "path:12" or "path:12-18" into the path and its line span.

    A citation that names lines is checked against the file, so a stale line
    number cannot keep passing as proof after the file it points into moves on.
    Returns (None, None) when the suffix is present but not numeric.
    """
    head, sep, tail = item.rpartition(":")
    if not sep or not tail:
        return item, None
    first, _, last = tail.partition("-")
    if not first.isdigit() or (last and not last.isdigit()):
        return (None, None) if head else (item, None)
    return head, (int(first), int(last or first))


DECISION_KEYS = frozenset({"id", "status", "selection", "evidence"})
DECISION_NOTES = frozenset(
    {"resolved", "authority", "rationale", "consequence", "not_evidence"}
)


def inspect_contract(root, document, data, baseline):
    """Return structural errors and pending obligations without conflating them."""
    errors, pending, blockers = [], [], []
    waived, waived_ids = [], set()
    declared = ID.findall(document)
    approved_counts = re.findall(
        r"^Approved supplemental criteria: ([0-9]+)$", document, re.M
    )
    if len(approved_counts) != 1 or int(approved_counts[0]) != len(declared):
        errors.append(
            "approved supplemental criterion count does not match requirements"
        )
    if not declared or len(declared) != len(set(declared)):
        errors.append("scope requirements must declare a nonempty set of unique IDs")
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "criteria",
        "decisions",
    }:
        return ["ledger must contain schema_version, criteria and decisions"], [], []
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        errors.append("unsupported scope ledger schema_version")

    criteria = data["criteria"]
    seen = set()
    if not isinstance(criteria, list):
        errors.append("criteria must be a list")
        criteria = []
    for position, row in enumerate(criteria, start=1):
        # Name the offending row: the rest of its diagnostics are skipped, so
        # without this the reader has to diff the whole ledger by hand.
        named = isinstance(row, dict) and isinstance(row.get("id"), str)
        label = row["id"] if named else f"criterion #{position}"
        if not isinstance(row, dict) or not CRITERION_KEYS <= set(row):
            errors.append(
                f"{label}: each criterion needs id, status, stage, blocked_on,"
                " evidence and note"
            )
            continue
        for key in sorted(set(row) - CRITERION_KEYS - WAIVER_KEYS):
            errors.append(f"{label}: {key} is not a criterion field")
        ident = row["id"]
        if not isinstance(ident, str):
            errors.append("criterion ID must be a string")
            continue
        if ident in seen:
            errors.append(f"duplicate criterion: {ident}")
        seen.add(ident)
        if row["status"] not in ("pending", "met", "waived"):
            errors.append(f"{ident}: status must be pending, met or waived")
        elif row["status"] == "waived" and ident not in APPROVED_WAIVERS:
            errors.append(f"{ident}: not an approved waiver for this release")
        errors.extend(waiver_errors(row, ident))
        if row["status"] == "waived" and isinstance(row.get("waived_by"), str):
            waived.append((ident, row["waived_by"]))
        if row["status"] == "waived":
            waived_ids.add(ident)
        if row["stage"] not in STAGES:
            errors.append(f"{ident}: stage must be one of {', '.join(STAGES)}")
        elif (row["stage"] == "met") != (row["status"] == "met"):
            # Only the terminal stage may claim the tag-blocking status, so a row
            # cannot advertise progress it has not finished or hide a finished one.
            errors.append(f"{ident}: stage 'met' and status 'met' must agree")
        if row["blocked_on"] not in BLOCKED_ON:
            errors.append(
                f"{ident}: blocked_on must be one of {', '.join(BLOCKED_ON)}"
            )
        elif row["blocked_on"] != "none" and row["stage"] == "met":
            # Nothing is still held by someone once it is finished, and a row
            # claiming both would keep a closed criterion on the held list.
            errors.append(f"{ident}: a met criterion cannot still be blocked")
        if not isinstance(row["note"], str) or not row["note"].strip():
            errors.append(f"{ident}: a verdict needs a nonempty explanatory note")
        errors.extend(
            evidence_errors(root, row["evidence"], ident, row["status"] == "met")
        )
        if row["status"] == "pending":
            pending.append(ident)
    for ident in sorted(set(declared) - seen):
        errors.append(f"missing criterion verdict: {ident}")
    for ident in sorted(seen - set(declared)):
        errors.append(f"verdict without a requirement: {ident}")
    # The other half of the exact match. Scoped to the criteria this ledger
    # governs, so the approved set cannot keep holding permission for a waiver
    # nobody is taking; dropping the row instead is caught just above as a
    # missing verdict, since the requirements document still declares it.
    for ident in sorted((APPROVED_WAIVERS & seen) - waived_ids):
        errors.append(
            f"{ident}: approved as a waiver but no longer waived; remove it"
            " from APPROVED_WAIVERS in this change"
        )

    decisions = data["decisions"]
    # Keyed by ID so a waiver can be resolved back to the ruling behind it,
    # not just told that some decision by that name exists.
    decision_ids = {}
    if not isinstance(decisions, list):
        errors.append("decisions must be a list")
        decisions = []
    for row in decisions:
        if not isinstance(row, dict) or not DECISION_KEYS <= set(row):
            errors.append("each decision needs id, status, selection and evidence")
            continue
        ident = row["id"]
        # A ruling carries why it was taken and who took it. The four keys above
        # stay mandatory; the rest is a closed set so the row cannot become a
        # dumping ground for prose the gate never reads.
        for key in sorted(set(row) - DECISION_KEYS - DECISION_NOTES):
            errors.append(f"{ident}: {key} is not a decision field")
        for key in sorted(DECISION_NOTES & set(row)):
            if not isinstance(row[key], str) or not row[key].strip():
                errors.append(f"{ident}: {key} must carry text when present")
        if not isinstance(ident, str):
            errors.append("decision ID must be a string")
            continue
        if ident in decision_ids:
            errors.append(f"duplicate decision: {ident}")
        decision_ids[ident] = row
        if row["status"] not in ("pending", "resolved"):
            errors.append(f"{ident}: decision must be pending or resolved")
        if not isinstance(row["selection"], str):
            errors.append(f"{ident}: selection must be text")
        elif row["status"] == "resolved" and not row["selection"].strip():
            errors.append(f"{ident}: resolved decision needs the operator's selection")
        elif row["status"] == "pending" and row["selection"].strip():
            errors.append(
                f"{ident}: do not record a selection while awaiting the operator"
            )
        errors.extend(
            evidence_errors(root, row["evidence"], ident, row["status"] == "resolved")
        )
        if row["status"] == "pending":
            pending.append(f"decision:{ident}")
    if not REQUIRED_DECISIONS <= decision_ids.keys():
        errors.append("required decision set differs from the approved contract")
    errors.extend(waiver_authority_errors(waived, decision_ids))

    rows, malformed = counter.rows(baseline)
    if malformed or not rows:
        errors.append("baseline ledger is empty or has malformed criterion rows")
    blockers.extend(ident for _, blocking, ident in rows if blocking == "yes")
    return errors, pending, blockers


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check", action="store_true", help="check consistency; report pending work"
    )
    mode.add_argument(
        "--release", action="store_true", help="also require completed acceptance"
    )
    mode.add_argument(
        "--publish-check",
        action="store_true",
        help="enforce completed 4.0.0 acceptance on a final publish",
    )
    args = parser.parse_args(argv)
    try:
        data = json.loads((ROOT / STATUS).read_text(), object_pairs_hook=unique_object)
        errors, pending, blockers = inspect_contract(
            ROOT, (ROOT / SCOPE).read_text(), data, (ROOT / BASELINE).read_text()
        )
    except (OSError, ValueError) as error:
        print(f"Invalid scope contract: {error}", file=sys.stderr)
        return 2

    require_acceptance = args.release
    if args.publish_check:
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        ref = os.environ.get("GITHUB_REF", "")
        if is_publishing_context(event_name, ref):
            version, manifest_errors = manifest_version_errors(ROOT)
            errors.extend(manifest_errors)
            ref_tag = ""
            if event_name == "push" and ref.startswith("refs/tags/"):
                ref_tag = normalize_ref(ref)
            elif event_name == "workflow_dispatch":
                ref_tag = normalize_ref(os.environ.get("INPUT_TAG", ""))
            require_acceptance = bool(
                (version is not None and requires_400_acceptance(version))
                or (ref_tag and requires_400_acceptance(ref_tag))
            )

    # Keep all of the existing coverage/count/method checks; this adds acceptance,
    # rather than maintaining another implementation of the baseline parser.
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/release/count-release-criteria.py"),
            "--check",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        errors.append("baseline consistency check did not pass")
        print(result.stdout + result.stderr, file=sys.stderr, end="")
    if errors:
        print("Invalid scope contract:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 2

    print(
        f"Scope contract consistent: {len(data['criteria'])} criteria "
        f"({waived_burnup(data['criteria'])}); "
        f"{len(pending)} pending criteria/decisions; {len(blockers)} baseline blocking rows."
    )
    print("Stage burnup: " + stage_burnup(data["criteria"]))
    waivers = waiver_lines(data["criteria"])
    if waivers:
        print(
            "Accepted unmet by operator ruling:\n"
            + "\n".join(waivers)
            + "\n  Each ruling's scope -- shipping unmet, in this release -- is"
            " asserted by the named ruling, not proved by this gate."
        )
    if require_acceptance and (pending or blockers):
        print(
            "Release acceptance incomplete:\n  " + "\n  ".join(pending + blockers),
            file=sys.stderr,
        )
        return 1
    print(
        "Release acceptance complete."
        if require_acceptance
        else "Plan check only; not release approval."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
