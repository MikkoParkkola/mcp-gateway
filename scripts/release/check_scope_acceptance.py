#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: MIT
"""Validate the approved scope; release mode also rejects unresolved acceptance.

Evidence existence is the agreed bar, not automatic proof of a test execution.
Exit 0: valid plan (--check), or accepted release (--release/--publish-check).
Exit 1: valid but incomplete release. Exit 2: invalid/unreadable contract.

--publish-check runs the same consistency checks as --check on every ref, and
additionally requires completed acceptance when GITHUB_EVENT_NAME/GITHUB_REF
(and, for workflow_dispatch, INPUT_TAG) show a tag push or manual dispatch
(publishing context) whose Cargo.toml [package].version or normalized tag/
input is 4.0.0. The manifest must exist and parse with a valid version in
that context regardless of which version it names.
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
        path = pathlib.Path(item)
        resolved = (root / path).resolve()
        if path.is_absolute() or not resolved.is_relative_to(root.resolve()):
            errors.append(
                f"{label}: evidence must remain inside the repository: {item}"
            )
        elif not resolved.is_file():
            errors.append(f"{label}: evidence file does not exist: {item}")
    return errors


def inspect_contract(root, document, data, baseline):
    """Return structural errors and pending obligations without conflating them."""
    errors, pending, blockers = [], [], []
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
    for row in criteria:
        if not isinstance(row, dict) or set(row) != {
            "id",
            "status",
            "evidence",
            "note",
        }:
            errors.append("each criterion needs id, status, evidence and note")
            continue
        ident = row["id"]
        if not isinstance(ident, str):
            errors.append("criterion ID must be a string")
            continue
        if ident in seen:
            errors.append(f"duplicate criterion: {ident}")
        seen.add(ident)
        if row["status"] not in ("pending", "met"):
            errors.append(f"{ident}: status must be pending or met")
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

    decisions = data["decisions"]
    decision_ids = set()
    if not isinstance(decisions, list):
        errors.append("decisions must be a list")
        decisions = []
    for row in decisions:
        if not isinstance(row, dict) or set(row) != {
            "id",
            "status",
            "selection",
            "evidence",
        }:
            errors.append("each decision needs id, status, selection and evidence")
            continue
        ident = row["id"]
        if not isinstance(ident, str):
            errors.append("decision ID must be a string")
            continue
        if ident in decision_ids:
            errors.append(f"duplicate decision: {ident}")
        decision_ids.add(ident)
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
    if not REQUIRED_DECISIONS <= decision_ids:
        errors.append("required decision set differs from the approved contract")

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
        help="enforce completed 4.0.0 acceptance in publish context",
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
                (version is not None and VERSION_400.match(version))
                or (ref_tag and VERSION_400.match(ref_tag))
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
        f"Scope contract consistent: {len(data['criteria'])} criteria; "
        f"{len(pending)} pending criteria/decisions; {len(blockers)} baseline blocking rows."
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
