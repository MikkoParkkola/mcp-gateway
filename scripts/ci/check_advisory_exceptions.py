#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Cargo-audit advisory ignores stay time-boxed and floored (MIK-8577).

CI's Dependency audit job runs bare `cargo audit`, which reads
`.cargo/audit.toml`. That file ignores RUSTSEC-2026-0381 because
webpki-roots 0.26.11 is a re-export shim of webpki-roots 1.x with no
patched 0.26 release. A cargo-audit ignore has no expiry and is per
advisory id, so it never expires and would also hide an unpatched
webpki-roots 1.0.x. The release gate's `.github/osv-scanner.toml`
instead time-boxes exceptions with `[[IgnoredVulns]]` entries carrying
`id`, `ignoreUntil` and `reason`.

This check requires every id ignored in `.cargo/audit.toml` to appear
in `.github/osv-scanner.toml` with an `ignoreUntil` that has not
passed, and requires the 1.x line of webpki-roots in `Cargo.lock` to
stay at or above the patched floor below. Any webpki-roots version
outside that floored line must be an exact version in the shim list
below; any other version fails, since it could bundle its own
unpatched certificate list hidden by the per-advisory ignore.

  check_advisory_exceptions.py
  check_advisory_exceptions.py --self-test
"""
from __future__ import annotations

import datetime
import sys
import tomllib
from pathlib import Path

# The floor is what keeps the RUSTSEC-2026-0381 ignore from hiding an
# unpatched 1.0.x: cargo-audit ignores are per advisory id, so without
# a floor the 0.26 shim exception would also hide a vulnerable 1.0.x.
FLOORS = {"webpki-roots": (1, 0, 10)}

# These are the only versions whose major is not the floor's major
# (below it, for the entry listed) that the exception covers, because
# they are verified re-export shims of the floored major with no
# certificates of their own: webpki-roots 0.26.11, sha256
# 521bc38abb08001b01866da9f51eb7c5d647a19260e00054a8c7fd5f9e57f7a9,
# `pub use parent::TLS_SERVER_ROOTS;`, MIK-8577. Any other version
# outside the floored line could bundle a real, unpatched certificate
# list that the per-advisory ignore would hide, so it must fail.
SHIMS = {"webpki-roots": {"0.26.11"}}


def floor_problems(lock: dict) -> list[str]:
    problems: list[str] = []
    for package in lock.get("package") or []:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        if not isinstance(name, str) or name not in FLOORS:
            continue
        floor = FLOORS[name]
        floor_text = ".".join(str(part) for part in floor)
        version = package.get("version")
        if not isinstance(version, str):
            problems.append(f"{name}: missing version in Cargo.lock")
            continue
        core = version.split("+", 1)[0]
        numeric = core.split("-", 1)[0]
        try:
            parsed = tuple(int(part) for part in numeric.split("."))
        except ValueError:
            problems.append(f"{name} {version}: unparseable version")
            continue
        if not parsed or parsed[0] != floor[0]:
            if version not in SHIMS.get(name, set()):
                problems.append(
                    f"{name} {version}: not the floored {floor[0]}.x line "
                    f"and not a listed re-export shim"
                )
            continue
        if "-" in core:
            problems.append(
                f"{name} {version}: pre-release version does not "
                f"satisfy the {floor_text} floor"
            )
            continue
        if parsed < floor:
            problems.append(
                f"{name} {version}: below the {floor_text} floor"
            )
    return problems


def exception_problems(audit: dict, osv: dict, today: datetime.date) -> list[str]:
    advisories = audit.get("advisories")
    ignores = advisories.get("ignore") if isinstance(advisories, dict) else None
    entries: dict = {}
    for entry in osv.get("IgnoredVulns") or []:
        if isinstance(entry, dict) and entry.get("id") is not None:
            entries[entry["id"]] = entry
    problems: list[str] = []
    for vuln_id in ignores or []:
        entry = entries.get(vuln_id)
        if entry is None:
            problems.append(
                f"{vuln_id}: ignored in .cargo/audit.toml but missing "
                f"from .github/osv-scanner.toml [[IgnoredVulns]]"
            )
            continue
        raw_until = entry.get("ignoreUntil")
        if raw_until is None:
            problems.append(
                f"{vuln_id}: no ignoreUntil in .github/osv-scanner.toml"
            )
            continue
        if isinstance(raw_until, datetime.datetime):
            until = raw_until.date()
        elif isinstance(raw_until, datetime.date):
            until = raw_until
        elif isinstance(raw_until, str):
            try:
                until = datetime.date.fromisoformat(raw_until)
            except ValueError:
                problems.append(
                    f"{vuln_id}: unparseable ignoreUntil {raw_until!r}"
                )
                continue
        else:
            problems.append(
                f"{vuln_id}: unparseable ignoreUntil {raw_until!r}"
            )
            continue
        if today > until:
            problems.append(
                f"{vuln_id}: ignoreUntil {until.isoformat()} has expired; "
                f"fix the dependency or renew the entry with a reason"
            )
    return problems


def load_toml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("rb") as handle:
        return tomllib.load(handle)


def self_test() -> int:
    today = datetime.date(2026, 10, 12)
    future = today + datetime.timedelta(days=30)
    yesterday = today - datetime.timedelta(days=1)
    vuln = "RUSTSEC-2026-0381"
    audit = {"advisories": {"ignore": [vuln]}}

    def lock(version: str) -> dict:
        return {"package": [{"name": "webpki-roots", "version": version}]}

    def osv(until: object) -> dict:
        return {"IgnoredVulns": [{"id": vuln, "ignoreUntil": until, "reason": "shim"}]}

    floor_cases: list[tuple[str, dict, bool]] = [
        ("webpki-roots 1.0.10 passes", lock("1.0.10"), True),
        ("webpki-roots 1.0.11 passes", lock("1.0.11"), True),
        ("webpki-roots 0.26.11 passes", lock("0.26.11"), True),
        ("webpki-roots 0.26.10 fails", lock("0.26.10"), False),
        ("webpki-roots 0.25.4 fails", lock("0.25.4"), False),
        ("webpki-roots 2.0.0 fails", lock("2.0.0"), False),
        ("webpki-roots 1.0.9 fails", lock("1.0.9"), False),
        ("webpki-roots 1.0.10-alpha fails", lock("1.0.10-alpha"), False),
        ("no webpki-roots passes", {"package": [{"name": "other", "version": "0.1.0"}]}, True),
    ]
    exception_cases: list[tuple[str, dict, dict, bool]] = [
        ("ignored id with a future date passes", audit, osv(future), True),
        ("ignored id with today's date passes", audit, osv(today), True),
        ("ignored id with yesterday fails", audit, osv(yesterday), False),
        ("ignored id absent from the osv config fails", audit, {"IgnoredVulns": []}, False),
        ("ignored id without ignoreUntil fails", audit, {"IgnoredVulns": [{"id": vuln, "reason": "shim"}]}, False),
        ("empty audit config passes", {}, {}, True),
    ]
    failures: list[str] = []
    for label, data, passes in floor_cases:
        if (not floor_problems(data)) is not passes:
            failures.append(label)
    for label, audit_data, osv_data, passes in exception_cases:
        if (not exception_problems(audit_data, osv_data, today)) is not passes:
            failures.append(label)
    if failures:
        for label in failures:
            print(f"self-test failed: {label}", file=sys.stderr)
        return 1
    print("self-test OK")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[2]
    today = datetime.datetime.now(datetime.timezone.utc).date()
    problems = floor_problems(load_toml(root / "Cargo.lock"))
    problems += exception_problems(
        load_toml(root / ".cargo" / "audit.toml"),
        load_toml(root / ".github" / "osv-scanner.toml"),
        today,
    )
    for problem in problems:
        print(f"check_advisory_exceptions: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("check_advisory_exceptions: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
