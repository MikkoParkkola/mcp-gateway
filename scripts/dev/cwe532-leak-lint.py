#!/usr/bin/env python3
"""Semantic secret-leak lint (CWE-532) — CI Gate 1.

Flags the exact bug class fixed in #323 (fix(security): redact credentials
from Debug output): a struct that derives `Debug` over a field whose name
looks like a secret, or a log/print macro that interpolates a variable
whose name looks like a secret. Both leak plaintext credentials into traces,
error contexts, or log aggregators.

Two checks:

  1. `#[derive(... Debug ...)]` on a struct with a field matching the
     secret-keyword regex, unless:
       - the struct already has a manual `impl ... Debug for <Name>` in the
         same file (the redaction pattern used by #323), or
       - a `// ci-allow-secret-debug: <reason>` marker sits on the line
         immediately above the derive attribute or the flagged field.

  2. A `info!/debug!/trace!/warn!/error!/println!/eprintln!/print!` macro
     call whose format string interpolates `{ident}` (inline capture) or
     whose top-level (non-nested) argument is a bare identifier / simple
     field-access chain matching the secret-keyword regex, unless a
     `// ci-allow-secret-log: <reason>` marker sits on the same line or the
     line immediately above.

     `format!` is deliberately NOT in this list — see the LOG_MACROS
     comment below for why. It builds strings, not log/trace sinks.

     Arguments nested inside a function call (e.g. `fingerprint(token)`,
     `redact(&self.bearer_token)`) are NOT flagged — that is the documented
     safe pattern (see gateway/auth.rs bearer_token_fingerprint). Only a
     *bare* secret-named value reaching the macro is a leak.

Baseline (cwe532-baseline.txt): a checked-in allowlist of pre-existing,
NOT-YET-FIXED findings, keyed by stable (path, kind, struct.field/macro.ident)
identity — not by line number, so it doesn't churn on unrelated edits. A
finding whose key is in the baseline is reported but does not fail the
build; any finding NOT in the baseline (i.e. newly introduced) fails the
build immediately. This lets the gate go live on day one against an
existing codebase without either (a) requiring every pre-existing risk to
be fixed first, or (b) dishonestly marking real secrets as false positives
via `ci-allow`. See the comment header in cwe532-baseline.txt.

Exit code 0 = clean, 1 = new findings not covered by baseline, 2 = usage/
internal error.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SECRET_RE = re.compile(
    # `token(?!s)` deliberately excludes the plural "tokens" — in this
    # codebase (and most LLM-adjacent Rust code) plural "tokens" is
    # overwhelmingly an LLM usage COUNT (cached_tokens, total_tokens,
    # tokens_saved, max_tokens_per_identity), never credential material.
    # Singular "token" still matches (access_token, bearer_token, token_jti).
    r"(?i)(token(?!s)|secret|password|passwd|api_?key|bearer|credential|private_key|client_secret)"
)

# Field/identifier names that are secret-*shaped* by substring but are not,
# in practice, credential material. Kept intentionally small and each entry
# justified — prefer a ci-allow marker at the call site for anything not
# obviously safe by construction. These exist for names where "safe" is
# true from the name alone: a count, id, label, or well-known OAuth
# discovery-metadata field (URLs / capability lists, never a live secret
# value).
SAFE_FIELD_SUFFIXES = (
    "_name",
    "_names",
    "_id",
    "_ids",
    "_count",
    "_present",
    "_hash",
    "_fingerprint",
    "_type",
    "_types",
)

# Substring (not just suffix) exclusions: OAuth discovery metadata
# (`token_endpoint`, `token_endpoint_auth_methods_supported`,
# `bearer_methods_supported`, `registration_endpoint`) is URLs / capability
# lists advertised in a PUBLIC `.well-known` document, not secret values.
# `jti` is a JWT ID claim, explicitly kept visible for revocation lookups
# elsewhere in this codebase (see key_server/store.rs TemporaryToken).
SAFE_FIELD_CONTAINS = (
    "endpoint",
    "methods_supported",
    "jti",
)

# Boolean-flag naming convention: `has_bearer`, `is_credentialed`, etc. name
# a presence check, never the secret value itself.
BOOL_NAME_PREFIX_RE = re.compile(r"(?i)^(has|is|should|use)_")

# Field types that can never hold plaintext credential material worth
# flagging by this lint (numeric counts, durations, presence flags). A
# String-typed secret is always the actual risk; a u64 "token count" or a
# bool "has_bearer" flag is not, regardless of what its name contains.
NUMERIC_OR_BOOL_TYPE_RE = re.compile(
    r"^(?:Atomic)?(?:bool|u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|"
    r"f32|f64|Duration|SystemTime|Instant|NonZero(?:U8|U16|U32|U64|U128|Usize))\b"
)
TYPE_WRAPPER_RE = re.compile(
    r"^(?:Option|Vec|Box|Arc|Rc|RwLock|Mutex)<\s*(.+)\s*>$"
)

DEBUG_MARKER_RE = re.compile(r"//\s*ci-allow-secret-debug:\s*(\S.*)$")
LOG_MARKER_RE = re.compile(r"//\s*ci-allow-secret-log:\s*(\S.*)$")

DERIVE_RE = re.compile(r"#\[derive\(([^)]*)\)\]")
STRUCT_RE = re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)")
MANUAL_DEBUG_IMPL_RE = re.compile(
    r"impl(?:<[^>]*>)?\s+(?:std::fmt::Debug|fmt::Debug|Debug)\s+for\s+(\w+)"
)
FIELD_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*([^,{}]+?)\s*,?\s*$"
)

# `format!` is deliberately excluded. It is used constantly for legitimate
# secret-*handling* (building an `Authorization: Bearer {token}` header
# value, constructing an error message, building test fixtures) where the
# resulting String is never logged — auditing every `format!` call site
# produced 100% false positives in this codebase (header construction in
# transport/http/mod.rs, identity_propagation/mod.rs; test fixtures in
# redactor.rs, key_server/store.rs). The actual CWE-532 risk is a value
# reaching a tracing/print SINK, which the macros below cover.
LOG_MACROS = (
    "info",
    "debug",
    "trace",
    "warn",
    "error",
    "println",
    "eprintln",
    "print",
)
MACRO_CALL_RE = re.compile(r"\b(" + "|".join(LOG_MACROS) + r")!\s*\(")

INLINE_CAPTURE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_.]*)(?::[^}]*)?\}")

# A "bare" argument: an identifier or a simple field-access / method chain
# with only no-op accessors, e.g. `token`, `self.bearer_token`,
# `cfg.api_key.clone()`, `req.token.as_str()`. Nested calls that WRAP the
# ident (e.g. `hash(token)`) never match this — the ident there is inside
# the call's argument list, which is a different regex position entirely
# (see is_bare_secret_arg).
BARE_TAIL_RE = re.compile(
    r"^&?\**(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\.(?:clone|to_string|as_str|as_ref|as_deref|to_owned)\(\))*$"
)


@dataclass
class Finding:
    path: str
    line: int
    kind: str  # "debug" | "log"
    detail: str
    # Stable identity independent of line number (line numbers drift on any
    # unrelated edit to the file). Used to match against the baseline file
    # so pre-existing, not-yet-fixed findings don't force every future PR
    # to touch unrelated code, while any *new* secret-shaped Debug/log site
    # still fails the build immediately.
    key: str = ""


def is_safe_by_name(name: str) -> bool:
    lname = name.lower()
    if any(lname.endswith(suf) for suf in SAFE_FIELD_SUFFIXES):
        return True
    if any(sub in lname for sub in SAFE_FIELD_CONTAINS):
        return True
    if BOOL_NAME_PREFIX_RE.match(name):
        return True
    return False


def is_numeric_or_bool_type(type_text: str) -> bool:
    t = type_text.strip().lstrip("&").strip()
    # Unwrap common container wrappers (Option<Vec<u64>>, etc.) up to a
    # handful of levels — deep enough for any realistic field declaration.
    for _ in range(4):
        m = TYPE_WRAPPER_RE.match(t)
        if not m:
            break
        t = m.group(1).strip()
    return bool(NUMERIC_OR_BOOL_TYPE_RE.match(t))


def has_marker_above_or_on(lines: list[str], idx: int, marker_re: re.Pattern) -> bool:
    """Check line idx (0-based) and the line immediately above for a marker."""
    for i in (idx, idx - 1):
        if 0 <= i < len(lines) and marker_re.search(lines[i]):
            return True
    return False


def find_manual_debug_impls(lines: list[str]) -> set[str]:
    names = set()
    for line in lines:
        m = MANUAL_DEBUG_IMPL_RE.search(line)
        if m:
            names.add(m.group(1))
    return names


def scan_struct_debug(path: str, lines: list[str], manual_impls: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        dm = DERIVE_RE.search(line)
        if dm and "Debug" in [p.strip() for p in dm.group(1).split(",")]:
            derive_line_idx = i
            # Walk forward past any further attributes/doc comments to the
            # struct declaration.
            j = i + 1
            struct_name = None
            while j < n and j < i + 12:
                sm = STRUCT_RE.search(lines[j])
                if sm:
                    struct_name = sm.group(1)
                    break
                # Stop scanning if we hit another item first (not a struct).
                if re.search(r"\b(fn|enum|impl|trait|mod)\b", lines[j]) and not lines[
                    j
                ].strip().startswith("#["):
                    break
                j += 1

            if struct_name and struct_name not in manual_impls:
                if not has_marker_above_or_on(lines, derive_line_idx, DEBUG_MARKER_RE):
                    # Scan the struct body for secret-shaped fields.
                    body_start = j
                    depth = 0
                    started = False
                    k = body_start
                    while k < n:
                        depth += lines[k].count("{") - lines[k].count("}")
                        if "{" in lines[k]:
                            started = True
                        if started and depth <= 0:
                            break
                        k += 1
                    body_end = k

                    for fline_idx in range(body_start, min(body_end + 1, n)):
                        fm = FIELD_RE.match(lines[fline_idx])
                        if not fm:
                            continue
                        fname = fm.group(1)
                        ftype = fm.group(2)
                        if fname in ("Self",):
                            continue
                        if (
                            SECRET_RE.search(fname)
                            and not is_safe_by_name(fname)
                            and not is_numeric_or_bool_type(ftype)
                        ):
                            if has_marker_above_or_on(lines, fline_idx, DEBUG_MARKER_RE):
                                continue
                            findings.append(
                                Finding(
                                    path=path,
                                    line=fline_idx + 1,
                                    kind="debug",
                                    detail=(
                                        f"struct `{struct_name}` derives Debug over "
                                        f"secret-shaped field `{fname}` "
                                        f"(derive at line {derive_line_idx + 1})"
                                    ),
                                    key=f"{path}|debug|{struct_name}.{fname}",
                                )
                            )
        i += 1
    return findings


def split_top_level_args(arg_text: str) -> list[str]:
    """Split on commas at paren/bracket/brace depth 0, respecting string
    literals so commas inside format strings don't split incorrectly."""
    args: list[str] = []
    depth = 0
    current = []
    in_string = False
    escape = False
    i = 0
    while i < len(arg_text):
        c = arg_text[i]
        if in_string:
            current.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            current.append(c)
            i += 1
            continue
        if c in "([{":
            depth += 1
            current.append(c)
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            current.append(c)
            i += 1
            continue
        if c == "," and depth == 0:
            args.append("".join(current))
            current = []
            i += 1
            continue
        current.append(c)
        i += 1
    if current:
        args.append("".join(current))
    return [a.strip() for a in args if a.strip()]


def extract_call_args(text: str, open_paren_idx: int) -> tuple[str, int]:
    """Given text and the index of the opening '(', return (args_text,
    index_just_after_matching_close_paren)."""
    depth = 0
    in_string = False
    escape = False
    i = open_paren_idx
    start = open_paren_idx + 1
    while i < len(text):
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    return text[start:], len(text)


def is_bare_secret_arg(arg: str) -> str | None:
    """Return the matched identifier if `arg` is a bare identifier / simple
    field-access chain whose tail matches the secret regex, else None."""
    arg = arg.strip()
    if arg.startswith('"'):
        return None
    m = BARE_TAIL_RE.match(arg)
    if not m:
        return None
    tail = m.group(1)
    if SECRET_RE.search(tail) and not is_safe_by_name(tail):
        return tail
    return None


def scan_log_macros(path: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    # Join with a joined-text + per-char line map so a macro call spanning
    # multiple physical lines is still parsed as one logical call.
    joined = "\n".join(lines)
    offsets = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1

    def line_of(idx: int) -> int:
        lo, hi = 0, len(offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offsets[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo

    for m in MACRO_CALL_RE.finditer(joined):
        macro_name = m.group(1)
        open_idx = m.end() - 1  # index of '('
        args_text, _end_idx = extract_call_args(joined, open_idx)
        call_line_idx = line_of(m.start())

        if has_marker_above_or_on(lines, call_line_idx, LOG_MARKER_RE):
            continue

        args = split_top_level_args(args_text)
        if not args:
            continue

        # First arg is conventionally the format string for these macros.
        fmt_arg = args[0]
        rest_args = args[1:]

        flagged_names: list[str] = []

        if fmt_arg.startswith('"') or fmt_arg.startswith('r"'):
            for cm in INLINE_CAPTURE_RE.finditer(fmt_arg):
                ident = cm.group(1).split(".")[-1]
                if SECRET_RE.search(ident) and not is_safe_by_name(ident):
                    flagged_names.append(ident)
        else:
            # No literal format string (e.g. a single non-string arg to
            # println!-style macros isn't valid Rust, but be defensive).
            bare = is_bare_secret_arg(fmt_arg)
            if bare:
                flagged_names.append(bare)

        for a in rest_args:
            bare = is_bare_secret_arg(a)
            if bare:
                flagged_names.append(bare)

        if flagged_names:
            names = ", ".join(sorted(set(flagged_names)))
            findings.append(
                Finding(
                    path=path,
                    line=call_line_idx + 1,
                    kind="log",
                    detail=(
                        f"`{macro_name}!` interpolates secret-shaped value(s): {names}"
                    ),
                    key=f"{path}|log|{macro_name}|{names}",
                )
            )
    return findings


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    lines = text.splitlines()
    manual_impls = find_manual_debug_impls(lines)
    findings = scan_struct_debug(str(path), lines, manual_impls)
    findings += scan_log_macros(str(path), lines)
    return findings


def collect_rs_files(roots: list[str]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        rp = Path(root)
        if not rp.exists():
            continue
        for p in rp.rglob("*.rs"):
            parts = p.parts
            if "target" in parts:
                continue
            files.append(p)
    return sorted(files)


BASELINE_PATH = Path(__file__).resolve().parent / "cwe532-baseline.txt"


def load_baseline() -> set[str]:
    if not BASELINE_PATH.exists():
        return set()
    keys = set()
    for line in BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        keys.add(line)
    return keys


def main(argv: list[str]) -> int:
    roots = argv[1:] if len(argv) > 1 else ["src", "crates"]
    files = collect_rs_files(roots)
    if not files:
        print(f"cwe532-leak-lint: no .rs files found under {roots}", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    for f in files:
        all_findings.extend(scan_file(f))

    if not all_findings:
        print(f"cwe532-leak-lint: clean ({len(files)} files scanned, 0 findings)")
        return 0

    baseline = load_baseline()
    new_findings = [fnd for fnd in all_findings if fnd.key not in baseline]
    baselined_findings = [fnd for fnd in all_findings if fnd.key in baseline]

    all_findings.sort(key=lambda fnd: (fnd.path, fnd.line))
    new_findings.sort(key=lambda fnd: (fnd.path, fnd.line))

    if new_findings:
        print(
            f"cwe532-leak-lint: {len(new_findings)} NEW finding(s) not covered by "
            f"{BASELINE_PATH.name} (CWE-532 risk)\n"
        )
        for fnd in new_findings:
            print(f"{fnd.path}:{fnd.line}: [{fnd.kind}] {fnd.detail}")
        if baselined_findings:
            print(
                f"\n({len(baselined_findings)} additional pre-existing finding(s) "
                f"are tracked in {BASELINE_PATH.name} and did not fail the build.)"
            )
        print(
            "\nFix: give the struct a manual `impl Debug` that redacts the field, "
            "mark a genuine false positive with `// ci-allow-secret-debug: <reason>` "
            "/ `// ci-allow-secret-log: <reason>` on the line above, or — only for "
            "pre-existing debt being tracked, not new code — add the finding's key "
            f"to {BASELINE_PATH.name}."
        )
        return 1

    print(
        f"cwe532-leak-lint: 0 new findings ({len(files)} files scanned, "
        f"{len(baselined_findings)} pre-existing finding(s) tracked in "
        f"{BASELINE_PATH.name}, 0 unbaselined)"
    )
    stale = baseline - {fnd.key for fnd in all_findings}
    if stale:
        print(
            f"\nNote: {len(stale)} baseline entr{'y is' if len(stale) == 1 else 'ies are'} "
            "stale (no longer detected) — safe to remove from "
            f"{BASELINE_PATH.name}:"
        )
        for k in sorted(stale):
            print(f"  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
