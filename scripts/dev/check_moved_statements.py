#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prove MIK-8143's dispatcher split moved statements without changing them.

Usage: check_moved_statements.py <base> <head>

Reassembles `meta_mcp_dispatch` at <head> from its pieces (the `intake`
prelude, the dispatcher, the `tools_call` arm) and compares it, in order, with
the dispatcher at <base>, after normalising only the rewrites the move made:
each early `return x` became `return Err(x)` (applied to <base> too), the
labelled `break` became `return Ok`, names that became references lost their
`&` (and `ref`, and a now-redundant `field: field`), `super::` paths became
`crate::gateway::router::`, the in-flight permit lost its leading underscore,
and the two outputs the arm writes became `*name`. Comments, whitespace and the
punctuation rustfmt reshapes (`,` `;` `{` `}`) are ignored. The alias blocks the move added are cut out by their marker lines.
Exit 0 when the sequences are equal; otherwise print the differing tokens.
"""

from __future__ import annotations

import difflib
import re
import subprocess
import sys

DIR = "src/gateway/router/"


def show(ref: str, path: str) -> list[str]:
    text = subprocess.check_output(["git", "show", f"{ref}:{path}"], text=True)
    return text.split("\n")


def body(lines: list[str], header: str) -> list[str]:
    """The lines inside the fn whose signature line starts with `header`."""
    start = next(i for i, line in enumerate(lines) if line.startswith(header))
    open_at = next(i for i in range(start, len(lines)) if lines[i].endswith("{"))
    close_at = next(i for i in range(open_at + 1, len(lines)) if lines[i] == "}")
    return lines[open_at + 1 : close_at]


def cut(lines: list[str], first: str, last: str) -> list[str]:
    """`lines` without the block from the line containing `first` through
    the line containing `last`."""
    a = next(i for i, line in enumerate(lines) if first in line)
    b = next(i for i in range(a, len(lines)) if last in lines[i])
    return lines[:a] + lines[b + 1 :]


def wrap_returns(s: str) -> str:
    """`return x` -> `return Err(x)`, skipping comments: the rewrite the move made."""
    out, i = [], 0
    while True:
        j = s.find("return ", i)
        if j < 0:
            out.append(s[i:])
            return "".join(out)
        line_start = s.rfind("\n", 0, j) + 1
        if "//" in s[line_start:j] or (j > 0 and (s[j - 1].isalnum() or s[j - 1] == "_")):
            out.append(s[i : j + 7])
            i = j + 7
            continue
        out.append(s[i:j])
        k, depth, in_str = j + 7, 0, False
        while k < len(s):
            c = s[k]
            if in_str:
                if c == "\\":
                    k += 2
                    continue
                if c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c in ";," and depth == 0:
                break
            k += 1
        out.append("return Err(" + s[j + 7 : k].rstrip() + ")")
        i = k


def strip_comments(text: str) -> str:
    out = []
    for line in text.split("\n"):
        in_str, prev, cut_at = False, "", len(line)
        for i, c in enumerate(line):
            if in_str:
                if c == '"' and prev != "\\":
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "/" and prev == "/":
                cut_at = i - 1
                break
            prev = "" if prev == "\\" and c == "\\" else c
        out.append(line[:cut_at])
    return "\n".join(out)


def normalise(text: str) -> str:
    text = strip_comments(text)
    text = text.replace("(ref ", "(").replace("crate::gateway::router::", "super::")
    text = text.replace("_inflight_permit", "inflight_permit")
    text = re.sub(r"\s+", "", text).replace("&", "")
    text = re.sub(r"\b(\w+):\1\b(?=[,}])", r"\1", text)
    return text.replace("*response_targets=", "response_targets=").replace("*execution=", "execution=")


def region(lines: list[str], first: str, last_test) -> tuple[int, int]:
    a = next(i for i, line in enumerate(lines) if line.strip() == first)
    b = next(i for i in range(a + 1, len(lines)) if last_test(lines, i))
    return a, b


def base_sequence(ref: str) -> str:
    lines = body(show(ref, DIR + "handlers.rs"), "async fn meta_mcp_dispatch(")
    pa, pb = region(lines, "// Extract headers and authenticated client from request",
                    lambda ls, i: ls[i] == "    };" and "let external_tool" in ls[i - 4])
    ta, tb = region(lines, "\"tools/call\" => 'tools_call: {",
                    lambda ls, i: ls[i] == "        }" and ls[i + 1].strip() == "// Resources")
    tools = "\n".join(lines[ta : tb + 1]).replace("'tools_call: {", "{", 1)
    tools = tools.replace("break 'tools_call *answer;", "return Ok(*answer);")
    tools = wrap_returns(tools).replace("return Err(Ok(*answer))", "return Ok(*answer)")
    parts = [wrap_returns("\n".join(lines[pa : pb + 1])), "\n".join(lines[pb + 1 : ta]),
             tools, "\n".join(lines[tb + 1 :])]
    return normalise("\n".join(parts))


def head_sequence(ref: str) -> str:
    intake = body(show(ref, DIR + "handlers/dispatch_intake.rs"), "pub(super) async fn intake(")
    intake = intake[: next(i for i, line in enumerate(intake) if line == "    Ok((")]
    tools = body(show(ref, DIR + "handlers/dispatch_tools_call.rs"), "pub(super) async fn tools_call(")
    tools = cut(tools, "// The prelude's facts under the names", "let params = intake.params();")
    tools_text = "\n".join(tools).replace(
        "let response = if let Some((response, audit)) = replay {",
        "if let Some((response, audit)) = replay {", 1)
    disp = body(show(ref, DIR + "handlers.rs"), "async fn meta_mcp_dispatch(")
    disp = cut(disp, "// The prelude (MIK-8143).", "let id = intake.id.clone();")
    sa, sb = region(disp, '"tools/call" => {', lambda ls, i: ls[i] == "        }")
    text = "\n".join(intake + disp[:sa]) + '\n"tools/call" => {\n' + tools_text + "\n}\n" + "\n".join(disp[sb + 1 :])
    norm = normalise(text)
    assert norm.count("};Ok(response)}") == 1, "the arm's tail is not where expected"
    return norm.replace("};Ok(response)}", "}}", 1)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    base, head = base_sequence(sys.argv[1]), head_sequence(sys.argv[2])
    a, b = tokens(base), tokens(head)
    diff = list(difflib.unified_diff(a, b, "base", "head", n=3, lineterm=""))
    if not diff:
        print(f"moved statements equal: {len(a)} tokens, in order")
        return 0
    print("\n".join(diff[:80]))
    return 1


def tokens(text: str) -> list[str]:
    """Every identifier, literal, operator and parenthesis, in order; `,` `;`
    `{` `}` dropped, since rustfmt reshapes them when indentation changes
    (trailing commas, `=> x,` versus `=> { x }`). Block structure is the
    compiler's to check; this checks that no statement moved or changed."""
    return [t for t in re.findall(r'"(?:\\.|[^"\\])*"|\w+|[^\w\s]', text) if t not in ",;{}"]


if __name__ == "__main__":
    sys.exit(main())
