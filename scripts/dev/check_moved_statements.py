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
and the two outputs the arm writes became `*name`. Comments and whitespace are ignored; so are the two shapes rustfmt changes
with indentation (trailing commas, `=> { x }` arms). Literals, `&&` and
braces are compared as written. The alias blocks the move added are cut out by their marker lines.
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


TOKEN = re.compile(
    r'b?r##"[\s\S]*?"##|b?r#"[\s\S]*?"#|b?r"[^"]*"'  # raw strings, kept whole
    r'|"(?:\\.|[^"\\])*"'  # string literals, kept whole
    r"|'(?:\\.|[^'\\])'"  # char literals
    r"|'[A-Za-z_]\w*"  # lifetimes and labels
    r"|\d[\w.]*|\w+"  # numbers, identifiers
    r"|::|->|=>|==|!=|<=|>=|&&|\|\||\.\.=?|[^\w\s]"
)
VALUE_END = re.compile(r'^(\w+|"|\'|\)|\]|\?)')


def normalise(text: str) -> list[str]:
    """Tokens of `text` with only the move's rewrites and rustfmt's reshaping
    undone. Literals, `&&`, braces and `;` are kept."""
    text = strip_comments(text).replace("crate::gateway::router::", "super::")
    toks = TOKEN.findall(text)
    out: list[str] = []
    for k, t in enumerate(toks):
        nxt = toks[k + 1] if k + 1 < len(toks) else ""
        if t == "&" and nxt != "mut" and not (out and VALUE_END.match(out[-1])):
            continue  # a unary borrow on a name that is now a reference
        if t == "ref":
            continue  # `Some(ref x)` on what is now a reference
        if t == "*" and nxt in ("response_targets", "execution") and toks[k + 2] == "=":
            continue  # the arm writes its two outputs through `&mut`
        out.append("inflight_permit" if t == "_inflight_permit" else t)
    out = shorthand(out)
    return reshape(out)


def shorthand(toks: list[str]) -> list[str]:
    out: list[str] = []
    k = 0
    while k < len(toks):
        if (k + 3 < len(toks) and toks[k + 1] == ":" and toks[k] == toks[k + 2]
                and re.fullmatch(r"\w+", toks[k]) and toks[k + 3] in (",", "}")):
            out.append(toks[k])
            k += 3
            continue
        out.append(toks[k])
        k += 1
    return out


def reshape(toks: list[str]) -> list[str]:
    """Fold what rustfmt changes with indentation: `=> { x }` and
    `=> { return x; }` arms become `=> x,`; trailing commas and commas after
    a block are dropped."""
    out: list[str] = []
    k = 0
    while k < len(toks):
        if toks[k] == "=>" and k + 1 < len(toks) and toks[k + 1] == "{":
            depth, end, semis = 0, None, []
            for m in range(k + 1, len(toks)):
                if toks[m] in "([{":
                    depth += 1
                elif toks[m] in ")]}":
                    depth -= 1
                    if depth == 0:
                        end = m
                        break
                elif toks[m] == ";" and depth == 1:
                    semis.append(m)
            inner = toks[k + 2 : end]
            single_return = semis == [end - 1] and inner[:1] == ["return"]
            if end is not None and (not semis or single_return):
                out.append("=>")
                out.extend(inner[:-1] if single_return else inner)
                out.append(",")
                k = end + 1
                continue
        out.append(toks[k])
        k += 1
    cleaned: list[str] = []
    for k, t in enumerate(out):
        nxt = out[k + 1] if k + 1 < len(out) else ""
        if t == "," and (nxt in (")", "]", "}") or (cleaned and cleaned[-1] == "}")):
            continue
        cleaned.append(t)
    return cleaned


def region(lines: list[str], first: str, last_test) -> tuple[int, int]:
    a = next(i for i, line in enumerate(lines) if line.strip() == first)
    b = next(i for i in range(a + 1, len(lines)) if last_test(lines, i))
    return a, b


def base_sequence(ref: str) -> list[str]:
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


def head_sequence(ref: str) -> list[str]:
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
    toks = normalise(text)
    tail = ["}", ";", "Ok", "(", "response", ")", "}"]
    at = [k for k in range(len(toks)) if toks[k : k + len(tail)] == tail]
    assert len(at) == 1, "the arm's tail is not where expected"
    return toks[: at[0]] + ["}", "}"] + toks[at[0] + len(tail) :]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    a, b = base_sequence(sys.argv[1]), head_sequence(sys.argv[2])
    diff = list(difflib.unified_diff(a, b, "base", "head", n=4, lineterm=""))
    if not diff:
        print(f"moved statements equal: {len(a)} tokens, in order")
        return 0
    print("\n".join(diff[:80]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
