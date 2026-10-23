# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reading GitHub Actions `run:` text as the shell does (MIK-8410).

`HEREDOC`, `heredocs_dropped`, `joined` and `segments` moved here unchanged from
`scripts/release/test_check_tag_manifest.py`, which imports them back, so the
tag-manifest assertions and the pre-push drift test share one reading of
workflow shell text instead of two that can diverge.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# A heredoc opener: `<<EOF`, `<< 'EOF'`, `<<-"EOF"`, `<<~EOF`. What follows is
# data a command is handed, not command text — but to a textual reader it is
# indistinguishable from workflow YAML, so a `steps:`, a `continue-on-error:`,
# a `DIGEST:` binding or a gate invocation printed inside one satisfies an
# assertion about wiring that no longer exists. `<<:` — YAML's merge key — is
# not an opener and does not match: a delimiter is a word.
HEREDOC = re.compile(r"<<[-~]?\s*(['\"]?)(\w+)\1")

def heredocs_dropped(lines):
    """`lines` with every heredoc body and terminator removed."""
    kept, delimiter = [], None
    for line in lines:
        if delimiter is not None:
            # Inside a payload only the terminator is looked for. Scanning for
            # a further opener here would resume on `<<~CAVEATS` — Ruby source
            # inside a shell heredoc — and hand the rest of the payload back to
            # the assertions as workflow text.
            if line.strip() == delimiter:
                delimiter = None
            continue
        kept.append(line)
        opener = HEREDOC.search(line)
        if opener:
            delimiter = opener.group(2)
    return kept


def joined(lines):
    """`lines` with `\\` continuations joined into one command each.

    Assertions about a cosign invocation have to see the whole command. Read
    line by line, a flag on a continuation line looks like a separate
    statement, and a check for it can be satisfied by a different command
    further down the file.
    """
    commands, buffer, folded, literal = [], "", None, False
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if folded is not None:
            # A folded scalar is one command written across lines: YAML joins
            # them with spaces before Actions ever sees it, so reading them
            # separately rejects a spelling that runs exactly what the
            # one-line form runs.
            if indent > folded:
                # A literal block keeps its newlines, a folded one loses
                # them. Either way the whole scalar is ONE step body: read
                # per line and `exit 0` on the line above the gate is a
                # different command, so nothing can see that the shell is
                # already gone.
                if not literal:
                    separator = " "
                elif buffer.endswith("\\"):
                    # A backslash continuation is the shell's own way of
                    # writing one command across lines, so it splices where
                    # a bare newline separates.
                    buffer, separator = buffer[:-1].rstrip(), " "
                else:
                    separator = "\n"
                buffer = f"{buffer}{separator}{stripped}".strip()
                continue
            commands.append(buffer)
            buffer, folded = "", None
        opener = re.match(r"^(- )?run: *([|>])[-+0-9]*$", stripped)
        if opener and not buffer:
            folded = indent + (2 if opener.group(1) else 0)
            literal = opener.group(2) == "|"
            buffer = "run:"
            continue
        buffer = f"{buffer} {stripped}".strip() if buffer else stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].strip()
            continue
        commands.append(buffer)
        buffer = ""
    if buffer:
        commands.append(buffer)
    return commands


def segments(command):
    """`command` split at its unquoted shell separators.

    Each piece starts where the shell starts reading a command name, which is
    what an assertion about a program being *run* has to anchor on. A
    separator inside quotes is data — `echo "skipped; cosign sign …"` is one
    command that runs nothing — so the quote state is tracked rather than the
    text split on the punctuation.
    """
    found, current, quote, escaped = [], "", None, False
    for char in command:
        if escaped:
            escaped, current = False, current + char
        elif char == "\\" and quote != "'":
            escaped, current = True, current + char
        elif quote:
            if char == quote:
                quote = None
            current += char
        elif char in "'\"":
            quote, current = char, current + char
        elif char in ";&|\n":
            found.append(current)
            current = ""
        else:
            current += char
    found.append(current)
    return [piece.strip() for piece in found if piece.strip()]


@dataclass(frozen=True)
class Execution:
    """One program a `run:` block executes, as an invocation form."""

    argv0: str
    script: str
    args: tuple[str, ...] = ()
    pipeline: tuple[str, ...] = field(default=())


class UnsupportedSyntax(Exception):
    """Execution syntax the walker cannot classify; the drift test fails closed on it."""


def executions(run_block: str) -> list[Execution]:
    """Every script execution in one `run:` block. SKELETON: returns nothing yet."""
    return []
