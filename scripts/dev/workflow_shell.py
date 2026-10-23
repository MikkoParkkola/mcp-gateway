# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reading GitHub Actions `run:` text as the shell does (MIK-8410).

`HEREDOC`, `heredocs_dropped`, `joined` and `segments` moved here unchanged from
`scripts/release/test_check_tag_manifest.py`, which imports them back, so the
tag-manifest assertions and the pre-push drift test share one reading of
workflow shell text instead of two that can diverge.
"""
from __future__ import annotations

import itertools
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
    """One program a `run:` block executes, as an invocation form.

    `auto_class` is set when the form's own step makes it CI-only whatever any
    table says (a base bound to a URL or to push-only event data, §5.2)."""

    argv0: str
    script: str
    args: tuple[str, ...] = ()
    pipeline: tuple[str, ...] = field(default=())
    auto_class: str = ""


class UnsupportedSyntax(Exception):
    """Execution syntax the walker cannot classify; the drift test fails closed on it."""


KEYWORDS = {"if", "then", "else", "elif", "fi", "for", "do", "done", "while", "until", "case", "esac", "!"}
PYTHONS = {"python", "python3"}
SCRIPT = re.compile(r"^(?:scripts|benchmarks)/[\w./*-]+\.py$")
SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
ASSIGN = re.compile(r"^([A-Za-z_]\w*)=(.*)$")
FOR_GLOB = re.compile(r"^for\s+(\w+)\s+in\s+(\S+)\s*$")
UNSUPPORTED = ("eval", "source", ".")


def _token(word, bound):
    """`word` with CI tokens replaced by placeholders (§5.2), quotes stripped."""
    word = word.strip("'\"")
    for name, value in bound.items():
        word = word.replace("${" + name + "}", value).replace("$" + name, value)
    word = re.sub(r"\$\{?BASE_SHA\}?", "<BASE_TIP>", word)
    word = re.sub(r"\$\{?HEAD_SHA\}?", "<HEAD>", word)
    word = word.replace("origin/${{github.base_ref}}", "<BASE_TIP>").replace("${{github.base_ref}}", "<BASE_TIP>")
    return re.sub(r"\$\{?RUNNER_TEMP\}?", "<TMP>", word)


def _binding(value):
    """What an assignment's right-hand side binds a variable to (§5.2)."""
    value = value.strip("'\"")
    if "git merge-base" in value:
        return "<MERGE_BASE>", ""
    if "BASE_SHA" in value or "github.base_ref" in value:
        return "<BASE_TIP>", ""
    if re.match(r"https?://", value):
        return value, "network: the base is a download URL, not a commit"
    if "BEFORE" in value or "github.event.before" in value or "HEAD^" in value:
        return value, "ci-env: push-only event data (github.event.before)"
    return value, ""


def _without_redirections(words):
    """`words` with shell redirections (`> f`, `2>&1`, `>/dev/null`) removed."""
    kept, skip = [], False
    for word in words:
        if skip:
            skip = False
            continue
        if re.fullmatch(r"\d*>>?|<", word):
            skip = True
            continue
        if re.match(r"^\d*>>?|^\d*>&", word):
            continue
        kept.append(word)
    return kept


def _single_value(value):
    """Whether `value` is one shell word: quoted, a substitution, or space-free."""
    value = value.strip()
    if value[:1] in "'\"" and value.endswith(value[:1]) and len(value) > 1:
        return True
    if value.startswith("$(") and value.endswith(")"):
        return True
    return " " not in value


def _command_words(piece):
    words = piece.split()
    while words and (words[0] in KEYWORDS or ASSIGN.match(words[0])):
        words = words[1:]
    return words


def executions(run_block: str) -> list[Execution]:
    """Every script execution in one `run:` block, in order."""
    # One word per `${{ … }}` expression, so whitespace splitting keeps it whole.
    run_block = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: "${{" + m.group(1).replace(" ", "") + "}}", run_block)
    lines = heredocs_dropped(run_block.replace("\\\n", " ").splitlines())
    found, bound, loops = [], {}, {}
    for raw in lines:
        if raw.strip().startswith("#"):
            continue
        for pipeline in _split_keep_pipes(raw):
            for inner in SUBSTITUTION.findall(pipeline):
                found += executions(inner[0] or inner[1])
            stages = [s.strip() for s in pipeline.split("|") if s.strip()]
            if not stages:
                continue
            first = stages[0]
            loop = FOR_GLOB.match(first)
            if loop:
                loops[loop.group(1)] = loop.group(2)
                continue
            assign = ASSIGN.match(first)
            if assign and _single_value(assign.group(2)):
                # Every assignment is kept: `base="${BASE_SHA:-}"` and its
                # fallback `base="$(git rev-parse HEAD^)"` are two forms.
                bound.setdefault(assign.group(1), []).append(_binding(assign.group(2)))
                continue
            words = _command_words(SUBSTITUTION.sub("", first))
            if not words:
                continue
            if words[0] in UNSUPPORTED:
                raise UnsupportedSyntax(f"`{words[0]}` hides what it executes: {first}")
            if words[0] not in PYTHONS:
                continue
            # Interpreter flags (`-B`, `-I`) come before the script; the
            # script's own flags after it are arguments and are kept.
            rest = list(words[1:])
            while rest and rest[0].startswith("-") and rest[0] != "-":
                rest.pop(0)
            if not rest:
                continue
            target = rest[0].strip("'\"")
            for var, pattern in loops.items():
                if target in ("$" + var, "${" + var + "}"):
                    target = pattern
            if not SCRIPT.match(target):
                continue
            words_after = _without_redirections(rest[1:])
            used = [v for v in bound if any(("$" + v) in w for w in words_after)]
            for combo in itertools.product(*(bound[v] for v in used)):
                values = {v: value for v, (value, _) in zip(used, combo)}
                klass = next((k for _, k in combo if k), "")
                found.append(Execution(
                    argv0=words[0], script=target, args=tuple(_token(w, values) for w in words_after),
                    pipeline=tuple(stages) if len(stages) > 1 else (),
                    auto_class=klass,
                ))
    return found


def _split_keep_pipes(command):
    """`command` split at `;`, `&&`, `||` and newlines, keeping `|` pipelines whole."""
    pieces, current, quote, i = [], "", None, 0
    while i < len(command):
        char = command[i]
        two = command[i:i + 2]
        if quote:
            if char == quote:
                quote = None
            current += char
        elif char in "'\"":
            quote, current = char, current + char
        elif two in ("&&", "||"):
            pieces.append(current)
            current, i = "", i + 2
            continue
        elif char in ";\n":
            pieces.append(current)
            current = ""
        else:
            current += char
        i += 1
    pieces.append(current)
    return [p.strip() for p in pieces if p.strip()]
