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
import shlex
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
    if value.startswith(("$(", "`")):
        return None  # computed at run time: the variable stays opaque
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
    """Whether `value` is one shell word (`x="a b"` is; `x=a b` is a prefix)."""
    value = value.strip()
    if not value:
        return True
    top, _ = _lex(value)
    return not any(flag and char.isspace() for flag, char in zip(top, value))


def _lex(text):
    """One reading of shell quoting for `text`: (top, spans).

    `top[i]` is True where the shell would see an operator at index i: outside
    quotes, escapes and command substitutions. `spans` are the outermost
    command substitutions as (start, end, body): `$( … )` and backticks,
    nested ones included in their parent's body, single-quoted ones never.
    A context stack, not a set of regexes, so `"it's $(x)"`, `"a\\"b"` and
    `$(a $(b))` read as the shell reads them.
    """
    top, spans, stack, escaped, i, start = [False] * len(text), [], [], False, 0, None
    while i < len(text):
        frame = stack[-1] if stack else None
        char, width = text[i], 1
        if escaped:
            escaped = False
        elif frame == "'":
            if char == "'":
                stack.pop()
        elif char == "\\":
            escaped = True
        elif frame == '"' and char == '"':
            stack.pop()
        elif text.startswith("$(", i):
            if not any(f in ("$(", "`") for f in stack):
                start = i
            stack.append("$(")
            width = 2
        elif char == "`" and frame == "`":
            stack.pop()
        elif char == "`":
            if not any(f in ("$(", "`") for f in stack):
                start = i
            stack.append("`")
        elif char == ")" and frame == "$(":
            stack.pop()
        elif char in "'\"" and frame != '"':
            stack.append(char)
        else:
            top[i] = not stack
        if start is not None and not any(f in ("$(", "`") for f in stack):
            body = text[start + (2 if text.startswith("$(", start) else 1):i]
            spans.append((start, i + width, body))
            start = None
        i += width
    # An unterminated quote leaves the rest non-top: a Python stage then fails
    # to tokenize (fail closed); any other command runs nothing seen here.
    return top, spans


def _split_top(text, separators):
    """`text` split at the `separators` the shell sees (top-level only), stripped."""
    top, _ = _lex(text)
    pieces, current, i = [], "", 0
    while i < len(text):
        sep = next((s for s in separators if top[i] and text.startswith(s, i)
                    and all(top[i + k] for k in range(len(s)))), None)
        if sep == "|" and text.startswith("||", i):
            sep = None if "||" not in separators else "||"
        if sep:
            pieces.append(current)
            current, i = "", i + len(sep)
            continue
        current += text[i]
        i += 1
    pieces.append(current)
    return [piece.strip() for piece in pieces if piece.strip()]


def _chains(command):
    """`command` split at `;`, `&&`, `||` and newlines, keeping `|` pipelines whole."""
    return _split_top(command, ("&&", "||", ";", "\n"))


def _pipe_stages(pipeline):
    """`pipeline` split at the `|` the shell sees, stages stripped."""
    return _split_top(pipeline, ("|",))


def _without_substitutions(text):
    """`text` with its outermost command substitutions removed (they run separately)."""
    _, spans = _lex(text)
    for start, end, _ in reversed(spans):
        text = text[:start] + text[end:]
    return text


def _command_words(piece):
    """The words of a simple command, prefixes peeled: keywords, `VAR=value`
    assignments and `env [VAR=value…]`. Python commands must tokenize; other
    commands whose quoting shlex cannot read run nothing this check sees."""
    try:
        words = shlex.split(piece)
    except ValueError as err:
        if not PYTHONS & set(re.split(r"[\s\"'/]+", piece)):
            return []
        raise UnsupportedSyntax(f"{err}: {piece}") from None
    while words and (words[0] in KEYWORDS or ASSIGN.match(words[0])):
        words = words[1:]
    if words and words[0] == "env":
        words = words[1:]
        while words and ASSIGN.match(words[0]):
            words = words[1:]
        if words and words[0].startswith("-"):
            raise UnsupportedSyntax(f"`env {words[0]}` changes what runs: {piece}")
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
        for pipeline in _chains(raw):
            # A substitution runs its own commands (nested ones recursively);
            # single-quoted text is data and holds none.
            for _, _, body in _lex(pipeline)[1]:
                found += executions(body)
            stages = _pipe_stages(pipeline)
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
                name = assign.group(1)
                bound.setdefault(name, []).append(_binding(assign.group(2)) or ("$" + name, ""))
                continue
            # Every stage is a command: `cat f | python3 scripts/x.py` runs x.py.
            for stage in stages:
                found += _stage_execution(stage, stages, bound, loops)
    return found


def _stage_execution(stage, stages, bound, loops):
    """The script execution forms one pipeline stage runs (none, or one per binding)."""
    found = []
    words = _command_words(_without_substitutions(stage))
    if not words:
        return found
    if words[0] in UNSUPPORTED:
        raise UnsupportedSyntax(f"`{words[0]}` hides what it executes: {stage}")
    if words[0] not in PYTHONS:
        return found
    # Interpreter flags (`-B`, `-I`) come before the script; the
    # script's own flags after it are arguments and are kept.
    rest = list(words[1:])
    while rest and rest[0].startswith("-") and rest[0] != "-":
        rest.pop(0)
    if not rest:
        return found
    target = rest[0].strip("'\"")
    for var, pattern in loops.items():
        if target in ("$" + var, "${" + var + "}"):
            target = pattern
    if not SCRIPT.match(target):
        return found
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
