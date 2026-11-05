# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reading GitHub Actions `run:` text as the shell does (MIK-8410).

`HEREDOC`, `heredocs_dropped`, `joined` and `segments` moved here unchanged from
`scripts/release/test_check_tag_manifest.py`, which imports them back, so the
tag-manifest assertions and the pre-push drift test share one reading of
workflow shell text instead of two that can diverge.
"""
from __future__ import annotations

import collections
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
# The gates' pinned environment (scripts/gate-env): its interpreter by path in
# the workflows, and as pre-push binds it.
GATE_PYTHONS = {"scripts/gate-env/.venv/bin/python", "$GATE_PY", "${GATE_PY}"}
SCRIPT = re.compile(r"^(?:scripts|benchmarks)/[\w./*-]+\.py$")
# A shell-script step: `bash|sh <script>` or the script run directly. Any repo-relative path
# counts (not absolute, not $VAR, not ../); a leading ./ is not part of the form.
SHELLS = {"bash", "sh"}
SH_SCRIPT = re.compile(r"^(?:\./)?(?!\.\./)((?:[\w.*-]+/)*[\w.*-]+\.sh)$")
SH_PATH = re.compile(r"(?<![\w./$-])(?:\./)?(?:[\w*-][\w.*-]*/)+[\w*-][\w.*-]*\.sh(?![\w.])")
ASSIGN = re.compile(r"^([A-Za-z_]\w*)=(.*)$")
FOR_GLOB = re.compile(r"^for\s+(\w+)\s+in\s+(\S+)\s*$")
UNSUPPORTED = ("eval", "source", ".")


def _interpreter_split(words):
    """(interpreter flags, the rest) of `python|bash|sh <flags> <script> <args>`; `-o` takes its value."""
    rest, flags = list(words[1:]), []
    while rest and rest[0].startswith("-") and rest[0] != "-":
        flags.append(rest.pop(0))
        if re.fullmatch(r"-[A-Za-z]*o", flags[-1]) and rest:  # `-o pipefail`, `-eo pipefail`
            rest.pop(0)
    return flags, rest


def _is_syntax_check(words):
    """`bash -n <files>`: parses, runs nothing. Not with -c, whose text is a command to read."""
    if not (words and words[0] in SHELLS):
        return False
    flags, _ = _interpreter_split(words)
    short = [f[1:].split("o")[0] for f in flags if not f.startswith("--")]
    return any("n" in f for f in short) and not any("c" in f for f in short)


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
    if len(words) > 1 and words[0] == "command" and not words[1].startswith("-"):
        words = words[1:]  # `command bash x.sh` runs bash; `command -v` is a lookup (LOOKUPS)
    if words and words[0] == "env":
        words = words[1:]
        while words and ASSIGN.match(words[0]):
            words = words[1:]
        if words and words[0].startswith("-"):
            raise UnsupportedSyntax(f"`env {words[0]}` changes what runs: {piece}")
    return words


# The completeness guard (lead ruling 2026-10-23, after r2 and r3 each found
# bash forms the walker missed): enumerating bash grammar does not converge, an
# invariant that fails closed does. Every python word and every repo-relative
# `.py` path in a block must be accounted for by an Execution; an excess raises
# UnsupportedSyntax naming it. Both exception lists are closed and pinned (D29).
LOOKUPS = ("command -v", "which", "type", "hash")  # name a program, run nothing
DATA_COMMANDS = ("echo", "printf")  # their `.py` arguments are text, not scripts
PY_WORD = re.compile(r"(?<![\w./$-])python3?(?:\.\d+)?(?![\w.-])")
PY_PATH = re.compile(r"(?<![\w./$-])(?:\./)?(?:[\w*-]+/)*[\w*-]+\.py(?![\w.])")
_LOOKUP_BEFORE = re.compile(r"(?:^|[\s;&|(])(?:" + "|".join(l.replace(" ", r"\s+") for l in LOOKUPS) + r")(?:\s+[\w./-]+)*\s+$")
_INLINE_AFTER = re.compile(r"^(?:\s+-[A-Za-z]+)*\s+-(?:[A-Za-z]*[cm]\b|\s|$)")  # -c, -m, - (stdin)


def _guard_lines(run_block):
    """`run_block`'s command text for the guard: continuations joined, comment
    lines and QUOTED heredoc bodies dropped (unquoted ones expand `$( )`)."""
    text = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: "${{" + m.group(1).replace(" ", "") + "}}", run_block)
    kept, quoted = [], None
    for line in text.replace("\\\n", " ").splitlines():
        if quoted is not None:
            if line.strip() == quoted[0]:
                quoted = None
            elif not quoted[1]:
                kept.append(line)
            continue
        if not line.strip().startswith("#"):
            kept.append(line)
        opener = HEREDOC.search(line)
        if opener:
            quoted = (opener.group(2), bool(opener.group(1)))
    return kept


def _data_stripped(line):
    """`line` without the arguments of its echo/printf commands (DATA_COMMANDS)."""
    kept = []
    for piece in _chains(line):
        for stage in _pipe_stages(piece):
            words = stage.split()
            if not (words and words[0] in DATA_COMMANDS):
                kept.append(stage)
    return " ; ".join(kept)


def _check_complete(run_block, found):
    """Raise UnsupportedSyntax when the block names more Python than `found` runs."""
    lines = _guard_lines(run_block)
    loose = []
    for line in lines:
        for m in PY_WORD.finditer(line):
            if not (_LOOKUP_BEFORE.search(line[:m.start()]) or _INLINE_AFTER.match(line[m.end():])):
                loose.append(line.strip())
    # Only Python runs answer for Python mentions: a shell-script run must not cover a missed one.
    pythons = [e for e in found if e.argv0 in PYTHONS or e.argv0 in GATE_PYTHONS]
    if len(loose) > len(pythons):
        raise UnsupportedSyntax(
            f"{len(loose)} python command(s), {len(pythons)} read as script executions; "
            f"a form the walker cannot read: {' | '.join(dict.fromkeys(loose))}"
        )
    scripts = {e.script for e in found}
    unread = [m.group(0).removeprefix("./") for line in lines for m in PY_PATH.finditer(_data_stripped(line))]
    unread = [path for path in dict.fromkeys(unread) if path not in scripts]
    if unread:
        raise UnsupportedSyntax(f".py path(s) named but not read as an execution: {', '.join(unread)}")
    # Fail closed on shell scripts too: `bash -c 'x.sh'` or a form the walker misreads names a
    # .sh path it never records. A syntax check (`bash -n x.sh`) runs nothing and accounts for it.
    # Every occurrence: a script recorded once must not cover a second, unread invocation of it.
    checked = _syntax_checked_loop_items(lines)
    named = collections.Counter(m.group(0).removeprefix("./") for line in lines
                                for m in SH_PATH.finditer(_syntax_checks_stripped(_data_stripped(line))))
    ran = collections.Counter(e.script for e in found if e.script.endswith(".sh"))
    sh_unread = [path for path, n in named.items() if path not in checked and n > ran[path]]
    if sh_unread:
        raise UnsupportedSyntax(f".sh path(s) named but not read as an execution: {', '.join(sh_unread)}")


def _syntax_checked_loop_items(lines):
    """Paths a `for VAR in a.sh b.sh; do bash -n "$VAR"` loop hands to a syntax check."""
    text = " ; ".join(lines)
    items = set()
    for m in re.finditer(r"\bfor\s+(\w+)\s+in\s+([^;]+);", text):
        use = r"\$\{?" + re.escape(m.group(1)) + r"\b"
        uses = len(re.findall(use, text))
        checks = len(re.findall(r"\b(?:ba)?sh\s+-[A-Za-z]*n[A-Za-z]*\s+\"?" + use, text))
        if uses and uses == checks:  # a loop that also runs `$f` accounts for nothing
            items.update(w.strip("'\"").removeprefix("./") for w in m.group(2).split())
    return items


def _syntax_checks_stripped(line):
    """`line` without its `bash -n` / `sh -n` stages, which only parse their files."""
    kept = []
    for piece in _chains(line):
        for stage in _pipe_stages(piece):
            try:
                words = _command_words(stage)
            except UnsupportedSyntax:
                words = []
            if _is_syntax_check(words):
                continue
            kept.append(stage)
    return " ; ".join(kept)


def executions(run_block: str) -> list[Execution]:
    """Every script execution in one `run:` block, in order; UnsupportedSyntax
    when the block names Python the walker cannot account for."""
    found = _walk(run_block)
    _check_complete(run_block, found)
    return found


def _walk(run_block: str) -> list[Execution]:
    """The walker proper: every script execution it can read, in order."""
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
                found += _walk(body)
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
    direct = SH_SCRIPT.match(words[0].strip("'\""))
    if not direct and words[0].strip("'\"").endswith(".sh"):
        raise UnsupportedSyntax(f"a shell script the walker cannot resolve: {stage}")
    if direct:
        target, rest = direct.group(1), list(words)
        if "*" in target:
            raise UnsupportedSyntax(f"a glob operand runs only its first match: {stage}")
    elif words[0] in PYTHONS or words[0] in GATE_PYTHONS or words[0] in SHELLS:
        # Interpreter flags (`-B`, `-I`, `-e`) come before the script; the
        # script's own flags after it are arguments and are kept.
        flags, rest = _interpreter_split(words)
        # `bash -n` only parses its files (a syntax check) and executes nothing.
        if _is_syntax_check(words):
            return found
        if not rest:
            return found
        target = rest[0].strip("'\"")
        from_loop = False
        for var, pattern in loops.items():
            if target in ("$" + var, "${" + var + "}"):
                target, from_loop = pattern, True
        if "*" in target and not from_loop and target.endswith((".py", ".sh")):
            # `bash scripts/check-*.sh` runs the FIRST match and passes the rest as its arguments.
            raise UnsupportedSyntax(f"a glob operand runs only its first match: {stage}")
        if words[0] in SHELLS:
            sh = SH_SCRIPT.match(target)
            if not sh:
                if target.endswith(".sh"):
                    raise UnsupportedSyntax(f"a shell script the walker cannot resolve: {stage}")
                return found  # `bash -c ...` is not a script execution (the path guard reads its text)
            target = sh.group(1)
        elif not SCRIPT.match(target):
            return found
    else:
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
