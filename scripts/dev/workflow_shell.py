# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reading GitHub Actions `run:` text as the shell does (MIK-8410).

`HEREDOC`, `heredocs_dropped`, `joined` and `segments` moved here unchanged from
`scripts/release/test_check_tag_manifest.py`, which imports them back, so the
tag-manifest assertions and the pre-push drift test share one reading of
workflow shell text instead of two that can diverge.
"""
from __future__ import annotations

import enum
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


class Reading(enum.Enum):
    """How `_heredoc_scan` reads its lines. YAML_TEXT: whole workflow files read as text (the
    tag-manifest assertions): one line is one command, any `HEREDOC` match opens a body, and a
    terminator may be indented like the YAML around it. SHELL: one `run:` block read as bash
    reads it: continuations joined, a quoted string or substitution spanning lines kept whole,
    comments dropped, openers only where bash sees an operator, delimiters queued in order, and
    a terminator matched exactly (`<<-` strips leading tabs only)."""

    YAML_TEXT = "yaml-text"
    SHELL = "shell"


class Role(enum.Enum):
    COMMAND = "command"
    BODY = "body"  # unquoted delimiter: bash expands `$( )` in it
    QUOTED_BODY = "quoted-body"  # any quoting in the delimiter: the body is data


@dataclass(frozen=True)
class _Opener:
    delimiter: str
    strip_tabs: bool
    quoted: bool


def _heredoc_scan(lines, reading: Reading) -> list[tuple[str, Role]]:
    """The one heredoc reader: `lines` as (text, Role) in order, terminators dropped.

    Inside a payload only the terminator is looked for. Scanning for a further opener there
    would resume on `<<~CAVEATS` (Ruby source inside a shell heredoc) and hand the rest of
    the payload back to the assertions as workflow text."""
    out, pending, buffer, carry = [], [], None, ""
    for line in lines:
        if pending and buffer is None:
            head = pending[0]
            if reading is Reading.YAML_TEXT:
                closes = line.strip() == head.delimiter
            else:
                # In an unquoted body bash joins backslash-newlines first and compares the
                # joined line: `a\` + `EOF` is body, a lone `\` + `EOF` still ends it.
                joined = carry + line
                closes = (joined.lstrip("\t") if head.strip_tabs else joined) == head.delimiter
            if closes:
                pending.pop(0)
                carry = ""
            else:
                out.append((line, Role.QUOTED_BODY if head.quoted else Role.BODY))
                trailing = len(line) - len(line.rstrip("\\"))
                continues = reading is Reading.SHELL and not head.quoted and trailing % 2 == 1
                carry = (carry + line)[:-1] if continues else ""
            continue
        if reading is Reading.YAML_TEXT:
            out.append((line, Role.COMMAND))
            opener = HEREDOC.search(line)
            if opener:
                pending.append(_Opener(opener.group(2), False, bool(opener.group(1))))
            continue
        buffer = line if buffer is None else buffer + line
        state = _lex_state(buffer)
        if state.continued:
            buffer = buffer[:-1]  # bash drops the backslash-newline: the lines join with nothing
            continue
        if state.open:
            buffer += "\n"  # a quote or substitution spans the newline: one command still
            continue
        command = _comment_dropped(buffer, state)
        buffer = None
        if command.strip():
            out.append((command, Role.COMMAND))
        pending += _openers(_ansi_c_decoded(command))  # `<<$'EOF'` is delimiter EOF, quoted
    if buffer is not None and buffer.strip():
        out.append((buffer, Role.COMMAND))  # unterminated: read as written (Python fails to tokenize)
    return out


def heredocs_dropped(lines):
    """`lines` (workflow text) with every heredoc body and terminator removed."""
    return [text for text, role in _heredoc_scan(lines, Reading.YAML_TEXT) if role is Role.COMMAND]


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
ASSIGN = re.compile(r"^([A-Za-z_]\w*)=(.*)$")
FOR_GLOB = re.compile(r"^for\s+(\w+)\s+in\s+(\S+)\s*$")
UNSUPPORTED = ("eval", "source", ".")

# Shell scripts (lead ruling 2026-11-05, after three review rounds each found a shell form the walker
# misread): a .sh is never parsed out of arbitrary shell. A line (continuations joined) that names a
# repo .sh path must be exactly one canonical form, with nothing chained (`|`, `&&`, `||`, `;`, `&`,
# `$( )`, backticks, a `VAR=`/env prefix, `if`); only trailing redirections may follow:
#   run           `bash <path>.sh [args]`  or  `<path>.sh [args]` (a leading ./ is not part of the form)
#   syntax check  `bash -n <path>.sh`, or `for f in <path>.sh ...; do bash -n "$f"; done`
# Anything else naming a .sh fails closed: rewrite the workflow line or list it CI_ONLY.
SH_SCRIPT = re.compile(r"^(?:\./)?(?!\.\./)((?:[\w.-]+/)*[\w.-]+\.sh)$")
# Any word ending in .sh triggers the rule, however it is spelled ($DIR/x.sh, x-*.sh, "x.sh").
SH_MENTION = re.compile(r"\.sh(?![\w.-])")
# The same, with quotes or escapes between the letters, for text shlex cannot split.
SH_MENTION_QUOTED = re.compile(r"\.[\\'\"]*s[\\'\"]*h(?![\w.-])")


def _names_sh(text):
    """Whether `text` names a .sh, as written or once the shell drops quotes and escapes (x.s"h",
    x.$'\x73h'). Text shlex cannot split counts if `.sh` survives any quotes or escapes between."""
    if SH_MENTION.search(text):
        return True
    text = _ansi_c_decoded(text)
    try:
        return bool(SH_MENTION.search(" ".join(shlex.split(text))))
    except ValueError:
        return bool(SH_MENTION_QUOTED.search(text))


_ANSI_C_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
                  "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_ANSI_C_ESCAPE = re.compile(r"\\(?:x([0-9A-Fa-f]{1,2})|([0-7]{1,3})|u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|c(.)|(.))", re.S)


def _ansi_c_value(body):
    r"""What bash makes of the text between `$'` and `'`: octal and hex give one byte (an octal
    past 255 wraps), `\u`/`\U` a code point, `\cX` a control character; an unknown escape keeps
    its backslash."""
    def one(m):
        hexa, octal, u4, u8, ctrl, other = m.groups()
        if hexa or octal:
            return chr(int(hexa, 16) if hexa else int(octal, 8) & 0xFF)
        if u4 or u8:
            return chr(min(int(u4 or u8, 16), 0x10FFFF))
        if ctrl:
            return chr(ord(ctrl) & 0x1F)
        return _ANSI_C_SIMPLE.get(other, "\\" + other)
    return _ANSI_C_ESCAPE.sub(one, body).split("\0", 1)[0]  # bash ends the value at a NUL


def _ansi_c_decoded(text):
    """`text` with every `$'…'` bash reads rewritten as the single-quoted string it stands for, and
    a top-level `$"…"` as plain double quotes, so every reader after this sees what bash passes.
    A `$'` left unterminated stays as written (and is refused where a word must be read)."""
    state = _lex_state(text)
    out, i = [], 0
    for begin, finish in state.ansi_c:
        out.append(text[i:begin])
        out.append("'" + _ansi_c_value(text[begin + 2:finish - 1]).replace("'", "'\\''") + "'")
        i = finish
    out.append(text[i:])
    decoded = "".join(out)
    top, _ = _lex(decoded)
    locale = [k for k in range(len(decoded)) if top[k] and decoded.startswith('$"', k)]
    return "".join(ch for k, ch in enumerate(decoded) if k not in locale)  # `$"x"` -> `"x"`


SH_SYNTAX_LOOP = re.compile(r'^for\s+(\w+)\s+in\s+((?:\S+\.sh\s+)*\S+\.sh)\s*;\s*do\s+bash\s+-n\s+"\$\1"\s*;\s*done$')


class ShellLines(enum.Enum):
    """What a `run:` block's non-canonical .sh line does: STRICT raises (workflows);
    SKIP contributes no form (pre-push.sh, read only to credit forms it already runs)."""

    STRICT = "strict"
    SKIP = "skip"


def _token(word, bound):
    """`word` (already dequoted) with CI tokens replaced by placeholders (§5.2)."""
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


_REDIRECT = re.compile(r"\d*(?:>>?|>\||<<<|<>?|>&|<&)|&>>?")
# The run list writes CI tokens as placeholders (`<BASE_TIP>`, `<HEAD>..x`): words, not input
# redirections. No workflow line can use the spelling: bash would read a file named `BASE_TIP>`.
_PLACEHOLDER = re.compile(r"<[A-Z_]+>")


def _without_redirections(words):
    """`words` (as written, quotes kept) with shell redirections removed: an operator alone
    (`> f`, `<<< w`, `&> f`) takes the next word with it; one with its target attached
    (`>f`, `2>&1`, `<in`, `&>log`, `<<EOF`) is dropped alone."""
    kept, skip = [], False
    for word in words:
        if skip:
            skip = False
            continue
        if _REDIRECT.fullmatch(word):
            skip = True
            continue
        if _REDIRECT.match(word) and not _PLACEHOLDER.match(word):
            continue
        kept.append(word)
    return kept


def _words(text):
    """`text`'s shell words as (written, value): split where `_lex` sees top-level whitespace,
    so adjacent quoted and unquoted fragments stay one word (`"--"strict` is `--strict`).
    Redirections are removed on the written words (a quoted ">" is an argument), then each is
    dequoted. ValueError on an unterminated quote."""
    top, _ = _lex(text)
    written, current = [], ""
    for flag, char in zip(top, text):
        if flag and char.isspace():
            if current:
                written.append(current)
            current = ""
        else:
            current += char
    if current:
        written.append(current)
    return [(w, "".join(shlex.split(w))) for w in _without_redirections(written)]


def _ansi_c(written):
    """Whether a word uses `$'…'` quoting bash reads (complete or unterminated) or `$"…"`: a
    credited command using it is refused, since no decoding here is trusted for its value."""
    state = _lex_state(written)
    top = state.top
    return bool(state.ansi_c) or state.ansi_c_open or any(
        top[i] and written.startswith('$"', i) for i in range(len(written)))


def _single_value(value):
    """Whether `value` is one shell word (`x="a b"` is; `x=a b` is a prefix)."""
    value = value.strip()
    if not value:
        return True
    top, _ = _lex(value)
    return not any(flag and char.isspace() for flag, char in zip(top, value))


def _lex(text):
    """One reading of shell quoting for `text`: (top, spans); see `_lex_state`."""
    state = _lex_state(text)
    return state.top, state.spans


@dataclass(frozen=True)
class _LexState:
    top: list
    spans: list
    open: bool  # `text` ends inside a quote or a command substitution
    continued: bool  # `text` ends in a backslash bash removes with the newline after it
    comment: int  # where a top-level `#` comment starts, -1 for none
    ansi_c: list  # (start, end) of each complete `$'…'` (start at the `$`, end past the `'`)
    ansi_c_open: bool  # `text` ends inside a `$'…'`


def _lex_state(text):
    """One reading of shell quoting for `text`.

    `top[i]` is True where the shell would see an operator at index i: outside
    quotes, escapes, comments and command substitutions. `spans` are the outermost
    command substitutions as (start, end, body): `$( … )` and backticks,
    nested ones included in their parent's body, single-quoted ones never.
    A context stack, not a set of regexes, so `"it's $(x)"`, `"a\\"b"` and
    `$(a $(b))` read as the shell reads them. A `#` starting a word at top level
    comments out the rest of its line: quotes in a comment open nothing.
    """
    top, spans, stack, escaped, i, start, comment = [False] * len(text), [], [], False, 0, None, -1
    ansi_c, ansi_start = [], None
    while i < len(text):
        frame = stack[-1] if stack else None
        char, width = text[i], 1
        if escaped:
            escaped = False
        elif frame == "'":
            if char == "'":
                stack.pop()
        elif frame == "$'":
            # Bash's ANSI-C quoting: a backslash escapes here, so `\'` does not end it.
            if char == "\\":
                escaped = True
            elif char == "'":
                stack.pop()
                ansi_c.append((ansi_start, i + 1))
        elif text.startswith("$'", i) and frame != '"':
            stack.append("$'")
            ansi_start, width = i, 2
        elif not stack and char == "#" and (i == 0 or (top[i - 1] and text[i - 1] in " \t\n;&|()")):
            end = text.find("\n", i)
            comment = i if comment < 0 else comment
            i = len(text) if end < 0 else end
            continue
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
    return _LexState(top, spans, bool(stack), escaped, comment, ansi_c, "$'" in stack)


def _comment_dropped(text, state):
    """`text` without its top-level comment (it runs to the end: see `_heredoc_scan`)."""
    return text[:state.comment].rstrip() if state.comment >= 0 else text


_WORD_END = frozenset(" \t\n;&|()<>")


def _arithmetic_spans(command, top):
    """(start, end) of each top-level `(( … ))` arithmetic command (`$(( ))` is a substitution
    and never top-level). An unclosed one runs to the end: nothing after it opens a heredoc."""
    spans, i = [], 0
    while i < len(command) - 1:
        if top[i] and top[i + 1] and command.startswith("((", i) and (i == 0 or command[i - 1] != "$"):
            end = next((k for k in range(i + 2, len(command) - 1)
                        if top[k] and top[k + 1] and command.startswith("))", k)), len(command))
            spans.append((i, end))
            i = end + 2
            continue
        i += 1
    return spans


def _openers(command):
    """The heredocs `command` opens, in the order bash reads their bodies. A delimiter is the
    whole word after `<<`/`<<-`; quoting anywhere in it makes the body data and is removed."""
    top, _ = _lex(command)
    found, i, arithmetic = [], 0, _arithmetic_spans(command, top)
    while i < len(command) - 1:
        if any(a <= i < b for a, b in arithmetic):
            i += 1  # `((x = 1 << n))`: a shift, not an opener
            continue
        if command.startswith("<<<", i):
            i += 3  # a here-string, not an opener (and its last two `<` are not one either)
            continue
        if not (top[i] and top[i + 1] and command.startswith("<<", i)):
            i += 1
            continue
        j = i + 2
        strip_tabs = command.startswith("-", j)
        j += strip_tabs
        while j < len(command) and command[j] in " \t":
            j += 1
        word, quoted = "", False
        while j < len(command) and command[j] not in _WORD_END:
            char = command[j]
            if char == "'":
                close = command.find("'", j + 1)
                close = len(command) if close < 0 else close
                word, quoted, j = word + command[j + 1:close], True, close + 1
            elif char == '"':
                j, quoted = j + 1, True
                while j < len(command) and command[j] != '"':
                    if command[j] == "\\" and command[j + 1:j + 2] in ('"', "\\", "$", "`"):
                        j += 1
                    word, j = word + command[j:j + 1], j + 1
                j += 1
            elif char == "\\":
                word, quoted, j = word + command[j + 1:j + 2], True, j + 2
            else:
                word, j = word + char, j + 1
        if word or quoted:  # `<<''` is an empty delimiter; a bare `<<` opens nothing
            found.append(_Opener(word, strip_tabs, quoted))
        i = j
    return found


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
    """The words of a simple command, redirections removed and prefixes peeled: keywords,
    `VAR=value` assignments and `env [VAR=value…]`. Python commands must tokenize and may not
    use `$'…'` quoting; other commands whose quoting cannot be read run nothing this check sees."""
    decoded = _ansi_c_decoded(piece)
    try:
        names = set(shlex.split(decoded)) | {w.rsplit("/", 1)[-1] for w in shlex.split(decoded)}
    except ValueError:
        names = set(re.split(r"[\s\"'/]+", decoded))
    is_python = bool((PYTHONS | GATE_PYTHONS) & names)
    try:
        pairs = _words(piece)
    except ValueError as err:
        if not is_python:
            return []
        raise UnsupportedSyntax(f"{err}: {piece}") from None
    if is_python and any(_ansi_c(w) for w, _ in pairs):
        raise UnsupportedSyntax(f"`$'…'` quoting in a Python command is not decoded: {piece}")
    words = [value for _, value in pairs]
    while words and (words[0] in KEYWORDS or ASSIGN.match(words[0])):
        words = words[1:]
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
    """`run_block`'s command text for the guard: commands as bash reads them (see
    `_heredoc_scan`) plus UNQUOTED heredoc bodies (they expand `$( )`)."""
    text = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: "${{" + m.group(1).replace(" ", "") + "}}", run_block)
    return [_ansi_c_decoded(line) for line, role in _heredoc_scan(text.splitlines(), Reading.SHELL)
            if role is not Role.QUOTED_BODY]


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
    if len(loose) > len(found):
        raise UnsupportedSyntax(
            f"{len(loose)} python command(s), {len(found)} read as script executions; "
            f"a form the walker cannot read: {' | '.join(dict.fromkeys(loose))}"
        )
    scripts = {e.script for e in found}
    unread = [m.group(0).removeprefix("./") for line in lines for m in PY_PATH.finditer(_data_stripped(line))]
    unread = [path for path in dict.fromkeys(unread) if path not in scripts]
    if unread:
        raise UnsupportedSyntax(f".py path(s) named but not read as an execution: {', '.join(unread)}")


def executions(run_block: str, shell_lines: ShellLines = ShellLines.STRICT,
               ci_only_lines: frozenset = frozenset()) -> list[Execution]:
    """Every script execution in one `run:` block, in order; UnsupportedSyntax
    when the block names Python the walker cannot account for, or (STRICT) a
    .sh in anything but a canonical line. A line in `ci_only_lines` (compared with
    its whitespace collapsed) is CI-only by its table entry and yields nothing."""
    ci_only_lines = frozenset(" ".join(line.split()) for line in ci_only_lines)
    found = _walk(run_block, shell_lines, ci_only_lines)
    _check_complete(run_block, [e for e in found if not e.script.endswith(".sh")])
    return found


def _walk(run_block: str, shell_lines: ShellLines = ShellLines.STRICT, ci_only_lines=frozenset()) -> list[Execution]:
    """The walker proper: every script execution it can read, in order."""
    # One word per `${{ … }}` expression, so whitespace splitting keeps it whole.
    run_block = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda m: "${{" + m.group(1).replace(" ", "") + "}}", run_block)
    scanned = _heredoc_scan(run_block.splitlines(), Reading.SHELL)
    # A heredoc body is data to the Python reading, but it may be a script fed to a shell
    # (`bash <<EOF`): a .sh named in one fails closed unless that exact line is listed.
    for body, role in scanned:
        if (role is not Role.COMMAND and _names_sh(body) and " ".join(body.split()) not in ci_only_lines
                and shell_lines is ShellLines.STRICT):
            raise UnsupportedSyntax(f"a .sh inside a heredoc body: {body.strip()}")
    lines = [text for text, role in scanned if role is Role.COMMAND]
    found, bound, loops = [], {}, {}
    for raw in lines:
        if any("\n" in body and (PY_WORD.search(body) or PY_PATH.search(body) or _names_sh(body))
               for _, _, body in _lex(raw)[1]):
            # One that names a script is refused, as before the one scanner (lead ruling 2026-11-08, after a review found
            # `out=$(python3 x.py<newline>) |`, which bash rejects, credited as a run): reading it
            # would need bash's own parse to tell a runnable command from a syntax error.
            raise UnsupportedSyntax(f"a command substitution spanning lines; write it on one line: {raw.strip()}")
        if _names_sh(raw):
            if " ".join(raw.split()) in ci_only_lines:
                continue
            try:
                found += _shell_line(raw.strip(), bound)
            except UnsupportedSyntax:
                if shell_lines is ShellLines.STRICT:
                    raise
            continue
        for pipeline in _chains(raw):
            # A substitution runs its own commands (nested ones recursively);
            # single-quoted text is data and holds none.
            for _, _, body in _lex(pipeline)[1]:
                found += _walk(body, shell_lines, ci_only_lines)
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
    if words[0] not in PYTHONS and words[0] not in GATE_PYTHONS:
        return found
    # Interpreter flags (`-B`, `-I`) come before the script; the
    # script's own flags after it are arguments and are kept.
    rest = list(words[1:])
    while rest and rest[0].startswith("-") and rest[0] != "-":
        rest.pop(0)
    if not rest:
        return found
    target = rest[0]
    for var, pattern in loops.items():
        if target in ("$" + var, "${" + var + "}"):
            target = pattern
    if not SCRIPT.match(target):
        return found
    if "*" in target and not any(target == p for p in loops.values()):
        raise UnsupportedSyntax(f"a glob operand runs only its first match: {stage}")
    return found + _forms(words[0], target, rest[1:], stages, bound)


def _forms(argv0, target, args, stages, bound):
    """One Execution per combination of the bound values its arguments use (redirections already removed)."""
    found = []
    words_after = list(args)
    used = [v for v in bound if any(("$" + v) in w for w in words_after)]
    for combo in itertools.product(*(bound[v] for v in used)):
        values = {v: value for v, (value, _) in zip(used, combo)}
        klass = next((k for _, k in combo if k), "")
        found.append(Execution(
            argv0=argv0, script=target, args=tuple(_token(w, values) for w in words_after),
            pipeline=tuple(stages) if len(stages) > 1 else (),
            auto_class=klass,
        ))
    return found


def _shell_line(line, bound):
    """The forms one line naming a .sh runs: [] for a syntax check, one per binding for a run;
    UnsupportedSyntax for anything but a canonical line (see SH_SCRIPT above)."""
    if SH_SYNTAX_LOOP.match(line):
        paths = SH_SYNTAX_LOOP.match(line).group(2).split()
        if all(SH_SCRIPT.match(p) for p in paths):
            return []
        raise UnsupportedSyntax(f"a syntax-check loop over a path that is not a plain repo script: {line}")
    top, spans = _lex(line)
    chained = [i for i, (flag, char) in enumerate(zip(top, line)) if flag and char in ";&|"
               and not (char == "&" and ">" in line[max(i - 1, 0):i + 2])]  # 2>&1, &>f are redirections
    # `<( )` and `>( )` run their own commands, like `$( )`.
    process = [i for i, (flag, char) in enumerate(zip(top, line)) if flag and char in "<>" and line[i + 1:i + 2] == "("]
    if spans or chained or process:
        raise UnsupportedSyntax(f"a .sh in a chained or substituted command; write it as its own line: {line}")
    # Words as bash reads them (see `_words`); the script word itself must be written plainly
    # (no quotes or escapes), and no word may use `$'…'` quoting, which is not decoded here.
    try:
        pairs = _words(line)
    except ValueError as err:
        raise UnsupportedSyntax(f"{err}: {line}") from None
    if any(_ansi_c(w) for w, _ in pairs):
        raise UnsupportedSyntax(f"`$'…'` quoting on a .sh line is not decoded: {line}")
    written, words = [w for w, _ in pairs], [v for _, v in pairs]
    argv0 = words[0] if words else ""
    if argv0 == "bash":
        words = words[1:]
        if words[:1] == ["-n"]:
            if len(words) == 2 and written[-1] == words[1] and SH_SCRIPT.match(words[1]):
                return []
            raise UnsupportedSyntax(f"`bash -n` checks one plainly written script per line (or the loop form): {line}")
    plain = written[len(written) - len(words):] if words else []
    script = SH_SCRIPT.match(words[0]) if words and plain[0] == words[0] else None
    if not script:
        raise UnsupportedSyntax(f"not `bash <path>.sh [args]`, `<path>.sh [args]` or `bash -n <path>.sh`: {line}")
    return _forms(argv0 if argv0 == "bash" else script.group(1), script.group(1), words[1:], (), bound)
