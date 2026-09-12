# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression tests for the tag/manifest publish gate and its channel predicate."""

import contextlib
import importlib.util
import io
import os
import pathlib
import re
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "check_tag_manifest", pathlib.Path(__file__).with_name("check_tag_manifest.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

MANIFEST = """\
[package]
name = "mcp-gateway"
version = "{version}"
edition = "2024"
"""

LOCKFILE = """\
version = 4

[[package]]
name = "anyhow"
version = "1.0.100"

[[package]]
name = "mcp-gateway"
version = "{version}"
dependencies = [
 "anyhow",
]
"""


@contextlib.contextmanager
def repo(manifest_version, lock_version=None, lock_crate="mcp-gateway"):
    """A throwaway root carrying a manifest and lockfile at the given versions."""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        (root / "Cargo.toml").write_text(
            MANIFEST.format(version=manifest_version), encoding="utf-8"
        )
        (root / "Cargo.lock").write_text(
            LOCKFILE.format(version=lock_version or manifest_version).replace(
                'name = "mcp-gateway"\nversion', f'name = "{lock_crate}"\nversion'
            ),
            encoding="utf-8",
        )
        yield root


def run(root, tag=None, env=None, output=None):
    """Drive the gate's CLI, returning (exit code, stderr text)."""
    argv = ["check_tag_manifest.py", "--root", str(root)]
    if tag is not None:
        argv += ["--tag", tag]
    environ = {"GITHUB_REF_NAME": ""}
    environ.update(env or {})
    if output is not None:
        environ["GITHUB_OUTPUT"] = str(output)
    stderr = io.StringIO()
    with (
        mock.patch("sys.argv", argv),
        mock.patch.dict(gate.os.environ, environ, clear=True),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(stderr),
    ):
        return gate.main(), stderr.getvalue()


class PrereleasePredicate(unittest.TestCase):
    def test_hyphen_marks_a_prerelease(self):
        self.assertTrue(gate.is_prerelease("4.0.0-rc.1"))

    def test_plain_version_is_stable(self):
        self.assertFalse(gate.is_prerelease("4.0.0"))

    def test_hyphen_in_build_metadata_is_still_stable(self):
        # semver §10: build metadata may carry hyphens and does not make a
        # prerelease. Testing the whole string would misclassify this as an rc
        # and withhold a stable release from every channel.
        self.assertFalse(gate.is_prerelease("4.0.0+build-linux"))

    def test_prerelease_with_build_metadata_is_a_prerelease(self):
        self.assertTrue(gate.is_prerelease("4.0.0-rc.1+build-linux"))


class LockfileParse(unittest.TestCase):
    def test_the_package_delimiter_inside_a_string_does_not_hide_a_crate(self):
        # Splitting the lockfile on "[[package]]" leaves the block holding a
        # literal occurrence unterminated, so the crate after it becomes
        # invisible or the parse raises. Reading the document once cannot be
        # fooled by the contents of a value.
        text = (
            'version = 4\n\n'
            '[[package]]\n'
            'name = "decoy"\n'
            'version = "0.1.0"\n'
            'source = "a [[package]] inside a string"\n\n'
            '[[package]]\n'
            'name = "mcp-gateway"\n'
            'version = "4.0.0"\n'
        )
        self.assertEqual(gate.lock_version(text, "mcp-gateway"), "4.0.0")

    def test_an_absent_crate_reads_as_none(self):
        self.assertIsNone(gate.lock_version("version = 4\n", "mcp-gateway"))


class TagManifestAgreement(unittest.TestCase):
    def test_matching_stable_tag_passes(self):
        with repo("4.0.0") as root:
            code, _ = run(root, tag="v4.0.0")
        self.assertEqual(code, 0)

    def test_matching_prerelease_tag_passes(self):
        with repo("4.0.0-rc.1") as root:
            code, _ = run(root, tag="v4.0.0-rc.1")
        self.assertEqual(code, 0)

    def test_prerelease_tag_on_a_stable_manifest_fails(self):
        # The defect this gate exists for: cargo publish would take 4.0.0 from
        # the manifest and ship the candidate as the final release.
        with repo("4.0.0") as root:
            code, stderr = run(root, tag="v4.0.0-rc.1")
        self.assertEqual(code, 1)
        self.assertIn("Cargo.toml version is '4.0.0'", stderr)

    def test_stable_tag_on_a_prerelease_manifest_fails(self):
        with repo("4.0.0-rc.1") as root:
            code, stderr = run(root, tag="v4.0.0")
        self.assertEqual(code, 1)
        self.assertIn("4.0.0-rc.1", stderr)

    def test_lockfile_disagreeing_with_a_matching_manifest_fails(self):
        with repo("4.0.0-rc.1", lock_version="4.0.0") as root:
            code, stderr = run(root, tag="v4.0.0-rc.1")
        self.assertEqual(code, 1)
        self.assertIn("Cargo.lock", stderr)

    def test_lockfile_without_the_crate_fails(self):
        with repo("4.0.0", lock_crate="something-else") as root:
            code, stderr = run(root, tag="v4.0.0")
        self.assertEqual(code, 1)
        self.assertIn("no entry", stderr)


class EffectiveTag(unittest.TestCase):
    def test_ref_name_is_used_when_no_tag_is_passed(self):
        with repo("4.0.0") as root:
            code, _ = run(root, env={"GITHUB_REF_NAME": "v4.0.0"})
        self.assertEqual(code, 0)

    def test_tag_argument_wins_over_ref_name(self):
        # workflow_dispatch sets GITHUB_REF_NAME to the dispatch branch, so the
        # input has to override it or an rc dispatch is checked against 'main'.
        with repo("4.0.0-rc.1") as root:
            code, _ = run(root, tag="v4.0.0-rc.1", env={"GITHUB_REF_NAME": "main"})
        self.assertEqual(code, 0)

    def test_empty_tag_falls_back_to_ref_name(self):
        # release.yml passes `--tag "$INPUT_TAG"` unconditionally, and
        # inputs.tag renders empty on a tag push. The fallback therefore has to
        # be keyed on emptiness, not on the argument being absent: keyed on
        # absence, the main release path would exit 2 and block every publish.
        with repo("4.0.0") as root:
            code, _ = run(root, tag="", env={"GITHUB_REF_NAME": "v4.0.0"})
        self.assertEqual(code, 0)

    def test_empty_tag_and_ref_name_is_unusable(self):
        with repo("4.0.0") as root:
            code, stderr = run(root, tag="")
        self.assertEqual(code, 2)
        self.assertIn("No tag to check", stderr)

    def test_non_tag_ref_is_unusable(self):
        with repo("4.0.0") as root:
            code, stderr = run(root, env={"GITHUB_REF_NAME": "main"})
        self.assertEqual(code, 2)
        self.assertIn("does not start with 'v'", stderr)

    def test_non_semver_tag_is_unusable(self):
        with repo("4.0.0") as root:
            code, stderr = run(root, tag="v4.0")
        self.assertEqual(code, 2)
        self.assertIn("not a semver version", stderr)


class WorkflowOutputs(unittest.TestCase):
    def outputs(self, manifest_version, tag):
        with repo(manifest_version) as root:
            path = root / "gh-output"
            path.touch()
            code, _ = run(root, tag=tag, output=path)
            return code, dict(
                line.split("=", 1) for line in path.read_text().splitlines()
            )

    def test_prerelease_tag_exports_true(self):
        code, outputs = self.outputs("4.0.0-rc.1", "v4.0.0-rc.1")
        self.assertEqual(code, 0)
        self.assertEqual(
            outputs,
            {"tag": "v4.0.0-rc.1", "version": "4.0.0-rc.1", "is_prerelease": "true"},
        )

    def test_stable_tag_exports_false(self):
        # Lowercase: consumers compare against the string 'true' in a GitHub
        # expression, where Python's 'False' would also be truthy as a string.
        code, outputs = self.outputs("4.0.0", "v4.0.0")
        self.assertEqual(code, 0)
        self.assertEqual(
            outputs,
            {"tag": "v4.0.0", "version": "4.0.0", "is_prerelease": "false"},
        )

    def test_version_output_drops_the_leading_v(self):
        # Both ghcr publishers must agree on the image tag; ci.yml historically
        # pushed ':v4.0.0-rc.1' while docker.yml pushed ':4.0.0-rc.1'.
        _, outputs = self.outputs("4.0.0-rc.1", "v4.0.0-rc.1")
        self.assertEqual(outputs["version"], "4.0.0-rc.1")

    def test_a_mismatch_writes_no_outputs(self):
        with repo("4.0.0") as root:
            path = root / "gh-output"
            path.touch()
            code, _ = run(root, tag="v4.0.0-rc.1", output=path)
            self.assertEqual(code, 1)
            self.assertEqual(path.read_text(), "")


# Overridable so the mutation harness can point these assertions at a copy of
# the workflows instead of editing the ones in the working tree.
WORKFLOWS = pathlib.Path(
    os.environ.get("MCPGW_WORKFLOWS_DIR")
    or pathlib.Path(__file__).parents[2] / ".github" / "workflows"
)
JOB_HEADER = re.compile(r"^  ([A-Za-z][\w-]*):\s*$")
# A cosign verb ends where the word ends: without the boundary, `verify`
# matches `verify-attestation` and a deleted signature check passes on the
# attestation check standing in for it.
COSIGN_VERIFY = re.compile(r"cosign\s+verify(-attestation)?(?![-\w])")
# Any cosign verb, in command position. `\bcosign` would also match the word
# inside `echo "run cosign sign …"`, which signs nothing; these patterns are
# matched against command positions by `runs()`, never searched for.
COSIGN_ANY = re.compile(r"cosign\s+\w")
# The gate, however it is spelled. Shared by the assertion that it runs at all
# and by the one that protects the steps running it, so a step cannot be
# protected under one spelling and unguarded under the other.
GATE_SCRIPT = re.compile(r"(?:python3?|uv run)\s+scripts/release/")
# A step key that turns a failure into a log line, or a condition that is false
# whatever the run: both leave every wiring assertion above satisfied.
NEVER_RUNS = re.compile(r"^(?:- )?if:\s*['\"]?(?:\$\{\{\s*)?false(?:\s*\}\})?['\"]?$")
SWALLOWS = re.compile(r"^(?:- )?continue-on-error:")


def needs_of(body):
    """A job's `needs:` declaration as text, inline or block form, else None.

    Matching only the inline form would make a job that is correctly wired in
    block form fail these tests for the wrong reason.
    """
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("    needs:"):
            continue
        declared = line.split(":", 1)[1]
        for following in lines[index + 1 :]:
            if following.strip().startswith("-"):
                declared += " " + following.strip()[1:]
            elif following.strip():
                break
        return declared
    return None


# `steps:` at the job-key indentation and nowhere else. A shell heredoc is
# free to contain a line reading `steps:`, and treating that as the start of a
# steps list would close the step it sits in and drop the rest of it.
STEPS_KEY = re.compile(r"^ {4}steps:$")


def uncommented(line):
    """`line` with a trailing YAML comment removed, quoting respected.

    A `#` opens a comment only outside quotes and after whitespace, which is
    what YAML itself requires. Both directions matter: a trailing comment
    naming a command satisfies an assertion the executable part no longer
    does, and a harmless `# v3` pin comment makes an exact-value assertion
    fail on a step that is wired correctly.
    """
    quote, escaped, skip = None, False, False
    for index, char in enumerate(line):
        if skip:
            skip = False
        elif quote == "'" and char == "'" and line[index + 1 : index + 2] == "'":
            # `''` inside a single-quoted scalar is YAML's escaped apostrophe,
            # not the end of the scalar. Closing on the first of the pair
            # leaves the rest of the line read as unquoted, so a `#` in it ends
            # the line early and the command it carries is read truncated.
            skip = True
        elif escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            # Only a double-quoted scalar has escapes; inside single quotes a
            # backslash is literal, so treating one as an escape there would
            # swallow the closing quote and mangle the rest of the line.
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"" and (index == 0 or line[index - 1].isspace()):
            # A quote opens only where a token does. Mid-token an apostrophe
            # is a letter — `name: Don't execute` is a plain YAML scalar, not
            # an open quote — and reading one as a quote leaves the state open
            # to the end of the line, so a real trailing comment survives.
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line


# A heredoc opener: `<<EOF`, `<< 'EOF'`, `<<-"EOF"`, `<<~EOF`. What follows is
# data a command is handed, not command text — but to a textual reader it is
# indistinguishable from workflow YAML, so a `steps:`, a `continue-on-error:`,
# a `DIGEST:` binding or a gate invocation printed inside one satisfies an
# assertion about wiring that no longer exists. `<<:` — YAML's merge key — is
# not an opener and does not match: a delimiter is a word.
HEREDOC = re.compile(r"<<[-~]?\s*(['\"]?)(\w+)\1")


def live_lines(workflow):
    """A workflow's executable lines, comments and heredoc payloads dropped.

    Every assertion here is textual, so a rule commented out rather than
    deleted would still satisfy an `assertIn` against the raw file. That is
    the shape a regression takes: a step disabled during debugging and
    committed. Reading only executable lines makes the mutation fail.

    A heredoc payload is the same hazard written as data: `cat <<'EOF'` turns
    every line up to the terminator into an argument, so text that reads as a
    gate invocation, an env binding or a step key runs nothing at all.
    """
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    live = (uncommented(raw) for raw in text.splitlines())
    return heredocs_dropped([line for line in live if line.strip()])


def inert_scalars_dropped(lines):
    """`lines` with the body of every non-`run:` block scalar removed.

    Applied where lines are read as COMMANDS, not where they are read as
    structure: a folded `if:` condition is a block scalar too, and its body is
    the condition itself.
    """
    kept, depth, dropping = [], None, False
    for line in lines:
        indent = len(line) - len(line.lstrip())
        if depth is not None:
            if indent > depth:
                # A `run:` body is passed through verbatim rather than
                # rescanned: shell text can contain `NOTE: |`, and reading
                # that as a YAML key would drop the commands under it.
                if not dropping:
                    kept.append(line)
                continue
            depth = None
        # `|`, `>`, and either indicator order after them — `|2-` and `|-2`
        # are the same scalar. Matching only `|-` leaves `NOTE: |2` unread.
        opener = re.match(r"^(\s*)(?:- )?([\w.-]+): *[|>][-+0-9]*$", line)
        if opener:
            depth = indent + (2 if line.lstrip().startswith("- ") else 0)
            dropping = opener.group(2) != "run"
        kept.append(line)
    return kept


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


def shell(command):
    """A joined step line as the shell sees it: `run:` key and YAML quotes off.

    `run: 'python3 …'` runs exactly what `run: python3 …` runs, and an
    assertion reading the raw line sees a different string for each — so one
    spelling is rejected while `echo "…; python3 …"`, which runs nothing, is
    accepted. What is left after this is the text bash parses, and the quoting
    in it is the quoting bash applies.
    """
    body, inline = re.subn(r"^(?:- )?run: ", "", command)
    if not inline:
        # A block scalar's lines carry no YAML quoting — `run: |` already ended
        # the YAML scalar — so a quote in one is a shell quote bash keeps.
        # Stripping it turns `'python3 …'`, which bash reads as one unfindable
        # command name, into the invocation the assertions want to see.
        return body
    quoted = re.match(r"^(['\"])(.*)\1$", body)
    return quoted.group(2) if quoted else body


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


def runs(command, program):
    """Whether `command` runs `program` — a compiled pattern — as a command.

    Shared by every assertion that asks whether something executes, because
    each of them is wrong in the same way on its own: a mention satisfies a
    search, and `echo cosign sign …` mentions.
    """
    return any(program.match(piece) for piece in segments(shell(command)))


def env_of(block):
    """A step's `env:` mapping entries, taken by indentation.

    A binding is only a binding where Actions reads one. Stripped of its
    indentation, `DIGEST: ${{ steps.build.outputs.digest }}` printed by the
    step — or sitting in a `run:` block as shell text — is the same string as
    the env entry that actually binds it, so the mapping has to be located
    before the line is read.
    """
    found, depth = [], None
    for line in block:
        indent = len(line) - len(line.lstrip())
        if depth is not None:
            if indent > depth:
                found.append(line.strip())
                continue
            depth = None
        if re.match(r"^\s*(?:- )?env:\s*$", line):
            # Written `- env:`, the key sits two columns right of the item,
            # so a sibling key of the step is not read as one of its bindings.
            depth = indent + (2 if line.lstrip().startswith("- ") else 0)
    return found


def commands(workflow):
    """A workflow's executable lines as whole commands.

    A block scalar under any key but `run:` is the heredoc hazard one level
    out: `NOTE: |` makes its body the value of a variable. It reads exactly
    like a command and Actions never executes a character of it.
    """
    return joined(inert_scalars_dropped(live_lines(workflow)))


def steps(workflow):
    """A workflow's step blocks, each as a list of its executable lines.

    An assertion about a command and the environment it runs in has to read
    one step at a time. A `DIGEST` bound in a neighbouring step does not reach
    this one, so checking the file for any binding at all passes a signing
    step that lost its own.

    A block opens at every list item at the steps-list indentation, not only
    at `- name:`. A step written `- run:` or `- id:` first is the same step to
    Actions, but splitting on the name alone would merge it into its
    predecessor and let it inherit that step's bindings.
    """
    blocks, current, indent = [], None, None

    def close():
        nonlocal current
        if current:
            blocks.append(current)
        current = None

    for line in live_lines(workflow):
        if JOB_HEADER.match(line):
            close()
            indent = None
            continue
        if STEPS_KEY.match(line):
            close()
            indent = -1  # the first list item below fixes the indentation
            continue
        if indent is None:
            continue
        item = re.match(r"^(\s*)- ", line)
        depth = len(line) - len(line.lstrip())
        if item and indent in (-1, len(item.group(1))):
            indent = len(item.group(1))
            close()
            current = [line]
        elif current is not None and depth > indent:
            current.append(line)
        elif depth <= indent and indent >= 0:
            close()  # the steps list ended
            indent = None
    close()
    return blocks


def jobs(workflow):
    """Split a workflow's `jobs:` mapping into {name: body text}."""
    lines = live_lines(workflow)
    start = lines.index("jobs:") + 1
    found, name, body = {}, None, []
    for line in lines[start:]:
        header = JOB_HEADER.match(line)
        if header:
            if name:
                found[name] = "\n".join(body)
            name, body = header.group(1), []
        elif name:
            body.append(line)
    if name:
        found[name] = "\n".join(body)
    return found


# The dispatch input, in either notation. `inputs['tag']` reads the same value
# as `inputs.tag`, so a check spelled for one of them is a check nobody has to
# evade deliberately. Outside `${{ }}` neither is interpolated at all, which is
# why the reference has to be read inside the delimiters: a shell comment
# mentioning inputs.tag is inert text, not an injection.
TAG_INPUT = r"inputs\s*(?:\.\s*tag\b|\[\s*['\"]tag['\"]\s*\])"
TAG_EXPRESSION = re.compile(r"\$\{\{[^}]*" + TAG_INPUT + r"[^}]*\}\}")


def job_if(workflow, job):
    """A job's own `if:` scalar, folded to one line.

    Its own: a step-level `if:` carrying the same clause skips one step while
    the job — and its other steps — run anyway, and an `if` nested under some
    other job key (`env:`, say) is not a condition at all. Both read as a
    guard to a search of the job body, so the scalar is taken by indentation.
    """
    lines = jobs(workflow)[job].splitlines()
    for index, line in enumerate(lines):
        if not re.match(r"^ {4}if:", line):
            continue
        scalar = [line.split(":", 1)[1]]
        for following in lines[index + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= 4:
                break  # the next job key ends a folded condition
            scalar.append(following)
        return " ".join(" ".join(scalar).split())
    return ""


def job_output(workflow, job, name):
    """A job's `outputs:` entry for `name`, folded to one line, or None.

    Taken by indentation like `job_if`: the mapping's keys sit six columns in
    under an `outputs:` key at four. A search of the job body would instead
    find the same name in a step's `env:`, in an `echo` writing to
    $GITHUB_OUTPUT, or in a comment — none of which is what a dependent job
    reads.
    """
    lines = jobs(workflow)[job].splitlines()
    for index, line in enumerate(lines):
        if not re.match(r"^ {4}outputs:\s*$", line):
            continue
        for following in lines[index + 1 :]:
            if following.strip() and len(following) - len(following.lstrip()) <= 4:
                break  # the next job key ends the mapping
            entry = re.match(rf"^ {{6}}{re.escape(name)}:(.*)$", following)
            if entry:
                return " ".join(entry.group(1).split())
    return None


def conjuncts(condition):
    """`condition`'s top-level `&&` operands, block indicator and `${{ }}` off."""
    body = re.sub(r"^[>|][-+]?\s*", "", condition.strip())
    wrapped = re.match(r"^\$\{\{(.*)\}\}$", body)
    if wrapped:
        body = wrapped.group(1)
    found, depth, current, index = [], 0, "", 0
    while index < len(body):
        char = body[index]
        depth += (char == "(") - (char == ")")
        if not depth and body[index : index + 2] == "&&":
            found.append(current.strip())
            current, index = "", index + 2
            continue
        current += char
        index += 1
    found.append(current.strip())
    return [unwrapped(operand) for operand in found]


def unwrapped(operand):
    """`operand` with balanced enclosing parentheses removed.

    `(a != 'true')` guards exactly what `a != 'true'` guards, so rejecting the
    parenthesised spelling fails a workflow that is wired correctly. Only an
    enclosing pair is removed: in `!(a)` the leading `!` is not a parenthesis,
    so a negated guard stays negated and stays rejected.
    """
    while operand.startswith("(") and operand.endswith(")"):
        depth = 0
        for index, char in enumerate(operand):
            depth += (char == "(") - (char == ")")
            if not depth and index < len(operand) - 1:
                return operand  # the pair closes early: `(a) && (b)`
        operand = operand[1:-1].strip()
    return operand


class WorkflowWiring(unittest.TestCase):
    """The gate is only worth what the workflows calling it are wired to do.

    These read the workflow text rather than run it. They cannot prove a
    release publishes correctly — only CI on a real tag does that — but they
    catch the rewiring mistakes that are silent at author time and only visible
    once a release has already gone to the wrong channel.

    Textual, deliberately: the gate runs on stdlib alone in three workflows, so
    a YAML parser is a dependency it does not get to have. The cost is that
    equivalence is handled case by case — comments stripped, optional quotes,
    folded conditions, continuations joined, step blocks scoped — rather than
    decided by a parser. Every case here is pinned by
    `test_workflow_wiring_mutations.py`, which is what keeps the list honest:
    a spelling nobody thought of fails loudly instead of passing silently.
    """

    def test_every_reader_of_verify_outputs_needs_verify_directly(self):
        # `needs` exposes direct dependencies only. A job that reads
        # needs.verify.outputs.is_prerelease while reaching verify transitively
        # gets the empty string, which is not 'true', so a release candidate
        # publishes down every stable path. Nothing fails at author time.
        for name, body in jobs("release.yml").items():
            if "needs.verify.outputs." not in body:
                continue
            declared = needs_of(body)
            self.assertIsNotNone(declared, f"{name} reads verify's outputs with no needs:")
            # Exact membership, not a substring: a comment naming verify, or a
            # job called verify-something, is not a dependency on verify.
            self.assertIn(
                "verify",
                re.findall(r"[\w-]+", declared),
                f"{name} reads verify's outputs without naming verify in needs:",
            )

    def test_all_three_tag_triggered_workflows_run_the_gate(self):
        # release.yml, ci.yml and docker.yml each fire on the same `v*` tag and
        # none can read another's job outputs, so each has to run the gate
        # itself. Dropping it from one leaves that workflow's publishes
        # ungated while the other two stay green.
        # Read executable commands, not the file: an invocation commented out
        # still satisfies a search of the raw text.
        for workflow in ("release.yml", "ci.yml", "docker.yml"):
            live = commands(workflow)
            for script in ("check_tag_manifest.py", "test_check_tag_manifest.py"):
                # A command position, not a mention. `run: echo python3
                # scripts/release/check_tag_manifest.py` names the gate
                # without running it, and so would a paths filter listing the
                # file; both would satisfy a substring search.
                # The complete filename, ending at a shell argument
                # boundary: without it `check_tag_manifest.py.bak` — a
                # different script, or none — satisfies the assertion.
                invocation = re.compile(
                    rf"(?:python3?|uv run)\s+scripts/release/{re.escape(script)}(?=\s|$)"
                )
                running = [c for c in live if runs(c, invocation)]
                self.assertTrue(
                    running,
                    f"{workflow} never runs scripts/release/{script}",
                )
                for command in running:
                    text = shell(command)
                    # `||` in the gate's own command is fatal in both
                    # directions: `true || python3 …` never reaches the gate,
                    # and `python3 … || echo ignored` discards the exit status
                    # that IS the gate. Either way the step succeeds and
                    # nothing was checked.
                    self.assertNotIn(
                        "||", text, f"{workflow}: the gate's failure is optional: {text}"
                    )
                    # Arguments, not just the program: `--help` makes argparse
                    # print usage and exit 0, which is a passing step that
                    # verified nothing.
                    pieces = segments(text)
                    index = next(
                        i for i, p in enumerate(pieces) if invocation.match(p)
                    )
                    # Reachable, not merely present. `exit 0; python3 …`
                    # leaves the invocation in the file AND in a command
                    # position; the shell is gone before it is reached.
                    for earlier in pieces[:index]:
                        self.assertNotRegex(
                            earlier,
                            r"^(?:exit|return|exec)(?=\s|$)",
                            f"{workflow}: the shell exits before the gate: {text}",
                        )
                    piece = pieces[index]
                    self.assertNotRegex(
                        piece,
                        r"(?:^|\s)(?:--help|-h)(?=\s|$)",
                        f"{workflow}: the gate is invoked as help: {piece}",
                    )
            # The step's own condition. A gate that never fires is a gate
            # that passed: `refs/heads/` matches no tag, and a folded
            # `false` matches nothing at all. Both leave the step, its name
            # and its command exactly where every search above looks.
            # Read only where a condition exists — a gate with none runs
            # whenever its job does, which is never less often. And only on
            # the gate itself: another `scripts/release/` script in its own
            # step answers a different question and carries its own guard.
            gate_step = re.compile(
                r"(?:python3?|uv run)\s+scripts/release/check_tag_manifest\.py(?=\s|$)"
            )
            for block in steps(workflow):
                if not any(gate_step.search(line) for line in block):
                    continue
                own = [
                    line.split(":", 1)[1].strip()
                    for line in block
                    if re.match(r"^\s*(?:- )?if:", line)
                ]
                for condition in own:
                    self.assertIn(
                        "refs/tags/",
                        condition,
                        f"{workflow}: the gate step is not scoped to tags: {condition}",
                    )

    def test_prerelease_skips_are_declared_where_they_are_claimed(self):
        # The three stable-only surfaces. Each is skipped by an expression
        # rather than by a comment; losing the expression publishes a candidate
        # to a channel nobody opted into.
        # Whitespace is collapsed first so a condition folded across lines —
        # `if: >` — still reads as one expression. The `if:` anchor stays, so a
        # condition that drifts into an unrelated key still fails.
        def condition(workflow, job):
            return " ".join(jobs(workflow)[job].split())

        for workflow, job, gate in (
            ("release.yml", "homebrew-update", "verify"),
            ("docker.yml", "publish-mcp-registry", "build"),
        ):
            own = job_if(workflow, job)
            # The clause has to be one of the condition's own top-level
            # conjuncts, spelled affirmatively. Searching the text for it
            # instead accepts `!(needs.verify.outputs.is_prerelease != 'true')`,
            # which matches the clause and reverses the guard.
            self.assertIn(
                f"needs.{gate}.outputs.is_prerelease != 'true'",
                conjuncts(own),
                f"{workflow} {job}: its `if:` does not require a non-prerelease",
            )
            # A disjunction makes the guard optional: `!= 'true' || true`
            # matches the clause and skips nothing.
            self.assertNotIn("||", own, f"{workflow} {job}: its skip is not mandatory")
        # Affirmatively: a leading `!` matches the clause and reverses which
        # builds are tagged :latest, so the operand is read from its start.
        # The false branch is read too. Pinning only the true branch leaves
        # `… && ':latest' || ':latest'`, where both branches yield the same
        # name and the condition decides nothing.
        self.assertRegex(
            condition("ci.yml", "docker"),
            r"(?<![!\w.])steps\.\w+\.outputs\.is_prerelease != 'true'"
            r" && 'ghcr\.io/[^']*:latest' \|\| ''",
        )
        # The step that decides it has to exist. `steps.missing.outputs.…`
        # is not an error in Actions — it is the empty string, and `'' !=
        # 'true'` tags every release candidate :latest.
        body = jobs("ci.yml")["docker"]
        producer = re.search(
            r"(?<![!\w.])steps\.(\w+)\.outputs\.is_prerelease != 'true'"
            r" && 'ghcr\.io/[^']*:latest'",
            condition("ci.yml", "docker"),
        )
        self.assertIsNotNone(producer, "ci.yml docker: nothing decides :latest")
        self.assertRegex(
            body,
            rf"(?m)^\s+id:\s*{re.escape(producer.group(1))}\s*$",
            f"ci.yml docker: no step is id {producer.group(1)}",
        )
        # And nothing tags :latest beside it. A second entry in the same
        # `tags:` list carries no expression, moves the name on every build,
        # and leaves the guarded entry above it untouched and green.
        for line in live_lines("ci.yml"):
            self.assertNotRegex(
                line.strip(),
                r"^-?\s*ghcr\.io/[\w./-]+:latest$",
                f"ci.yml: :latest is tagged unconditionally: {line.strip()}",
            )

    def test_the_prerelease_classification_is_computed(self):
        # Every guard above reads `needs.<job>.outputs.is_prerelease` from
        # another job. Nothing above reads the job that PRODUCES it. Bind that
        # output to a constant, or to a step that does not exist, and each
        # guard keeps its text, stays green, and decides nothing: a guard
        # reading a constant is not a guard.
        for workflow, job in (("release.yml", "verify"), ("docker.yml", "build")):
            body = jobs(workflow)[job]
            value = job_output(workflow, job, "is_prerelease")
            self.assertIsNotNone(
                value, f"{workflow} {job}: declares no is_prerelease output"
            )
            # The whole value, not an expression somewhere inside it.
            # `${{ … }}x` leaves the substring intact and makes a prerelease
            # publish `truex`, which every `!= 'true'` guard reads as stable.
            source = re.fullmatch(
                r"\$\{\{\s*steps\.(\w+)\.outputs\.is_prerelease\s*\}\}",
                (value or "").strip(),
            )
            self.assertIsNotNone(
                source,
                f"{workflow} {job}: is_prerelease is not a step's output: {value}",
            )
            # The step has to exist. `steps.missing.outputs.is_prerelease`
            # is not an error in Actions — it is the empty string, which
            # every `!= 'true'` guard downstream reads as a stable release.
            self.assertRegex(
                body,
                rf"(?m)^\s+id:\s*{re.escape(source.group(1))}\s*$",
                f"{workflow} {job}: no step is id {source.group(1)}",
            )
            # A disabled producer is the same failure by another route: the
            # job never runs, its outputs are empty, and every downstream
            # guard reads a stable release.
            self.assertNotIn(
                "false",
                conjuncts(job_if(workflow, job)),
                f"{workflow} {job}: the classifying job is disabled",
            )

    def test_the_npm_dist_tag_is_chosen_by_the_channel(self):
        # npm has no skip to delete: a prerelease is published either way, and
        # the only thing separating `next` from `latest` is this expression.
        # Hardcode the value and `npm install mcp-gateway` starts resolving to
        # a release candidate, with every `if:` guard above still green.
        # The binding is read from the step's own `env:` mapping, so the same
        # text echoed by a script does not satisfy it.
        bindings = [
            entry
            for block in steps("release.yml")
            for entry in env_of(block)
            if entry.startswith("DIST_TAG:")
        ]
        self.assertTrue(bindings, "release.yml: nothing binds DIST_TAG")
        for binding in bindings:
            self.assertRegex(
                binding,
                r"\$\{\{[^}]*needs\.\w+\.outputs\.is_prerelease[^}]*\}\}",
                f"release.yml: DIST_TAG is not chosen by the channel: {binding}",
            )
            # And which way round. Swapping the branches keeps the channel
            # in the expression, keeps every assertion above green, and
            # makes `npm install mcp-gateway` resolve to a candidate.
            self.assertRegex(
                binding,
                r"needs\.\w+\.outputs\.is_prerelease == 'true' && 'next' \|\| 'latest'",
                f"release.yml: DIST_TAG is inverted: {binding}",
            )

    def test_both_ghcr_publishers_sign_what_they_push(self):
        # Both push :VERSION from the same commit on the same tag with no
        # ordering between them, so the name resolves to whichever pushed last.
        # If only one signs, that name can carry no signature at all while the
        # signing workflow's own verify-by-digest still passes.
        for workflow in ("ci.yml", "docker.yml"):
            live = commands(workflow)
            # Each verb separately, and `verify` bounded so it cannot be
            # satisfied by `verify-attestation`: an attestation is not a
            # signature, and deleting either step has to fail.
            for verb in ("sign", "attest", "verify", "verify-attestation"):
                pattern = re.compile(rf"cosign\s+{re.escape(verb)}(?![-\w])")
                found = [c for c in live if runs(c, pattern)]
                self.assertTrue(found, f"{workflow} never runs cosign {verb}")
                for command in found:
                    # `cosign sign … || echo ignored` runs cosign, keeps the
                    # step green when it fails, and pushes an unsigned image.
                    # The same for `verify`: a verification whose failure is
                    # discarded verified nothing.
                    self.assertNotIn(
                        "||",
                        shell(command),
                        f"{workflow}: cosign {verb} may fail silently: {shell(command)}",
                    )
                    # Sign and verify the digest the build step produced, not a
                    # tag: a tag is a mutable pointer the other publisher can
                    # move, and a signature is over a digest.
                    # Double-quoted or bare, but not shell-single-quoted:
                    # the first two expand the digest and the third passes
                    # `${DIGEST}` through literally, signing a name no
                    # registry resolves. YAML quoting is stripped first, so
                    # this reads the quoting bash actually applies.
                    # The whole argument, so its opening quote is read too:
                    # matching from the `@` inward accepts
                    # `'…@${DIGEST} '`, where the single quotes bash keeps
                    # make the reference a literal the registry cannot resolve.
                    # Read the cosign segment, not the whole `run:` body. The
                    # body is every command the step runs, so
                    # `cosign sign …:latest; echo "…@${DIGEST}"` satisfies a
                    # search of it while cosign signs a mutable tag and the
                    # digest only ever reaches `echo`.
                    signed = next(
                        piece
                        for piece in segments(shell(command))
                        if pattern.match(piece)
                    )
                    self.assertRegex(
                        signed,
                        r"(?:^|\s)(?:\"[^\"]*@\$\{DIGEST\}\"|[^\s\"']*@\$\{DIGEST\})(?:\s|$)",
                        f"{workflow}: {command}",
                    )
            # Read the binding per step, not per file. `DIGEST` is step-scoped
            # env, so a step that lost its own binding expands it to the empty
            # string and signs a bare repository name.
            # Quoting and inner spacing are the author's choice; the expression
            # is not. A job-level binding would also reach these steps and is
            # rejected anyway: step-scoped env is what these steps use, and an
            # assertion that accepted either could not tell a step that lost
            # its binding from one that never had it.
            digest = re.compile(
                r"^DIGEST: [\"']?\$\{\{\s*steps\.build\.outputs\.digest\s*\}\}[\"']?$"
            )
            identity = re.compile(
                r"^IDENTITY: [\"']?https://github\.com/MikkoParkkola/mcp-gateway"
                rf"/\.github/workflows/{re.escape(workflow)}@\$\{{\{{\s*github\.ref\s*\}}\}}[\"']?$"
            )
            signing = 0
            for block in steps(workflow):
                bindings = env_of(block)
                block = joined(block)
                if not any(runs(c, COSIGN_ANY) for c in block):
                    continue
                signing += 1
                name = block[0]
                self.assertTrue(
                    any(digest.match(c) for c in bindings),
                    f"{workflow}: {name} runs cosign without binding DIGEST to the build digest",
                )
                # The env binding is only worth what the shell leaves of it: a
                # `DIGEST=` assignment in the run body rebinds the name the
                # cosign command below expands, and the env check still passes.
                # Every declaring builtin, not just `export`: `declare`,
                # `local`, `typeset` and `readonly` all rebind the name, and a
                # check naming one of them invites the other four.
                for command in block:
                    # Per command position: one `run: |` body is one command
                    # here, and a rebinding on its third line is neither at
                    # the start of the text nor after a `;`.
                    for piece in segments(shell(command)):
                        self.assertNotRegex(
                            piece,
                            r"(?:^|\b(?:export|declare|local|typeset|readonly)\s+)"
                            r"DIGEST=",
                            f"{workflow}: {name} reassigns DIGEST in its shell",
                        )
                if not any(runs(c, COSIGN_VERIFY) for c in block):
                    continue
                # An identity is what makes a signature mean something: an
                # unpinned verify, or one relaxed to a regexp, accepts a
                # signature from any workflow that can mint an OIDC token.
                self.assertTrue(
                    any(identity.match(c) for c in bindings),
                    f"{workflow}: {name} verifies without pinning this workflow's identity",
                )
                for command in block:
                    # Every verify in the body, not the body as a whole: one
                    # relaxed `--certificate-identity-regexp` beside a pinned
                    # sibling satisfies a search of the joined text.
                    for piece in segments(shell(command)):
                        if COSIGN_VERIFY.match(piece):
                            self.assertIn(
                                '--certificate-identity "${IDENTITY}"',
                                piece,
                                f"{workflow}: {piece}",
                            )
            # Non-vacuity: if the step scan found nothing, the per-step
            # assertions above never ran and the whole loop is decoration.
            self.assertTrue(signing, f"{workflow}: no step containing a cosign command was read")

    def test_a_comment_is_stripped_and_a_quoted_hash_is_not(self):
        # Every assertion here reads uncommented text, so both directions are
        # load-bearing: a comment left in place satisfies an assertion the
        # executable line no longer does, and a `#` cut out of a quoted scalar
        # rewrites a command that was wired correctly. An apostrophe inside a
        # word is neither — it is a letter.
        self.assertEqual(uncommented("name: Don't execute # a comment"), "name: Don't execute")
        self.assertEqual(uncommented("run: echo 'a # b'"), "run: echo 'a # b'")
        self.assertEqual(uncommented('run: echo "a # b" # c'), 'run: echo "a # b"')
        self.assertEqual(uncommented("run: echo don't # c"), "run: echo don't")

    def test_a_doubled_apostrophe_does_not_end_a_single_quoted_scalar(self):
        # `''` is how YAML writes an apostrophe inside a single-quoted scalar.
        # Read as a closing quote, everything after it looks unquoted, so the
        # next `#` truncates a command that runs in full.
        self.assertEqual(uncommented("run: 'echo don''t # keep' # cut"), "run: 'echo don''t # keep'")

    def test_a_heredoc_payload_is_not_read_as_workflow_text(self):
        # The payload is an argument to `cat`. Every line in it reads as
        # whatever it spells — a step key, an env binding, an invocation — and
        # none of it runs.
        lines = [
            "        run: |",
            "          cat <<'EOF'",
            "          steps:",
            "          DIGEST: x",
            "          EOF",
            "          echo after",
        ]
        kept = heredocs_dropped(lines)
        self.assertEqual(kept, [lines[0], lines[1], lines[5]])

    def test_a_quote_inside_a_block_scalar_belongs_to_the_shell(self):
        # `run: '…'` is a YAML scalar whose quotes never reach bash. The same
        # text on a block-scalar line is a command name in quotes, which bash
        # looks for and does not find.
        self.assertEqual(shell("run: 'python3 gate.py'"), "python3 gate.py")
        self.assertEqual(shell("'python3 gate.py'"), "'python3 gate.py'")

    def test_a_command_is_found_by_position_not_by_mention(self):
        # `echo cosign sign …` mentions; `true && cosign sign …` runs.
        program = re.compile(r"cosign\s+sign\b")
        self.assertFalse(runs("run: echo cosign sign x", program))
        self.assertFalse(runs('run: echo "a; cosign sign x"', program))
        self.assertTrue(runs("run: true && cosign sign x", program))
        self.assertTrue(runs("run: cleanup; cosign sign x", program))

    def test_a_parenthesised_conjunct_guards_what_the_bare_one_guards(self):
        # Parentheses are formatting. A negation is not.
        self.assertEqual(conjuncts("${{ (a != 'x') && b }}"), ["a != 'x'", "b"])
        self.assertEqual(conjuncts("${{ !(a != 'x') }}"), ["!(a != 'x')"])
        self.assertEqual(conjuncts("${{ (a) && (b) }}"), ["a", "b"])

    def test_a_folded_scalar_is_one_command(self):
        # YAML joins the lines with spaces before Actions sees them.
        self.assertEqual(
            joined(["        run: >-", "          python3", "          gate.py"]),
            ["run: python3 gate.py"],
        )

    def test_a_binding_is_read_only_where_actions_binds_one(self):
        # Stripped of indentation, a printed `DIGEST:` and a real one are the
        # same string.
        block = [
            "      - name: Sign",
            "        env:",
            "          DIGEST: real",
            "        run: |",
            "          DIGEST: printed",
        ]
        self.assertEqual(env_of(block), ["DIGEST: real"])

    def test_no_signing_or_gate_step_is_allowed_to_fail(self):
        # `continue-on-error` keeps the job green when the step fails. On a
        # step that signs, verifies, or runs the gate, that is the whole
        # check turned into a log line: a mismatched manifest or a missing
        # signature still publishes, and every assertion above still passes
        # because the wiring is all still there. The key is rejected however
        # it is valued — `false` today is `true` in one character.
        guarded = 0
        for workflow in ("release.yml", "ci.yml", "docker.yml"):
            for block in steps(workflow):
                commands_in = joined(block)
                if not any(
                    runs(c, COSIGN_ANY) or runs(c, GATE_SCRIPT) for c in commands_in
                ):
                    continue
                guarded += 1
                for line in block:
                    self.assertNotRegex(
                        line.strip(),
                        SWALLOWS,
                        f"{workflow}: {block[0].strip()} is allowed to fail",
                    )
                    # A step-level `if:` is legitimate here — these steps are
                    # tag-gated — but one that is false whatever the run is a
                    # deletion that leaves the step in the file.
                    self.assertNotRegex(
                        line.strip(),
                        NEVER_RUNS,
                        f"{workflow}: {block[0].strip()} never runs",
                    )
                # A step's status is its last command's. `cosign sign … ||
                # true`, or a `; true` after it, reports success on a failed
                # signature exactly as `continue-on-error` does, and `set +e`
                # does it for every command that follows.
                for command in commands_in:
                    # A no-op *after* a command: `cosign sign … || true` and
                    # `… ; true` both report success on a failed signature. A
                    # leading one — `true && cosign sign …` — decides nothing,
                    # because the status still comes from what follows it.
                    for piece in segments(shell(command))[1:]:
                        self.assertNotIn(
                            piece,
                            ("true", ":"),
                            f"{workflow}: {block[0].strip()} swallows a failure",
                        )
                    self.assertNotRegex(
                        shell(command),
                        r"(?:^|\s)set\s+[-+]?\+e",
                        f"{workflow}: {block[0].strip()} disables failure exit",
                    )
        # Non-vacuity: a scan that classified no step would pass with the
        # steps it is about never read.
        self.assertTrue(guarded, "no signing or gate step was read")

    def test_the_dispatch_tag_is_not_interpolated_into_a_shell_command(self):
        # A dispatch input expanded inside `run:` is substituted before bash
        # parses the line, so shell metacharacters in a tag would execute on the
        # runner holding the publishing credentials.
        # Checking only lines that start with `run:` would miss the body of a
        # `run: |` block, which is where an interpolation would actually sit.
        # So every mention is read, and each has to be an `env:` assignment or
        # an `if:` condition — evaluated by the expression engine, never
        # reaching a shell — with `run:` bodies tracked separately because
        # inside one no spelling is safe.
        permitted = re.compile(
            r"^(?:[A-Z][A-Z0-9_]*: [\"']?\$\{\{\s*" + TAG_INPUT + r"\s*\}\}[\"']?"
            r"|if: (?:[>|][-+]?\s)?\$\{\{ [^}]*" + TAG_INPUT + r"[^}]*\}\})$"
        )
        raw = (WORKFLOWS / "release.yml").read_text(encoding="utf-8").splitlines()
        block, kind = None, None
        for raw_line in raw:
            stripped = raw_line.strip()
            depth = len(raw_line) - len(raw_line.lstrip())
            if block is not None:
                if not stripped or depth > block:
                    if kind == "run":
                        # Inside a `run:` body, read the line raw. A `#` here
                        # opens a *shell* comment, and a tag carrying a newline
                        # ends it — so an interpolation in a comment executes
                        # too. Nothing is permitted in this position.
                        self.assertNotRegex(raw_line, TAG_EXPRESSION, raw_line)
                    continue  # a folded `if:` is evaluated, never executed
                block, kind = None, None
            folded = re.match(r"^(- )?(run|if): *[|>]", stripped)
            if folded:
                # A list marker is not part of the key. `- if: >-` puts the
                # key two columns right of the item, and the step's other
                # keys — `run:` among them — sit at that same column; taking
                # the item's indentation as the scalar's would swallow them.
                block = depth + (2 if folded.group(1) else 0)
                kind = folded.group(2)
                continue
            # A list marker is not part of the key here either: `- if: ${{ … }}`
            # is the same condition as the `if:` that follows a `- name:`, and
            # the expression engine evaluates both without a shell.
            line = re.sub(r"^- ", "", uncommented(raw_line).strip())
            if not TAG_EXPRESSION.search(line):
                continue
            self.assertRegex(line, permitted, raw_line)


if __name__ == "__main__":
    unittest.main()
