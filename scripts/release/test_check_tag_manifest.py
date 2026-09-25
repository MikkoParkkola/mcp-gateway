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
# The one command that makes a name resolvable. Every tag the release exposes
# is created by it, so the ordering assertions anchor on it rather than on the
# tag strings, which also appear in `inspect` calls and log lines.
IMAGETOOLS_CREATE = re.compile(r"docker\s+buildx\s+imagetools\s+create(?![-\w])")
# The gate, however it is spelled. Shared by the assertion that it runs at all
# and by the one that protects the steps running it, so a step cannot be
# protected under one spelling and unguarded under the other.
GATE_SCRIPT = re.compile(r"(?:python3?|uv run)\s+scripts/release/")
# The one step that starts a container. An interpreter in front of it runs the
# same gate, so the spelling is not what is pinned -- the complete filename is,
# ending at a shell argument boundary, or `smoke-image.sh.bak` (a different
# script, or none) satisfies every assertion below.
SMOKE_GATE = re.compile(r"(?:(?:ba)?sh\s+)?scripts/ci/smoke-image\.sh(?=\s|$)")
# Separate from SMOKE_GATE: an alternation would read the variant as the base.
SMOKE_FULL_GATE = re.compile(r"(?:(?:ba)?sh\s+)?scripts/ci/smoke-full-image\.sh(?=\s|$)")
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


def steps(workflow, job=None):
    """A workflow's step blocks, each as a list of its executable lines.

    `job` narrows the result to one job's steps, in file order. Order across a
    whole workflow is not an ordering Actions honours — two jobs' steps
    interleave at runtime — so any assertion that reads one step as running
    before another has to be confined to the job that sequences them.

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
    where = None

    def close():
        nonlocal current
        if current and (job is None or where == job):
            blocks.append(current)
        current = None

    for line in live_lines(workflow):
        header = JOB_HEADER.match(line)
        if header:
            close()
            where = header.group(1)
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
            ("ci.yml", "publish-mcp-registry", "docker-manifest"),
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
            condition("ci.yml", "docker-manifest"),
            r"(?<![!\w.])steps\.\w+\.outputs\.is_prerelease != 'true'"
            r" && 'ghcr\.io/[^']*:latest' \|\| ''",
        )
        # The step that decides it has to exist. `steps.missing.outputs.…`
        # is not an error in Actions — it is the empty string, and `'' !=
        # 'true'` tags every release candidate :latest.
        body = jobs("ci.yml")["docker-manifest"]
        producer = re.search(
            r"(?<![!\w.])steps\.(\w+)\.outputs\.is_prerelease != 'true'"
            r" && 'ghcr\.io/[^']*:latest'",
            condition("ci.yml", "docker-manifest"),
        )
        self.assertIsNotNone(producer, "ci.yml docker-manifest: nothing decides :latest")
        self.assertRegex(
            body,
            rf"(?m)^\s+id:\s*{re.escape(producer.group(1))}\s*$",
            f"ci.yml docker-manifest: no step is id {producer.group(1)}",
        )
        # And nothing else names :latest. A second `--tag` in the publisher's
        # own argument array moves the name on every release candidate and
        # leaves the guarded expression above it untouched and green, so the
        # rule is about the name wherever it appears, not about one list.
        for line in live_lines("ci.yml"):
            if ":latest" not in line:
                continue
            self.assertIn(
                "is_prerelease != 'true'",
                line,
                f"ci.yml: :latest is named without the channel guard: {line.strip()}",
            )

    def test_the_publisher_runs_the_tag_gate_in_its_own_job(self):
        # docker-manifest names the tag from steps.meta.outputs.version, and
        # the gate is the step that binds it. docker-build running its own
        # copy answers a different job's question: echo the invocation here
        # and the publisher creates a tag whose version is the empty string.
        body = jobs("ci.yml")["docker-manifest"]
        invocation = re.compile(
            r"(?:python3?|uv run)\s+scripts/release/check_tag_manifest\.py(?=\s|$)"
        )
        running = [
            command
            for block in steps("ci.yml")
            if "\n".join(block) in body
            for command in joined(block)
            if runs(command, invocation)
        ]
        self.assertTrue(running, "ci.yml docker-manifest: nothing runs the tag gate")

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

    def test_the_single_ghcr_publisher_signs_what_it_pushes(self):
        # One publisher owns :VERSION. A second one would push the same name
        # from the same commit with no ordering between them, so the name
        # would resolve to whichever pushed last and could carry no signature
        # at all while the signing workflow's own verify-by-digest passed.
        # docker.yml gave up the tag; it must not sign, because signing is
        # what it would do if it had started pushing one again.
        for command in commands("docker.yml"):
            self.assertFalse(
                runs(command, COSIGN_ANY),
                f"docker.yml runs cosign, so a second publisher is back: {command}",
            )
        for workflow in ("ci.yml",):
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
                        r"(?:^|\s)(?:\"[^\"]*@\$\{\w+\}\"|[^\s\"']*@\$\{\w+\})(?:\s|$)",
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
            # Every published digest, not just the list's. A client on arm64
            # resolves the arm64 child, so a signature over the index alone
            # leaves what that client pulls unverifiable. Each name is bound
            # from a step output: a literal here is a digest that cannot
            # follow the build.
            digests = [
                re.compile(
                    rf"^{name}: [\"']?\$\{{\{{\s*steps\.\w+"
                    rf"\.outputs\.{name.lower()}\s*\}}\}}[\"']?$"
                )
                for name in (
                    "LIST",
                    "AMD64",
                    "ARM64",
                    "LIST_FULL",
                    "AMD64_FULL",
                    "ARM64_FULL",
                )
            ]
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
                for digest in digests:
                    self.assertTrue(
                        any(digest.match(c) for c in bindings),
                        f"{workflow}: {name} runs cosign without binding "
                        f"every published digest to a step output",
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
                            r"(?:LIST|AMD64|ARM64|LIST_FULL|AMD64_FULL|ARM64_FULL|d)=",
                            f"{workflow}: {name} reassigns a digest in its shell",
                        )
                # Bound is not used. cosign expands the loop variable, so a
                # `for` list that lost its platform children signs the index
                # alone while all three bindings above still pass — the env
                # check reads what the step declares, never what the shell
                # reaches for.
                body = "\n".join(block)
                for digest_name in ("LIST", "AMD64", "ARM64", "LIST_FULL", "AMD64_FULL", "ARM64_FULL"):
                    self.assertIn(
                        f"${{{digest_name}}}",
                        body,
                        f"{workflow}: {name} binds {digest_name} without expanding it",
                    )
                self.assertRegex(
                    body,
                    r'for d in "\$\{LIST\}" "\$\{AMD64\}" "\$\{ARM64\}" '
                    r'"\$\{LIST_FULL\}" "\$\{AMD64_FULL\}" "\$\{ARM64_FULL\}"; do',
                    f"{workflow}: {name} does not iterate every published digest",
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

    def test_the_release_tag_is_created_only_after_the_signature_verifies(self):
        # The window this closes: a tag created before signing is pullable and
        # unsigned for the whole signing span, and `cosign verify` by digest
        # passes afterwards regardless — it never reads the tag. Order is the
        # only thing that closes it, so this reads step positions inside the
        # one job that sequences them, not the presence of the commands.
        blocks = steps("ci.yml", "docker-manifest")
        self.assertTrue(blocks, "ci.yml: docker-manifest has no steps to read")

        def pieces(block):
            return [
                piece
                for command in joined(block)
                for piece in segments(shell(command))
            ]

        creates, verifies = [], []
        for index, block in enumerate(blocks):
            found = [p for p in pieces(block) if IMAGETOOLS_CREATE.match(p)]
            if found:
                creates.append((index, block[0], found))
            if any(COSIGN_VERIFY.match(p) for p in pieces(block)):
                verifies.append(index)
        self.assertTrue(creates, "ci.yml: docker-manifest creates no manifest list")
        self.assertTrue(verifies, "ci.yml: docker-manifest never verifies a signature")

        release = [
            (index, name, found)
            for index, name, found in creates[1:]
        ]
        self.assertTrue(
            release,
            "ci.yml: the only imagetools create is the one that publishes a tag",
        )
        # After the LAST verify: a first verify followed by the tag and then a
        # second one would satisfy a check against the earliest index while
        # the tag still appeared mid-flight.
        for index, name, _ in release:
            self.assertGreater(
                index,
                max(verifies),
                f"ci.yml: {name} publishes a release tag before cosign verify",
            )
        # And it is the release tag, not some third provenance name.
        self.assertTrue(
            any(
                "${VERSION}" in "\n".join(blocks[index])
                for index, _, _ in release
            ),
            "ci.yml: no step creates the release tag :${VERSION}",
        )

        # The index is built under a provenance-only name. If the first create
        # carried the release tag, the ordering above would hold and the tag
        # would still have existed unsigned from that moment.
        first, name, found = creates[0]
        self.assertLess(first, max(verifies), f"ci.yml: {name} builds nothing to sign")
        for piece in found:
            for forbidden in ("${VERSION}", "latest", "LATEST_TAG", "MAJOR_MINOR"):
                self.assertNotIn(
                    forbidden,
                    piece,
                    f"ci.yml: {name} creates a release tag before signing: {piece}",
                )
            self.assertRegex(
                piece,
                r"--tag\s+[\"']?\$\{IMAGE\}:sha-\$\{GITHUB_SHA\}[\"']?",
                f"ci.yml: {name} does not name the provenance tag: {piece}",
            )

        # The falsifier for "copying an index by digest preserves the digest".
        # Without it the release tag can resolve to bytes no signature covers
        # and every step above still passes.
        proof = [
            index
            for index, block in enumerate(blocks)
            if index > max(i for i, _, _ in release)
            and "${LIST}" in "\n".join(block)
            and "${VERSION}" in "\n".join(block)
        ]
        self.assertTrue(
            proof,
            "ci.yml: nothing asserts :${VERSION} resolves to the signed digest",
        )

    def test_the_stable_channel_keeps_its_major_minor_pointer(self):
        # `main` published :MAJOR.MINOR through metadata-action. This job took
        # the tag over, so consumers pinned to :4.0 break silently unless it
        # publishes one too — under :latest's guard, or a prerelease moves the
        # pointer every stable consumer follows.
        blocks = [
            block
            for block in steps("ci.yml", "docker-manifest")
            if any(
                IMAGETOOLS_CREATE.match(piece)
                for command in joined(block)
                for piece in segments(shell(command))
            )
            and "${VERSION}" in "\n".join(block)
        ]
        self.assertEqual(
            len(blocks), 1, "ci.yml: expected one step to create the release tags"
        )
        body = "\n".join(blocks[0])

        # Derived, not spelled: a literal `4.0` here is a pointer that stops
        # following the release the first time the minor moves. Exactly one
        # derivation, whatever it is named — a second one is how the pointer
        # gets moved outside the guard while the guarded one still reads
        # correctly.
        derived = re.findall(
            r"(\w+)=[\"']?\$\([^)]*\$\{VERSION\}[^)]*cut\s+-d\.\s+-f1,2[^)]*\)", body
        )
        self.assertEqual(
            len(derived),
            1,
            "ci.yml: expected exactly one major.minor value derived from ${VERSION}, "
            f"found {derived}",
        )
        name = derived[0]

        # Inside :latest's own guard, by position. Two conditions spelled
        # alike are two conditions, and only one of them has to be edited for
        # a candidate to start moving the stable pointer.
        guard = re.search(
            r'if \[ -n "\$\{LATEST_TAG\}" \]; then\n(.*?)\n\s*fi', body, re.S
        )
        self.assertIsNotNone(guard, "ci.yml: :latest is no longer added under a guard")
        self.assertIn(
            f"{name}=",
            guard.group(1),
            "ci.yml: the major.minor value is derived outside the stable guard",
        )
        self.assertIn(
            f"${{{name}}}",
            guard.group(1),
            "ci.yml: the major.minor tag is not gated on the stable channel",
        )
        outside = body.count(f"${{{name}}}") - guard.group(1).count(f"${{{name}}}")
        self.assertEqual(
            outside,
            0,
            "ci.yml: the major.minor tag is also used outside the stable guard",
        )

    def test_both_publishers_start_the_image_before_they_hand_it_on(self):
        # NFR.PKG.1: "the container image the release publishes starts, and
        # serves an MCP request from outside the container". Every other image
        # gate reads the image at rest -- trivy walks layers, cosign signs a
        # digest, syft reads a filesystem -- and none of them start a
        # container, which is how `:a2505be` shipped green while exiting 1 on
        # startup. `scripts/ci/smoke-image.sh` is the only step that runs it,
        # and nothing until now asserted that either publisher calls it: the
        # gate could be dropped from a workflow and the whole suite stay green.
        #
        # Order is half the claim. A smoke step after the handoff still proves
        # the image boots, but about bytes that are already reachable, which is
        # a report, not a gate. Both publishers now push by digest under no
        # name at all, so nothing is reachable when the build job ends; what
        # makes a name resolve is the manifest job, whose only input is the
        # uploaded digest -- so that upload is each job's point of no return.
        for workflow, job, handoff, marker in (
            (
                "docker.yml",
                "build",
                "the digest upload the branch tags are built from",
                re.compile(r"^\s*uses:\s*actions/upload-artifact@"),
            ),
            (
                "ci.yml",
                "docker-build",
                "the digest upload the release tag is built from",
                re.compile(r"^\s*uses:\s*actions/upload-artifact@"),
            ),
        ):
            blocks = steps(workflow, job)
            self.assertTrue(blocks, f"{workflow}: {job} has no steps to read")
            # A command position, not a mention: a `paths:` filter naming the
            # script, or an `echo` of the command, satisfies a text search of
            # the file while starting nothing.
            smoke = [
                index
                for index, block in enumerate(blocks)
                if any(runs(command, SMOKE_GATE) for command in joined(block))
            ]
            # Asserted before it is indexed. An empty list here IS the
            # regression this test is about, and an IndexError would report it
            # as a crashed assertion rather than a failed one.
            self.assertTrue(
                smoke,
                f"{workflow}: {job} never runs scripts/ci/smoke-image.sh, so "
                "nothing starts the image it publishes",
            )
            handoffs = [
                index
                for index, block in enumerate(blocks)
                if any(marker.match(line) for line in block)
            ]
            self.assertTrue(
                handoffs, f"{workflow}: {job} no longer reaches {handoff}"
            )
            # Earliest against earliest. Against the last handoff, a smoke step
            # wedged between two of them would pass while the first already
            # went out unstarted; against the last smoke step, a second one
            # added after the handoff would satisfy the check for the first.
            self.assertLess(
                min(smoke),
                min(handoffs),
                f"{workflow}: {job} reaches {handoff} before the image is ever "
                f"started ({blocks[min(handoffs)][0].strip()})",
            )
            full = [
                index
                for index, block in enumerate(blocks)
                if any(runs(command, SMOKE_FULL_GATE) for command in joined(block))
            ]
            self.assertTrue(
                full,
                f"{workflow}: {job} never runs scripts/ci/smoke-full-image.sh, so "
                "the variant it publishes is started by nothing",
            )
            self.assertLess(
                min(full),
                min(handoffs),
                f"{workflow}: {job} reaches {handoff} before the variant is ever "
                f"started ({blocks[min(full)][0].strip()})",
            )
            for index in full:
                for command in joined(blocks[index]):
                    if not runs(command, SMOKE_FULL_GATE):
                        continue
                    self.assertRegex(
                        shell(command),
                        r"smoke-full-image\.sh\s+\S",
                        f"{workflow}: the variant smoke gate is handed no image: "
                        f"{shell(command)}",
                    )
            for index in smoke:
                for command in joined(blocks[index]):
                    if not runs(command, SMOKE_GATE):
                        continue
                    # The script takes the image to start as its one argument
                    # and exits non-zero without it. Run bare it is a usage
                    # error, which is a red step today -- but a `|| true` away
                    # from a green one that started nothing.
                    self.assertRegex(
                        shell(command),
                        r"smoke-image\.sh\s+\S",
                        f"{workflow}: the smoke gate is handed no image: "
                        f"{shell(command)}",
                    )

    def test_the_variant_index_is_composed_from_the_variant_legs(self):
        # Every gate downstream of this reads the index by digest and compares
        # it to itself, so an index composed from the base legs passes all of
        # them while `:latest-full` serves the default image.
        #
        # Both provenance tags carry the rehearsal suffix, or a manifest
        # rehearsal publishes a real `sha-<commit>-full` while the base index
        # stays isolated under its rehearsal name.
        body = "\n".join(commands("ci.yml"))
        self.assertRegex(
            body,
            r"--tag \"\$\{IMAGE\}:sha-\$\{GITHUB_SHA\}-full\$\{REHEARSAL_SUFFIX\}\"[^\n]*"
            r'\$\{IMAGE\}@\$\{FULL_AMD64\}" "\$\{IMAGE\}@\$\{FULL_ARM64\}"',
            "ci.yml: the variant provenance index is not composed from its legs "
            "under the rehearsal-aware name",
        )
        self.assertRegex(
            body,
            r'--tag \"\$\{IMAGE\}:sha-\$\{GITHUB_SHA\}\$\{REHEARSAL_SUFFIX\}\"[^\n]*'
            r'\$\{IMAGE\}@\$\{AMD64\}" "\$\{IMAGE\}@\$\{ARM64\}"',
            "ci.yml: the base provenance index is not composed from its legs "
            "under the rehearsal-aware name",
        )
        # The image name is spelled by the author, `"${IMAGE}@…"` or inline;
        # what is pinned is which index the tags are put on.
        self.assertRegex(
            body,
            r'docker buildx imagetools create "\$\{FULL_TAGS\[@\]\}" '
            r'[^\n]*@\$\{LIST_FULL\}"',
            "ci.yml: the variant release tags are not created from the variant index",
        )
        self.assertRegex(
            body,
            r'docker buildx imagetools create "\$\{TAGS\[@\]\}" '
            r'[^\n]*@\$\{LIST\}"',
            "ci.yml: the base release tags are not created from the base index",
        )

    def test_each_leg_builds_the_stage_its_digest_claims(self):
        wanted = {"build": "runtime", "build_full": "runtime-full"}
        for workflow in ("ci.yml", "docker.yml"):
            for block in steps(workflow):
                text = "\n".join(block)
                found = [
                    step
                    for step, target in wanted.items()
                    if re.search(rf"(?m)^\s*id:\s*{step}\s*$", text)
                ]
                if not found:
                    continue
                step = found[0]
                target = re.escape(wanted[step])
                self.assertRegex(
                    text,
                    rf"(?m)^\s*target:\s*{target}\s*$|--target\s+{target}(?:\s|$)",
                    f"{workflow}: the {step} step does not build {wanted[step]}",
                )

    def test_each_recorded_digest_comes_from_the_build_it_names(self):
        # The legs are composed into two lists by digest, so a recording step
        # that writes the base digest under the `-full` filename publishes the
        # default image as `:latest-full` with every other check still green.
        blocks = [
            block
            for block in steps("ci.yml")
            if "mkdir -p digests" in "\n".join(block)
        ]
        self.assertEqual(len(blocks), 1, "the digest recording step is not unique")
        block = blocks[0]
        keyed = {
            "DIGEST": "build",
            "DIGEST_FULL": "build_full",
        }
        bindings = env_of(block)
        for name, build in keyed.items():
            self.assertTrue(
                any(
                    re.match(
                        rf"^{name}: [\"']?\$\{{\{{\s*steps\.{build}"
                        rf"\.outputs\.digest\s*\}}\}}[\"']?$",
                        binding,
                    )
                    for binding in bindings
                ),
                f"ci.yml: {name} is not bound to steps.{build}.outputs.digest",
            )
        for name, build in keyed.items():
            suffix = "-full" if name == "DIGEST_FULL" else ""
            self.assertIn(
                f'printf \'%s\' "${{{name}}}" > "digests/${{{{ matrix.arch }}}}{suffix}"',
                "\n".join(block),
                f"ci.yml: {name} is not written to the {build} filename",
            )

    def test_every_build_of_the_root_image_names_its_target(self):
        # The variant is the file's last stage, so an untargeted build is it.
        for workflow in ("ci.yml", "docker.yml"):
            for block in steps(workflow):
                text = "\n".join(block)
                if not re.search(r"^\s*uses:\s*docker/build-push-action@", text, re.M):
                    continue
                self.assertRegex(
                    text,
                    r"(?m)^\s*target:\s*\S+",
                    f"{workflow}: {block[0].strip()} builds the root image with "
                    "no target, so it builds the last stage in the file",
                )
            for block in steps(workflow):
                text = "\n".join(block).replace("\n", " ")
                if not re.search(r"docker\s+buildx\s+build(?![\w-])", text):
                    continue
                if not re.search(r"\s\.\s*$", text.strip()):
                    continue
                # Which stage, not merely that one is named: the variant's leg
                # built from `runtime` is a `-full` tag serving the default
                # image, which is the same defect spelled the other way round.
                want = "runtime-full" if "full" in block[0].lower() else "runtime"
                self.assertRegex(
                    text,
                    rf"--target\s+{re.escape(want)}(?:\s|$)",
                    f"{workflow}: {block[0].strip()} does not build {want}",
                )

    def test_the_branch_builder_still_refuses_to_push_on_a_tag(self):
        # A regression lock, green today: docker.yml handed :VERSION over, and
        # this condition is the only thing keeping the second publisher from
        # coming back on the same name from the same commit.
        #
        # It used to live on one step-level `push:`. It no longer can: the
        # build job pushes by digest under no name and a `manifest` job creates
        # the branch tags, so the condition sits on the publishing steps' `if:`
        # and on that job's own `if:`. A job-level `if:` cannot read a step
        # output or an env alias, so the sites carry the literal expression --
        # and the lock is that they agree. One site left off skips a step the
        # others still run: an ungated record step reads an empty digest on a
        # pull request, and an ungated manifest job tags a tag build.
        publishers = [
            block
            for block in steps("docker.yml", "build")
            for line in block
            if re.search(r"\bpush\s*=\s*true\b", line)
            or re.match(r"^\s*push:\s*\$\{\{", line)
            or re.match(r"^\s*uses:\s*actions/upload-artifact@", line)
            or re.search(r"\bdigests/", line)
        ]
        # Asserted before it is read. An empty list here IS the regression --
        # a build job that publishes through some step this no longer finds.
        self.assertTrue(
            publishers, "docker.yml: build declares no publishing step"
        )
        conditions = []
        for block in publishers:
            guard = [line for line in block if re.match(r"^\s*if:", line)]
            self.assertTrue(
                guard,
                "docker.yml: a publishing step carries no condition: "
                f"{block[0].strip()}",
            )
            conditions.extend(line.split(":", 1)[1].strip() for line in guard)
        conditions.append(job_if("docker.yml", "manifest"))
        for condition in conditions:
            self.assertRegex(
                condition,
                r"!\s*startsWith\(\s*github\.ref\s*,\s*'refs/tags/v'\s*\)",
                f"docker.yml pushes on a tag again: {condition}",
            )
        self.assertEqual(
            len(set(conditions)),
            1,
            "docker.yml: the publish sites no longer agree, so one of them "
            f"runs where the others skip: {sorted(set(conditions))}",
        )

    def test_the_publish_sites_admit_one_cell_of_event_by_ref_by_input(self):
        # A condition reading github.ref has a case space of events x refs x
        # inputs, and a dispatch can be aimed at a tag ref — where a ref test
        # alone is true. That cell is how a run asking to rehearse could
        # promote, sign and list a real release, and no assertion above can
        # see it: they all read text. These evaluate it.
        #
        # The release sites admit exactly one cell, a tag PUSH. The two jobs
        # the rehearsal needs admit that cell plus a dispatch whose input is
        # set, in either spelling — and nothing else, so a dispatch that
        # leaves the input alone builds and publishes nothing.
        events = ("push", "pull_request", "workflow_dispatch")
        refs = ("refs/heads/docs/ranking-1-release-line", "refs/tags/v4.0.0")
        values = (True, "true", False, "false", None)

        def evaluate(condition, event, ref, value):
            """`condition` under one cell, translated rather than interpreted.

            `&&`, `||`, `==`, `!=` and `startsWith` mean the same thing in
            both languages for these operands, and a string equals no boolean
            in either. A dotted name Python cannot spell is bound first, and
            `true` is rewritten only unquoted: inside `'true'` it is a string
            the workflow compares against, not a literal.
            """
            body = re.sub(r"^[>|][-+]?\s*", "", condition.strip())
            body = re.sub(r"^\$\{\{(.*)\}\}$", r"\1", body.strip())
            body = body.replace(
                "needs.docker-manifest.outputs.is_prerelease", "prerelease"
            )
            body = body.replace("github.event_name", "event")
            body = body.replace("github.ref", "ref")
            body = body.replace("inputs.rehearse_manifest", "value")
            body = body.replace("&&", " and ").replace("||", " or ")
            body = re.sub(r"(?<!')\btrue\b(?!')", "True", body)
            return bool(
                eval(  # noqa: S307 - restricted namespace, workflow-authored text
                    body,
                    {"__builtins__": {}},
                    {
                        "startsWith": lambda a, b: str(a).startswith(b),
                        "event": event,
                        "ref": ref,
                        "value": value,
                        # A stable release: the one classification that lets
                        # the registry job through, so the cell under test is
                        # the event and the ref rather than the channel.
                        "prerelease": "false",
                    },
                )
            )

        rehearsable = ("docker-build", "docker-manifest")
        sites = {f"{job} (job)": job_if("ci.yml", job) for job in rehearsable}
        sites["publish-mcp-registry (job)"] = job_if("ci.yml", "publish-mcp-registry")
        for job in rehearsable:
            for block in steps("ci.yml", job):
                named = [
                    line.split(":", 1)[1].strip()
                    for line in block
                    if re.match(r"^\s+(?:- )?name:", line)
                ]
                for line in block:
                    if re.match(r"^\s*(?:- )?if:", line):
                        label = f"{job} -> {named[0] if named else block[0].strip()}"
                        sites[label] = line.split(":", 1)[1].strip()
        # Asserted before it is read: a site scan that found nothing would
        # report this whole matrix as passing.
        self.assertEqual(
            len(sites),
            12,
            f"ci.yml: expected 12 publish-path conditions, read {sorted(sites)}",
        )

        for label, condition in sites.items():
            for event in events:
                for ref in refs:
                    for value in values:
                        release = event == "push" and ref.startswith("refs/tags/v")
                        rehearse = event == "workflow_dispatch" and value in (
                            True,
                            "true",
                        )
                        want = release or (
                            label.endswith("(job)")
                            and not label.startswith("publish-mcp-registry")
                            and rehearse
                        )
                        self.assertEqual(
                            evaluate(condition, event, ref, value),
                            want,
                            f"ci.yml {label}: {event} on {ref} with "
                            f"rehearse_manifest={value!r} should be {want}: "
                            f"{condition}",
                        )

    def test_the_provenance_name_carries_no_rehearsal_suffix_on_a_tag(self):
        # The staging name is the one thing the matrix above cannot see: it
        # evaluates admission conditions, and this is the VALUE of an
        # interpolated string. `A && '' || B` yields B whichever way A goes —
        # the empty string is falsy — so the guard that was supposed to keep
        # the release name unchanged appended the rehearsal suffix to it, and
        # the release provenance index stopped being published at
        # :sha-<GITHUB_SHA>. Evaluated per cell, because the defect is a
        # coercion rather than a missing clause.
        blocks = [
            block
            for block in steps("ci.yml", "docker-manifest")
            if any("REHEARSAL_SUFFIX:" in line for line in block)
        ]
        self.assertEqual(
            len(blocks),
            1,
            "ci.yml: expected exactly one step to bind REHEARSAL_SUFFIX",
        )
        block = blocks[0]
        binding = next(
            line.split(":", 1)[1].strip()
            for line in block
            if re.match(r"^\s+REHEARSAL_SUFFIX:", line)
        )
        # Named where it matters: an empty suffix proves nothing if the tag is
        # composed from something else.
        for marker in ("imagetools create", "imagetools inspect"):
            self.assertTrue(
                any(
                    marker in line and ":sha-${GITHUB_SHA}${REHEARSAL_SUFFIX}" in line
                    for line in block
                ),
                f"ci.yml: {marker} does not name sha-${{GITHUB_SHA}}${{REHEARSAL_SUFFIX}}",
            )

        def suffix(event, ref):
            body = re.sub(r"^\$\{\{(.*)\}\}$", r"\1", binding.strip())
            body = body.replace("github.event_name", "event")
            body = body.replace("github.run_attempt", "attempt")
            body = body.replace("github.run_id", "run_id")
            body = body.replace("github.ref", "ref")
            body = body.replace("&&", " and ").replace("||", " or ")
            body = re.sub(r"!(?!=)", " not ", body)
            return eval(  # noqa: S307 - restricted namespace, workflow-authored text
                body,
                {"__builtins__": {}},
                {
                    "startsWith": lambda a, b: str(a).startswith(b),
                    "format": lambda spec, *args: re.sub(
                        r"\{(\d+)\}", lambda m: str(args[int(m.group(1))]), spec
                    ),
                    "event": event,
                    "ref": ref,
                    "run_id": "42",
                    "attempt": "1",
                },
            )

        release = suffix("push", "refs/tags/v4.0.0")
        self.assertEqual(
            release,
            "",
            "ci.yml: a tag push stages under a name that is not "
            f"sha-${{GITHUB_SHA}}: suffix {release!r}",
        )
        for event, ref in (
            ("push", "refs/heads/topic"),
            ("workflow_dispatch", "refs/heads/topic"),
            ("workflow_dispatch", "refs/tags/v4.0.0"),
        ):
            value = suffix(event, ref)
            # Every non-release cell gets a name of its own, run and attempt
            # included: two rehearsals of one commit must not share a tag a
            # release could read back mid-flight.
            self.assertEqual(
                value,
                "-rehearsal-42-1",
                f"ci.yml: {event} on {ref} shares the release staging name",
            )

    def test_every_release_sensitive_step_carries_the_push_guard(self):
        # Inventoried by what a step DOES, not by the conditions present.
        # Counting guards cannot see a publishing step added without one: the
        # population has to come from the actions, and the guard is then the
        # property asserted over it.
        markers = (
            re.compile(r"\bcosign\s+(?:sign|attest|verify)"),
            re.compile(r"\bsyft\s"),
            re.compile(r"scripts/release/check_tag_manifest\.py"),
            re.compile(r"\$\{VERSION\}"),
            re.compile(r"\bmcp-publisher\b"),
            re.compile(r"^\s*uses:\s*sigstore/cosign-installer@"),
            re.compile(r"^\s*uses:\s*anchore/sbom-action/"),
        )
        found = []
        for job in ("docker-build", "docker-manifest", "publish-mcp-registry"):
            for block in steps("ci.yml", job):
                if not any(m.search(line) for line in block for m in markers):
                    continue
                named = [
                    line.split(":", 1)[1].strip()
                    for line in block
                    if re.match(r"^\s+(?:- )?name:", line)
                ]
                label = f"{job} -> {named[0] if named else block[0].strip()}"
                own = [
                    line.split(":", 1)[1].strip()
                    for line in block
                    if re.match(r"^\s*(?:- )?if:", line)
                ]
                # A job-level condition covers its own steps, so the registry
                # job's steps are guarded by the job. Everything inside the
                # two rehearsable jobs has to carry it itself.
                guard = own or (
                    [job_if("ci.yml", job)] if job == "publish-mcp-registry" else []
                )
                found.append((label, guard))
        self.assertGreaterEqual(
            len(found),
            9,
            f"ci.yml: the release-sensitive inventory shrank to {sorted(f[0] for f in found)}",
        )
        for label, guard in found:
            self.assertTrue(guard, f"ci.yml: {label} publishes with no condition")
            for condition in guard:
                self.assertIn(
                    "github.event_name == 'push'",
                    " ".join(condition.split()),
                    f"ci.yml: {label} admits an event other than a push: {condition}",
                )
                self.assertIn(
                    "refs/tags/v",
                    condition,
                    f"ci.yml: {label} is not scoped to a release tag: {condition}",
                )

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

    def test_the_verify_step_is_bounded_and_keeps_payloads_out_of_the_log(self):
        # v4.0.0-beta.2 (run 36193916273): `cosign verify-attestation` writes
        # the whole base64 SBOM attestation to stdout — about 52 MB across the
        # six digests, single lines up to 14.5 MB — and the step never
        # finished, so the release tags were never published. The verdict is
        # the exit status and the summary on stderr, so stdout goes to
        # /dev/null (stderr stays: it is the evidence), and the step carries
        # its own timeout so a stall fails in minutes rather than in 6 hours.
        # End-anchored: `> /dev/null >&2` re-points stdout after the drop.
        stdout_dropped = re.compile(r"(?:^|\s)1?>\s*/dev/null$")
        verifying = 0
        for block in steps("ci.yml", "docker-manifest"):
            pieces = [
                piece
                for command in joined(block)
                for piece in segments(shell(command))
                if COSIGN_VERIFY.match(piece)
            ]
            if not pieces:
                continue
            verifying += 1
            # An `exec 2>…` anywhere in the step redirects every later
            # command's stderr, which the per-command check cannot see.
            for command in joined(block):
                for piece in segments(shell(command)):
                    self.assertNotRegex(
                        piece,
                        r"^exec\b[^|]*\d*>",
                        f"ci.yml: {block[0].strip()} redirects the whole step: {piece}",
                    )
                    # segments() splits `&>` and `>&` at the `&`, so a piece
                    # that starts with a redirect is the tail of one of them.
                    self.assertNotRegex(
                        piece,
                        r"^\d*>",
                        f"ci.yml: {block[0].strip()} has a split &>/>& redirect: {piece}",
                    )
            # Bounded low: a timeout raised to 360 is the 6-hour stall again.
            minutes = [
                int(m.group(1))
                for line in block
                if (m := re.match(r"^\s+timeout-minutes:\s*(\d+)\s*$", line))
            ]
            self.assertTrue(minutes, f"ci.yml: {block[0].strip()} has no step timeout-minutes")
            self.assertLessEqual(max(minutes), 15, f"ci.yml: {block[0].strip()} timeout is not low")
            # Twelve registry and Rekor round trips need room: a floor keeps a
            # valid tag push from flaking on a too-tight bound.
            self.assertGreaterEqual(min(minutes), 5, f"ci.yml: {block[0].strip()} timeout is too tight")
            for piece in pieces:
                self.assertRegex(
                    piece,
                    stdout_dropped,
                    f"ci.yml: cosign verify stdout reaches the log: {piece}",
                )
                # stderr carries the verification summary: the evidence stays.
                self.assertNotRegex(
                    piece,
                    r"2>",
                    f"ci.yml: cosign verify stderr is redirected: {piece}",
                )
        self.assertTrue(verifying, "ci.yml: docker-manifest verifies nothing")

    def test_no_signing_or_gate_step_is_allowed_to_fail(self):
        # `continue-on-error` keeps the job green when the step fails. On a
        # step that signs, verifies, starts the image, or runs the gate, that
        # is the whole check turned into a log line: a mismatched manifest, a
        # missing signature or an image that exits on startup still publishes,
        # and every assertion above still passes because the wiring is all
        # still there. The key is rejected however it is valued — `false`
        # today is `true` in one character.
        guarded = 0
        for workflow in ("release.yml", "ci.yml", "docker.yml"):
            for block in steps(workflow):
                commands_in = joined(block)
                if not any(
                    runs(c, COSIGN_ANY)
                    or runs(c, GATE_SCRIPT)
                    or runs(c, SMOKE_GATE)
                    or runs(c, SMOKE_FULL_GATE)
                    for c in commands_in
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
        # So every mention is read, and each has to be an `env:` assignment, an
        # `if:` condition, or an input to a step or a called workflow — all
        # evaluated by the expression engine and handed over as a value, never
        # reaching a shell — with `run:` bodies tracked separately because
        # inside one no spelling is safe.
        # The input case is spelled as "any lowercase key that is not `run`"
        # rather than an allowlist of key names, because naming the keys would
        # make this assertion silently vacuous the next time a step takes the
        # tag under a name nobody added here. `run` stays excluded by name:
        # that is the one position where a value does reach a shell, and a
        # single-line `run:` never enters the folded-block branch above.
        # A called workflow moves the value rather than consuming it, so the
        # hazard travels with it: today `release.yml` passes the tag to
        # `task-sdk-recovery.yml`, which binds it to `actions/checkout`'s `ref:`
        # and interpolates it into none of its four `run:` steps. That was
        # checked by hand, not here — this scan reads `release.yml` alone, so a
        # callee that shell-interpolates its input would satisfy this assertion
        # while reopening the hole. Extending the scan across every workflow a
        # permitted input reaches is the real closure; until then, a new `with:`
        # consumer of the tag needs the callee read before it is added.
        permitted = re.compile(
            r"^(?:[A-Z][A-Z0-9_]*: [\"']?\$\{\{\s*" + TAG_INPUT + r"\s*\}\}[\"']?"
            r"|if: (?:[>|][-+]?\s)?\$\{\{ [^}]*" + TAG_INPUT + r"[^}]*\}\}"
            r"|(?!run:)[a-z][a-z0-9_-]*: [\"']?\$\{\{ ?[^}]*"
            + TAG_INPUT
            + r"[^}]*\}\}[\"']?)$"
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


# The smoke gate is a shell script, not a workflow, so it is read directly.
# Overridable for the same reason the workflows are: the mutation harness
# points these assertions at a copy.
# The variant's gate: a shell script like the one above, pinned by what it
# runs rather than by being called, so deleting its checks does not read as
# the gate surviving.
# The image definition itself. The variant exists as a third stage, and the
# workflows only name it -- delete it and every `--target runtime-full` fails
# at build time, but nothing here would have said so first.
DOCKERFILE = pathlib.Path(
    os.environ.get("MCPGW_DOCKERFILE")
    or pathlib.Path(__file__).parents[2] / "Dockerfile"
)
SMOKE_FULL = pathlib.Path(
    os.environ.get("MCPGW_SMOKE_FULL_SCRIPT")
    or pathlib.Path(__file__).parents[2] / "scripts" / "ci" / "smoke-full-image.sh"
)
SMOKE = pathlib.Path(
    os.environ.get("MCPGW_SMOKE_SCRIPT")
    or pathlib.Path(__file__).parents[2] / "scripts" / "ci" / "smoke-image.sh"
)
# A release asset URL that names a version rather than whatever is newest.
# `releases/latest` resolves at run time, so the bytes a release runs are not
# the bytes anyone reviewed.
PINNED_RELEASE = re.compile(r"/releases/download/v\d+\.\d+\.\d+/")


class SupplyChain(unittest.TestCase):
    """The registry publisher runs a third-party binary with publish rights.

    `publish-mcp-registry` hands `mcp-publisher` an OIDC token that can write
    to a public registry under this project's name. An unpinned download gives
    whoever can cut a release in that upstream repository -- or anyone who can
    swap an asset on it -- that token. Pinning without verifying is only half
    the control: a release asset can be replaced in place.
    """

    def test_the_registry_publisher_pins_and_verifies_its_publisher_binary(self):
        body = (WORKFLOWS / "ci.yml").read_text()
        install = [
            block
            for block in steps("ci.yml", job="publish-mcp-registry")
            if any("mcp-publisher_" in line for line in block)
        ]
        self.assertEqual(
            len(install), 1, "ci.yml: expected exactly one mcp-publisher download step"
        )
        text = "\n".join(install[0])
        self.assertNotIn(
            "releases/latest",
            text,
            "ci.yml: mcp-publisher is fetched from `releases/latest`, so the "
            "binary handed the publish token is whatever upstream published last",
        )
        self.assertRegex(
            text,
            PINNED_RELEASE,
            "ci.yml: the mcp-publisher download names no pinned version",
        )
        self.assertRegex(
            text,
            r"sha256sum\s+(-c|--check)",
            "ci.yml: the mcp-publisher download is never checksum-verified",
        )
        # A verification that runs after the binary has already been executed
        # verifies nothing. Both live in the install step, so the check is that
        # no later step runs it before this one finishes -- and within the step,
        # that the checksum line precedes the first `mcp-publisher` invocation.
        run = text.index("sha256sum")
        invoked = [
            m.start() for m in re.finditer(r"\./mcp-publisher(?![-\w])", text)
        ]
        for at in invoked:
            self.assertGreater(
                at,
                run,
                "ci.yml: mcp-publisher is executed before its checksum is checked",
            )
        # File-wide, so a second unpinned fetch cannot be added elsewhere in
        # this workflow. Matched at the download position rather than on the
        # bare phrase, which also appears in prose explaining why it is gone.
        self.assertEqual(
            body.count("releases/latest/download"),
            0,
            "ci.yml: an unpinned `releases/latest` download remains somewhere",
        )


class VariantStage(unittest.TestCase):
    """The third stage, read rather than assumed.

    Docker builds the file’s last stage when a build names none, so the
    variant being last is what makes an untargeted build dangerous -- and what
    makes the base stage’s name load-bearing.
    """

    def setUp(self):
        self.body = DOCKERFILE.read_text()

    def test_the_variant_is_the_last_stage_and_runtime_is_named(self):
        stages = re.findall(r"(?m)^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$", self.body)
        self.assertTrue(stages, "the Dockerfile declares no stage")
        self.assertEqual(
            stages[-1][1],
            "runtime-full",
            "the variant is not the file's last stage",
        )
        names = [name for _, name in stages]
        self.assertIn("runtime", names, "the base stage is no longer named")

    def variant_stage(self):
        # Comments dropped: an instruction installs a tool, a comment naming one
        # installs nothing.
        body = "\n".join(
            line
            for line in self.body.splitlines()
            if not line.lstrip().startswith("#")
        )
        return body[body.index("FROM runtime AS runtime-full") :]

    def test_the_variant_installs_what_its_smoke_gate_exercises(self):
        stage = self.variant_stage()
        for tool in ("nodejs", "git", "openssh-client"):
            self.assertRegex(
                stage,
                rf"apt-get install[^\n]*(?:\n[^\n]*)*?\b{re.escape(tool)}\b",
                f"the variant stage does not apt-get install {tool}",
            )
        self.assertRegex(
            stage,
            r"COPY --from=ghcr\.io/astral-sh/uv:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}\s+/uv\s+/uvx\s",
            "the variant stage does not install uv from a digest-pinned image",
        )

    def test_the_variant_executes_no_downloaded_installer(self):
        # A fetched script runs whatever its URL serves on the day of the build.
        # Node's integrity rests on apt verifying packages against a key whose
        # fingerprint is pinned here, and uv's on an image digest.
        stage = self.variant_stage()
        for script in (r"setup_\d+\.x", r"install\.sh"):
            self.assertNotRegex(
                stage, script, f"the variant stage executes a downloaded {script}"
            )
        self.assertIn(
            "6F71F525282841EEDAF851B42F59B5F99B1BE0B4",
            stage,
            "the variant stage does not pin the NodeSource signing key fingerprint",
        )

    def test_the_node_and_npm_assertions_are_at_build_time(self):
        self.assertRegex(
            self.body,
            r"node --version \| grep -q '\^v24\\\.'",
            "the variant stage does not assert the Node major at build time",
        )
        self.assertRegex(
            self.body,
            r'npm install -g \./npm-\d+\.\d+\.\d+\.tgz',
            "the variant stage does not install npm from its verified tarball",
        )

    def test_every_npm_tarball_is_verified_against_a_pinned_hash(self):
        # A pinned version is still the registry's word on the bytes; the
        # sha512 (as in the registry's `dist.integrity`) is this repo's.
        # Continuations folded as Docker folds them, before the shell runs.
        stage = self.variant_stage().replace("\\\n", "")
        found = re.search(r'pins="([^"]*)"', stage)
        self.assertIsNotNone(found, "the variant stage declares no npm pins")
        pins = found.group(1).split()
        self.assertTrue(pins, "the variant stage's npm pin list is empty")
        for pin in pins:
            self.assertRegex(
                pin,
                r"^[a-z0-9._-]+@\d+\.\d+\.\d+:sha512-[A-Za-z0-9+/]{86}==$",
                f"{pin!r} is not name@version:sha512-<integrity>",
            )
        names = {pin.split("@")[0] for pin in pins}
        for name in ("npm", "brace-expansion", "ip-address", "tar"):
            self.assertIn(name, names, f"{name} is fetched without a pinned hash")
        # A pin that is never compared is text: the tarball must be hashed and
        # the result checked against it, as an exact string.
        self.assertIn("createHash('sha512')", stage)
        self.assertIn('test "${got}" = "${want}"', stage)
        # Every fetch goes through the verified list; a literal spec on an npm
        # command line would bypass it.
        self.assertNotRegex(
            stage,
            r"npm\s+(?:install|i|pack)\b[^\n]*[a-z]@\d",
            "an npm command fetches a spec that is not in the verified list",
        )


class VariantGateCoverage(unittest.TestCase):
    """What the variant's gate proves, as opposed to that it is called.

    The wiring assertions pin the call site. Nothing pinned the body, so the
    npx, uvx, git and cache checks could be deleted with every suite green and
    an image carrying no runnable npx still published as `:latest-full`.
    """

    def setUp(self):
        self.body = SMOKE_FULL.read_text()

    def test_every_toolchain_the_variant_exists_for_is_exercised(self):
        for label, probe in (
            ("npx", r"npx\s+--yes"),
            ("uvx", r"uvx\s"),
            ("git", r"git\s+ls-remote"),
            ("the caches", r"touch\s+/home/gateway/\.npm"),
        ):
            self.assertRegex(self.body, probe, f"the variant gate never runs {label}")

    def test_a_probe_that_fails_still_fails_the_step(self):
        # `fail` without its `exit` prints an annotation and reports success,
        # which turns every probe in the file into an advisory log line.
        self.assertRegex(
            self.body,
            r"(?s)fail\(\)\s*\{.*?\bexit\s+[1-9]",
            "the variant gate's fail() does not exit non-zero",
        )

    def test_it_still_starts_the_image(self):
        self.assertRegex(
            self.body,
            r"smoke-image\.sh\"?\s+\S",
            "the variant gate no longer starts the image it publishes",
        )

    def test_every_probe_is_bounded(self):
        # Four probes here resolve over the network. Unbounded, a runner whose
        # resolver stops answering waits on the first of them until the job is
        # killed, and reports `cancelled` with no annotation and nothing in the
        # log between the step's first line and the cancellation -- a red step
        # that names neither the probe nor the reason.
        # Comments dropped: the word appears in the file's own prose, and a
        # sentence about a probe is not a probe.
        code = "\n".join(
            line
            for line in self.body.splitlines()
            if not line.lstrip().startswith("#")
        )
        calls = re.findall(r"\bprobe\s+(\S+)", code)
        self.assertTrue(calls, "the variant gate runs no probe")
        for call in calls:
            self.assertRegex(
                call,
                r'^"\$\{[A-Z_]+_TIMEOUT\}"',
                f"a probe is unbounded, so a stalled network hangs the job: probe {call}",
            )

    def test_the_probe_ceiling_is_applied_not_only_declared(self):
        # Every call site passing a ceiling proves nothing if the helper that
        # runs the probe drops it: deleting `timeout` from `run_as_gateway`
        # would leave the call-site test green and the gate unbounded again.
        helper = re.search(r"run_as_gateway\(\) \{(.*?)\n\}", self.body, re.S)
        self.assertIsNotNone(helper, "run_as_gateway is gone")
        self.assertRegex(
            helper.group(1),
            r"timeout\s+-k\s+\d+\s+\$\{1\}",
            "run_as_gateway no longer applies the probe's ceiling",
        )

    def test_a_probe_that_times_out_says_so(self):
        # A timeout leaves the probe's output empty, so without the exit code a
        # stalled network is reported as a broken image and the reader is sent
        # after the wrong thing.
        for code in (124, 137):
            self.assertRegex(
                self.body,
                rf'"\$\{{rc\}}"\s*=\s*{code}\b',
                f"the variant gate cannot tell a {code} timeout from a failure",
            )
        self.assertRegex(
            self.body,
            r"(?s)probe\(\)\s*\{.*?did not finish within",
            "the variant gate never reports which probe timed out",
        )


class SmokeGateCoverage(unittest.TestCase):
    """What the container gate actually proves about the published image.

    NFR.PKG.1 reads: "the container image the release publishes starts, and
    serves an MCP request from outside the container". A gate that only reads
    the image's own HEALTHCHECK proves the first clause and asserts the second
    by assumption -- the HEALTHCHECK probes from inside, where a loopback bind
    answers and a published port still reaches nothing.
    """

    def setUp(self):
        self.body = SMOKE.read_text()
        # Line continuations folded first. A `docker run` here spans several
        # physical lines, and a line-anchored match reads only the first of
        # them -- so an assertion about an argument on a later line passes
        # whether or not the argument is there.
        self.folded = re.sub(r"\\\n\s*", " ", self.body)

    def test_the_gate_probes_the_image_from_outside_the_container(self):
        self.assertRegex(
            self.folded,
            r"docker run[^\n]*(-p|--publish)\s",
            "smoke-image.sh: no container publishes a port, so nothing can "
            "reach the image from the runner",
        )
        self.assertRegex(
            self.body,
            r'"method"\s*:\s*"initialize"',
            "smoke-image.sh: no MCP request is made; NFR.PKG.1 asks for one",
        )
        self.assertRegex(
            self.folded,
            r"curl[^\n]*/mcp\b",
            "smoke-image.sh: the external probe does not reach the MCP endpoint",
        )

    def test_the_gate_exercises_the_image_as_an_operator_runs_it(self):
        # Every `docker run` in the gate overrides the Dockerfile's CMD, so the
        # default invocation -- the one an operator types first -- is untested.
        # `if docker run ...` is still a run of the image: anchoring on the
        # start of the line alone would skip the one leg that cannot use a
        # bare command, because it expects a non-zero exit.
        runs = re.findall(
            r"^\s*(?:if\s+)?docker run\b.*$", self.folded, re.MULTILINE
        )
        self.assertTrue(runs, "smoke-image.sh: no `docker run` at all")
        self.assertTrue(
            any("--config" not in block for block in runs),
            "smoke-image.sh: every run injects a --config, so the image's own "
            "default entrypoint is never exercised",
        )

    def test_the_gate_publishes_a_port_no_other_process_can_hold(self):
        # A fixed host port is answerable by whatever already holds it. Docker
        # reports success for `-p 127.0.0.1:39401:39400` when a native process
        # owns 39401 -- the container binds inside the VM and the host-side
        # forward loses to the incumbent -- so the probe reaches the stranger
        # and the leg passes while the image under test serves nobody. Observed
        # on 39401 against a developer machine's own gateway, and the same
        # collision voided a performance run before any rep. Letting Docker
        # allocate the port makes attribution structural rather than assumed,
        # and keeps two concurrent gate runs from fighting over one number.
        published = [
            spec
            for line in re.findall(
                r"^\s*(?:if\s+)?docker run\b.*$", self.folded, re.MULTILINE
            )
            for spec in re.findall(r"(?:-p|--publish)\s+\"?([^\"\s]+)\"?", line)
        ]
        self.assertTrue(published, "smoke-image.sh: no published port at all")
        for spec in published:
            self.assertRegex(
                spec,
                r"^(?:[\d.]+:)?:\d+$",
                f"smoke-image.sh: publish spec {spec!r} pins a host port, so "
                "any process already holding it can satisfy the MCP leg",
            )
        # An allocated port is only usable if the gate reads back which one.
        self.assertRegex(
            self.body,
            r"docker port\b",
            "smoke-image.sh: the published port is never read back, so the "
            "probe cannot know where to reach the container",
        )

    def test_the_gate_refuses_a_healthcheck_that_proves_nothing(self):
        # The gate's verdict IS the HEALTHCHECK, so a degenerate one -- `CMD
        # true`, or a probe aimed at a port nothing serves -- turns the whole
        # gate green with no evidence behind it.
        self.assertIn(
            ".Config.Healthcheck.Test",
            self.body,
            "smoke-image.sh: the HEALTHCHECK is checked for existence only, "
            "never for being a real probe",
        )
        self.assertRegex(
            self.body,
            r"/health",
            "smoke-image.sh: nothing pins the HEALTHCHECK to the health endpoint",
        )


if __name__ == "__main__":
    unittest.main()
