# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Regression tests for the tag/manifest publish gate and its channel predicate."""

import collections.abc
import contextlib
import fnmatch
import importlib.util
import io
import itertools
import os
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

import yaml

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
RECURSION_MARGIN = re.compile(r"(?:(?:ba)?sh\s+)?scripts/ci/check-recursion-margin\.sh(?=\s|$)")
RECIPE_SMOKE = re.compile(r"(?:(?:ba)?sh\s+)?scripts/dev/docker-smoke\.sh(?=\s|$)")
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


# W8 (GH1941.SIGN.1): the post-publish re-check, matched at command position.
VERIFY_ASSETS = re.compile(r"scripts/release/verify-release-assets\.sh\s+\S+")
GH_RELEASE_DOWNLOAD = re.compile(r"gh\s+release\s+download\b")


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


RELEASE_LINE_ONLY = (
    "github.event_name == 'push' && "
    "github.ref == 'refs/heads/docs/ranking-1-release-line'"
)


EXPORT_ARTIFACT_NAME = "image-${{ matrix.arch }}-${{ github.sha }}"


def is_release_line_export(block):
    """True for the one step that hands verifiers an image and publishes nothing.

    Safe by what it does, never by what it is called. The parsed step must be an
    upload-artifact whose own `if:` is exactly the release-line push condition
    (so it cannot run on main or a tag) and whose artifact is exactly the export
    name -- not anything under `image-digest-`, the prefix the manifest job
    consumes to create tags. Parsed, not pattern-matched: a nested `if:` or a
    quoted name must not be able to satisfy it.
    """
    try:
        step = yaml.safe_load("\n".join(block))[0]
    except (yaml.YAMLError, IndexError, KeyError, TypeError):
        return False
    if not isinstance(step, dict) or not isinstance(step.get("with") or {}, dict):
        return False
    return (
        " ".join(str(step.get("if", "")).split()) == RELEASE_LINE_ONLY
        and str(step.get("uses", "")).lower().startswith("actions/upload-artifact@")
        and str((step.get("with") or {}).get("name", "")) == EXPORT_ARTIFACT_NAME
    )


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


TAG_GATE = re.compile(
    r"(?:python3?|uv run)\s+scripts/release/check_tag_manifest\.py(?=\s|$)"
)


def step_props(block):
    """The step mapping's own keys, without the `run:`/`env:`/`with:` bodies
    nested under it: a key at any other depth is not a property of the step, so
    a `timeout-minutes:` or `id:` written inside a body must not count."""
    item = len(block[0]) - len(block[0].lstrip())
    return [block[0].lstrip()[2:]] + [
        line.strip() for line in block[1:] if len(line) - len(line.lstrip()) == item + 2
    ]


def gate_steps(workflow, job):
    """`job`'s own steps that run the tag gate under `id: meta`."""
    return [
        block
        for block in steps(workflow, job=job)
        if "id: meta" in step_props(block)
        and any(runs(command, TAG_GATE) for command in joined(block))
    ]


# `gh api repos/MikkoParkkola/mcp-gateway/actions/permissions/artifact-and-log-retention`
# reports `days: 14`. upload-artifact clamps `retention-days` to that value.
HANDOFF_RETENTION_DAYS = 14

# The oldest cosign the workflows may install. v2.6.5 fixes GHSA-fx35-mq7g-6g98
# (verification bypass via a public key in a legacy bundle); v2.6.2 fixed
# GHSA-whqx-f9j3-ch6m (verification accepts any valid Rekor entry under
# certain conditions).
COSIGN_FLOOR = (2, 6, 5)
# One recogniser for an installer step, shared by the checks that must know a
# step is the installer (push-guard inventory, rehearsal exemption): YAML
# allows the key and the action reference bare, single- or double-quoted,
# GitHub matches the owner and repository in any case, and a check that knows
# fewer forms than the others lets a step escape it. The parser decides which
# steps are installers; test_the_text_recogniser_finds_every_parsed_installer
# holds this recogniser to the same steps.
COSIGN_INSTALLER = re.compile(r"""^\s*(?:-\s+)?(["']?)uses\1:\s*["']?(?i:sigstore/cosign-installer)@""")


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses what Actions may resolve differently.

    PyYAML keeps the last of two equal keys and flattens `<<` merge keys; a
    floor that read either could pass a pin the runner never applies.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(None, None, "a `<<` merge key", key_node.start_mark)
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, collections.abc.Hashable):
                raise yaml.constructor.ConstructorError(None, None, "an unhashable key", key_node.start_mark)
            if key in seen:
                raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def installer_steps(path):
    """(job, index, step) for every cosign-installer step of a parsed workflow."""
    # A workflow the parser refuses fails the check that asked (a failure,
    # not an error): its installers cannot be read, so none can be trusted.
    try:
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictLoader)
    except (yaml.YAMLError, UnicodeDecodeError) as error:
        raise AssertionError(f"{path.name} does not parse as a workflow: {error}") from None
    jobs_ = doc.get("jobs") if isinstance(doc, dict) else None
    for job, body in (jobs_ if isinstance(jobs_, dict) else {}).items():
        for index, step in enumerate((body.get("steps") if isinstance(body, dict) else None) or []):
            if isinstance(step, dict) and str(step.get("uses", "")).lower().startswith("sigstore/cosign-installer@"):
                yield job, index, step


def artifact_keys(block, keys):
    """The values of `keys` under a step's `with:`, in order.

    Read under `with:` only: the step's own `name:` is a label, and taking it
    for the artifact name would match nothing or, worse, the wrong artifact.
    """
    found, depth = [], None
    for line in block:
        indent = len(line) - len(line.lstrip())
        if re.match(r"^\s*(- )?with:\s*$", line):
            depth = indent + (2 if line.lstrip().startswith("- ") else 0)
            continue
        if depth is None:
            continue
        if indent <= depth:
            depth = None
            continue
        match = re.match(r"^\s*(\w[\w-]*):\s*(.+?)\s*$", line)
        if match and match.group(1) in keys:
            found.append(match.group(2).strip("'\""))
    return found


class WorkflowWiring(unittest.TestCase):
    """The gate is only worth what the workflows calling it are wired to do.

    These read the workflow text rather than run it. They cannot prove a
    release publishes correctly — only CI on a real tag does that — but they
    catch the rewiring mistakes that are silent at author time and only visible
    once a release has already gone to the wrong channel.

    Mostly textual: equivalence is handled case by case — comments stripped,
    optional quotes, folded conditions, continuations joined, step blocks
    scoped. The cosign floor is the exception: it reads a strict YAML parse
    (PyYAML 6.0.2, which every job running this suite installs first),
    because a text scan kept missing spellings of one installer step, and the
    text recogniser is held to the parser's steps. Every case here is pinned by
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
        #
        # Attributed by structure, not by text. docker-build carries a gate
        # step whose executable lines are identical to the publisher's, so
        # "this text appears in the job" cannot tell whose step it is (#570).
        # The step must run the gate AND be `meta`, the id the tags read.
        self.assertTrue(
            gate_steps("ci.yml", "docker-manifest"),
            "ci.yml docker-manifest: no step with id meta runs the tag gate",
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
                raw, block = block, joined(block)
                if not any(runs(c, COSIGN_ANY) for c in block):
                    continue
                signing += 1
                name = block[0]
                # E1: the rehearsal verify binds pinned literals on purpose; it
                # verifies a signed release, never the build. Held to E1 here,
                # and to the release step's body by RehearsalVerify.
                if condition_of(raw) == REHEARSAL_CONDITION:
                    self.assertEqual(readonly_verify_refusals(raw), [], f"{workflow}: {name}")
                    continue
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
                # The rehearsal verify checks a pinned older release, not this
                # index, so it cannot be the verify a release tag waits for.
                if condition_of(block) != REHEARSAL_CONDITION:
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

    def test_a_required_linux_job_holds_the_recursion_margin(self):
        # MIK-7678: Clippy is a required Linux check, so it carries the depth
        # margin Windows and Kani would otherwise be first to break, fatally.
        blocks = steps("ci.yml", "check")  # "Clippy (pedantic)"
        margin = [
            "\n".join(b) for b in blocks
            if any(runs(c, RECURSION_MARGIN) for c in joined(b))
        ]
        self.assertEqual(len(margin), 1, "Clippy (pedantic) no longer runs scripts/ci/check-recursion-margin.sh")
        self.assertNotRegex(margin[0], r"(?m)continue-on-error:\s*true|^\s+if:", "the margin check must be unconditional and fatal")
        script = (pathlib.Path(__file__).parents[2] / "scripts" / "ci" / "check-recursion-margin.sh").read_text(encoding="utf-8")
        self.assertRegex(script, r"(?m)^LIMIT=\d+$")
        self.assertIn("Pin<Box<dyn Future + Send>>", script, "the failure must say to erase the future's type")

    def test_the_chart_is_published_and_signed_by_this_workflow(self):
        # MIK-7952: the chart is signed by ci.yml at the tag, the image's own
        # signer, after the manifest job has signed and named the image, and a
        # verify under any other identity is refused for its identity.
        body = jobs("ci.yml").get("helm-chart-publish", "")
        self.assertTrue(body, "ci.yml has no helm-chart-publish job")
        self.assertIn("docker-manifest", needs_of(body) or "", "the chart must wait for the signed image")
        gate = job_if("ci.yml", "helm-chart-publish")
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", gate)
        self.assertIn("needs.docker-manifest.result == 'success'", gate, "a tag run publishes only over a signed image")
        self.assertIn("needs.docker-manifest.outputs.is_prerelease == 'false'", gate, "a prerelease must not take a stable chart version")
        manifest = jobs("ci.yml")["docker-manifest"]
        self.assertRegex(manifest, r"(?m)^\s+list: \$\{\{ steps\.list\.outputs\.list \}\}$")
        self.assertIn("SIGNED_LIST: ${{ needs.docker-manifest.outputs.list }}", body)
        self.assertRegex(body, r"(?m)^\s+id-token:\s*write\b")
        self.assertIn("IDENTITY: https://github.com/${{ github.workflow_ref }}", body)
        self.assertIn("SIGNER_ISSUER: https://token.actions.githubusercontent.com", body)
        ran = "\n".join(c for b in steps("ci.yml", "helm-chart-publish") for c in joined(b))
        self.assertRegex(ran, r'SIGNER_IDENTITY="\$IDENTITY"[^\n]*\n?[^\n]*scripts/release/publish_pinned_chart\.sh "\$image" "\$repo"')
        self.assertIn('image="ghcr.io/mikkoparkkola/mcp-gateway@${SIGNED_LIST}"; repo=oci://ghcr.io/mikkoparkkola/charts\n', ran + "\n",
                      "the release chart must pin the digest docker-manifest verified, not a tag")
        self.assertRegex(ran, r'(?m)^\s*if cosign verify --certificate-identity "\$wrong"', "no wrong-identity verify")
        self.assertRegex(
            ran,
            r"(?m)^\s*grep -q 'none of the expected identities matched' \"\$RUNNER_TEMP/wrong-identity\.err\" \|\| \{",
            "a wrong-identity refusal must be for its identity",
        )

    def test_the_documented_recipe_serves_a_call_before_the_handoff(self):
        # MIK-7484: smoke-image.sh proves the image starts; only
        # scripts/dev/docker-smoke.sh runs the documented recipe (127.0.0.1
        # publish, 0.0.0.0 bind, the unauthenticated-bind opt-in) through to a
        # routed tool call. It must run on the image this job built, with no
        # host build, fatally, and before the digest leaves the job.
        blocks = steps("docker.yml", "build")
        recipe = [i for i, b in enumerate(blocks) if any(runs(c, RECIPE_SMOKE) for c in joined(b))]
        self.assertTrue(recipe, "docker.yml: build never runs scripts/dev/docker-smoke.sh")
        handoffs = [
            i for i, b in enumerate(blocks)
            if any(re.match(r"^\s*uses:\s*actions/upload-artifact@", line) for line in b)
        ]
        self.assertTrue(handoffs, "docker.yml: build no longer uploads its digest")
        self.assertLess(min(recipe), min(handoffs), "the recipe smoke runs after the digest is handed on")
        step = "\n".join(blocks[min(recipe)])
        for setting in (
            'MCP_GATEWAY_DOCKER_BUILD: "0"',
            'MCP_GATEWAY_INIT_IN_IMAGE: "1"',
            "MCP_GATEWAY_DOCKER_IMAGE: ${{ env.REGISTRY }}/mikkoparkkola/mcp-gateway:scan",
        ):
            self.assertIn(setting, step, "the recipe smoke must run the image this job built")
        self.assertNotRegex(step, r"continue-on-error:\s*true", "the recipe smoke must be fatal")

    def test_a_source_pull_request_compiles_on_both_declared_toolchains(self):
        # MIK-7835: a source-only PR into the release line does not build the
        # image before merge, so it must at least compile as the image does, on
        # the Dockerfile's toolchain and on the declared rust-version.
        body = jobs("docker.yml").get("release-compile", "")
        self.assertTrue(body, "docker.yml: the release-compile job is gone")
        self.assertRegex(body, r"(?m)^    needs: scope$")
        self.assertRegex(body, r"(?m)^    if: needs\.scope\.outputs\.compile_check == 'true'$")
        rows = re.search(r"(?m)^        source: \[([^\]]*)\]$", body)
        self.assertTrue(rows, "release-compile has no source matrix")
        self.assertEqual(
            sorted(r.strip() for r in rows.group(1).split(",")),
            ["dockerfile", "rust-version"],
            "release-compile must compile on both the Dockerfile's toolchain and the rust-version",
        )
        self.assertIn("sed -n 's/^FROM mirror\\.gcr\\.io\\/library\\/rust:", body, "the Dockerfile row no longer reads the Dockerfile")
        self.assertIn("sed -n 's/^rust-version = ", body, "the rust-version row no longer reads Cargo.toml")
        # The Dockerfile row builds the binary (MIK-8188) so the next step can
        # grep it for the debug-only test trust roots; the rust-version row
        # still only checks.
        self.assertRegex(body, r'(?m)^            cargo \+"\$TOOLCHAIN" build --release --locked --bin mcp-gateway$')
        self.assertRegex(body, r'(?m)^            cargo \+"\$TOOLCHAIN" check --release --locked$')
        self.assertIn("if: matrix.source == 'dockerfile'", body, "the test-hook check must run on the built row")
        self.assertIn("scripts/release/grep_no_test_hook.sh target/release/mcp-gateway", body, "the release binary is no longer checked")
        self.assertNotRegex(body, r"continue-on-error:\s*true", "the compile must be fatal")
        scope = jobs("docker.yml")["scope"]
        self.assertRegex(scope, r"compile_check: \$\{\{ steps\.decide\.outputs\.compile_check \}\}")
        self.assertRegex(
            scope,
            r"grep -Eq '\^\(src/\|crates/[^']*' <<<\"\$files\"; then\s+compile true",
            "a source change no longer selects the compile",
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

    def test_the_release_line_export_exemption_is_keyed_on_what_makes_it_safe(self):
        # A step name is a free-text label: keying the exemption on it would
        # let any future step walk past the main-only rule by copying it.
        def step(cond=RELEASE_LINE_ONLY, uses="actions/upload-artifact@x",
                 name=EXPORT_ARTIFACT_NAME, env=""):
            lines = ["- name: Upload the scanned image (release-line push only)"]
            if cond:
                lines.append(f"  if: {cond}")
            lines.append(f"  uses: {uses}")
            if env:
                lines += ["  env:", f"    if: {env}"]
            lines += ["  with:", f"    name: {name}"]
            return lines

        self.assertTrue(is_release_line_export(step()))
        # Each requirement fails on its own, the others held valid.
        for held, why in (
            (step(cond="github.ref == 'refs/heads/main'"), "main-only condition"),
            (step(cond=""), "no condition"),
            (step(cond="", env=RELEASE_LINE_ONLY), "condition only nested in env"),
            (step(name="image-digest-${{ matrix.arch }}"), "digest artifact"),
            (step(name="'image-digest-amd64'"), "quoted digest artifact"),
            (step(name="other"), "unlisted artifact name"),
            (step(uses="docker/build-push-action@x"), "registry publisher"),
        ):
            self.assertFalse(is_release_line_export(held), why)

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
            if not is_release_line_export(block)
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
            # Either spelling excludes a tag: the old `!startsWith(... 'refs/tags/v')`,
            # or the current pin to main alone (a release-line push builds the
            # image but must publish nothing, so the sites name main exactly).
            self.assertRegex(
                condition,
                r"!\s*startsWith\(\s*github\.ref\s*,\s*'refs/tags/v'\s*\)"
                r"|github\.ref\s*==\s*'refs/heads/main'",
                f"docker.yml pushes on a tag again: {condition}",
            )
            # A main pin OR-ed with a tag test would still match the pin above.
            self.assertNotRegex(
                condition,
                r"(?<!!)\bstartsWith\(\s*github\.ref\s*,\s*'refs/tags/",
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
            13,
            f"ci.yml: expected 13 publish-path conditions, read {sorted(sites)}",
        )
        # Classified by exact label: a blanket "release or rehearse" would
        # green a later edit that signs on a rehearsal.
        rehearsal_capable = {"docker-manifest -> Install cosign"}
        rehearsal_only = {f"docker-manifest -> {REHEARSAL_VERIFY}"}
        self.assertLessEqual(rehearsal_capable | rehearsal_only, set(sites))

        for label, condition in sites.items():
            for event in events:
                for ref in refs:
                    for value in values:
                        release = event == "push" and ref.startswith("refs/tags/v")
                        rehearse = event == "workflow_dispatch" and value in (
                            True,
                            "true",
                        )
                        if label in rehearsal_only:
                            want = rehearse
                        else:
                            want = release or (
                                (
                                    label.endswith("(job)")
                                    and not label.startswith("publish-mcp-registry")
                                    or label in rehearsal_capable
                                )
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
            COSIGN_INSTALLER,
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
                found.append((label, guard, block))
        self.assertGreaterEqual(
            len(found),
            9,
            f"ci.yml: the release-sensitive inventory shrank to {sorted(f[0] for f in found)}",
        )
        tag_guarded_verifies = 0
        for label, guard, block in found:
            self.assertTrue(guard, f"ci.yml: {label} publishes with no condition")
            self.assertEqual(len(guard), 1, f"ci.yml: {label} has more than one if:")
            condition = " ".join(guard[0].split())
            # E1 (design 2026-09-26): a read-only verify of a pinned, already
            # signed release may run on a rehearsal alone. Nothing that writes
            # qualifies, whatever its env holds.
            if condition == REHEARSAL_CONDITION:
                self.assertEqual(
                    readonly_verify_refusals(block),
                    [],
                    f"ci.yml: {label} runs on a rehearsal but is not a read-only pinned verify",
                )
                continue
            # E2: the cosign installer may add the rehearsal, and only that.
            if condition == f"({' && '.join(TAG_CONJUNCTS)}) || ({REHEARSAL_CONDITION})":
                self.assertTrue(
                    any(COSIGN_INSTALLER.match(l) for l in block)
                    and not any(re.match(r"^\s*(?:- )?run:", l) for l in block),
                    f"ci.yml: {label} takes the installer's exemption without being it",
                )
                continue
            # Exact top-level conjuncts, not substrings: `push && (tag || x)`
            # contains both strings and admits any event x admits.
            parts = conjuncts(condition)
            for want in TAG_CONJUNCTS:
                self.assertIn(
                    want,
                    parts,
                    f"ci.yml: {label} is not scoped to a tag push by an exact conjunct: {condition}",
                )
            if any(COSIGN_VERIFY.match(p) for c in joined(block) for p in segments(shell(c))):
                tag_guarded_verifies += 1
        # The rehearsal verify is an addition. The release verify stays guarded.
        self.assertGreaterEqual(tag_guarded_verifies, 1, "ci.yml: no tag-guarded cosign verify remains")

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
                for line in step_props(block)
                if (m := re.match(r"^timeout-minutes:\s*(\d+)\s*$", line))
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

    def test_the_packaged_crate_is_built_on_every_ref_and_run_after_merge(self):
        # #1812: tests that read a repository file the package leaves out
        # compile in a checkout and fail from the published crate. Every ref
        # builds them from the package; the full run is post-merge, so a pull
        # request does not pay for a second test run.
        body = jobs("ci.yml").get("package-tests")
        self.assertIsNotNone(body, "ci.yml has no package-tests job")
        self.assertNotRegex(body, r"(?m)^ {4}continue-on-error:", "package-tests must block")
        # The one condition allowed is the throwaway skip every other ci.yml job
        # carries: a same-repo `throwaway/` PR is never merged and runs only
        # `Tests (throwaway)`. Anything else would let some ref merge unbuilt.
        conditions = re.findall(r"(?m)^ {4}if:\s*(.*)$", body)
        throwaway_only = (
            "${{ !(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line' "
            "&& github.event.pull_request.head.repo.full_name == github.repository "
            "&& startsWith(github.head_ref, 'throwaway/')) }}"
        )
        self.assertIn(conditions, ([], [throwaway_only]), "package-tests must run on every ref but throwaway PRs")
        built = [c for b in steps("ci.yml", "package-tests") for c in joined(b)]
        self.assertTrue(any(re.search(r"scripts/ci/packaged-tests\.sh\s+build\b", c) for c in built), built)
        self.assertIn("package-tests", needs_of(jobs("ci.yml")["docker-build"]) or "")

        on = "\n".join(live_lines("packaged-suite.yml"))
        self.assertRegex(on, r"(?m)^on:$", "packaged-suite.yml has no on: block")
        self.assertRegex(on, r"(?m)^jobs:$", "packaged-suite.yml has no jobs: block")
        trigger = on[on.index("\non:") : on.index("\njobs:")]
        self.assertRegex(trigger, r"(?m)^  push:\n    branches: \[[^\]]*\bdocs/ranking-1-release-line\b")
        self.assertNotRegex(trigger, r"(?m)^  pull_request", "a PR trigger would run the suite twice per PR")
        self.assertRegex(trigger, r"(?m)^  workflow_call:")
        ran = [c for b in steps("packaged-suite.yml", "packaged-suite") for c in joined(b)]
        self.assertTrue(any(re.search(r"scripts/ci/packaged-tests\.sh\s+run\b", c) for c in ran), ran)

        # On a tag nothing publishes until the packaged suite has passed: a
        # crates.io or npm version cannot be replaced, and the checkout-based
        # tests cannot see a file the package leaves out.
        release_jobs = jobs("release.yml")
        self.assertIn("uses: ./.github/workflows/packaged-suite.yml", release_jobs.get("packaged-suite", ""))

        self.assertIn("packaged-suite", needs_of(release_jobs["release"]) or "", "release must wait for the packaged suite")
        for publisher in ("publish", "npm-publish", "homebrew-update"):
            self.assertIn("release", needs_of(release_jobs[publisher]) or "", f"{publisher} must wait for release")
        # The rehearsal reaches the post-merge path from a dispatch only.
        self.assertEqual(
            conjuncts(job_if("ci.yml", "packaged-suite-rehearsal"))[0],
            "github.event_name == 'workflow_dispatch'",
        )
        self.assertIn("uses: ./.github/workflows/packaged-suite.yml", jobs("ci.yml")["packaged-suite-rehearsal"])

        # The packaged run skips what ci.yml `test` skips, plus only the tests
        # that read repository files deliberately kept out of the crate.
        script = (pathlib.Path(__file__).parents[2] / "scripts" / "ci" / "packaged-tests.sh").read_text(encoding="utf-8")
        test_cmd = " ".join(c for b in steps("ci.yml", "test") for c in joined(b))
        packaged_only: set[str] = set()  # none: every file the suite reads ships (MIK-8163)
        self.assertEqual(
            set(re.findall(r"--skip\s+(\S+)", script)),
            set(re.findall(r"--skip\s+(\S+)", test_cmd)) | packaged_only,
            "the packaged run must skip ci.yml test's list plus only the repo-only reads",
        )

    def test_release_tooling_unit_tests_block_on_every_ref(self):
        # release-criteria is report-only off a tag because its live-ledger
        # checks read documents edited mid-flight. The tooling's own unit tests
        # read nothing live, so they run in a job that fails every ref: in the
        # report-only job a broken publish-gate test merged green and first
        # failed on the tag.
        unit = (
            "test_count_release_criteria.py",
            "test_scope_acceptance.py",
            "test_check_tag_manifest.py",
            "test_check_nfr_demo_1_recordings.py",
            "test_workflow_wiring_mutations.py",
            "test_grep_no_test_hook.py",
        )
        body = jobs("ci.yml").get("release-script-tests")
        self.assertIsNotNone(body, "ci.yml has no release-script-tests job")
        swallow = [
            line for line in body.splitlines()
            if re.match(r"^ {4}continue-on-error:", line)
            and not re.match(r"^ {4}continue-on-error:\s*false\s*$", line)
        ]
        self.assertEqual(swallow, [], "release-script-tests must not swallow failures")
        ran = {script for block in steps("ci.yml", "release-script-tests")
               for command in joined(block) for script in unit if f"scripts/release/{script}" in command}
        self.assertEqual(ran, set(unit), "release-script-tests must run every tooling unit test")
        stray = {script for block in steps("ci.yml", "release-criteria")
                 for command in joined(block) for script in unit if f"scripts/release/{script}" in command}
        self.assertEqual(stray, set(), "a unit test left in the report-only job is swallowed off a tag")
        self.assertIn("release-script-tests", needs_of(jobs("ci.yml")["docker-build"]) or "")

    def test_every_c6_obligation_is_resolved_on_every_pull_request_and_release_push(self):
        # MIK-8245: an obligation whose function moved, or whose patched lines
        # changed, would be scored VOID at gate day and replaced silently. The
        # resolver catches it in the change that caused it, so it must run on
        # every pull request and every release-line push, unconditionally, and
        # fail the run: no filter, no `if:`, nothing that swallows its status.
        path = WORKFLOWS / "c6-obligations.yml"
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictLoader)
        on = doc.get("on", doc.get(True))
        self.assertIsInstance(on, dict, "c6-obligations.yml must name its triggers")
        self.assertIn("pull_request", on, "the resolver must run on pull requests")
        self.assertFalse(on["pull_request"], "the pull_request trigger must carry no branch or path filter")
        push = on.get("push") or {}
        self.assertIn("docs/ranking-1-release-line", push.get("branches", []), "the resolver must run on release-line pushes")
        self.assertNotIn("paths", push, "the push trigger must carry no path filter")
        self.assertNotIn("paths-ignore", push, "the push trigger must carry no path filter")
        resolving = []
        for name, job in doc["jobs"].items():
            for step in job.get("steps", []):
                if "c6_resolve.py" in str(step.get("run", "")):
                    resolving.append((name, job, step))
        self.assertEqual(len(resolving), 1, "exactly one step must run the C6 resolver")
        name, job, step = resolving[0]
        self.assertNotIn("if", job, f"job {name} must not be conditional")
        self.assertNotIn("if", step, "the resolver step must not be conditional")
        self.assertFalse(job.get("continue-on-error") or step.get("continue-on-error"),
                         "the resolver's failure must fail the run")
        self.assertEqual(step["run"].strip(), "python3 scripts/release/c6_resolve.py --tree HEAD",
                         "the resolver must run alone, on the checked-out head, with its exit status")

    def test_the_ranking_corpus_is_regenerated_and_compared_every_ref(self):
        # MIK-7850: the held-out corpus must stay what gen_corpus.py derives
        # from the frozen tree. A dropped step, or a compare whose failure is
        # masked, lets a hand-edited corpus merge green.
        compare = [block for block in steps("ci.yml", "release-script-tests")
                   if any("gen_corpus.py" in command and "| cmp - benchmarks/ranking-baseline/corpus.json" in command
                          for command in joined(block))]
        self.assertEqual(len(compare), 1, "release-script-tests must regenerate and compare the ranking corpus once")
        text = "\n".join(compare[0])
        self.assertIn("set -euo pipefail", text, "the corpus compare must fail on any failed command")
        self.assertNotRegex(text, r"\|\|\s*(true|:)|continue-on-error:\s*true", "the corpus compare must not swallow failures")

    def test_every_installed_cosign_is_past_the_verification_advisory(self):
        # Every cosign the workflows install signs or verifies the images and
        # charts users trust, and a verify step on a vulnerable pin can pass
        # on what it should refuse (see COSIGN_FLOOR). Read from the parsed
        # workflow, not its text: YAML spells one step many ways (quoting and
        # escapes in keys and values, flow style, anchors, continuations), and
        # a text scan misses whichever spelling it was not written for.
        found = []
        for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
            for job, index, step in installer_steps(path):
                where = f"{path.name}: job {job} step {index + 1}"
                inputs = step.get("with")
                pin = inputs.get("cosign-release") if isinstance(inputs, dict) else None
                m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", pin) if isinstance(pin, str) else None
                self.assertIsNotNone(m, f"{where}: cosign-release must be a vX.Y.Z string under with:, got {pin!r}")
                found.append((where, tuple(int(x) for x in m.groups())))
        self.assertTrue(found, "no cosign installer found")
        # The floor is for the v2 line the workflows use. A v3 pin needs its
        # own floor added here first, or any v3.0.x would compare above it.
        self.assertEqual({v[0] for _, v in found}, {COSIGN_FLOOR[0]}, "cosign pin outside the v2 line")
        below = [f"{w}: cosign v{'.'.join(map(str, v))}" for w, v in found if v < COSIGN_FLOOR]
        self.assertEqual(below, [], f"cosign pins below the patched floor v{'.'.join(map(str, COSIGN_FLOOR))}")

    def test_every_job_running_the_floor_installs_its_parser_first(self):
        # The floor imports yaml; a job that runs these suites without the
        # pinned PyYAML fails at import on a runner that lacks it, or parses
        # with whatever version the image ships.
        missing = []
        for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
            for job in jobs(path.name):
                installed = False
                for block in steps(path.name, job):
                    text = "\n".join(block)
                    if "yaml.__version__ != \"6.0.2\"" in text and "pyyaml==6.0.2" in text:
                        installed = True
                    elif not installed and any(
                        suite in text for suite in ("test_check_tag_manifest.py", "test_workflow_wiring_mutations.py", "scripts/release/test_*.py")
                    ):
                        missing.append(f"{path.name}: {job}")
                        break
        self.assertEqual(missing, [], "a job runs the release suites before installing PyYAML 6.0.2")

    def test_the_text_recogniser_finds_every_parsed_installer(self):
        # The push-guard inventory and the rehearsal exemption read step text
        # through COSIGN_INSTALLER. The parser is the authority on which steps
        # install cosign, so the two must name the same steps (job and
        # position), not merely the same number of them.
        for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
            parsed = {(job, index) for job, index, _ in installer_steps(path)}
            text = {
                (job, index)
                for job in {j for j, _ in parsed} | set(jobs(path.name))
                for index, block in enumerate(steps(path.name, job))
                if any(COSIGN_INSTALLER.match(line) for line in block)
            }
            self.assertEqual(text, parsed, f"{path.name}: the text recogniser and the parser disagree on the installer steps")

    def test_the_release_builds_tests_and_publishes_the_event_commit(self):
        # The release commit is GITHUB_SHA, which a re-run keeps, and it is what
        # actions/checkout and both called workflows use when no ref is named.
        # A named ref can only be worse: a tag name looked up again later may
        # have moved. So no checkout of this repository and no called workflow
        # names one, and every job waits, directly or through its needs, for
        # the `resolve` guard that refuses a dispatch away from the tag.
        release_jobs = jobs("release.yml")
        self.assertIn("resolve", release_jobs, "release.yml has no resolve job")
        self.assertIsNone(needs_of(release_jobs["resolve"]), "resolve must run first")
        named, sites = [], 0
        for name, body in release_jobs.items():
            for block in steps("release.yml", name):
                if not any(re.search(r"uses:\s*actions/checkout@", l) for l in block):
                    continue
                if artifact_keys(block, ("repository",)):
                    continue  # another repository (the Homebrew tap)
                sites += 1
                named += [f"{name}: ref {r}" for r in artifact_keys(block, ("ref",))]
            if re.search(r"""(?m)^    uses:\s*["']?\./\.github/workflows/""", body):
                sites += 1
                named += [f"{name}: with ref {r}" for r in re.findall(r"(?m)^      (?:ref|tag):\s*(.+?)\s*$", body)]
        self.assertGreaterEqual(sites, 10, "the checkout and call inventory shrank")
        self.assertEqual(named, [], "a checkout or called workflow names a ref instead of the event commit")

        def reaches_resolve(name, seen=()):
            needs = re.findall(r"[\w-]+", needs_of(release_jobs[name]) or "")
            return "resolve" in needs or any(n not in seen and reaches_resolve(n, (*seen, name)) for n in needs)

        stray = [name for name in release_jobs if name != "resolve" and not reaches_resolve(name)]
        self.assertEqual(stray, [], "a job runs without waiting for the dispatch guard")

    def test_the_release_commit_is_the_event_commit_and_a_branch_dispatch_is_refused(self):
        # GITHUB_SHA is the commit the event names, an annotated tag peeled,
        # and a re-run keeps it; it is what npm provenance attests. Looking
        # the tag up again (ls-remote) can land on a commit the tag was moved
        # to after the event. A dispatch runs at `--ref <tag>`, so a dispatch
        # from anywhere else would build one commit and label it another.
        self.assertNotIn("ls-remote", "\n".join(live_lines("release.yml")), "release.yml must not look a tag up again")
        (block,) = steps("release.yml", "resolve")
        start = next(i for i, l in enumerate(block) if re.match(r"^\s*run:\s*\|\s*$", l))
        indent = len(block[start]) - len(block[start].lstrip())
        body = textwrap.dedent("\n".join(
            itertools.takewhile(lambda l: not l.strip() or len(l) - len(l.lstrip()) > indent, block[start + 1:])))
        event = "a" * 40
        for label, name, ref, tag, ok in [
            ("tag push", "push", "refs/tags/v4.0.0", "", True),
            ("dispatch at the tag", "workflow_dispatch", "refs/tags/v4.0.0", "v4.0.0", True),
            ("dispatch from a branch", "workflow_dispatch", "refs/heads/main", "v4.0.0", False),
            ("dispatch at another tag", "workflow_dispatch", "refs/tags/v3.5.1", "v4.0.0", False),
            ("dispatch with no tag", "workflow_dispatch", "refs/tags/v4.0.0", "", False),
        ]:
            env = {"PATH": os.environ["PATH"], "GITHUB_EVENT_NAME": name, "GITHUB_REF": ref,
                   "GITHUB_SHA": event, "TAG": tag}
            run = subprocess.run(["bash", "-c", body], env=env, capture_output=True, text=True)
            if ok:
                self.assertEqual((run.returncode, run.stdout), (0, f"release commit: {event}\n"), f"{label}: {run.stderr}")
            else:
                self.assertNotEqual(run.returncode, 0, f"{label} must be refused")
                self.assertIn("::error::", run.stdout, f"{label}: refused without saying why")

    def test_throwaway_runs_carry_the_release_tooling_python_suites(self):
        # A throwaway pull request skips `release-script-tests`, so without its
        # own run of the Python suites a workflow-wiring or release-script red
        # cannot show on one: the throwaway passes on cargo alone.
        throwaway = {
            name: body for name, body in jobs("ci.yml").items()
            if re.search(r"(?m)^    name: Tests \(throwaway\)$", body)
        }
        self.assertGreaterEqual(len(throwaway), 1, "ci.yml has no Tests (throwaway) job")
        for name in throwaway:
            text = "\n".join("\n".join(b) for b in steps("ci.yml", name))
            self.assertRegex(
                text, r"for suite in scripts/release/test_\*\.py; do",
                f"{name}: must run every scripts/release/test_*.py suite",
            )
            self.assertRegex(text, r'python3 "\$suite" \|\| \{ echo "::error::\$suite failed"; fail=1; \}')
            self.assertRegex(text, r'exit "\$fail"', f"{name}: a failed suite must fail the step")
            self.assertNotRegex(throwaway[name], r"(?m)^\s+continue-on-error:", f"{name}: must not swallow failures")

    def test_release_binaries_are_signed_and_verified_before_they_are_public(self):
        # OWASP ASI04: every release binary ships with an SBOM and a keyless
        # signature, verified before and after upload, and the release stays a
        # draft until what it serves has been verified.
        build = [c for b in steps("release.yml", "build") for c in joined(b)]
        self.assertTrue(any(re.search(r"\bcargo auditable build\b", c) for c in build), "W1: build without cargo auditable")
        self.assertFalse(any(re.search(r"\bcargo build\b", c) for c in build), "W1: a plain cargo build ships no crate list")

        blocks = steps("release.yml", "release")
        names = [b[0].strip() for b in blocks]

        def index(pattern):
            found = [i for i, b in enumerate(blocks) if any(re.search(pattern, c) for c in joined(b)) or re.search(pattern, b[0])]
            self.assertTrue(found, f"release job has no step matching {pattern}")
            return found[0]

        sign = index(r"scripts/release/sign-release-assets\.sh\b")
        create = index(r"Create Release")
        check = index(r"scripts/release/verify-release-assets\.sh\s+published\b")
        publish = index(r"gh release edit .*--draft=false")
        guard = index(r"Refuse to upload onto a published release")
        self.assertLess(guard, create, "an upload onto a published release must be refused first")
        self.assertTrue(
            any(re.search(r"(^|\s)scripts/release/refuse-published-release\.sh\b", c) for c in joined(blocks[guard])),
            "the published-release guard must run the fail-closed script",
        )
        self.assertRegex(
            jobs("release.yml")["release"],
            r"(?m)^    concurrency:\n      group: release-\$\{\{ needs\.verify\.outputs\.tag \}\}\n      cancel-in-progress: false$",
            "release jobs for one tag must run one at a time and never be cancelled",
        )
        self.assertLess(sign, create, "W2: signing must come before the release exists")
        self.assertLess(create, check, "W3: the draft must be verified after it is created")
        self.assertLess(check, publish, "W3: publish only after the draft is verified")
        # W8 (GH1941.SIGN.1): the release as published is downloaded and
        # verified again, so a change between the draft check and publication
        # fails the run instead of passing unseen.
        recheck = [
            i for i, b in enumerate(blocks)
            if i > publish and any(runs(c, VERIFY_ASSETS) for c in joined(b))
        ]
        self.assertTrue(recheck, "W8: the published release must be verified again after it is published")
        self.assertTrue(
            any(runs(c, GH_RELEASE_DOWNLOAD) for c in joined(blocks[recheck[0]])),
            "W8: the re-check must read what the release serves",
        )
        self.assertIn("set -euo pipefail", "\n".join(blocks[recheck[0]]), "W8: the re-check must stop on the first failure")
        self.assertNotRegex("\n".join(blocks[recheck[0]]), r"continue-on-error|if:\s*always\(\)", "W8: the re-check must not be skipped past")
        self.assertIn("draft: true", "\n".join(blocks[create]), "W3: the release must be created as a draft")
        for i in (sign, check, publish):
            text = "\n".join(blocks[i])
            self.assertNotRegex(text, r"continue-on-error|if:\s*always\(\)", f"W3: {names[i]} must not be skipped past")
        for i in (sign, check):
            self.assertIn("set -euo pipefail", "\n".join(blocks[i]), f"W2: {names[i]} must stop on the first failure")
        # W7: nothing after signing rewrites the signed checksum file.
        for block in blocks[sign + 1 :]:
            self.assertNotRegex("\n".join(joined(block)), r"SHA256SUMS\.txt\s*$|>\s*SHA256SUMS", "W7: SHA256SUMS.txt rewritten after signing")

        # W4: identity is the OIDC subject GitHub actually issues.
        release = jobs("release.yml")["release"]
        self.assertRegex(release, r"IDENTITY: https://github\.com/\$\{\{ github\.workflow_ref \}\}")
        # W5: OIDC is granted where it is used and nowhere else. The image
        # and registry jobs held it before release signing; the release job
        # and its rehearsal followed, then the chart publisher (MIK-7952).
        oidc = sorted(
            f"{wf}:{job}" for wf in ("release.yml", "ci.yml", "docker.yml")
            for job, body in jobs(wf).items() if re.search(r"(?m)^\s+id-token:\s*write\b", body)
        )
        self.assertEqual(
            oidc,
            sorted([
                "release.yml:release", "release.yml:npm-publish",
                "ci.yml:binary-signing-rehearsal", "ci.yml:docker-manifest", "ci.yml:publish-mcp-registry",
                "ci.yml:helm-chart-publish",
            ]),
            "W5: id-token: write outside its allow-list",
        )
        # W6: a dispatch runs at the tag it releases; the `resolve` guard,
        # which every job waits for, refuses any other ref (tested with it).
        self.assertIn("resolve", jobs("release.yml"), "W6: a branch dispatch would sign as the branch")

        # The rehearsal: dispatch only, draft only, always cleaned up.
        self.assertEqual(
            conjuncts(job_if("ci.yml", "binary-signing-rehearsal"))[0],
            "github.event_name == 'workflow_dispatch'",
        )
        rehearsal = jobs("ci.yml")["binary-signing-rehearsal"]
        self.assertRegex(rehearsal, r"gh release create .*--draft")
        self.assertRegex(rehearsal, r"DRAFT: rehearsal-binary-signing-\$\{\{ github\.run_id \}\}")
        self.assertRegex(rehearsal, r"(?s)if: always\(\)\s+env:.*?gh release delete \"\$DRAFT\"")
        # Every release target is rehearsed with cargo auditable before a tag:
        # the rehearsal matrix is the release matrix, and each leg checks that
        # its SBOM lists crates.
        def matrix(workflow, job):
            body = jobs(workflow)[job]
            m = re.search(r"(?ms)^ +include:\n(.*?)(?=^ {4}\S)", body)
            self.assertIsNotNone(m, f"{workflow} {job} has no matrix include")
            return [l.strip() for l in m.group(1).splitlines() if l.strip()]
        self.assertEqual(
            matrix("ci.yml", "binary-sbom-rehearsal"), matrix("release.yml", "build"),
            "the SBOM rehearsal must build exactly the release targets",
        )
        legs = "\n".join(c for b in steps("ci.yml", "binary-sbom-rehearsal") for c in joined(b))
        self.assertRegex(legs, r"\bcargo auditable build --release --target\b")
        self.assertRegex(legs, r"check_release_assets\.py\b.*--sbom-only")
        self.assertEqual(
            conjuncts(job_if("ci.yml", "binary-sbom-rehearsal"))[0],
            "github.event_name == 'workflow_dispatch'",
        )
        # The fail-closed tests block on every ref but a throwaway PR, whose
        # `Tests (throwaway)` job runs these same scripts/release/test_*.py suites.
        checks = jobs("ci.yml").get("release-signing-checks")
        self.assertIsNotNone(checks, "ci.yml has no release-signing-checks job")
        self.assertNotRegex(checks, r"(?m)^ {4}continue-on-error:")
        throwaway_only = (
            "${{ !(github.event_name == 'pull_request' && github.base_ref == 'docs/ranking-1-release-line' "
            "&& github.event.pull_request.head.repo.full_name == github.repository "
            "&& startsWith(github.head_ref, 'throwaway/')) }}"
        )
        self.assertIn(
            re.findall(r"(?m)^ {4}if:\s*(.*)$", checks), ([], [throwaway_only]),
            "release-signing-checks must run on every ref but throwaway PRs",
        )
        for script in ("test_check_release_assets.py", "test_sign_release_assets.py", "test_refuse_published_release.py"):
            self.assertIn(f"scripts/release/{script}", checks)
        self.assertIn("release-signing-checks", needs_of(jobs("ci.yml")["docker-build"]) or "")

    def test_the_release_restores_no_cache(self):
        # A cache restored into a release job is input nobody reviewed at the
        # tag: whatever an earlier run saved under a matching key is built,
        # signed and published with the release. Release jobs build cold.
        # Covers release.yml and every workflow it calls, whose jobs run in
        # the release's context. setup-node caches on its own when it finds a
        # package manager, so it must say it will not.
        release = WORKFLOWS / "release.yml"
        called = re.findall(r"""(?m)^    uses:\s*["']?\./\.github/workflows/([^"'\s#]+)""", release.read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(called),
            ["mrtr7b-full-burst.yml", "packaged-suite.yml", "task-sdk-recovery.yml"],
            "the called-workflow inventory changed",
        )
        found = []
        for wf in ["release.yml", *called]:
            for block in steps(wf):
                uses = " ".join(l for l in block if re.match(r"""^\s*(?:-\s+)?["']?uses["']?\s*:""", l))
                label = f"{wf}: {block[0].strip()}"
                if re.search(r"actions/cache(?:/\w+)?@|Swatinem/rust-cache@", uses):
                    found.append(f"{label} restores a cache")
                if artifact_keys(block, ("cache",)):
                    found.append(f"{label} sets cache:")
                flags = [v.lower() for v in artifact_keys(block, ("package-manager-cache",))]
                if "actions/setup-node@" in uses and (not flags or set(flags) != {"false"}):
                    found.append(f"{label} leaves package-manager-cache on")
        self.assertEqual(found, [], "a release job restores a cache")

    def test_the_release_runs_the_full_burst_every_pr_job_skips(self):
        # MIK-7534/MIK-7479: every per-PR test job skips mik_7479_full_burst,
        # so the release is where it must have passed on the tagged revision.
        on = "\n".join(live_lines("mrtr7b-full-burst.yml"))
        trigger = on[on.index("\non:") : on.index("\njobs:")]
        self.assertRegex(trigger, r"(?m)^  workflow_call:", "the release cannot call the full burst")
        ran = [c for b in steps("mrtr7b-full-burst.yml", "full-burst") for c in joined(b)]
        self.assertTrue(any("mik_7479_full_burst" in c for c in ran), ran)
        release_jobs = jobs("release.yml")
        self.assertIn("uses: ./.github/workflows/mrtr7b-full-burst.yml", release_jobs.get("mrtr7b-full-burst", ""))
        self.assertIn("mrtr7b-full-burst", needs_of(release_jobs["verify"]) or "", "verify must wait for the full burst")

    def test_windows_skips_the_full_burst_and_keeps_its_property(self):
        # MIK-7644: 1,026 calls miss the full burst's deadline on the Windows
        # runner, so the Windows suite skips it by name as `test` does. The
        # property it checks still runs there at the per-PR size: `--skip`
        # matches substrings, so no Windows skip may occur in that test's name.
        suite = [
            c for b in steps("ci.yml", "windows-check") for c in joined(b)
            if re.search(r"\bcargo test --all-features --tests\b", c)
        ]
        self.assertEqual(len(suite), 1, suite)
        skips = re.findall(r"--skip\s+(\S+)", suite[0])
        self.assertIn("mik_7479_full_burst", skips, "Windows must skip the full burst by name")
        per_pr = "ac_mrtr_7b_every_call_reaches_one_terminal_frame"
        self.assertFalse([s for s in skips if s in per_pr], f"a Windows skip also drops {per_pr}")
        ledger = (pathlib.Path(__file__).parents[2] / "tests" / "mik_7479_mrtr7b_ledger.rs").read_text(encoding="utf-8")
        self.assertIn(f"async fn {per_pr}()", ledger)

    def test_a_job_handoff_is_kept_as_long_as_the_repository_allows(self):
        # An artifact a later job of the same run downloads is that job's only
        # input. Once it expires, re-running that job publishes nothing
        # (release.yml copies whatever it finds) or fails its download, and the
        # only recovery is a rebuild. So each handoff is kept for exactly the
        # repository's artifact retention setting, HANDOFF_RETENTION_DAYS:
        # shorter loses re-run days for nothing, and longer is clamped to the
        # setting without a word, so the workflow would promise a window it
        # does not have. The setting is not readable from a unit test; if it
        # changes, change the constant and RELEASING.md rule 4 with it. The key
        # must be written out: an unset one inherits the setting silently.
        handoffs = []
        for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
            blocks = steps(path.name)
            downloads = [
                b for b in blocks
                if any(re.match(r"^\s*(- )?uses:\s*actions/download-artifact@", l) for l in b)
            ]
            if not downloads:
                continue
            # One selector per download, as the action reads it: `name:` wins,
            # then `pattern:`; with neither it takes every artifact of the run.
            wanted = [
                (artifact_keys(block, ("name",)) or artifact_keys(block, ("pattern",)) or ["*"])[0]
                for block in downloads
            ]
            for block in blocks:
                if not any(re.match(r"^\s*(- )?uses:\s*actions/upload-artifact@", l) for l in block):
                    continue
                # An upload without `name:` is stored as `artifact`.
                name = (artifact_keys(block, ("name",)) or ["artifact"])[0]
                if not any(fnmatch.fnmatchcase(name, k) for k in wanted):
                    continue
                days = artifact_keys(block, ("retention-days",))
                handoffs.append((path.name, block[0].strip(), days))
        # release.yml's binaries, ci.yml's and docker.yml's image digests. One
        # missing means the scan stopped seeing a handoff, not that it went
        # away; a count across all workflows would let a new one elsewhere
        # hide the loss.
        for workflow in ("release.yml", "ci.yml", "docker.yml"):
            self.assertIn(workflow, {h[0] for h in handoffs}, handoffs)
        wrong = [
            f"{workflow}: {step} retention-days {days or 'unset'}"
            for workflow, step, days in handoffs
            if days != [str(HANDOFF_RETENTION_DAYS)]
        ]
        self.assertEqual(
            wrong, [], f"handoff retention is not the repository's {HANDOFF_RETENTION_DAYS} days"
        )


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


class StepAttribution(unittest.TestCase):
    """A step belongs to the job it sits in, even when another job has its twin (#570).

    Two jobs carrying a byte-identical step is the real shape here: docker-build
    and docker-manifest run the same tag-gate step. Attribution by text gives
    the step to whichever job's body happens to contain the text, so the fixture
    moves the only `id: meta` gate between two jobs and checks it follows.
    """

    TWIN = (
        "      - name: Extract tag\n"
        "        id: meta\n"
        "        run: python3 scripts/release/check_tag_manifest.py\n"
    )

    def workflow(self, first, second):
        text = (
            "on: push\njobs:\n"
            f"  first:\n    runs-on: x\n    steps:\n{first}"
            "      - run: echo first\n"
            f"  second:\n    runs-on: x\n    steps:\n{second}"
            "      - run: echo second\n"
        )
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        (pathlib.Path(tmp.name) / "fixture.yml").write_text(text, encoding="utf-8")
        patch = mock.patch.dict(globals(), {"WORKFLOWS": pathlib.Path(tmp.name)})
        patch.start()
        self.addCleanup(patch.stop)

    def test_identical_steps_are_each_their_own_jobs(self):
        self.workflow(self.TWIN, self.TWIN)
        self.assertEqual(len(gate_steps("fixture.yml", "first")), 1)
        self.assertEqual(len(gate_steps("fixture.yml", "second")), 1)

    def test_a_gate_in_another_job_does_not_answer_for_this_one(self):
        self.workflow(self.TWIN, "")
        self.assertEqual(len(gate_steps("fixture.yml", "first")), 1)
        self.assertEqual(gate_steps("fixture.yml", "second"), [])

    def test_a_gate_step_without_the_meta_id_does_not_count(self):
        self.workflow(self.TWIN.replace("        id: meta\n", ""), "")
        self.assertEqual(gate_steps("fixture.yml", "first"), [])


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

    def test_the_variant_installs_what_a_deployment_declares(self):
        stage = self.variant_stage()
        self.assertRegex(
            stage,
            r"COPY[^\n]*docker/entrypoint-full\.sh",
            "the variant does not copy the entrypoint into the image",
        )
        self.assertRegex(
            stage,
            r"ENTRYPOINT \[[^\]]*entrypoint-full\.sh",
            "the variant does not run its own entrypoint",
        )
        script = (
            pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"
        ).read_text()
        self.assertIn(
            "EXTRA_APT_PACKAGES",
            script,
            "the entrypoint ignores the packages a deployment declares",
        )
        self.assertRegex(
            script,
            r"apt-get install",
            "the entrypoint never installs anything",
        )
        # Installing needs root, but the image must not *default* to it: a
        # deployment asks for root itself, and the entrypoint drops back.
        self.assertEqual(
            re.findall(r"(?m)^USER\s+(\S+)\s*$", stage)[-1],
            "gateway",
            "the variant leaves the image declaring root as its user",
        )

    def test_a_deployment_gets_its_startup_steps_before_the_gateway(self):
        script = (
            pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"
        ).read_text()
        self.assertRegex(
            script,
            r"/docker-entrypoint\.d",
            "the entrypoint has no drop-in directory for a deployment's steps",
        )
        self.assertRegex(
            script,
            r"\.envsh\)\s*\.\s*\"\$f\"|\.\s*\"\$f\"",
            "the entrypoint does not source an envsh drop-in",
        )
        self.assertRegex(
            script,
            r"\[ ! -x \"\$f\" \]",
            "the entrypoint runs a drop-in that arrived without the exec bit",
        )
        run = script.index("run_dropins\n")
        drop = script.index("setpriv --reuid=gateway")
        self.assertLess(
            run,
            drop,
            "the entrypoint drops privileges before a deployment's steps run, "
            "so a step that needs root would fail",
        )
        self.assertEqual(
            script.count("run_dropins\n"),
            2,
            "a path through the entrypoint skips the drop-ins: root and "
            "non-root each call them once",
        )

    def test_the_variant_keeps_the_default_invocation(self):
        # An ENTRYPOINT declared in the stage resets the CMD the base stage set.
        # The variant's own invocation carries no arguments, so a variant
        # without it execs a gateway with no config that starts and never exits.
        self.assertRegex(
            self.variant_stage(),
            r'(?m)^CMD \["--config", "/config\.yaml"\]',
            "the variant declares an ENTRYPOINT without the base stage's CMD, "
            "so its default invocation is not the image's",
        )

    def test_a_startup_that_cannot_finish_stops_the_container(self):
        script = self.entrypoint_script()
        self.assertRegex(
            script,
            r"apt-get update[^\n]*&&[^\n]*apt-get install",
            "the entrypoint does not run the update and install as one chain",
        )
        # `set -e` does not end the script on a failing link of an `&&` list, so
        # the chain's status has to be carried to an explicit exit.
        self.assertRegex(
            script,
            r"install failed[^\n]*\n\s*exit 1",
            "the entrypoint does not stop the container when the install fails",
        )
        self.assertRegex(
            script,
            r"DEBIAN_FRONTEND=noninteractive",
            "the entrypoint lets apt prompt, which no container can answer",
        )
        self.assertRegex(
            script,
            r"timeout -k \d+ \"\$INSTALL_TIMEOUT\"",
            "the entrypoint leaves the install unbounded",
        )
        # PID 1 ignores SIGTERM with no handler installed, so without a trap a
        # stop during the install waits out the grace period and SIGKILLs.
        self.assertRegex(
            script,
            r"trap \w+ TERM",
            "the entrypoint does not handle a stop while the install runs",
        )

    def test_the_privilege_drop_names_the_user_it_drops_to(self):
        script = self.entrypoint_script()
        # A numeric group id is whatever this distribution put in it, and Debian
        # puts an unrelated `users` there.
        self.assertRegex(
            script,
            r"setpriv --reuid=gateway --regid=gateway --init-groups",
            "the entrypoint drops to a fixed id rather than the image's user",
        )
        self.assertNotRegex(
            script,
            r"--groups=\d",
            "the entrypoint drops to a fixed group id",
        )

    def test_the_lists_cleanup_removes_the_directory(self):
        script = self.entrypoint_script()
        self.assertRegex(
            script,
            r"(?m)^\s*rm -rf /var/lib/apt/lists\s*$",
            "the entrypoint leaves the apt indexes it fetched in the image",
        )
        self.assertNotRegex(
            script,
            r"/var/lib/apt/lists/\*",
            "the cleanup globs a directory whose indexes stay while globbing is "
            "off in that shell",
        )

    def entrypoint_script(self):
        return (
            pathlib.Path(__file__).parents[2] / "docker" / "entrypoint-full.sh"
        ).read_text()

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
        for name in ("npm", "brace-expansion", "ip-address", "tar", "undici"):
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

    def test_the_gate_exercises_the_root_path(self):
        # Every other run of this image is the image's own user, so the root
        # path -- install, steps as root, drop, exec -- is untested without a
        # leg of its own.
        for probe, label in (
            (r"\-\-user root", "the root path"),
            (r"EXTRA_APT_PACKAGES=iproute2", "a declared package"),
            (r"/docker-entrypoint\.d", "a mounted startup step"),
        ):
            self.assertRegex(
                self.body, probe, f"the variant gate never exercises {label}"
            )
        # The two failures a deployment has to hear about: a step that exits
        # non-zero, and an install that cannot complete.
        self.assertRegex(
            self.body,
            r"(?s)exit 7.*?FAIL_LOG|FAIL_LOG.*?exit 7",
            "the variant gate never runs a startup step that fails",
        )
        self.assertRegex(
            self.body,
            r"BAD_LOG",
            "the variant gate never runs an install that cannot complete",
        )
        # A stop during startup is the case PID 1 hangs on.
        self.assertRegex(
            self.body,
            r"docker stop -t \d+",
            "the variant gate never stops the image while startup is running",
        )
        self.assertRegex(
            self.body,
            r"proc/1/status",
            "the variant gate never checks which user the gateway runs as",
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


# The read-only rehearsal verify (docs/design/2026-09-26-rehearsal-readonly-verify.md).
# A rehearsal cannot sign (a public Rekor entry per dispatch), so it verifies a
# release that is already signed, with the release step's own command.
RELEASE_VERIFY = "Verify the release signature + SBOM attestation"
REHEARSAL_VERIFY = "Rehearse the release verify against a pinned signed release"
TAG_CONJUNCTS = ("github.event_name == 'push'", "startsWith(github.ref, 'refs/tags/v')")
REHEARSAL_CONDITION = (
    "github.event_name == 'workflow_dispatch' && "
    "(inputs.rehearse_manifest == true || inputs.rehearse_manifest == 'true')"
)
DIGEST_KEYS = ("LIST", "AMD64", "ARM64", "LIST_FULL", "AMD64_FULL", "ARM64_FULL")
PINNED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IDENTITY = re.compile(
    r"^https://github\.com/MikkoParkkola/mcp-gateway/\.github/workflows/ci\.yml"
    r"@refs/tags/v[0-9][0-9A-Za-z.-]*$"
)
# What a read-only verify may never run, however it is guarded.
WRITES = (
    re.compile(r"cosign\s+(?:sign|attest)(?![-\w])"),
    re.compile(r"\bsyft\s"),
    IMAGETOOLS_CREATE,
    re.compile(r"\$\{?VERSION\b"),
)


def step_named(job, name):
    """The one step of `job` whose `name:` is `name`, or None."""
    for block in steps("ci.yml", job):
        for line in block:
            match = re.match(r"^\s+(?:- )?name:\s*(.*)$", line)
            if match and match.group(1).strip() == name:
                return block
    return None


def condition_of(block):
    """A step's `if:` value, a folded `if: >-` joined, whitespace-normalised."""
    for index, line in enumerate(block):
        match = re.match(r"^(\s*)(?:- )?if:\s*(.*)$", line)
        if match:
            value = match.group(2)
            if re.match(r"^[>|][-+]?$", value.strip()):
                indent = len(match.group(1))
                value = " ".join(
                    l.strip()
                    for l in itertools.takewhile(
                        lambda l: len(l) - len(l.lstrip()) > indent, block[index + 1 :]
                    )
                )
            return " ".join(value.split())
    return None


def run_body(block):
    """A step's `run:` script, continuations joined."""
    return [c for c in joined(block) if c.startswith("run:")]


def cosign_calls(block):
    return [
        piece
        for command in joined(block)
        for piece in segments(shell(command))
        if COSIGN_ANY.match(piece)
    ]


def timeout_of(block):
    for line in step_props(block):
        match = re.match(r"^timeout-minutes:\s*(\d+)\s*$", line)
        if match:
            return int(match.group(1))
    return None


def env_map(block):
    found = {}
    for entry in env_of(block):
        key, _, value = entry.partition(":")
        found[key.strip()] = value.strip().strip("'\"")
    return found


def readonly_verify_refusals(block):
    """Why `block` is not the design's E1 read-only verify; empty if it is."""
    refusals = []
    pieces = [p for c in joined(block) for p in segments(shell(c))]
    if not any(COSIGN_VERIFY.match(p) for p in pieces):
        refusals.append("runs no cosign verify")
    for piece in pieces:
        if any(w.search(piece) for w in WRITES):
            refusals.append(f"writes: {piece}")
    env = env_map(block)
    if set(env) != set(DIGEST_KEYS) | {"IDENTITY"}:
        refusals.append(f"env keys are not the release verify's: {sorted(env)}")
    for key, value in env.items():
        if "${{" in value:
            refusals.append(f"{key} is derived: {value}")
    for key in DIGEST_KEYS:
        if not PINNED_DIGEST.match(env.get(key, "")):
            refusals.append(f"{key} is not a pinned digest: {env.get(key)}")
    if not PINNED_IDENTITY.match(env.get("IDENTITY", "")):
        refusals.append(f"IDENTITY is not a literal tag identity: {env.get('IDENTITY')}")
    words = " ".join(f'"${{{k}}}"' for k in DIGEST_KEYS)
    loops = [p for p in pieces if re.search(r"\bfor\s+d\s+in\b", p)]
    if not loops or any(not p.rstrip().endswith(f"in {words}") for p in loops):
        refusals.append(f"for-list is not exactly {words}: {loops}")
    for piece in pieces:
        if re.match(rf"^(?:export\s+|local\s+|readonly\s+)?(?:{'|'.join(DIGEST_KEYS)}|IDENTITY)=", piece):
            refusals.append(f"body reassigns a pinned key: {piece}")
    # An allowlist, not a blocklist: every command the body runs is one the
    # release verify runs. `cosign attach`, `docker push` or a new pusher are
    # refused without anyone having to name them first.
    body = pieces[pieces.index("run:") + 1 :] if "run:" in pieces else []
    if not body:
        refusals.append("no run body")
    issuer = r"--certificate-oidc-issuer 'https://token\.actions\.githubusercontent\.com'"
    allowed = (
        re.compile(r"^set -euo pipefail$"),
        re.compile(r"^IMAGE=ghcr\.io/mikkoparkkola/mcp-gateway$"),
        re.compile(rf"^for d in {re.escape(words)}$"),
        re.compile(r"^(?:do|done)$"),
        re.compile(
            r"^cosign (?:verify|verify-attestation --type spdxjson) "
            rf'--certificate-identity "\$\{{IDENTITY\}}" {issuer} '
            r'"\$\{IMAGE\}@\$\{d\}" > /dev/null$'
        ),
    )
    for piece in body:
        if "${{" in piece or not any(a.match(piece) for a in allowed):
            refusals.append(f"runs a command the release verify does not: {piece}")
    return refusals


class RehearsalVerify(unittest.TestCase):
    def setUp(self):
        self.release = step_named("docker-manifest", RELEASE_VERIFY)
        self.rehearsal = step_named("docker-manifest", REHEARSAL_VERIFY)
        self.assertIsNotNone(self.release, f"ci.yml: no step named {RELEASE_VERIFY!r}")

    def test_t1_a_rehearsal_step_runs_the_verify(self):
        self.assertIsNotNone(self.rehearsal, f"ci.yml: no step named {REHEARSAL_VERIFY!r}")
        calls = cosign_calls(self.rehearsal)
        self.assertTrue(any(re.match(r"cosign\s+verify\s", c) for c in calls), calls)
        self.assertTrue(any(c.startswith("cosign verify-attestation") for c in calls), calls)

    def test_t2_the_rehearsal_runs_the_release_command_verbatim(self):
        # Same body, same cosign calls in the same order, same timeout: only
        # the env differs, so a verify-step regression shows on a rehearsal.
        self.assertIsNotNone(self.rehearsal, f"ci.yml: no step named {REHEARSAL_VERIFY!r}")
        self.assertEqual(run_body(self.rehearsal), run_body(self.release))
        self.assertEqual(cosign_calls(self.rehearsal), cosign_calls(self.release))
        self.assertIsNotNone(timeout_of(self.release))
        self.assertEqual(timeout_of(self.rehearsal), timeout_of(self.release))

    def test_t3_t9_the_rehearsal_verifies_only_a_pinned_signed_release(self):
        self.assertIsNotNone(self.rehearsal, f"ci.yml: no step named {REHEARSAL_VERIFY!r}")
        self.assertEqual(readonly_verify_refusals(self.rehearsal), [])

    def test_t4_the_exemption_refuses_a_step_that_writes(self):
        # Fixtures, so the detector is proved before the live step exists.
        pinned = [f"          {k}: sha256:{'a' * 64}" for k in DIGEST_KEYS]
        base = [
            f"      - name: {REHEARSAL_VERIFY}",
            f"        if: {REHEARSAL_CONDITION}",
            "        env:",
            *pinned,
            "          IDENTITY: https://github.com/MikkoParkkola/mcp-gateway/.github/workflows/ci.yml@refs/tags/v4.0.0-beta.2",
            "        run: |",
            "          set -euo pipefail",
            "          IMAGE=ghcr.io/mikkoparkkola/mcp-gateway",
            '          for d in "${LIST}" "${AMD64}" "${ARM64}" "${LIST_FULL}" "${AMD64_FULL}" "${ARM64_FULL}"; do',
            '            cosign verify --certificate-identity "${IDENTITY}" '
            "--certificate-oidc-issuer 'https://token.actions.githubusercontent.com' "
            '"${IMAGE}@${d}" > /dev/null',
            "          done",
        ]
        self.assertEqual(readonly_verify_refusals(base), [])
        for extra in (
            '            cosign sign --yes "${IMAGE}@${d}"',
            '            cosign attest --yes --predicate x "${IMAGE}@${d}"',
            '            syft "${IMAGE}@${d}" -o spdx-json > sbom.json',
            '            docker buildx imagetools create --tag "${IMAGE}:${VERSION}" "${IMAGE}@${d}"',
            '            LIST="$(cat digests/amd64)"',
            '            cosign attach sbom --sbom x "${IMAGE}@${d}"',
            '            cosign copy "${IMAGE}@${d}" "${IMAGE}:4.0.0"',
            '            docker push "${IMAGE}:rehearsal"',
            '            oras push "${IMAGE}:x" f',
            '            echo "${{ github.ref }}"',
        ):
            block = base[:-1] + [extra, base[-1]]
            self.assertTrue(readonly_verify_refusals(block), f"admitted: {extra}")
        derived = [
            line.replace(f"sha256:{'a' * 64}", "${{ steps.list.outputs.list }}")
            if line.strip().startswith("LIST:")
            else line
            for line in base
        ]
        self.assertTrue(readonly_verify_refusals(derived), "admitted a derived subject")

    def test_t7_the_rehearsal_step_runs_on_a_rehearsal_only(self):
        self.assertIsNotNone(self.rehearsal, f"ci.yml: no step named {REHEARSAL_VERIFY!r}")
        self.assertEqual(condition_of(self.rehearsal), REHEARSAL_CONDITION)

    def test_t6_only_the_cosign_installer_is_widened_to_a_rehearsal(self):
        # E2: exactly tag-push OR rehearsal, on one line. syft stays tag-only.
        installer = step_named("docker-manifest", "Install cosign")
        self.assertIsNotNone(installer)
        self.assertEqual(
            condition_of(installer),
            f"({' && '.join(TAG_CONJUNCTS)}) || ({REHEARSAL_CONDITION})",
        )
        syft = step_named("docker-manifest", "Install syft (SBOM)")
        self.assertEqual(conjuncts(condition_of(syft)), list(TAG_CONJUNCTS))

    def test_t8_the_rehearsal_step_runs_after_cosign_is_installed(self):
        names = []
        for block in steps("ci.yml", "docker-manifest"):
            for line in block:
                match = re.match(r"^\s+(?:- )?name:\s*(.*)$", line)
                if match:
                    names.append(match.group(1).strip())
                    break
        self.assertIn(REHEARSAL_VERIFY, names)
        at = names.index(REHEARSAL_VERIFY)
        self.assertLess(names.index("Install cosign"), at)
        self.assertLess(at, names.index("Install syft (SBOM)"))


if __name__ == "__main__":
    unittest.main()
