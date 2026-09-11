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
COSIGN_VERIFY = re.compile(r"\bcosign verify(-attestation)?(?![-\w])")


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


def uncommented(line):
    """`line` with a trailing YAML comment removed, quoting respected.

    A `#` opens a comment only outside quotes and after whitespace, which is
    what YAML itself requires. Both directions matter: a trailing comment
    naming a command satisfies an assertion the executable part no longer
    does, and a harmless `# v3` pin comment makes an exact-value assertion
    fail on a step that is wired correctly.
    """
    quote, escaped = None, False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            # Only a double-quoted scalar has escapes; inside single quotes a
            # backslash is literal, so treating one as an escape there would
            # swallow the closing quote and mangle the rest of the line.
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line


def live_lines(workflow):
    """A workflow's executable lines, comments dropped.

    Every assertion here is textual, so a rule commented out rather than
    deleted would still satisfy an `assertIn` against the raw file. That is
    the shape a regression takes: a step disabled during debugging and
    committed. Reading only executable lines makes the mutation fail.
    """
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    return [line for line in (uncommented(raw) for raw in text.splitlines()) if line.strip()]


def joined(lines):
    """`lines` with `\\` continuations joined into one command each.

    Assertions about a cosign invocation have to see the whole command. Read
    line by line, a flag on a continuation line looks like a separate
    statement, and a check for it can be satisfied by a different command
    further down the file.
    """
    commands, buffer = [], ""
    for line in lines:
        stripped = line.strip()
        buffer = f"{buffer} {stripped}".strip() if buffer else stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].strip()
            continue
        commands.append(buffer)
        buffer = ""
    if buffer:
        commands.append(buffer)
    return commands


def commands(workflow):
    """A workflow's executable lines as whole commands."""
    return joined(live_lines(workflow))


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
        if re.match(r"^\s*steps:$", line):
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
                invocation = re.compile(
                    r"(?:^(?:run: )?|&&\s*|\|\|\s*|;\s*|\|\s*|\bthen\s+|\bdo\s+)"
                    rf"(?:python3?|uv run)\s+scripts/release/{re.escape(script)}"
                )
                self.assertTrue(
                    [c for c in live if invocation.search(c)],
                    f"{workflow} never runs scripts/release/{script}",
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

        def header(workflow, job):
            # The job's own keys only. A step-level `if:` carrying the same
            # clause skips one step while the job — and its other steps — run
            # anyway, so a search of the whole body passes a guard that was
            # moved rather than kept.
            lines = jobs(workflow)[job].splitlines()
            for index, line in enumerate(lines):
                if re.match(r"^\s*steps:$", line):
                    lines = lines[:index]
                    break
            return " ".join(" ".join(lines).split())

        def skip(job):
            # A condition may legitimately carry other clauses — the tag-ref
            # guard does — so a prefix is allowed, but only one holding no
            # colon: that keeps the match inside this `if:` instead of letting
            # it drift into a later key.
            return (
                r"if: (?:[>|][-+]?\s)?[^:]*?needs\." + job + r"\.outputs\.is_prerelease != 'true'"
            )

        for workflow, job, gate in (
            ("release.yml", "homebrew-update", "verify"),
            ("docker.yml", "publish-mcp-registry", "build"),
        ):
            own = header(workflow, job)
            self.assertRegex(own, skip(gate))
            # A disjunction makes the guard optional: `!= 'true' || true`
            # matches the clause and skips nothing.
            self.assertNotIn("||", own, f"{workflow} {job}: its skip is not mandatory")
        self.assertRegex(
            condition("ci.yml", "docker"),
            r"is_prerelease != 'true' && 'ghcr\.io/[^']*:latest'",
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
                pattern = rf"\bcosign {re.escape(verb)}(?![-\w])"
                found = [c for c in live if re.search(pattern, c)]
                self.assertTrue(found, f"{workflow} never runs cosign {verb}")
                for command in found:
                    # Sign and verify the digest the build step produced, not a
                    # tag: a tag is a mutable pointer the other publisher can
                    # move, and a signature is over a digest.
                    # The closing quote is optional — an unquoted reference is
                    # the same reference, and failing it would be a red CI on a
                    # reformat.
                    self.assertRegex(
                        command, r"@\$\{DIGEST\}[\"']?(?:\s|$)", f"{workflow}: {command}"
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
                block = joined(block)
                if not any(re.search(r"\bcosign \w", c) for c in block):
                    continue
                signing += 1
                name = block[0]
                self.assertTrue(
                    any(digest.match(c) for c in block),
                    f"{workflow}: {name} runs cosign without binding DIGEST to the build digest",
                )
                # The env binding is only worth what the shell leaves of it: a
                # `DIGEST=` assignment in the run body rebinds the name the
                # cosign command below expands, and the env check still passes.
                for command in block:
                    self.assertNotRegex(
                        command,
                        r"(?:^|[;&|]\s*|\bexport\s+)DIGEST=",
                        f"{workflow}: {name} reassigns DIGEST in its shell",
                    )
                if not any(COSIGN_VERIFY.search(c) for c in block):
                    continue
                # An identity is what makes a signature mean something: an
                # unpinned verify, or one relaxed to a regexp, accepts a
                # signature from any workflow that can mint an OIDC token.
                self.assertTrue(
                    any(identity.match(c) for c in block),
                    f"{workflow}: {name} verifies without pinning this workflow's identity",
                )
                for command in block:
                    if COSIGN_VERIFY.search(command):
                        self.assertIn(
                            '--certificate-identity "${IDENTITY}"',
                            command,
                            f"{workflow}: {command}",
                        )
            # Non-vacuity: if the step scan found nothing, the per-step
            # assertions above never ran and the whole loop is decoration.
            self.assertTrue(signing, f"{workflow}: no step containing a cosign command was read")

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
            r"^(?:[A-Z][A-Z0-9_]*: [\"']?\$\{\{\s*inputs\.tag\s*\}\}[\"']?"
            r"|if: (?:[>|][-+]?\s)?\$\{\{ [^}]*inputs\.tag[^}]*\}\})$"
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
                        self.assertNotIn("inputs.tag", raw_line, raw_line)
                    continue  # a folded `if:` is evaluated, never executed
                block, kind = None, None
            folded = re.match(r"^(?:- )?(run|if): *[|>]", stripped)
            if folded:
                block, kind = depth, folded.group(1)
                continue
            line = uncommented(raw_line).strip()
            if "inputs.tag" not in line:
                continue
            self.assertRegex(line, permitted, raw_line)


if __name__ == "__main__":
    unittest.main()
