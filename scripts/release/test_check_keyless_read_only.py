# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for check_keyless_read_only.py (MIK-7752 AC3): a read-only tool the
installed config would refuse without an idempotency key must fail the check,
and so must a catalog that did not enumerate every enabled backend."""

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "check_keyless_read_only", pathlib.Path(__file__).with_name("check_keyless_read_only.py")
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

READ = {"name": "search", "annotations": {"readOnlyHint": True}}
WRITE = {"name": "write", "annotations": {"readOnlyHint": False}}
CATALOG = {"vault": [READ, WRITE]}


def config(mode=None, listed=(), backends=("vault",), disabled=()):
    cfg = {"backends": {b: {"command": "x"} for b in backends}}
    for b in disabled:
        cfg["backends"][b] = {"command": "x", "enabled": False}
    if mode:
        cfg["server"] = {"idempotency_key": mode}
    if listed:
        cfg["idempotency"] = {"read_only_tools": [{"server": s, "tool": t} for s, t in listed]}
    return cfg


def found(cfg, catalog=CATALOG, mode="declared"):
    return mod.problems(cfg, catalog, mode)[0]


# The env layer is an input under test: no ambient value may reach a case.
@mock.patch.dict("os.environ", {}, clear=True)
class KeylessReadOnly(unittest.TestCase):
    def test_optional_mode_admits_every_tool(self):  # T1: today's installed config
        self.assertEqual(found(config()), [])
        self.assertEqual(found(config("optional")), [])

    def test_required_refuses_an_unlisted_read_only_tool(self):  # T2: the MIK-7752 defect
        self.assertEqual(found(config("required")),
                         ["vault:search: read-only tool refused without a key (required)"])

    def test_required_admits_a_listed_read_only_tool(self):  # T3
        self.assertEqual(found(config("required", listed=[("vault", "search")])), [])

    def test_listing_is_exact_server_and_tool(self):  # T4: no cross-server match
        self.assertEqual(len(found(config("required", listed=[("other", "search")]))), 1)

    def test_forced_required_grades_an_optional_config(self):  # T5: the required-mode case
        self.assertEqual(len(found(config(), mode="required")), 1)
        self.assertEqual(found(config(listed=[("vault", "search")]), mode="required"), [])

    def test_a_write_tool_refused_keyless_is_not_a_finding(self):  # T6: MIK-7216 stays
        self.assertEqual(found(config("required", listed=[("vault", "search")]),
                               {"vault": [READ, WRITE, {"name": "bare"}]}), [])

    def test_an_enabled_backend_missing_from_the_catalog_fails(self):  # T7
        self.assertEqual(found(config(backends=("vault", "linear"))),
                         ["linear: enabled backend not enumerated (listing failed or absent)"])
        # Listed with no tools (a prompt-only backend) is enumerated.
        self.assertEqual(found(config(backends=("vault", "linear")),
                               {"vault": [READ], "linear": []}), [])

    def test_a_disabled_backend_need_not_be_enumerated(self):  # T8
        self.assertEqual(found(config(disabled=("surreal",))), [])

    def test_an_empty_catalog_fails(self):  # T9: cannot pass by enumerating nothing
        self.assertIn("catalog has no tools: nothing was enumerated", found(config(backends=()), {}))

    def test_an_env_override_sets_the_declared_mode(self):  # T11
        with tempfile.TemporaryDirectory() as tmp:
            env = pathlib.Path(tmp) / "secrets.env"
            env.write_text("OTHER=1\nexport MCP_GATEWAY_SERVER__IDEMPOTENCY_KEY='required'\n")
            override = mod.env_override({"env_files": [str(env)]}, [])
            self.assertEqual(override, "required")
            self.assertEqual(len(mod.problems(config("optional"), CATALOG, "declared", override)[0]), 1)
            self.assertEqual(mod.env_override({}, [env]), "required")
        self.assertIsNone(mod.env_override({"env_files": ["/nonexistent"]}, []))

    def test_config_env_files_win_over_the_process_layer(self):  # T12: EnvOverlay::resolve
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "a.env").write_text("MCP_GATEWAY_SERVER__IDEMPOTENCY_KEY=required\n")
            (d / "b.env").write_text("MCP_GATEWAY_SERVER__IDEMPOTENCY_KEY=optional\n")
            with mock.patch.dict("os.environ", {mod.ENV_KEY: "optional"}):
                self.assertEqual(mod.env_override({"env_files": [str(d / "a.env")]}, [d / "b.env"]), "required")
                self.assertEqual(mod.env_override({}, [d / "a.env"]), "required")
                self.assertEqual(mod.env_override({}, []), "optional")
                # Later config env file wins.
                self.assertEqual(mod.env_override({"env_files": [str(d / "a.env"), str(d / "b.env")]}, []),
                                 "optional")

    def test_env_lines_it_cannot_model_fail_closed(self):  # T13
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "ok.env").write_text("# MCP_GATEWAY_IDEMPOTENCY__X=1\nMCP_GATEWAY_SERVER__IDEMPOTENCY_KEY=\"required\" # rollout\n")
            self.assertEqual(mod.env_override({}, [d / "ok.env"]), "required")
            (d / "lower.env").write_text("MCP_GATEWAY_server__idempotency_key=required\n")
            self.assertEqual(mod.env_override({}, [d / "lower.env"]), "required")
            for text in ("MCP_GATEWAY_SERVER__IDEMPOTENCY_KEY=\n",
                         "export\tMCP_GATEWAY_SERVER__IDEMPOTENCY_KEY=${MODE}\n",
                         "MCP_GATEWAY_IDEMPOTENCY__READ_ONLY_TOOLS=[]\n",
                         "MCP_GATEWAY_server__idempotency_key=${MODE}\n",
                         "MCP_GATEWAY_ENV_FILES=[/x.env]\n",
                         "HOME=/elsewhere\n",
                         "mcp_gateway_server__idempotency_key=optional\n"):
                (d / "bad.env").write_text(text)
                with self.assertRaises(mod.Unverifiable, msg=text):
                    mod.env_override({"env_files": [str(d / "bad.env")]}, [])
        with mock.patch.dict("os.environ", {"MCP_GATEWAY_IDEMPOTENCY__READ_ONLY_TOOLS": "[]"}):
            with self.assertRaises(mod.Unverifiable):
                mod.env_override({}, [])

    def test_a_filtering_default_profile_fails(self):  # T14
        full = {"default_routing_profile": "full", "routing_profiles": {"full": {"description": "d", "allow_tools": ["*"]}}}
        self.assertEqual(mod.profile_problems(full), [])
        self.assertEqual(mod.profile_problems({}), [])
        coding = {"default_routing_profile": "coding", "routing_profiles": {"coding": {"allow_tools": ["git_*"]}}}
        self.assertEqual(len(mod.profile_problems(coding)), 1)
        self.assertEqual(mod.profile_problems({"default_routing_profile": "missing"}), [])
        # An absent name is "default", which a config may define as filtering.
        self.assertEqual(len(mod.profile_problems({"routing_profiles": {"default": {"allow_tools": ["a"]}}})), 1)
        with mock.patch.dict("os.environ", {"MCP_GATEWAY_DEFAULT_ROUTING_PROFILE": "coding"}):
            with self.assertRaises(mod.Unverifiable):
                mod.env_override({}, [])

    def test_a_capture_key_that_filters_tools_fails(self):  # T15: MIK-7851.CHECK.1
        import hashlib
        digest = "sha256:" + hashlib.sha256(b"cap-key").hexdigest()
        def auth(**fields):
            return {"auth": {"bearer_token": "static", "api_keys": [
                {"name": "ops", "key_sha256": digest, "allowed_tools": None, **fields}]}}
        self.assertEqual(mod.key_problems(auth(), None), [])
        self.assertEqual(mod.key_problems(auth(), "static"), [])
        self.assertEqual(mod.key_problems(auth(), "cap-key"), [])
        self.assertEqual(len(mod.key_problems(auth(allowed_tools=["git_*"]), "cap-key")), 1)
        self.assertEqual(len(mod.key_problems(auth(denied_tools=["rm"]), "cap-key")), 1)
        with self.assertRaises(mod.Unverifiable):
            mod.key_problems(auth(), "absent-key")

    def test_auth_on_without_the_capture_key_fails_closed(self):  # T17: MIK-7851.CHECK.1
        with self.assertRaises(mod.Unverifiable):
            mod.key_problems({"auth": {"enabled": True}}, None)

    def test_an_env_layer_setting_auth_fails_closed(self):  # T18: key filters can come from env
        with tempfile.TemporaryDirectory() as tmp:
            env = pathlib.Path(tmp) / "launcher.env"
            env.write_text("MCP_GATEWAY_AUTH__API_KEYS='[]'\n")
            with self.assertRaises(mod.Unverifiable):
                mod.env_override({}, [env])
        with mock.patch.dict("os.environ", {"MCP_GATEWAY_AUTH__ENABLED": "true"}):
            with self.assertRaises(mod.Unverifiable):
                mod.env_override({}, [])

    def test_the_capability_state_limit_is_stated(self):  # T16: MIK-7851.CHECK.2
        # The capture reads one capability state; the limit is documented, so a
        # change that starts capturing other states must update this line.
        self.assertIn("exposed only in another capability state are not", mod.__doc__)

    def test_cli_exit_codes(self):  # T10
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "cat.json").write_text(json.dumps(CATALOG))
            for mode, cfg, want in (("declared", "server: {idempotency_key: optional}\nbackends: {vault: {}}\n", 0),
                                    ("required", "backends: {vault: {}}\n", 1),
                                    ("declared", "server: {idempotency_key: sometimes}\n", 2)):
                (d / "c.yaml").write_text(cfg)
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = mod.main(["check", "--config", str(d / "c.yaml"),
                                   "--catalog", str(d / "cat.json"), "--mode", mode])
                self.assertEqual(rc, want, (mode, cfg))


if __name__ == "__main__":
    unittest.main()
