#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Plain-assert checks for surface_docs.py (MIK-8044.SURF.2 P4).

User docs, examples and the Helm chart list only KEEP config keys and
variables. Runs the real check over the repository (R1), and proves each
matching rule on small fixtures.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import surface_docs as sd  # noqa: E402

DOC = """# x
## Surface: config
| Item | Class | Default | Reason | Migration | Defined at |
|---|---|---|---|---|---|
| `server` | KEEP | - | r | - | a |
| `server.port` | KEEP | - | r | - | a |
| `server.shutdown_timeout` | INTERNAL | - | r | - | a |
| `backends` | KEEP | - | r | - | a |
| `backends.<name>.url` | KEEP | - | r | - | a |
| `backends.<name>.http_url` | INTERNAL | - | r | - | a |
| `backends.<name>.streamable_http` | AUTO | - | r | - | a |
| `backends.<name>.env` | KEEP | - | r | - | a |
| `backends.<name>.circuit_breaker` | REMOVE | - | r | - | a |
| `auth` | KEEP | - | r | - | a |
| `auth.api_keys` | KEEP | - | r | - | a |
| `auth.api_keys[].name` | KEEP | - | r | - | a |
| `auth.api_keys[].rate_limit` | KEEP | - | r | - | a |
| `auth.api_keys[].key` | INTERNAL | - | r | - | a |
| `failsafe` | KEEP | - | r | - | a |
| `failsafe.retry` | KEEP | - | r | - | a |
| `failsafe.retry.max_attempts` | INTERNAL | - | r | - | a |
| `cache` | KEEP | - | r | - | a |
| `cache.enabled` | KEEP | - | r | - | a |
| `cache.default_ttl` | INTERNAL | - | r | - | a |
| `capabilities` | KEEP | - | r | - | a |
| `capabilities.name` | INTERNAL | - | r | - | a |
| `capabilities.directories` | KEEP | - | r | - | a |
| `error_budget` | KEEP | - | r | - | a |
| `error_budget.threshold` | KEEP | - | r | - | a |
| `webhooks` | KEEP | - | r | - | a |
| `webhooks.rate_limit` | INTERNAL | - | r | - | a |
## Surface: env
| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `MCP_GATEWAY_TOKEN` | KEEP | r | - | a |
| `MCP_GATEWAY_RUNTIME_DOCKER_SMOKE` | INTERNAL | r | - | a |
| `MCP_GATEWAY_<SECTION>__<KEY>` | KEEP | r | - | a |
## Notes
"""
ROWS = sd.Rows.from_doc(DOC)


def yaml_errs(text: str) -> list[str]:
    return sd.yaml_errors(text, "f.yaml", ROWS)


def md_errs(text: str, allowed: dict | None = None, used: set | None = None) -> list[str]:
    return sd.markdown_errors(text, "f.md", ROWS, allowed or {}, used if used is not None else set())


def names(errs: list[str]) -> str:
    return "\n".join(errs)


# ── R1: the real repository ──────────────────────────────────────────────────


def test_r1_the_repository_lists_only_keep_keys() -> None:
    errs = sd.repo_errors()
    assert errs == [], f"{len(errs)} problem(s):\n" + names(errs[:60])


# ── The YAML walk ────────────────────────────────────────────────────────────


def test_w1_a_hidden_key_is_named_at_its_line() -> None:
    errs = yaml_errs("backends:\n  foo:\n    http_url: x\n")
    assert len(errs) == 1 and errs[0].startswith("f.yaml:3:"), errs
    assert "backends.<name>.http_url is INTERNAL" in errs[0], errs


def test_w2_a_keep_key_beats_the_name_slot() -> None:
    assert yaml_errs("backends:\n  foo:\n    url: x\n") == []


def test_w3_a_commented_block_is_walked() -> None:
    errs = yaml_errs("#  failsafe:\n#    retry:\n#      max_attempts: 3\n")
    assert len(errs) == 1 and errs[0].startswith("f.yaml:3:"), errs
    assert "failsafe.retry.max_attempts is INTERNAL" in errs[0], errs


def test_w4_a_prose_comment_does_not_cut_the_path() -> None:
    errs = yaml_errs("failsafe:\n# Note: tune with care\n  retry:\n    max_attempts: 3\n")
    assert any("failsafe.retry.max_attempts" in e for e in errs), errs


def test_w5_a_list_item_opens_a_slot() -> None:
    errs = yaml_errs("auth:\n  api_keys:\n    - name: a\n      key: v\n")
    assert len(errs) == 1 and "auth.api_keys[].key is INTERNAL" in errs[0], errs


def test_w6_a_block_scalar_body_is_not_walked() -> None:
    assert yaml_errs("server:\n  port: |\n    failsafe:\n      retry:\n        max_attempts: 3\n") == []


def test_w7_free_form_under_a_childless_keep_row() -> None:
    assert yaml_errs("backends:\n  foo:\n    env:\n      ANY_VAR: x\n") == []


def test_w8_a_flow_list_item_is_walked() -> None:
    errs = yaml_errs("auth:\n  api_keys:\n    - {name: alice, key: x}\n")
    assert len(errs) == 1 and "auth.api_keys[].key is INTERNAL" in errs[0], errs


def test_w9_a_stray_key_under_a_known_parent_fails() -> None:
    errs = yaml_errs("backends:\n  foo:\n    transport:\n      url: x\n")
    assert any("backends.foo.transport is not a gateway config key" in e for e in errs), errs


def test_w11_a_child_inherits_a_non_keep_class() -> None:
    errs = yaml_errs("backends:\n  foo:\n    circuit_breaker:\n      enabled: true\n")
    assert any("is REMOVE" in e and e.startswith("f.yaml:4:") for e in errs), errs
    errs = yaml_errs("capabilities:\n  name:\n    x: 1\n")
    assert any("is INTERNAL" in e and e.startswith("f.yaml:3:") for e in errs), errs


def test_w12_capitalised_comment_words_are_not_keys() -> None:
    errs = yaml_errs("# Usage: copy this\nserver:\n# Example: below\n  shutdown_timeout: 5s\n")
    assert len(errs) == 1 and "server.shutdown_timeout" in errs[0], errs


def test_w13_a_block_with_no_config_key_is_skipped() -> None:
    assert yaml_errs("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n") == []


def test_w14_the_flow_parser_respects_quotes() -> None:
    errs = yaml_errs('auth:\n  api_keys:\n    - {name: "a,b: {c}", key: x}\n')
    assert len(errs) == 1 and "auth.api_keys[].key" in errs[0], errs
    errs = yaml_errs("cache: {enabled: true,\n  default_ttl: 60s}\n")
    assert len(errs) == 1 and "cache.default_ttl" in errs[0], errs


def test_w16_a_commented_child_keeps_its_parent() -> None:
    errs = yaml_errs("# cache:\n#   default_ttl: 60s\n")
    assert len(errs) == 1 and "cache.default_ttl" in errs[0], errs


# ── Markdown: fenced blocks and prose ────────────────────────────────────────


def test_m1_a_fenced_block_counts_lines_in_the_md_file() -> None:
    errs = md_errs("# t\n\ntext\n\n```yaml\nserver:\n  shutdown_timeout: 5s\n```\n")
    assert len(errs) == 1 and errs[0].startswith("f.md:7:"), errs


def test_m2_a_backticked_hidden_id_in_prose_fails() -> None:
    errs = md_errs("Set `failsafe.retry.max_attempts` to retry more.\n")
    assert len(errs) == 1 and errs[0].startswith("f.md:1:"), errs
    assert md_errs("Set `server.port` to move it.\n") == []


def test_m3_a_shell_fence_is_not_prose() -> None:
    assert md_errs("```bash\necho `failsafe.retry.max_attempts`\n```\n") == []


def test_f1_indented_unlabelled_and_four_tick_fences() -> None:
    assert len(md_errs("- item\n\n  ```yml\n  cache:\n    default_ttl: 1s\n  ```\n")) == 1
    assert len(md_errs("```\ncache:\n  default_ttl: 1s\n```\n")) == 1
    assert len(md_errs("````yaml\ncache:\n  default_ttl: 1s\n````\n")) == 1
    assert md_errs("```\n$ mcp-gateway serve\nListening: 39400\n```\n") == []


def test_b1_a_concrete_backend_name_resolves_to_the_slot() -> None:
    errs = md_errs("Point `backends.mail-svc.http_url` at it.\n")
    assert len(errs) == 1 and "backends.<name>.http_url is INTERNAL" in errs[0], errs


def test_b2_an_inline_flow_config_is_parsed() -> None:
    errs = md_errs("Add `cache: { enabled: true, default_ttl: 60s }` to your config.\n")
    assert len(errs) == 1 and "cache.default_ttl" in errs[0], errs


def test_b3_unambiguous_hidden_leaves_fail_shared_ones_pass() -> None:
    assert len(md_errs("Use `http_url:` here.\n")) == 1
    assert len(md_errs("Set `streamable_http` to true.\n")) == 1
    assert md_errs("Set `rate_limit` per key.\n") == []
    assert md_errs("The `error_budget` section and `error_budget.threshold`.\n") == []


# ── Variables ────────────────────────────────────────────────────────────────


def test_v1_variables_are_classified() -> None:
    assert len(md_errs("Set MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1.\n")) == 1
    assert md_errs("Set MCP_GATEWAY_TOKEN and MCP_GATEWAY_<SECTION>__<KEY>; any MCP_GATEWAY_ name.\n") == []


def test_c1_overlays_resolve_to_config_paths() -> None:
    errs = md_errs("MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT=5s\n")
    assert len(errs) == 1 and "server.shutdown_timeout is INTERNAL" in errs[0], errs
    assert md_errs("MCP_GATEWAY_SERVER__PORT=1\n") == []
    errs = md_errs("MCP_GATEWAY_BACKENDS__FOO__HTTP_URL=x\n")
    assert len(errs) == 1 and "backends.<name>.http_url is INTERNAL" in errs[0], errs
    assert md_errs("MCP_GATEWAY_ERROR_BUDGET__THRESHOLD=0.5\n") == []
    errs = md_errs("MCP_GATEWAY_NOPE__X=1\n")
    assert len(errs) == 1 and "not a gateway config key" in errs[0], errs


# ── The reviewed exemption list ──────────────────────────────────────────────


def test_a1_a_stale_entry_is_an_error() -> None:
    allowed = {("f.md", "MCP_GATEWAY_RUNTIME_DOCKER_SMOKE"): "test-script variable"}
    errs = sd.stale_allowed(allowed, set())
    assert len(errs) == 1 and "MCP_GATEWAY_RUNTIME_DOCKER_SMOKE" in errs[0], errs


def test_a2_an_entry_covers_its_file_and_prose_only() -> None:
    allowed = {("f.md", "failsafe.retry.max_attempts"): "reason"}
    used: set = set()
    assert md_errs("Set `failsafe.retry.max_attempts`.\n", allowed, used) == []
    assert used == {("f.md", "failsafe.retry.max_attempts")}, used
    assert len(sd.markdown_errors("Set `failsafe.retry.max_attempts`.\n", "g.md", ROWS, allowed, set())) == 1
    block = "```yaml\nfailsafe:\n  retry:\n    max_attempts: 3\n```\n"
    assert len(md_errs(block, allowed, set())) == 1


def test_a3_an_allowed_variable_passes_in_prose_only() -> None:
    allowed = {("f.md", "MCP_GATEWAY_RUNTIME_DOCKER_SMOKE"): "test-script variable"}
    assert md_errs("Set MCP_GATEWAY_RUNTIME_DOCKER_SMOKE=1.\n", allowed, set()) == []


def test_a4_every_real_entry_carries_a_reason() -> None:
    for key, reason in sd.DOC_MENTIONS_ALLOWED.items():
        assert len(reason.split()) >= 3, key


# ── The scanned set ──────────────────────────────────────────────────────────


def test_s1_examples_skip_the_same_files_as_c1() -> None:
    c1 = (sd.ROOT / "tests/c1_unrecognised_config_keys.rs").read_text(encoding="utf-8")
    for name in sd.NOT_GATEWAY_CONFIGS:
        assert f'"{name}"' in c1, name
    listed = {p.name for p in sd.doc_set() if p.parent.name == "examples"}
    assert listed and not listed & set(sd.NOT_GATEWAY_CONFIGS), listed


def test_s2_user_docs_are_in_and_design_docs_are_out() -> None:
    rel = {p.relative_to(sd.ROOT).as_posix() for p in sd.doc_set()}
    assert {"README.md", "docs/QUICKSTART.md", "gateway.example.yaml"} <= rel, rel
    assert any(r.startswith("docs/runtime/") for r in rel), rel
    assert not any(r.startswith("docs/design/") for r in rel), rel
    assert "docs/UPGRADING-4.0.md" not in rel


def test_x1_values_config_is_scanned_without_its_prefix() -> None:
    values = "replicaCount: 1\nconfig:\n  failsafe:\n    retry:\n      max_attempts: 3\nlogging:\n  level: info\n"
    errs = sd.values_errors(values, "values.yaml", ROWS)
    assert len(errs) == 1 and "failsafe.retry.max_attempts is INTERNAL" in errs[0], errs
    assert sd.values_errors("config:\n  failsafe:\n    retry: {}\n", "values.yaml", ROWS) == []


# ── Helm ─────────────────────────────────────────────────────────────────────

MANIFEST = """---
apiVersion: v1
kind: ConfigMap
metadata:
  name: t-mcp-gateway
data:
  gateway.yaml: |
    server:
      port: 39400
    failsafe:
      retry:
        max_attempts: 3
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: gateway
          env:
            - name: HOME
              value: /home/app
            - name: GATEWAY_API_KEY_CI
              value: x
            - name: MCP_GATEWAY_RUNTIME_DOCKER_SMOKE
              value: "1"
"""


def test_h1_a_hidden_key_in_the_rendered_config_fails() -> None:
    errs = sd.rendered_errors(MANIFEST, "mode=credential", ROWS)
    assert any("failsafe.retry.max_attempts is INTERNAL" in e for e in errs), errs


def test_h5_h9_only_gateway_variables_in_the_deployment_are_checked() -> None:
    errs = sd.rendered_errors(MANIFEST, "mode=credential", ROWS)
    assert any("MCP_GATEWAY_RUNTIME_DOCKER_SMOKE" in e for e in errs), errs
    assert not any("HOME" in e or "GATEWAY_API_KEY_CI" in e for e in errs), errs


def test_h8_a_stray_rendered_key_fails() -> None:
    errs = sd.rendered_errors(MANIFEST.replace("port: 39400", "prot: 39400"), "m", ROWS)
    assert any("server.prot is not a gateway config key" in e for e in errs), errs


SCHEMA = {
    "properties": {
        "config": {"type": "object"},
        "server": {"properties": {"cleartextHttp": {"type": "string"}}},
        "metrics": {"properties": {"existingSecret": {"type": "string"}}},
    }
}


def test_h2_a_leaf_set_by_no_fixture_fails() -> None:
    errs = sd.coverage_errors(SCHEMA, {"a": {"server": {"cleartextHttp": "refuse"}}})
    assert len(errs) == 1 and "metrics.existingSecret" in errs[0], errs
    full = {"a": {"server": {"cleartextHttp": "refuse"}, "metrics": {"existingSecret": "s"}}}
    assert sd.coverage_errors(SCHEMA, full) == []


def test_h6_a_falsy_fixture_value_counts_as_unset() -> None:
    for falsy in ("", 0, False):
        fx = {"a": {"server": {"cleartextHttp": "refuse"}, "metrics": {"existingSecret": falsy}}}
        assert len(sd.coverage_errors(SCHEMA, fx)) == 1, falsy


def test_h3_config_must_stay_free_form() -> None:
    assert sd.config_schema_errors(SCHEMA) == []
    bad = {"properties": {"config": {"type": "object", "properties": {"server": {}}}}}
    assert len(sd.config_schema_errors(bad)) == 1


def test_h7_an_expected_rendered_key_that_is_absent_fails() -> None:
    assert sd.expected_errors(MANIFEST, "m", ["server.port"]) == []
    errs = sd.expected_errors(MANIFEST, "m", ["security.transparency_log.rotation.max_segment_age_secs"])
    assert len(errs) == 1 and "max_segment_age_secs" in errs[0], errs


def test_h4_helm_mode_needs_helm() -> None:
    errs = sd.helm_errors(helm="/nonexistent/helm")
    assert len(errs) == 1 and "helm" in errs[0], errs


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {name}: {exc}")
            except Exception as exc:  # noqa: BLE001 - a crash is a failed row, named
                failed += 1
                print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    sys.exit(1 if failed else 0)
