#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Plain-assert checks for surface_shipped.py.

Shipped files use only KEEP commands, flags, config keys and variables.
A planted row names the hit. Its KEEP twin expects none.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import surface_docs as sd  # noqa: E402
import surface_shipped as ss  # noqa: E402

DOC = """# x
## Surface: cli
| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `mcp-gateway` | KEEP | r | - | a |
| `mcp-gateway --config` | KEEP | r | - | a |
| `mcp-gateway --port` | KEEP | r | - | a |
| `mcp-gateway --host` | INTERNAL | r | - | a |
| `mcp-gateway --no-meta-mcp` | INTERNAL | r | - | a |
| `mcp-gateway serve` | KEEP | r | - | a |
| `mcp-gateway add` | KEEP | r | - | a |
| `mcp-gateway add --name` | KEEP | r | - | a |
| `mcp-gateway kubernetes` | INTERNAL | r | - | a |
| `mcp-gateway kubernetes plan` | INTERNAL | r | - | a |
| `mcp-gateway kubernetes plan --namespace` | INTERNAL | r | - | a |
| `mcp-gateway kubernetes controller` | INTERNAL | r | - | a |
| `mcp-gateway kubernetes controller --cycles` | INTERNAL | r | - | a |
| `mcp-gateway trust` | INTERNAL | r | - | a |
| `mcp-gateway trust lab` | INTERNAL | r | - | a |
| `mcp-gateway trust lab evaluate` | INTERNAL | r | - | a |
| `mcp-gateway trust lab evaluate --capabilities` | INTERNAL | r | - | a |
| `mcp-gateway identity` | KEEP | r | - | a |
| `mcp-gateway identity grants` | KEEP | r | - | a |
| `mcp-gateway identity grants grant` | KEEP | r | - | a |
| `mcp-gateway identity grants grant --agent` | KEEP | r | - | a |
| `mcp-gateway identity grants grant --subject-label` | INTERNAL | r | - | a |
## Surface: config
| Item | Class | Default | Reason | Migration | Defined at |
|---|---|---|---|---|---|
| `server` | KEEP | - | r | - | a |
| `server.host` | KEEP | - | r | - | a |
| `server.port` | KEEP | - | r | - | a |
| `server.shutdown_timeout` | INTERNAL | - | r | - | a |
## Surface: env
| Item | Class | Reason | Migration | Defined at |
|---|---|---|---|---|
| `MCP_GATEWAY_SERVER__HOST` | KEEP | r | - | a |
## Notes
"""
TABLE = ss.CliTable.from_doc(DOC)
ROWS = sd.Rows.from_doc(DOC)
DOC_LAB_KEEP = DOC.replace(
    "| `mcp-gateway trust lab` | INTERNAL | r | - | a |",
    "| `mcp-gateway trust lab` | KEEP | r | - | a |",
)

REASON = "the page cannot drop the mention"
LAB_SNAP = frozenset({
    "mcp-gateway trust",
    "mcp-gateway trust lab",
    "mcp-gateway trust lab evaluate",
})
FLAG = "mcp-gateway trust lab evaluate --capabilities"

# Verbatim excerpts. Line numbers below are lines of these strings.
K3_FILE = "deploy/helm/mcp-gateway/templates/deployment.yaml"
K3 = """\
      containers:
        - name: gateway
          image: {{ include "mcp-gateway.image" . | quote }}
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          # No `serve`: --host/--port are top-level flags and the subcommand
          # takes only --stdio, so `serve --host` exits 2 before reading config.
          args:
            - "--config"
            - "/etc/mcp-gateway/gateway.yaml"
            - "--host"
            - "0.0.0.0"
            - "--port"
            - {{ .Values.service.port | quote }}
"""
K4_FILE = "deploy/kubernetes/enterprise-alpha/base/deployment.yaml"
K4 = """\
      containers:
        - name: gateway
          image: ghcr.io/mikkoparkkola/mcp-gateway:latest
          imagePullPolicy: IfNotPresent
          # No `serve`: --host/--port are top-level flags and the subcommand
          # takes only --stdio, so `serve --host` exits 2 before reading config.
          args:
            - "--config"
            - "/etc/mcp-gateway/gateway.yaml"
            - "--host"
            - "0.0.0.0"
            - "--port"
            - "39400"
"""
K5_FILE = "deploy/single-node/docker-compose.yaml"
K5 = """\
services:
  mcp-gateway:
    image: ghcr.io/mikkoparkkola/mcp-gateway:latest
    container_name: mcp-gateway
    restart: unless-stopped
    # Docker's 10 s default SIGKILLs the gateway mid-stop; it needs its stop
    # timeout (30 s by default) + 1 s (docs/DEPLOYMENT.md, Stop grace).
    stop_grace_period: 31s
    command: ["--config", "/config.yaml", "--host", "0.0.0.0", "--port", "39400"]
"""
K6_FILE = "deploy/single-node/mcp-gateway.service"
K6 = "ExecStart=/usr/local/bin/mcp-gateway --config /etc/mcp-gateway/gateway.yaml --host 127.0.0.1 --port 39400\n"
K7_FILE = "deploy/single-node/com.mikkoparkkola.mcp-gateway.plist"
K7 = """\
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/mcp-gateway</string>
    <string>--config</string>
    <string>/usr/local/etc/mcp-gateway/gateway.yaml</string>
    <string>--host</string>
    <string>127.0.0.1</string>
    <string>--port</string>
    <string>39400</string>
  </array>
"""
K8_FILE = "Dockerfile"
K8 = """\
# Run:    docker run -p 127.0.0.1:39400:39400 \\
#           -e MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND=true \\
#           -e MCP_GATEWAY_SERVER__CLEARTEXT_HTTP=host_local_publish \\
#           -v ./gateway.yaml:/config.yaml:ro mcp-gateway:latest \\
#           --config /config.yaml --host 0.0.0.0
"""
HOST_ITEM = '            - "--host"\n            - "0.0.0.0"\n'

ENV_HIDDEN = """\
services:
  gateway:
    image: mcp-gateway:1
    environment:
      MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT: "1"
"""
ENV_HOST = """\
services:
  gateway:
    image: mcp-gateway:1
    environment:
      MCP_GATEWAY_SERVER__HOST: "127.0.0.1"
"""
CM_FILE = "deploy/kubernetes/enterprise-alpha/base/configmap.yaml"
CM = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway
data:
  gateway.yaml: |
    server:
      shutdown_timeout: 5
"""
CM_KEEP = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway
data:
  gateway.yaml: |
    server:
      port: 1
"""
K14 = """\
ENTRYPOINT ["mcp-gateway"]
CMD ["--config", "/c", "--host", "0.0.0.0"]
"""
K14_KEEP = """\
ENTRYPOINT ["mcp-gateway"]
CMD ["--config", "/c"]
"""
C1 = """\
```sh
mcp-gateway identity grants grant \\
  --agent a \\
  --subject-label x
```
"""
C1_KEEP = """\
```sh
mcp-gateway identity grants grant \\
  --agent a
```
"""
C2_FILE = "deploy/kubernetes/enterprise-alpha/base/deployment.yaml"
C2 = """\
spec:
  containers:
    - name: gateway
      image: mcp-gateway:1
      args:
        - "--config"
        - "/c"
        - "--host"
"""
C2_KEEP = """\
spec:
  containers:
    - name: gateway
      image: mcp-gateway:1
      args:
        - "--config"
        - "/c"
"""
STRING_CMD = """\
services:
  gateway:
    image: mcp-gateway:1
    command: --config /c --host 0.0.0.0
"""
STRING_KEEP = """\
services:
  gateway:
    image: mcp-gateway:1
    command: --config /c --port 39400
"""
SHELL = """\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: gateway
          image: mcp-gateway:1
          args: ["sh", "-c", "mcp-gateway --host 0.0.0.0"]
"""
SHELL_KEEP = """\
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: gateway
          image: mcp-gateway:1
          args: ["sh", "-c", "mcp-gateway --port 39400"]
"""
FLOW = """\
services:
  gateway:
    image: mcp-gateway:1
    command: ["--config", "/c",
      "--host", "0.0.0.0"]
"""
FLOW_KEEP = """\
services:
  gateway:
    image: mcp-gateway:1
    command: ["--config", "/c",
      "--port", "39400"]
"""
POD_FILE = "deploy/kubernetes/enterprise-alpha/base/pod.yaml"
POD = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: sidecar
      image: busybox
      args:
        - "--host"
    - name: gateway
      args:
        - "--host"
      image: mcp-gateway:1
"""
SIDECAR = """\
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: sidecar
      image: busybox
      args:
        - "--host"
"""
LAB = """\
```sh
mcp-gateway trust lab evaluate
```
"""
LAB_FLAG = """\
```sh
mcp-gateway trust lab evaluate --capabilities x
```
"""
LAB_AND_LONE = """\
```sh
mcp-gateway trust lab evaluate
mcp-gateway trust
```
"""


def scan(file: str, text: str, table: ss.CliTable | None = None) -> list[tuple[str, int, str, str]]:
    hits = ss.scan_text(file, text, TABLE if table is None else table, ROWS)
    return sorted((h.file, h.line, h.cls, h.item) for h in hits)


def raw(file: str, text: str, table: ss.CliTable | None = None) -> list[ss.Hit]:
    return ss.scan_text(file, text, TABLE if table is None else table, ROWS)


def expect(file: str, pairs: list[tuple[int, str]]) -> list[tuple[str, int, str, str]]:
    return sorted((file, line, "INTERNAL", item) for line, item in pairs)


def sh(line: str) -> str:
    return f"```sh\n{line}\n```\n"


def lab_allow(file: str, snap: frozenset[str]) -> dict:
    return {(file, "mcp-gateway trust lab"): (REASON, snap)}


def triples(hits: list[ss.Hit]) -> list[tuple[str, int, str, str]]:
    return sorted((h.file, h.line, h.cls, h.item) for h in hits)


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), "-c", "core.hooksPath=/dev/null", *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )


def repo(files: dict[str, str]) -> tempfile.TemporaryDirectory[str]:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    git(root, "init")
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(root, "add", "-A")
    return tmp


def rels(files: list[Path], root: Path) -> set[str]:
    root_r = root.resolve()
    out = set()
    for item in files:
        path = Path(item)
        if not path.is_absolute():
            path = root_r / path
        try:
            out.add(path.resolve().relative_to(root_r).as_posix())
        except ValueError:
            out.add(Path(item).as_posix())
    return out


# ── Markdown and command lines ───────────────────────────────────────────────


def test_k1_markdown_sh_fence_reports_host() -> None:
    text = sh("mcp-gateway --host 0.0.0.0")
    assert scan("docs/k1.md", text) == expect("docs/k1.md", [(2, "mcp-gateway --host")]), scan("docs/k1.md", text)


def test_k1_keep_port() -> None:
    assert scan("docs/k1.md", sh("mcp-gateway --port 39400")) == []


def test_k2_markdown_inline_span_reports_host() -> None:
    text = "Bind `mcp-gateway --host 0.0.0.0` on the pod.\n"
    assert scan("docs/k2.md", text) == expect("docs/k2.md", [(1, "mcp-gateway --host")]), scan("docs/k2.md", text)


def test_k2_keep_port() -> None:
    assert scan("docs/k2.md", "Bind `mcp-gateway --port 39400` on the pod.\n") == []


def test_k10_kubernetes_plan_namespace() -> None:
    text = sh("mcp-gateway kubernetes plan --namespace x")
    assert scan("docs/k10.md", text) == expect("docs/k10.md", [
        (2, "mcp-gateway kubernetes"),
        (2, "mcp-gateway kubernetes plan"),
        (2, "mcp-gateway kubernetes plan --namespace"),
    ]), scan("docs/k10.md", text)


def test_k10_keep_identity_grant_agent() -> None:
    assert scan("docs/k10.md", sh("mcp-gateway identity grants grant --agent a")) == []


# ── Verbatim deploy excerpts ─────────────────────────────────────────────────


def test_k3_helm_template_args_report_host() -> None:
    assert scan(K3_FILE, K3) == expect(K3_FILE, [(10, "mcp-gateway --host")]), scan(K3_FILE, K3)


def test_k3_keep_without_host_pair() -> None:
    assert scan(K3_FILE, K3.replace(HOST_ITEM, "")) == []


def test_k4_kubernetes_base_args_report_host() -> None:
    assert scan(K4_FILE, K4) == expect(K4_FILE, [(10, "mcp-gateway --host")]), scan(K4_FILE, K4)


def test_k4_keep_without_host_pair() -> None:
    assert scan(K4_FILE, K4.replace(HOST_ITEM, "")) == []


def test_k5_compose_flow_list_reports_host() -> None:
    assert scan(K5_FILE, K5) == expect(K5_FILE, [(9, "mcp-gateway --host")]), scan(K5_FILE, K5)


def test_k5_keep_without_host_pair() -> None:
    text = K5.replace('"--host", "0.0.0.0", ', "")
    assert scan(K5_FILE, text) == []


def test_k6_systemd_execstart_reports_host() -> None:
    assert scan(K6_FILE, K6) == expect(K6_FILE, [(1, "mcp-gateway --host")]), scan(K6_FILE, K6)


def test_k6_keep_without_host() -> None:
    assert scan(K6_FILE, K6.replace(" --host 127.0.0.1", "")) == []


def test_k7_launchd_program_arguments_report_host() -> None:
    assert scan(K7_FILE, K7) == expect(K7_FILE, [(6, "mcp-gateway --host")]), scan(K7_FILE, K7)


def test_k7_keep_without_host() -> None:
    text = K7.replace("    <string>--host</string>\n    <string>127.0.0.1</string>\n", "")
    assert scan(K7_FILE, text) == []


def test_k8_dockerfile_comment_reports_host() -> None:
    assert scan(K8_FILE, K8) == expect(K8_FILE, [(5, "mcp-gateway --host")]), scan(K8_FILE, K8)


def test_k8_keep_without_host() -> None:
    assert scan(K8_FILE, K8.replace(" --host 0.0.0.0", "")) == []


def test_k9_example_comment_reports_host() -> None:
    text = "# mcp-gateway --host 0.0.0.0\nserver:\n  port: 1\n"
    assert scan("examples/x.yaml", text) == expect("examples/x.yaml", [(1, "mcp-gateway --host")]), scan("examples/x.yaml", text)


def test_k9_keep_port_comment() -> None:
    assert scan("examples/x.yaml", "# mcp-gateway --port 39400\nserver:\n  port: 1\n") == []


# ── Variables, config keys, exec form ───────────────────────────────────────


def test_k11_compose_hidden_variable_fails() -> None:
    assert scan(K5_FILE, ENV_HIDDEN) == expect(K5_FILE, [(5, "server.shutdown_timeout")]), scan(K5_FILE, ENV_HIDDEN)


def test_k11_compose_host_passes() -> None:
    assert scan(K5_FILE, ENV_HOST) == []


def test_k11_tpl_hidden_variable_fails() -> None:
    file = "deploy/helm/mcp-gateway/templates/env.tpl"
    assert scan(file, ENV_HIDDEN) == expect(file, [(5, "server.shutdown_timeout")]), scan(file, ENV_HIDDEN)


def test_k11_tpl_host_passes() -> None:
    assert scan("deploy/helm/mcp-gateway/templates/env.tpl", ENV_HOST) == []


def test_k11_json_description_hidden_variable_fails() -> None:
    file = "deploy/helm/mcp-gateway/values.schema.json"
    text = '{"description": "MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT"}\n'
    assert scan(file, text) == expect(file, [(1, "server.shutdown_timeout")]), scan(file, text)


def test_k11_json_description_host_passes() -> None:
    text = '{"description": "MCP_GATEWAY_SERVER__HOST"}\n'
    assert scan("deploy/helm/mcp-gateway/values.schema.json", text) == []


def test_k11_notes_hidden_variable_fails() -> None:
    file = "deploy/helm/mcp-gateway/templates/NOTES.txt"
    text = "Stop budget: MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT.\n"
    assert scan(file, text) == expect(file, [(1, "server.shutdown_timeout")]), scan(file, text)


def test_k11_notes_host_passes() -> None:
    text = "The Service listens on MCP_GATEWAY_SERVER__HOST.\n"
    assert scan("deploy/helm/mcp-gateway/templates/NOTES.txt", text) == []


def test_k13_notes_hidden_flag() -> None:
    file = "deploy/helm/mcp-gateway/templates/NOTES.txt"
    text = "mcp-gateway --host 0.0.0.0\n"
    assert scan(file, text) == expect(file, [(1, "mcp-gateway --host")]), scan(file, text)


def test_k13_keep_port() -> None:
    assert scan("deploy/helm/mcp-gateway/templates/NOTES.txt", "mcp-gateway --port 39400\n") == []


def test_k12_configmap_shutdown_timeout() -> None:
    assert scan(CM_FILE, CM) == expect(CM_FILE, [(8, "server.shutdown_timeout")]), scan(CM_FILE, CM)


def test_k12_keep_port() -> None:
    assert scan(CM_FILE, CM_KEEP) == []


def test_k14_dockerfile_exec_form_reports_host() -> None:
    assert scan(K8_FILE, K14) == expect(K8_FILE, [(2, "mcp-gateway --host")]), scan(K8_FILE, K14)


def test_k14_keep_without_host() -> None:
    assert scan(K8_FILE, K14_KEEP) == []


# ── Continuations and shapes ─────────────────────────────────────────────────


def test_c1_backslash_continuation_reports_subject_label() -> None:
    # Fence opener is line 1, so the third command line is file line 4.
    assert scan("docs/c1.md", C1) == expect(
        "docs/c1.md", [(4, "mcp-gateway identity grants grant --subject-label")]
    ), scan("docs/c1.md", C1)


def test_c1_keep_ends_at_agent() -> None:
    assert scan("docs/c1.md", C1_KEEP) == []


def test_c2_args_item_reports_host() -> None:
    assert scan(C2_FILE, C2) == expect(C2_FILE, [(8, "mcp-gateway --host")]), scan(C2_FILE, C2)


def test_c2_keep_config_only() -> None:
    assert scan(C2_FILE, C2_KEEP) == []


def test_shape_string_command_reports_host() -> None:
    assert scan(K5_FILE, STRING_CMD) == expect(K5_FILE, [(4, "mcp-gateway --host")]), scan(K5_FILE, STRING_CMD)


def test_shape_string_command_keep_port() -> None:
    assert scan(K5_FILE, STRING_KEEP) == []


def test_shape_shell_c_reports_host() -> None:
    assert scan(C2_FILE, SHELL) == expect(C2_FILE, [(9, "mcp-gateway --host")]), scan(C2_FILE, SHELL)


def test_shape_shell_c_keep_port() -> None:
    assert scan(C2_FILE, SHELL_KEEP) == []


def test_shape_flow_list_spans_lines() -> None:
    assert scan(K5_FILE, FLOW) == expect(K5_FILE, [(5, "mcp-gateway --host")]), scan(K5_FILE, FLOW)


def test_shape_flow_list_keep_port() -> None:
    assert scan(K5_FILE, FLOW_KEEP) == []


# ── Resolution ───────────────────────────────────────────────────────────────


def test_k15_a_flag_after_a_positional_still_counts() -> None:
    # The alpha README's shape: a file path, then the hidden command's flags.
    text = "```sh\nmcp-gateway kubernetes plan \\\n  base/example.yaml \\\n  --namespace ns\n```\n"
    assert scan("docs/k15.md", text) == expect("docs/k15.md", [
        (2, "mcp-gateway kubernetes"),
        (2, "mcp-gateway kubernetes plan"),
        (4, "mcp-gateway kubernetes plan --namespace"),
    ]), scan("docs/k15.md", text)


def test_k15_keep_positional_then_keep_flag() -> None:
    assert scan("docs/k15.md", sh("mcp-gateway add weather --name w")) == []


def test_g8_a_binary_after_a_positional_starts_its_own_command() -> None:
    # `mcp-gateway` as kubectl's namespace starts a walk; the real binary after
    # `--` must start its own, or its flags would read as values after `--`.
    text = sh("kubectl -n mcp-gateway exec gw -- mcp-gateway --host 0.0.0.0")
    assert scan("docs/g8.md", text) == expect("docs/g8.md", [(2, "mcp-gateway --host")]), scan("docs/g8.md", text)


def test_g9_a_flag_value_spelled_like_the_binary_starts_nothing() -> None:
    # `--namespace mcp-gateway` is a value: the flags after it stay on the command.
    text = sh("mcp-gateway kubernetes controller x.yaml --namespace mcp-gateway --cycles 2")
    hits = scan("docs/g9.md", text)
    assert ("docs/g9.md", 2, "INTERNAL", "mcp-gateway kubernetes controller --cycles") in hits, hits


def test_f5_a_hash_inside_a_word_is_not_a_comment() -> None:
    # Shell starts a comment only at a word: `x#y` is one word, flags after it count.
    text = sh("mcp-gateway --config c#1 --host 0.0.0.0")
    assert scan("docs/f5.md", text) == expect("docs/f5.md", [(2, "mcp-gateway --host")]), scan("docs/f5.md", text)


def test_f13_a_hash_inside_a_plain_flow_item_is_not_a_comment() -> None:
    # YAML starts a comment only after whitespace: `/c#1` is one plain scalar.
    text = "services:\n  gateway:\n    image: mcp-gateway:1\n    command: [--config, /c#1, --host, 0.0.0.0]\n"
    assert scan(K5_FILE, text) == expect(K5_FILE, [(4, "mcp-gateway --host")]), scan(K5_FILE, text)


def test_f14_an_escaped_space_keeps_the_hash_inside_the_word() -> None:
    text = sh("mcp-gateway --config c\\ #1 --host 0.0.0.0")
    assert scan("docs/f14.md", text) == expect("docs/f14.md", [(2, "mcp-gateway --host")]), scan("docs/f14.md", text)


def test_f15_a_backtick_substitution_is_its_own_command() -> None:
    # The flag after the substitution belongs to echo, not to the gateway inside it.
    assert scan("docs/f15.md", sh("echo `mcp-gateway --config c` --host 0.0.0.0")) == []


def test_f15_a_command_inside_backticks_still_counts() -> None:
    text = sh("echo `mcp-gateway --host 0.0.0.0`")
    assert scan("docs/f15.md", text) == expect("docs/f15.md", [(2, "mcp-gateway --host")]), scan("docs/f15.md", text)


def test_f16_a_final_shell_form_entrypoint_ignores_cmd() -> None:
    text = 'CMD ["--host", "0.0.0.0"]\nENTRYPOINT ["mcp-gateway"]\nENTRYPOINT /bin/sh -c "exec other"\n'
    assert scan(K8_FILE, text) == [], scan(K8_FILE, text)


def test_f6_an_escaped_json_string_is_decoded() -> None:
    file = "deploy/helm/mcp-gateway/values.schema.json"
    text = '{\n  "description": "run \\"mcp-gateway --host 0.0.0.0\\"\\nthen check"\n}\n'
    assert scan(file, text) == expect(file, [(2, "mcp-gateway --host")]), scan(file, text)


def test_f12_every_selected_user_doc_is_scanned() -> None:
    root = ss.ROOT.resolve()
    docs = {path.resolve().relative_to(root).as_posix() for path in sd.doc_set()}
    files, _errs = ss.shipped_files()
    missing = sorted(docs - rels(files, ss.ROOT))
    assert docs and not missing, missing[:5]


def test_g1_serve_host_resolves_through_parent() -> None:
    text = sh("mcp-gateway serve --host x")
    assert scan("docs/g1.md", text) == expect("docs/g1.md", [(2, "mcp-gateway --host")]), scan("docs/g1.md", text)


def test_g1_keep_serve_port() -> None:
    assert scan("docs/g1.md", sh("mcp-gateway serve --port 39400")) == []


def test_g2_docker_run_image_reports_host() -> None:
    text = sh("docker run -p 1:1 ghcr.io/o/mcp-gateway:4.0.0 --host 0.0.0.0")
    assert scan("docs/g2.md", text) == expect("docs/g2.md", [(2, "mcp-gateway --host")]), scan("docs/g2.md", text)


def test_g2_helm_install_release_name_no_hit() -> None:
    assert scan("docs/g2.md", sh("helm install mcp-gateway ./chart --set a=b")) == []


def test_g3_pipe_host_is_not_a_gateway_flag() -> None:
    assert scan("docs/g3.md", sh("mcp-gateway --config c | grep --host")) == []


def test_g3_unspaced_pipe_host_is_not_a_gateway_flag() -> None:
    assert scan("docs/g3.md", sh("mcp-gateway --config c|grep --host")) == []


def test_g4_no_meta_mcp_kubernetes_plan() -> None:
    text = sh("mcp-gateway --no-meta-mcp kubernetes plan")
    assert scan("docs/g4.md", text) == expect("docs/g4.md", [
        (2, "mcp-gateway --no-meta-mcp"),
        (2, "mcp-gateway kubernetes"),
        (2, "mcp-gateway kubernetes plan"),
    ]), scan("docs/g4.md", text)


def test_g4_keep_serve() -> None:
    assert scan("docs/g4.md", sh("mcp-gateway serve")) == []


def test_g5_add_name_trust_no_hit() -> None:
    assert scan("docs/g5.md", sh("mcp-gateway add --name trust")) == []


def test_g6_end_of_options_host_no_hit() -> None:
    assert scan("docs/g6.md", sh("mcp-gateway serve -- --host")) == []


def test_g7_config_equals_then_kubernetes() -> None:
    text = sh("mcp-gateway --config=c kubernetes")
    assert scan("docs/g7.md", text) == expect("docs/g7.md", [(2, "mcp-gateway kubernetes")]), scan("docs/g7.md", text)


def test_g7_keep_config_equals_serve() -> None:
    assert scan("docs/g7.md", sh("mcp-gateway --config=c serve")) == []


def test_pod_two_containers_only_the_gateway_host() -> None:
    assert scan(POD_FILE, POD) == expect(POD_FILE, [(11, "mcp-gateway --host")]), scan(POD_FILE, POD)


def test_pod_sidecar_busybox_host_passes() -> None:
    assert scan(POD_FILE, SIDECAR) == []


# ── Allow table (inline dict, not ss.ALLOWED) ───────────────────────────────


def test_al1_entry_covers_trust_lab_in_that_file() -> None:
    file = "docs/A.md"
    hits = raw(file, LAB)
    assert scan(file, LAB) == expect(file, [
        (2, "mcp-gateway trust"),
        (2, "mcp-gateway trust lab"),
        (2, "mcp-gateway trust lab evaluate"),
    ]), scan(file, LAB)
    kept, errs = ss.apply_allowed(hits, lab_allow(file, LAB_SNAP), TABLE)
    assert triples(kept) == [], kept
    assert errs == [], errs


def test_al1_same_text_in_another_file_is_reported() -> None:
    allowed = lab_allow("docs/A.md", LAB_SNAP)
    hits = raw("docs/A.md", LAB) + raw("docs/B.md", LAB)
    assert scan("docs/B.md", LAB) == expect("docs/B.md", [
        (2, "mcp-gateway trust"),
        (2, "mcp-gateway trust lab"),
        (2, "mcp-gateway trust lab evaluate"),
    ]), scan("docs/B.md", LAB)
    kept, errs = ss.apply_allowed(hits, allowed, TABLE)
    assert triples(kept) == expect("docs/B.md", [
        (2, "mcp-gateway trust"),
        (2, "mcp-gateway trust lab"),
        (2, "mcp-gateway trust lab evaluate"),
    ]), kept
    assert errs == [], errs


def test_al1_entry_with_no_matching_hit_is_stale() -> None:
    file = "docs/A.md"
    hits = raw(file, sh("mcp-gateway serve"))
    kept, errs = ss.apply_allowed(hits, lab_allow(file, frozenset({"mcp-gateway trust lab"})), TABLE)
    assert kept == [], kept
    assert any(file in e and "mcp-gateway trust lab" in e for e in errs), errs


def test_al2_keep_reclass_still_reports_the_flag() -> None:
    table = ss.CliTable.from_doc(DOC_LAB_KEEP)
    file = "docs/A.md"
    hits = raw(file, LAB_FLAG, table)
    assert (file, 2, "INTERNAL", FLAG) in scan(file, LAB_FLAG, table), scan(file, LAB_FLAG, table)
    snap = LAB_SNAP | {FLAG}
    kept, _errs = ss.apply_allowed(hits, lab_allow(file, snap), table)
    assert (file, 2, "INTERNAL", FLAG) in triples(kept), kept


def test_al3_ancestor_covered_lone_trust_reported() -> None:
    file = "docs/A.md"
    hits = raw(file, LAB_AND_LONE)
    assert scan(file, LAB_AND_LONE) == expect(file, [
        (2, "mcp-gateway trust"),
        (2, "mcp-gateway trust lab"),
        (2, "mcp-gateway trust lab evaluate"),
        (3, "mcp-gateway trust"),
    ]), scan(file, LAB_AND_LONE)
    kept, errs = ss.apply_allowed(hits, lab_allow(file, LAB_SNAP), TABLE)
    assert triples(kept) == expect(file, [(3, "mcp-gateway trust")]), kept
    assert errs == [], errs


def test_al4_flag_missing_from_snapshot_is_reported() -> None:
    file = "docs/A.md"
    hits = raw(file, LAB_FLAG)
    assert (file, 2, "INTERNAL", FLAG) in scan(file, LAB_FLAG), scan(file, LAB_FLAG)
    kept, errs = ss.apply_allowed(hits, lab_allow(file, LAB_SNAP), TABLE)
    assert triples(kept) == expect(file, [(2, FLAG)]), kept
    assert errs == [], errs


def test_al5_snapshot_id_no_longer_present_is_stale() -> None:
    file = "docs/A.md"
    hits = raw(file, LAB)
    assert scan(file, LAB) == expect(file, [
        (2, "mcp-gateway trust"),
        (2, "mcp-gateway trust lab"),
        (2, "mcp-gateway trust lab evaluate"),
    ]), scan(file, LAB)
    kept, errs = ss.apply_allowed(hits, lab_allow(file, LAB_SNAP | {FLAG}), TABLE)
    assert any(FLAG in e for e in errs), errs
    assert triples(kept) == [], kept


# ── Shipped set and the repository ───────────────────────────────────────────


def test_sh1_a_new_tracked_deploy_file_is_scanned_unlisted() -> None:
    # The cause this check removes: a hand-kept list missed new deploy kinds.
    # A tracked deploy file with a reader is scanned without anyone listing it.
    name = "deploy/new-kind/unit.yaml"
    tmp = repo({name: "note: 1\n"})
    try:
        root = Path(tmp.name)
        files, errs = ss.shipped_files(root)
        assert name in rels(files, root), files
        assert not any(name in e for e in errs), errs
    finally:
        tmp.cleanup()


def test_sh2_extension_with_no_reader() -> None:
    name = "deploy/helm/mcp-gateway/templates/extra.toml"
    tmp = repo({name: "x = 1\n"})
    try:
        root = Path(tmp.name)
        _files, errs = ss.shipped_files(root)
        assert any(name in e and "reader" in e.lower() for e in errs), errs
    finally:
        tmp.cleanup()


def test_sh3_not_shipped_name_with_no_file() -> None:
    key = "deploy/missing.yaml"
    saved = ss.NOT_SHIPPED.get(key)
    ss.NOT_SHIPPED[key] = "generated output, not a file a user copies"
    tmp = repo({"README": "ok\n"})
    try:
        _files, errs = ss.shipped_files(Path(tmp.name))
        assert any(key in e for e in errs), errs
    finally:
        tmp.cleanup()
        if saved is None:
            ss.NOT_SHIPPED.pop(key, None)
        else:
            ss.NOT_SHIPPED[key] = saved


# ── Fold: comments, containers, readers ──────────────────────────────────────

# Quoted block item, trailing comment. `--host` is line 4.
F1_BLOCK = """\
image: mcp-gateway:1
args:
  - "--config"
  - "--host" # bind
  - "0.0.0.0"
"""
F1_BLOCK_KEEP = F1_BLOCK.replace('"--host" # bind', '"--port" # bind')
# Comment inside a flow list. `--host` is line 5.
F1_FLOW = """\
services:
  gateway:
    image: mcp-gateway:1
    command: ["--config", "/c", # note
      "--host", "0.0.0.0"]
"""
F1_FLOW_KEEP = """\
services:
  gateway:
    image: mcp-gateway:1
    command: ["--config", "/c", # note
      "--port", "1"]
"""
F1_FILE = "deploy/single-node/docker-compose.yaml"


def test_f1_quoted_block_item_trailing_comment_reports_host() -> None:
    assert scan(F1_FILE, F1_BLOCK) == expect(F1_FILE, [(4, "mcp-gateway --host")]), scan(F1_FILE, F1_BLOCK)


def test_f1_keep_quoted_block_item_port_comment() -> None:
    assert scan(F1_FILE, F1_BLOCK_KEEP) == []


def test_f1_flow_list_comment_reports_host() -> None:
    assert scan(F1_FILE, F1_FLOW) == expect(F1_FILE, [(5, "mcp-gateway --host")]), scan(F1_FILE, F1_FLOW)


def test_f1_keep_flow_list_port_comment() -> None:
    assert scan(F1_FILE, F1_FLOW_KEEP) == []


# The mapping's first key is on the dash line. `--host` is line 4.
F2_GATEWAY = """\
containers:
  - image: mcp-gateway:1
    args:
      - "--host"
"""
F2_SIDECAR = """\
containers:
  - image: busybox
    args:
      - "--host"
"""
F2_FILE = "deploy/kubernetes/enterprise-alpha/base/pod.yaml"


def test_f2_image_on_the_dash_line_reports_host() -> None:
    assert scan(F2_FILE, F2_GATEWAY) == expect(F2_FILE, [(4, "mcp-gateway --host")]), scan(F2_FILE, F2_GATEWAY)


def test_f2_keep_busybox_image_on_the_dash_line() -> None:
    assert scan(F2_FILE, F2_SIDECAR) == []


# Sequence items sit at the same column as `args:` and stop at the next sibling key.
# `--host` is line 6.
F3 = """\
spec:
  containers:
    - name: gateway
      image: mcp-gateway:1
      args:
      - "--host"
      ports:
      - "80"
"""
F3_KEEP = F3.replace('- "--host"', '- "--port"')
F3_FILE = "deploy/kubernetes/enterprise-alpha/base/deployment.yaml"


def test_f3_indentless_args_report_host() -> None:
    assert scan(F3_FILE, F3) == expect(F3_FILE, [(6, "mcp-gateway --host")]), scan(F3_FILE, F3)


def test_f3_keep_indentless_port() -> None:
    assert scan(F3_FILE, F3_KEEP) == []


def _f4(service: str, image_first: bool) -> str:
    body = (
        '    image: busybox\n    command: ["--host", "x"]\n'
        if image_first
        else '    command: ["--host", "x"]\n    image: busybox\n'
    )
    return f"services:\n  a:\n    image: mcp-gateway\n  {service}:\n{body}"


F4_FILE = "deploy/single-node/docker-compose.yaml"


def test_f4_dashed_service_does_not_combine() -> None:
    # Command before the sidecar image: a missed service key glues it to a's image.
    text = _f4("b-x", image_first=False)
    assert scan(F4_FILE, text) == [], scan(F4_FILE, text)
    text = _f4("b-x", image_first=True)
    assert scan(F4_FILE, text) == [], scan(F4_FILE, text)


def test_f4_dotted_service_does_not_combine() -> None:
    text = _f4("other.service", image_first=False)
    assert scan(F4_FILE, text) == [], scan(F4_FILE, text)


def test_f4_keep_plain_service_name() -> None:
    assert scan(F4_FILE, _f4("b", image_first=False)) == []


F5 = "mcp-gateway --host 0.0.0.0 # user's bind\n"
F5_KEEP = "mcp-gateway --port 1 # user's bind\n"


def test_f5_apostrophe_in_trailing_comment_reports_host() -> None:
    text = sh(F5.strip())
    assert scan("docs/f5.md", text) == expect("docs/f5.md", [(2, "mcp-gateway --host")]), scan("docs/f5.md", text)


def test_f5_keep_port_with_apostrophe_comment() -> None:
    assert scan("docs/f5.md", sh(F5_KEEP.strip())) == []


F6_FILE = "deploy/helm/mcp-gateway/values.schema.json"
# The command sits in a string on line 2, not in the raw punctuation around it.
F6_HOST = """\
{
  "description": "run mcp-gateway --host 0.0.0.0"
}
"""
F6_PORT = """\
{
  "description": "mcp-gateway --port 1"
}
"""
F6_VAR = '{"description": "MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT"}\n'


def test_f6_json_string_reports_host_at_the_string_line() -> None:
    assert scan(F6_FILE, F6_HOST) == expect(F6_FILE, [(2, "mcp-gateway --host")]), scan(F6_FILE, F6_HOST)


def test_f6_keep_json_string_port() -> None:
    assert scan(F6_FILE, F6_PORT) == []


def test_f6_json_hidden_variable_still_reports() -> None:
    assert scan(F6_FILE, F6_VAR) == expect(F6_FILE, [(1, "server.shutdown_timeout")]), scan(F6_FILE, F6_VAR)


F7_CONT = """\
ENTRYPOINT ["mcp-gateway"]
CMD ["--config", "/c", \\
"--host", "0.0.0.0"]
"""
F7_SHELL = 'CMD ["sh", "-c", "mcp-gateway --host 0.0.0.0"]\n'
F7_BEFORE = """\
CMD ["--config", "/c", "--host", "0.0.0.0"]
ENTRYPOINT ["mcp-gateway"]
"""
F7_BEFORE_KEEP = """\
CMD ["--config", "/c", "--port", "1"]
ENTRYPOINT ["mcp-gateway"]
"""
F7_LAST = """\
ENTRYPOINT ["mcp-gateway"]
CMD ["--host", "0.0.0.0"]
ENTRYPOINT ["busybox"]
"""
F7_STAGE = """\
FROM a
CMD ["--host", "0.0.0.0"]
ENTRYPOINT ["mcp-gateway"]
FROM b
ENTRYPOINT ["busybox"]
"""


def test_f7_continued_exec_form_reports_host() -> None:
    assert scan(K8_FILE, F7_CONT) == expect(K8_FILE, [(3, "mcp-gateway --host")]), scan(K8_FILE, F7_CONT)


def test_f7_cmd_shell_c_reports_host() -> None:
    assert scan(K8_FILE, F7_SHELL) == expect(K8_FILE, [(1, "mcp-gateway --host")]), scan(K8_FILE, F7_SHELL)


def test_f7_cmd_before_entrypoint_reports_host() -> None:
    assert scan(K8_FILE, F7_BEFORE) == expect(K8_FILE, [(1, "mcp-gateway --host")]), scan(K8_FILE, F7_BEFORE)


def test_f7_keep_cmd_before_entrypoint_port() -> None:
    assert scan(K8_FILE, F7_BEFORE_KEEP) == []


def test_f7_last_entrypoint_of_the_stage_decides() -> None:
    assert scan(K8_FILE, F7_LAST) == [], scan(K8_FILE, F7_LAST)


def test_f7_stage_boundary_keeps_the_earlier_entrypoint() -> None:
    assert scan(K8_FILE, F7_STAGE) == expect(K8_FILE, [(2, "mcp-gateway --host")]), scan(K8_FILE, F7_STAGE)


# Fence opener is line 1, so the args item is file line 9.
F8 = """\
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: gateway
      image: mcp-gateway:1
      args:
        - "--host"
```
"""
F8_KEEP = F8.replace('- "--host"', '- "--port"')


def test_f8_yaml_fence_reports_host_at_file_line() -> None:
    assert scan("docs/f8.md", F8) == expect("docs/f8.md", [(9, "mcp-gateway --host")]), scan("docs/f8.md", F8)


def test_f8_keep_yaml_fence_port() -> None:
    assert scan("docs/f8.md", F8_KEEP) == []


F9 = "run `mcp-gateway --host 0.0.0.0`"
F9_KEEP = "run `mcp-gateway --port 1`"


def test_f9_yaml_comment_backticks_report_host() -> None:
    text = f"# {F9}\n"
    assert scan("examples/f9.yaml", text) == expect("examples/f9.yaml", [(1, "mcp-gateway --host")]), scan("examples/f9.yaml", text)


def test_f9_txt_backticks_report_host() -> None:
    text = f"{F9}\n"
    assert scan("deploy/f9.txt", text) == expect("deploy/f9.txt", [(1, "mcp-gateway --host")]), scan("deploy/f9.txt", text)


def test_f9_keep_txt_backticks_port() -> None:
    assert scan("deploy/f9.txt", f"{F9_KEEP}\n") == []


def _unit(line: str) -> str:
    return line if line.endswith("\n") else line + "\n"


def test_f10_exec_verbs_report_host() -> None:
    misses = []
    for verb in ("ExecStartPre", "ExecStartPost", "ExecReload", "ExecStop"):
        text = _unit(f"{verb}=/usr/local/bin/mcp-gateway --host 127.0.0.1")
        got = scan(K6_FILE, text)
        want = expect(K6_FILE, [(1, "mcp-gateway --host")])
        if got != want:
            misses.append((verb, got))
    assert not misses, misses


def test_f10_dash_prefix_reports_host() -> None:
    text = _unit("ExecStart=-/usr/local/bin/mcp-gateway --host 127.0.0.1")
    assert scan(K6_FILE, text) == expect(K6_FILE, [(1, "mcp-gateway --host")]), scan(K6_FILE, text)


def test_f10_mixed_prefix_reports_host() -> None:
    text = _unit("ExecStart=-@+!/usr/local/bin/mcp-gateway --host 127.0.0.1")
    assert scan(K6_FILE, text) == expect(K6_FILE, [(1, "mcp-gateway --host")]), scan(K6_FILE, text)


def test_f10_keep_execstartpre_port() -> None:
    assert scan(K6_FILE, _unit("ExecStartPre=/usr/local/bin/mcp-gateway --port 1")) == []


F11_SERVICE = "Environment=MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT=1\n"
F11_SERVICE_KEEP = "Environment=MCP_GATEWAY_SERVER__HOST=1\n"
F11_DOCKER = "ENV MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT=1\n"
F11_DOCKER_KEEP = "ENV MCP_GATEWAY_SERVER__HOST=1\n"
F11_PLIST = """\
<key>EnvironmentVariables</key>
<dict>
  <key>MCP_GATEWAY_SERVER__SHUTDOWN_TIMEOUT</key>
  <string>1</string>
</dict>
"""
F11_PLIST_KEEP = F11_PLIST.replace("SHUTDOWN_TIMEOUT", "HOST")
HIDDEN = (1, "server.shutdown_timeout")


def test_f11_service_environment_reports_shutdown_timeout() -> None:
    assert scan(K6_FILE, F11_SERVICE) == expect(K6_FILE, [HIDDEN]), scan(K6_FILE, F11_SERVICE)


def test_f11_keep_service_environment_host() -> None:
    assert scan(K6_FILE, F11_SERVICE_KEEP) == []


def test_f11_plist_environment_reports_shutdown_timeout() -> None:
    assert scan(K7_FILE, F11_PLIST) == expect(K7_FILE, [(3, "server.shutdown_timeout")]), scan(K7_FILE, F11_PLIST)


def test_f11_keep_plist_environment_host() -> None:
    assert scan(K7_FILE, F11_PLIST_KEEP) == []


def test_f11_dockerfile_env_reports_shutdown_timeout() -> None:
    assert scan(K8_FILE, F11_DOCKER) == expect(K8_FILE, [HIDDEN]), scan(K8_FILE, F11_DOCKER)


def test_f11_keep_dockerfile_env_host() -> None:
    assert scan(K8_FILE, F11_DOCKER_KEEP) == []


def test_f12_doc_set_file_is_scanned_and_a_skip_is_not() -> None:
    root = ss.ROOT.resolve()
    docs = [path.resolve().relative_to(root).as_posix() for path in sd.doc_set()]
    assert docs
    files, errs = ss.shipped_files()
    scanned = rels(files, ss.ROOT)
    assert docs[0] in scanned, (docs[0], errs)
    skipped = "docs/design/surface-4.0.md"
    assert (root / skipped).is_file()
    assert skipped not in docs
    assert skipped not in scanned


def test_r1_repo_errors_on_this_checkout() -> None:
    assert ss.repo_errors() == []


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
