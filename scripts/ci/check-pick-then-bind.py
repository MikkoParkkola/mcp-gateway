#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""No test picks a port, releases it, and binds it later (MIK-8211).

A socket bound to port 0, read for its port, and dropped before the port is
used lets a parallel test's port-0 bind take that port in between. This check
fails on the two shapes that do it, in every `.rs` file under `src/` and
`tests/`:

- a function returning a `u16` or `SocketAddr` read off a socket it binds to
  port 0 (the socket dies when the function returns);
- a port-0 socket that is `drop`ped, with the port read off it used after the
  drop in the same function.

The fixes are to keep the socket alive while the port is used, to let the
product bind port 0 and read back what it got, or to take a port from
`src/test_ports.rs` (`reserved_port`), whose range no port-0 bind can reach.

That module assumes test binaries run one after another, as cargo runs them.
So this check also fails if nextest, which runs test processes in parallel, is
introduced into CI or `.config/` without revisiting `src/test_ports.rs`.

A line that must keep one of these shapes carries
`// port-check: <reason>` on the bind line; the reason is required.

Threat model and stop rule: this is a guard against forgetting, not against
intent. It reads one function at a time and matches exactly the three shapes
above, spelled as `let <socket> = ...bind(... port 0 ...)`, a port read from
`<socket>.local_addr()`, and `drop(<socket>)`. It does not follow a socket or
a port through another variable, another function, a struct field or a
macro, and it does not notice a socket that dies at the end of a block
without an explicit `drop`. A review that names another spelling is not a
defect in this check: the fix for a racy test is the pattern in
`src/test_ports.rs`, and this check is not extended to chase spellings.
"""
import re
import sys
from pathlib import Path

BIND = re.compile(r'let\s+(?:mut\s+)?(\w+)\s*=\s*[^;]*?\bbind\(\s*(?:"[^"]*:0"|\(\s*[^)]*,\s*0\s*\))')
FN = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)\s*(?:->\s*([^{]+))?')
PORT_OF = re.compile(r'let\s+(?:mut\s+)?(\w+)\s*=\s*(\w+)\s*\.\s*local_addr\(\)')
MARKER = re.compile(r'//\s*port-check:\s*\S')
NEXTEST_ACK = "nextest-reviewed"


def code_of(line: str) -> str:
    """`line` without a trailing `//` comment; a `//` inside a string stays."""
    quoted = False
    escaped = False
    for at, ch in enumerate(line):
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
        elif not quoted and line.startswith("//", at):
            return line[:at]
    return line


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def scan_text(text: str, name: str) -> list[str]:
    """Findings in one Rust source text."""
    lines = text.splitlines()
    out = []
    fn_ret = ""
    sockets: dict[str, int] = {}
    ports: dict[str, str] = {}
    dropped: dict[str, int] = {}
    for i, raw in enumerate(lines, 1):
        # Code only: a comment that mentions a port is not a use of it, but
        # the marker lives in the comment, so it is read from the raw line.
        line = code_of(raw)
        fn = FN.match(line)
        if fn:
            fn_ret = (fn.group(3) or "").strip()
            sockets, ports, dropped = {}, {}, {}
        # A rebinding (shadowing `let`) ends the old variable's story.
        for port_var in list(ports):
            if re.search(rf'\blet\s+(?:mut\s+)?{port_var}\b', line):
                del ports[port_var]
        bind = BIND.search(line)
        if bind:
            dropped.pop(bind.group(1), None)
            if not MARKER.search(raw):
                sockets[bind.group(1)] = i
        port = PORT_OF.search(line)
        if port and port.group(2) in sockets:
            ports[port.group(1)] = port.group(2)
        for var, at in list(sockets.items()):
            if re.search(rf'\bdrop\(\s*{var}\s*\)', line):
                if indent_of(line) > indent_of(lines[at - 1]) and var in ports.values():
                    # Dropped inside a closure or task while the code that
                    # read its port goes on using it.
                    out.append(f"{name}:{at}: a socket is dropped in another task while its port is in use")
                    del sockets[var]
                    continue
                dropped[var] = at
            elif re.search(r'\b(u16|SocketAddr)\b', fn_ret) and re.match(
                rf'^\s*(?:return\s+)?{var}\s*\.\s*local_addr\(\)', line
            ):
                out.append(f"{name}:{at}: a helper returns the port of a socket it drops")
                del sockets[var]
        for port_var, socket in ports.items():
            if socket in dropped and re.search(rf'\b{port_var}\b', line) and not re.search(
                rf'\bdrop\(\s*{socket}\s*\)', line
            ):
                out.append(f"{name}:{dropped[socket]}: the port of a dropped socket is used after the drop")
                del dropped[socket]
    return out


def nextest_findings(root: Path) -> list[str]:
    """nextest in CI or config without `src/test_ports.rs` marked reviewed."""
    ports = root / "src" / "test_ports.rs"
    if ports.is_file() and NEXTEST_ACK in ports.read_text():
        return []
    hits = []
    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        if "nextest" in path.read_text():
            hits.append(str(path))
    if (root / ".config" / "nextest.toml").exists():
        hits.append(".config/nextest.toml")
    return [
        f"{hit}: nextest runs test processes in parallel; revisit src/test_ports.rs "
        f"(two processes can share a reserved port) and mark it `{NEXTEST_ACK}`"
        for hit in hits
    ]


SELF_TEST = {
    "helper": ("""
async fn free_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}
""", 1),
    "drop then use": ("""
fn t() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    connect(port);
}
""", 1),
    "use then drop": ("""
fn t() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    check(port);
    drop(listener);
}
""", 0),
    "shadowed after drop": ("""
fn t() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    check(port);
    drop(listener);
    let port = client.local_addr().unwrap().port();
    check(port);
}
""", 0),
    "dropped in a task": ("""
fn t() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = format!("http://localhost:{port}/x");
    spawn(async move {
        drop(listener);
    });
    get(target);
}
""", 1),
    "url string after drop": ("""
fn t() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let url = format!("http://127.0.0.1:{port}");
}
""", 1),
    "marked": ("""
fn t() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap(); // port-check: the drop is the subject
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    connect(port);
}
""", 0),
}


def self_test() -> int:
    failed = 0
    for case, (source, want) in SELF_TEST.items():
        got = len(scan_text(source, case))
        if got != want:
            print(f"self-test {case}: {got} findings, want {want}")
            failed += 1
    print("self-test ok" if not failed else f"self-test: {failed} failed")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    root = Path(".")
    findings = []
    for base in ("src", "tests"):
        for path in sorted((root / base).rglob("*.rs")):
            findings += scan_text(path.read_text(errors="replace"), str(path))
    findings += nextest_findings(root)
    for finding in findings:
        print(finding)
    if findings:
        print(f"{len(findings)} pick-then-bind finding(s); see the docstring for the fixes")
        return 1
    print("no pick-then-bind sites")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
