#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Test double for CLI capabilities (MIK-7782). Standard library only.

The FIRST argument is a mode the test fixes in the capability file; it is never
a caller parameter. Everything after it is reported back exactly as received.

  echo                  print {"argv", "stdin", "env_keys", "home", "cwd"} as JSON
  big                   print 3000 "a", every CAP_EXEC_TEST_* env value, 3000 "b" (plain text)
  fail <code>           print a gws-style {"error": {...}} echoing argv, and the
                        same argv plus CAP_EXEC_TEST_* env values on stderr, exit <code>
  unauthorized          print a gws-style 401 error, exit 2
  flood                 write 4 MiB to stdout
  grandchild <pidfile>  start a sleeping grandchild, write its pid, then sleep
  signal                end itself with SIGTERM (unix)
"""
import json
import os
import subprocess
import sys
import time

mode, rest = sys.argv[1], sys.argv[2:]

if mode == "echo":
    data = sys.stdin.read() if not sys.stdin.isatty() else ""
    # Names only (plus HOME): run by hand, this must not print a real environment.
    json.dump({"argv": rest, "stdin": data, "env_keys": sorted(os.environ),
               "home": os.environ.get("HOME", ""), "cwd": os.getcwd(),
               "test_values": {k: v for k, v in os.environ.items() if k.startswith("CAP_EXEC_TEST_")}},
              sys.stdout)
elif mode == "big":
    owned = "".join(v for k, v in os.environ.items() if k.startswith("CAP_EXEC_TEST_"))
    sys.stdout.write("a" * 3000 + owned + "b" * 3000)
elif mode == "fail":
    code = int(rest[0])
    sys.stderr.write("argv=" + " ".join(rest) + "\n")
    # Only test-owned names: run by hand, this must not print a real environment.
    sys.stderr.write("env=" + " ".join(v for k, v in os.environ.items() if k.startswith("CAP_EXEC_TEST_")) + "\n")
    owned = " ".join(v for k, v in os.environ.items() if k.startswith("CAP_EXEC_TEST_"))
    json.dump({"error": {"code": 400, "message": "bad request: " + " ".join(rest) + " " + owned}}, sys.stdout)
    sys.exit(code)
elif mode == "unauthorized":
    json.dump({"error": {"code": 401, "message": "invalid credentials"}}, sys.stdout)
    sys.exit(2)
elif mode == "flood":
    chunk = "x" * 65536
    for _ in range(64):
        sys.stdout.write(chunk)
elif mode == "signal":
    import signal
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(5)
elif mode == "grandchild":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    with open(rest[0], "w") as f:
        f.write(str(child.pid))
    time.sleep(120)
else:
    sys.exit(f"unknown mode {mode}")
