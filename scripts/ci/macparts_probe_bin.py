"""Throwaway probe helper (never merged): print the lib test executable from cargo's JSON messages."""
import json
import sys

found = ""
for line in open(sys.argv[1]):
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    target = msg.get("target", {})
    if (msg.get("reason") == "compiler-artifact" and msg.get("executable")
            and msg.get("profile", {}).get("test") and "lib" in target.get("kind", [])):
        found = msg["executable"]
print(found)
