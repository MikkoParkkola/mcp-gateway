"""Throwaway probe only, never merged: a release suite that always fails, so the proof run shows the cargo steps
still run after a red suite."""
import sys

sys.exit("probe-only suite: red on purpose")
