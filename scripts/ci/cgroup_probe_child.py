#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Throwaway probe child (R1): reports where it runs and touches 1 GiB, so the gate's memory.peak has a known floor."""
import os

with open("/proc/self/cgroup", encoding="utf-8") as f:
    print("child cgroup:", f.read().strip())
print("child uid:", os.getuid(), "HOME:", os.environ.get("HOME"))
block = b"\x01" * (1 << 30)  # filled, so every page is touched
print("child allocated MiB:", len(block) // (1 << 20))
