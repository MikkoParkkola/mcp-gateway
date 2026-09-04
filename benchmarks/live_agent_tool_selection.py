#!/usr/bin/env python3
"""Run MIK-6977's real Codex/MCP selection benchmark."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SERVER = Path(__file__).with_name("live_agent_mcp_server.py").resolve()


@dataclass
class TrialResult:
    mode: str
    n_tools: int
    trial: int
    expected_tool: str
    selected_tool: str | None
    selection_correct: bool
    task_success: bool
    tool_calls: int
    extra_turns: int
    latency_ms: float
    input_tokens: int | None
    cached_input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    process_exit: int
    final_message: str
    errors: list[str]
    warnings: list[str]
    stderr_tail: str
    turn_completed_events: int


def parse_events(
    stdout: str,
) -> tuple[dict[str, int], int, str, list[str], list[str]]:
    usage: dict[str, int] = {}
    turn_completed_events = 0
    messages: list[str] = []
    errors: list[str] = []
    warnings: list[str] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "turn.completed":
            turn_completed_events += 1
            for key, value in (event.get("usage") or {}).items():
                if isinstance(value, int):
                    usage[key] = usage.get(key, 0) + value
        item = event.get("item") or {}
        if (
            event.get("type") == "item.completed"
            and item.get("type") == "agent_message"
        ):
            messages.append(str(item.get("text") or ""))
        if event.get("type") == "item.completed" and item.get("type") == "error":
            message = str(item.get("message") or "")
            if message.startswith(
                ("Under-development features enabled:", "Skill descriptions were")
            ):
                warnings.append(message)
            else:
                errors.append(message)
    return usage, turn_completed_events, "\n".join(messages), errors, warnings


def read_calls(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], [f"call log was not created: {path}"]
    calls = []
    errors = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"invalid call log line {line_number}: {error.msg}")
            continue
        if event.get("event") == "tool_call":
            calls.append(event)
    return calls, errors


def target_index(n_tools: int, trial: int) -> int:
    return (trial * 131 + 7) % n_tools


def run_trial(
    mode: str, n_tools: int, trial: int, model: str, timeout: int
) -> TrialResult:
    expected_index = target_index(n_tools, trial)
    expected_tool = f"archive_case_{expected_index:03d}"
    trial_id = f"{mode}_n{n_tools}_t{trial}"
    proof = f"BENCH_OK_{trial_id}"
    with tempfile.TemporaryDirectory(prefix="mik6977-") as scratch:
        scratch_path = Path(scratch)
        call_log = scratch_path / "calls.jsonl"
        server_args = [
            str(SERVER),
            "--mode",
            mode,
            "--count",
            str(n_tools),
            "--expected-index",
            str(expected_index),
            "--trial-id",
            trial_id,
            "--log",
            str(call_log),
        ]
        prompt = (
            f"Retrieve the archived compliance evidence for case {expected_index:03d}. "
            "Use only the bench MCP tools, never the shell or memory. "
            "Finish only after a tool returns a BENCH_OK proof marker, then include that exact marker."
        )
        command = [
            "codex",
            "exec",
            "--json",
            "--color",
            "never",
            "--ephemeral",
            "--ignore-user-config",
            "--disable",
            "plugins",
            "--disable",
            "apps",
            "--disable",
            "memories",
            "--enable",
            "skip_host_skill_discovery",
            "--model",
            model,
            "--approve-for-me",
            "--skip-git-repo-check",
            "--config",
            f"mcp_servers.bench.command={json.dumps(sys.executable)}",
            "--config",
            f"mcp_servers.bench.args={json.dumps(server_args)}",
            prompt,
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=scratch,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            process_exit = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as error:
            process_exit = 124
            stdout = error.stdout or ""
            stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        elapsed_ms = (time.perf_counter() - started) * 1000
        usage, turn_events, final_message, event_errors, event_warnings = parse_events(
            stdout
        )
        calls, call_log_errors = read_calls(call_log)
        selected_tool = next(
            (
                str(call.get("selected_tool"))
                for call in reversed(calls)
                if mode == "direct" or call.get("name") == "gateway_invoke"
            ),
            None,
        )
        selection_correct = selected_tool == expected_tool
        task_success = (
            selection_correct and proof in final_message and process_exit == 0
        )
        errors = [*event_errors, *call_log_errors]
        if process_exit != 0 and stderr.strip():
            errors.append(stderr.strip()[-500:])
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        return TrialResult(
            mode=mode,
            n_tools=n_tools,
            trial=trial,
            expected_tool=expected_tool,
            selected_tool=selected_tool,
            selection_correct=selection_correct,
            task_success=task_success,
            tool_calls=len(calls),
            extra_turns=max(0, len(calls) - 1),
            latency_ms=round(elapsed_ms, 1),
            input_tokens=input_tokens,
            cached_input_tokens=usage.get("cached_input_tokens"),
            output_tokens=output_tokens,
            total_tokens=(input_tokens + output_tokens)
            if input_tokens is not None and output_tokens is not None
            else None,
            process_exit=process_exit,
            final_message=final_message,
            errors=errors,
            warnings=event_warnings,
            stderr_tail=stderr.strip()[-500:],
            turn_completed_events=turn_events,
        )


def ratio(values: list[bool]) -> float:
    return sum(values) / len(values) if values else 0.0


def summarize(results: list[TrialResult]) -> list[dict[str, Any]]:
    rows = []
    for n_tools in sorted({result.n_tools for result in results}):
        row: dict[str, Any] = {"n_tools": n_tools}
        for mode in ("direct", "meta"):
            selected = [r for r in results if r.n_tools == n_tools and r.mode == mode]
            token_values = [
                r.input_tokens for r in selected if r.input_tokens is not None
            ]
            total_token_values = [
                r.total_tokens for r in selected if r.total_tokens is not None
            ]
            row[mode] = {
                "samples": len(selected),
                "selection_accuracy": ratio([r.selection_correct for r in selected]),
                "task_success_rate": ratio([r.task_success for r in selected]),
                "latency_ms_median": round(
                    statistics.median(r.latency_ms for r in selected), 1
                ),
                "tool_calls_mean": round(
                    statistics.mean(r.tool_calls for r in selected), 2
                ),
                "extra_turns_mean": round(
                    statistics.mean(r.extra_turns for r in selected), 2
                ),
                "input_tokens_mean": round(statistics.mean(token_values), 1)
                if token_values
                else None,
                "total_task_tokens_mean": (
                    round(statistics.mean(total_token_values), 1)
                    if total_token_values
                    else None
                ),
            }
        direct_tokens = row["direct"]["input_tokens_mean"]
        meta_tokens = row["meta"]["input_tokens_mean"]
        row["measured_input_token_savings_percent"] = (
            round((1 - meta_tokens / direct_tokens) * 100, 2)
            if direct_tokens and meta_tokens
            else None
        )
        rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", default="50,100,200,500")
    parser.add_argument("--trials", type=int, default=2)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()
    sizes = [int(value) for value in args.sizes.split(",")]
    if any(size < 1 or size > 500 for size in sizes):
        parser.error("sizes must be between 1 and 500")
    if args.trials < 1:
        parser.error("trials must be positive")

    specs = [
        (mode, size, trial)
        for size in sizes
        for trial in range(args.trials)
        for mode in ("direct", "meta")
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(run_trial, mode, size, trial, args.model, args.timeout)
            for mode, size, trial in specs
        ]
        results = [future.result() for future in futures]
    results.sort(key=lambda row: (row.n_tools, row.trial, row.mode))

    report = {
        "schema_version": "mik-6977.live-agent.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "agent": {"runner": "codex exec", "model": args.model},
        "method": {
            "catalog_sizes": sizes,
            "trials_per_mode_and_size": args.trials,
            "direct_surface": "all generated tools exposed",
            "meta_surface": "two synthetic tools: gateway_search_tools plus gateway_invoke",
            "system_under_test": "isolated benchmark MCP server; the mcp-gateway binary is not in the request path",
            "search_behavior": "extract the requested case number; fall back to the runner-provided expected index when no number is present",
            "host_configuration": "plugins and apps disabled; memories and host skill discovery disabled; the host may still report shortened-skill and under-development-feature warnings",
            "latency_scope": "full codex process wall time",
            "token_source": "codex turn.completed usage input_tokens and output_tokens",
            "success_rule": "correct final tool plus exact returned proof marker in final answer",
        },
        "summary": summarize(results),
        "trials": [asdict(result) for result in results],
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    if any(
        result.process_exit != 0
        or result.input_tokens is None
        or result.output_tokens is None
        or result.total_tokens is None
        or not result.selection_correct
        or not result.task_success
        or bool(result.errors)
        for result in results
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
