"""Deterministic run-budget and loop-guard policy engine."""

from __future__ import annotations

import json
from typing import Any, Literal

Decision = Literal["continue", "halt"]


def _normalize_string(value: str) -> str:
    return " ".join(value.split())


def canonicalize_args(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: canonicalize_args(item)
            for key, item in sorted(value.items())
            if key != "client_ts"
        }
    if isinstance(value, list):
        return [canonicalize_args(item) for item in value]
    if isinstance(value, str):
        return _normalize_string(value)
    return value


def step_signature(step: dict[str, Any]) -> str:
    tool = step.get("tool", "")
    args = canonicalize_args(step.get("args", {}))
    return json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"))


def _total_tokens_used(steps: list[dict[str, Any]]) -> int:
    return sum(int(step.get("tokens_used", 0) or 0) for step in steps)


def _has_trailing_identical_calls(steps: list[dict[str, Any]], minimum: int = 3) -> bool:
    if len(steps) < minimum:
        return False

    signatures = [step_signature(step) for step in steps]
    trailing = signatures[-1]
    count = 1

    for signature in reversed(signatures[:-1]):
        if signature != trailing:
            break
        count += 1

    return count >= minimum


def _has_trailing_two_step_cycle(steps: list[dict[str, Any]], minimum_steps: int = 6) -> bool:
    if len(steps) < minimum_steps:
        return False

    signatures = [step_signature(step) for step in steps]

    for length in range(minimum_steps, len(signatures) + 1):
        suffix = signatures[-length:]
        if length % 2 != 0:
            continue

        first, second = suffix[0], suffix[1]
        if first == second:
            continue

        if all(
            suffix[index] == (first if index % 2 == 0 else second)
            for index in range(length)
        ):
            return True

    return False


def evaluate_run_control(payload: dict[str, Any]) -> tuple[Decision, str]:
    budget_tokens = int(payload.get("budget_tokens", 50000))
    steps = payload.get("steps", [])
    if not isinstance(steps, list):
        steps = []

    total_tokens = _total_tokens_used(steps)
    if total_tokens >= budget_tokens:
        return (
            "halt",
            f"Cumulative tokens_used ({total_tokens}) has reached the budget ({budget_tokens}).",
        )

    if _has_trailing_identical_calls(steps):
        return (
            "halt",
            "The same tool was called 3 or more times in a row with identical arguments.",
        )

    if _has_trailing_two_step_cycle(steps):
        return (
            "halt",
            "The trailing steps show a repeating two-step tool/args cycle.",
        )

    if not steps:
        return (
            "continue",
            "Fresh run is within budget and shows no loop pattern.",
        )

    return (
        "continue",
        "Run is within budget and shows no loop pattern.",
    )
