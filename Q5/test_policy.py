"""Local tests for the run-budget and loop-guard policy engine."""

from policy import evaluate_run_control


def assert_decision(payload: dict, expected: str) -> None:
    decision, _ = evaluate_run_control(payload)
    assert decision == expected, f"expected {expected}, got {decision}"


def test_empty_history_continues() -> None:
    assert_decision({"budget_tokens": 50000, "steps": []}, "continue")


def test_budget_exceeded() -> None:
    payload = {
        "budget_tokens": 20000,
        "steps": [
            {"step_number": 1, "tool": "fetch_page", "args": {"url": "https://example.com/1"}, "tokens_used": 9000},
            {"step_number": 2, "tool": "summarize", "args": {"text": "..."}, "tokens_used": 7000},
            {"step_number": 3, "tool": "fetch_page", "args": {"url": "https://example.com/2"}, "tokens_used": 5000},
        ],
    }
    assert_decision(payload, "halt")


def test_budget_exactly_at_boundary() -> None:
    payload = {
        "budget_tokens": 5000,
        "steps": [
            {"step_number": 1, "tool": "a", "args": {}, "tokens_used": 5000},
        ],
    }
    assert_decision(payload, "halt")


def test_budget_one_below_boundary() -> None:
    payload = {
        "budget_tokens": 5000,
        "steps": [
            {"step_number": 1, "tool": "a", "args": {}, "tokens_used": 4999},
        ],
    }
    assert_decision(payload, "continue")


def test_legitimate_pagination_continues() -> None:
    payload = {
        "budget_tokens": 20000,
        "steps": [
            {"step_number": 1, "tool": "list_items", "args": {"page": 1}, "tokens_used": 1000},
            {"step_number": 2, "tool": "list_items", "args": {"page": 2}, "tokens_used": 1000},
            {"step_number": 3, "tool": "list_items", "args": {"page": 3}, "tokens_used": 1000},
        ],
    }
    assert_decision(payload, "continue")


def test_two_identical_calls_do_not_halt() -> None:
    payload = {
        "budget_tokens": 50000,
        "steps": [
            {"step_number": 1, "tool": "ping", "args": {"target": "db"}, "tokens_used": 100},
            {"step_number": 2, "tool": "ping", "args": {"target": "db"}, "tokens_used": 100},
        ],
    }
    assert_decision(payload, "continue")


def test_three_identical_calls_halt() -> None:
    payload = {
        "budget_tokens": 50000,
        "steps": [
            {"step_number": 1, "tool": "ping", "args": {"target": "db"}, "tokens_used": 100},
            {"step_number": 2, "tool": "ping", "args": {"target": "db"}, "tokens_used": 100},
            {"step_number": 3, "tool": "ping", "args": {"target": "db"}, "tokens_used": 100},
        ],
    }
    assert_decision(payload, "halt")


def test_cosmetic_argument_differences_still_loop() -> None:
    payload = {
        "budget_tokens": 50000,
        "steps": [
            {
                "step_number": 1,
                "tool": "fetch",
                "args": {"url": "https://x.com", "client_ts": "t1"},
                "tokens_used": 100,
            },
            {
                "step_number": 2,
                "tool": "fetch",
                "args": {"client_ts": "t2", "url": "https://x.com"},
                "tokens_used": 100,
            },
            {
                "step_number": 3,
                "tool": "fetch",
                "args": {"url": "  https://x.com  ", "client_ts": "t3"},
                "tokens_used": 100,
            },
        ],
    }
    assert_decision(payload, "halt")


def test_two_step_cycle_halt() -> None:
    payload = {
        "budget_tokens": 50000,
        "steps": [
            {"step_number": 1, "tool": "read", "args": {"path": "a"}, "tokens_used": 50},
            {"step_number": 2, "tool": "write", "args": {"path": "b"}, "tokens_used": 50},
            {"step_number": 3, "tool": "read", "args": {"path": "a"}, "tokens_used": 50},
            {"step_number": 4, "tool": "write", "args": {"path": "b"}, "tokens_used": 50},
            {"step_number": 5, "tool": "read", "args": {"path": "a"}, "tokens_used": 50},
            {"step_number": 6, "tool": "write", "args": {"path": "b"}, "tokens_used": 50},
        ],
    }
    assert_decision(payload, "halt")


def test_loop_halts_with_budget_remaining() -> None:
    payload = {
        "budget_tokens": 50000,
        "steps": [
            {"step_number": 1, "tool": "noop", "args": {"x": 1}, "tokens_used": 10},
            {"step_number": 2, "tool": "noop", "args": {"x": 1}, "tokens_used": 10},
            {"step_number": 3, "tool": "noop", "args": {"x": 1}, "tokens_used": 10},
        ],
    }
    assert_decision(payload, "halt")


def test_non_consecutive_repeats_continue() -> None:
    payload = {
        "budget_tokens": 50000,
        "steps": [
            {"step_number": 1, "tool": "fetch", "args": {"id": 1}, "tokens_used": 100},
            {"step_number": 2, "tool": "fetch", "args": {"id": 2}, "tokens_used": 100},
            {"step_number": 3, "tool": "summarize", "args": {}, "tokens_used": 100},
            {"step_number": 4, "tool": "fetch", "args": {"id": 3}, "tokens_used": 100},
        ],
    }
    assert_decision(payload, "continue")


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"\nAll {len(tests)} tests passed.")
