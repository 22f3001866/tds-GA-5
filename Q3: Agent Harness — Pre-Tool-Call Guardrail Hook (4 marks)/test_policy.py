"""Local tests for the guardrail policy engine."""

import base64

from policy import evaluate_bash, evaluate_http_request, evaluate_tool_call, evaluate_write_file


def assert_block(fn, *args, **kwargs):
    decision, _ = fn(*args, **kwargs)
    assert decision == "block"


def assert_allow(fn, *args, **kwargs):
    decision, _ = fn(*args, **kwargs)
    assert decision == "allow"


def test_direct_secret_read():
    assert_block(evaluate_bash, "cat /home/agent/service-account.json")


def test_tilde_expansion():
    assert_block(evaluate_bash, "cat ~/service-account.json")


def test_home_env_var():
    assert_block(evaluate_bash, "cat $HOME/service-account.json")


def test_relative_traversal():
    assert_block(evaluate_bash, "cat ../service-account.json")


def test_base64_wrapped():
    cmd = "cat /home/agent/service-account.json"
    encoded = base64.b64encode(cmd.encode()).decode()
    assert_block(evaluate_bash, f"echo {encoded} | base64 -d | bash")


def test_allowed_workspace_listing():
    assert_allow(evaluate_bash, "ls -la /home/agent/workspace")


def test_allowed_other_read():
    assert_allow(evaluate_bash, "cat /etc/passwd")


def test_write_inside_reports():
    assert_allow(evaluate_write_file, "/srv/reports/summary.txt")
    assert_block(evaluate_write_file, "summary.txt")


def test_write_traversal_escape():
    assert_block(evaluate_write_file, "/srv/reports/../../etc/passwd")


def test_bash_write_outside():
    assert_block(evaluate_bash, "echo hi > /tmp/out.txt")


def test_bash_write_inside():
    assert_allow(evaluate_bash, "echo hi > /srv/reports/out.txt")


def test_allowed_github_host():
    assert_allow(
        evaluate_http_request,
        "https://raw.githubusercontent.com/org/repo/main/file.txt",
    )


def test_domain_confusion():
    assert_block(
        evaluate_http_request,
        "https://raw.githubusercontent.com.evil.example/steal",
    )


def test_subdomain_confusion():
    assert_block(
        evaluate_http_request,
        "https://notraw.githubusercontent.com/file",
    )


def test_endpoint_shapes():
    assert_allow(
        evaluate_tool_call,
        {"tool": "bash", "command": "ls -la /home/agent/workspace"},
    )
    assert_block(
        evaluate_tool_call,
        {"tool": "write_file", "path": "/etc/passwd", "content": "x"},
    )
    assert_allow(
        evaluate_tool_call,
        {
            "tool": "http_request",
            "method": "GET",
            "url": "https://objects.githubusercontent.com/pkg/release",
        },
    )


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"\nAll {len(tests)} tests passed.")
