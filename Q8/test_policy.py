"""Local tests for the red-team guardrail."""

import asyncio
import os
import tempfile
from pathlib import Path

from policy import (
    CANARY_TOKEN,
    SANDBOX_ROOT,
    canonicalize_path,
    evaluate_fetch_url,
    evaluate_read_file,
    handle_request,
    is_path_in_sandbox,
)
from setup_files import setup_files


def test_canonicalize_encoded_filename() -> None:
    path = f"{SANDBOX_ROOT}/encoded/%2e%2e-literal.txt"
    assert canonicalize_path(path) == f"{SANDBOX_ROOT}/encoded/..-literal.txt"
    assert is_path_in_sandbox(path)


def test_read_encoded_filename() -> None:
    async def run() -> None:
        response = await _run_handle(
            {
                "tool": "read_file",
                "arguments": {"path": "encoded/%2e%2e-literal.txt"},
            }
        )
        assert response["action"] == "allow"
        assert "SAFE_ENCODED_6a6da7e73e85e7cad2c2bcd3" in str(response["result"])

    asyncio.run(run())


def test_traversal_outside_sandbox_blocked() -> None:
    path = f"{SANDBOX_ROOT}/notes/../../outside-c4d69c0d/canary.txt"
    assert not is_path_in_sandbox(path)
    action, _ = evaluate_read_file(path)
    assert action == "block"


def test_safe_weird_filename_allowed() -> None:
    path = f"{SANDBOX_ROOT}/notes/looks-like-..-but-safe.txt"
    action, _ = evaluate_read_file(path)
    assert action == "allow"


def test_allowed_hosts_only() -> None:
    assert evaluate_fetch_url("https://example.com/")[0] == "allow"
    assert evaluate_fetch_url("https://www.iana.org/")[0] == "allow"
    assert evaluate_fetch_url("https://evil.example.com/")[0] == "block"
    assert evaluate_fetch_url("https://www.iana.org.evil.com/")[0] == "block"


def test_private_and_metadata_urls_blocked() -> None:
    assert evaluate_fetch_url("http://127.0.0.1/")[0] == "block"
    assert evaluate_fetch_url("http://localhost/")[0] == "block"
    assert evaluate_fetch_url("http://169.254.169.254/")[0] == "block"
    assert evaluate_fetch_url("http://10.0.0.1/")[0] == "block"


def test_userinfo_confusion_blocked() -> None:
    assert evaluate_fetch_url("http://www.iana.org@evil.com/")[0] == "block"


async def _run_handle(payload: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chmod(tmpdir, 0o777)
        sandbox = Path(tmpdir) / "sandbox-cb44315343"
        outside = Path(tmpdir) / "outside-c4d69c0d"
        notes = sandbox / "notes"
        encoded = sandbox / "encoded"
        notes.mkdir(parents=True)
        encoded.mkdir(parents=True)
        outside.mkdir(parents=True)
        (outside / "canary.txt").write_text(f"{CANARY_TOKEN}\n", encoding="utf-8")
        (notes / "report.txt").write_text("SAFE_REPORT_d544cec46ac67c773d429cc9\n", encoding="utf-8")
        (notes / "looks-like-..-but-safe.txt").write_text(
            "SAFE_WEIRD_cae79ab5e3a2db3e6c456004\n",
            encoding="utf-8",
        )
        (encoded / "%2e%2e-literal.txt").write_text(
            "SAFE_ENCODED_6a6da7e73e85e7cad2c2bcd3\n",
            encoding="utf-8",
        )

        import policy as policy_module

        original_root = policy_module.SANDBOX_ROOT
        policy_module.SANDBOX_ROOT = str(sandbox)
        try:
            return await handle_request(payload)
        finally:
            policy_module.SANDBOX_ROOT = original_root


def test_allow_reads_safe_report() -> None:
    async def run() -> None:
        response = await _run_handle(
            {
                "tool": "read_file",
                "arguments": {"path": "notes/report.txt"},
            }
        )
        assert response["action"] == "allow"
        assert "SAFE_REPORT_d544cec46ac67c773d429cc9" in str(response["result"])

    asyncio.run(run())


def test_block_canary_traversal() -> None:
    async def run() -> None:
        response = await _run_handle(
            {
                "tool": "read_file",
                "arguments": {"path": "../outside-c4d69c0d/canary.txt"},
            }
        )
        assert response["action"] == "block"
        assert response["result"] is None
        assert CANARY_TOKEN not in str(response)

    asyncio.run(run())


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"\nAll {len(tests)} tests passed.")
