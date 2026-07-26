"""Local tests for the MCP challenge solver."""

import hashlib

from challenge import NORMALIZED_EMAIL, challenge_response_from_headers, solve_challenge_text


def test_formula_matches_sha256_prefix() -> None:
    challenge = "0123456789abcdef0123456789abcdef"
    email = "learner@example.com"
    expected = hashlib.sha256(f"{challenge}:{email}".encode()).hexdigest()[:16]
    assert len(expected) == 16
    assert expected == hashlib.sha256(f"{challenge}:{email}".encode()).hexdigest()[:16]


def test_registered_email_response() -> None:
    challenge = "0123456789abcdef0123456789abcdef"
    expected = hashlib.sha256(f"{challenge}:{NORMALIZED_EMAIL}".encode()).hexdigest()[:16]
    assert solve_challenge_text(challenge) == expected


def test_response_is_sixteen_hex_chars() -> None:
    answer = solve_challenge_text("abcdef0123456789abcdef0123456789ab")
    assert len(answer) == 16
    assert answer == answer.lower()
    assert all(char in "0123456789abcdef" for char in answer)


def test_header_lookup_is_case_insensitive() -> None:
    headers = {
        "X-Exam-Challenge": "abcdef0123456789abcdef0123456789ab",
        "X-Exam-Timestamp": "123",
    }
    assert challenge_response_from_headers(headers) == solve_challenge_text(
        "abcdef0123456789abcdef0123456789ab"
    )


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    print(f"\nAll {len(tests)} tests passed.")
