"""Challenge response computation for the exam MCP tool."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

NORMALIZED_EMAIL = "22f3001866@ds.study.iitm.ac.in"


def solve_challenge_text(challenge: str) -> str:
    payload = f"{challenge}:{NORMALIZED_EMAIL}"
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def challenge_response_from_headers(headers: Mapping[str, str]) -> str:
    normalized = {key.lower(): value for key, value in headers.items()}
    challenge = normalized.get("x-exam-challenge", "").strip()
    if not challenge:
        raise ValueError("Missing X-Exam-Challenge header.")
    return solve_challenge_text(challenge)
