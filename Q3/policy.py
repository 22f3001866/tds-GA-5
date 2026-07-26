"""Deterministic pre-tool-call guardrail policy engine."""

from __future__ import annotations

import base64
import posixpath
import re
import shlex
from typing import Literal
from urllib.parse import urlparse

HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET_FILE = "/home/agent/service-account.json"
ALLOWED_WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = frozenset(
    {"raw.githubusercontent.com", "objects.githubusercontent.com"}
)

Decision = Literal["allow", "block"]

_PATH_FRAGMENT_RE = re.compile(
    r"""
    (?:
        (?:\$HOME|\$\{HOME\}|~)(?:/[^\s'"<>|&;()$`\\]*)?
        | /[^\s'"<>|&;()$`\\]+
        | \.\.?/[^\s'"<>|&;()$`\\]*
        | [A-Za-z0-9._-]+(?:/\.\./|/)[^\s'"<>|&;()$`\\]*
    )
    """,
    re.VERBOSE,
)
_SECRET_NAME_RE = re.compile(r"""[^\s'"<>|&;()$`\\]*service-account\.json""")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_CMD_SUB_RE = re.compile(r"\$\(([^)]*)\)|`([^`]*)`")
_REDIRECT_RE = re.compile(r"(?:^|[\s|&;])(?:\d*>>?|\d*<<?)\s*([^\s|&;]+)")
_TEE_RE = re.compile(r"\btee(?:\s+-a)?\s+([^\s|&;]+)")


def expand_home(path: str) -> str:
    if path == "~":
        return HOME
    if path.startswith("~/"):
        return HOME + path[1:]
    path = re.sub(r"\$\{HOME\}", HOME, path)
    path = re.sub(r"\$HOME", HOME, path)
    return path


def normalize_path(path: str, cwd: str = WORKSPACE) -> str:
    path = expand_home(path.strip().strip("'\""))
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    return posixpath.normpath(path)


def is_secret_path(path: str, cwd: str = WORKSPACE) -> bool:
    return normalize_path(path, cwd) == SECRET_FILE


def is_allowed_write_path(path: str, cwd: str = WORKSPACE) -> bool:
    normalized = normalize_path(path, cwd)
    return normalized == ALLOWED_WRITE_ROOT or normalized.startswith(
        f"{ALLOWED_WRITE_ROOT}/"
    )


def _try_decode_base64(text: str) -> list[str]:
    decoded: list[str] = []
    for match in _B64_RE.findall(text):
        try:
            raw = base64.b64decode(match, validate=True)
            decoded.append(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return decoded


def _extract_paths(text: str) -> set[str]:
    paths: set[str] = set()
    for match in _PATH_FRAGMENT_RE.findall(text):
        paths.add(match)
    for match in _SECRET_NAME_RE.findall(text):
        paths.add(match)
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()
    for token in tokens:
        if (
            token.startswith("/")
            or token.startswith("./")
            or token.startswith("../")
            or token.startswith("~")
            or "$HOME" in token
            or "service-account.json" in token
        ):
            paths.add(token)
    return paths


def _extract_write_targets(text: str) -> set[str]:
    targets: set[str] = set()
    for match in _REDIRECT_RE.findall(text):
        targets.add(match)
    for match in _TEE_RE.findall(text):
        targets.add(match)

    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()

    if tokens:
        cmd = posixpath.basename(tokens[0])
        if cmd in {"touch", "sponge"} and len(tokens) > 1:
            targets.add(tokens[-1])
        if cmd in {"cp", "mv", "install"} and len(tokens) >= 3:
            targets.add(tokens[-1])

    return targets


def _scan_text(
    text: str, *, depth: int = 0, cwd: str = WORKSPACE
) -> tuple[Decision, str] | None:
    if depth > 6:
        return None

    for decoded in _try_decode_base64(text):
        hit = _scan_text(decoded, depth=depth + 1, cwd=cwd)
        if hit is not None:
            return hit

    for group in _CMD_SUB_RE.findall(text):
        inner = group[0] or group[1]
        hit = _scan_text(inner, depth=depth + 1, cwd=cwd)
        if hit is not None:
            return hit

    for path in _extract_paths(text):
        if is_secret_path(path, cwd):
            return (
                "block",
                "Reading /home/agent/service-account.json is not permitted.",
            )

    for path in _extract_write_targets(text):
        if path in ("&", ">&", ">&2", "/dev/null"):
            continue
        if not is_allowed_write_path(path, cwd):
            return (
                "block",
                f"Writes are only permitted inside {ALLOWED_WRITE_ROOT}/.",
            )

    return None


def evaluate_bash(command: str) -> tuple[Decision, str]:
    violation = _scan_text(command)
    if violation is not None:
        return violation
    return ("allow", "Bash command complies with the agent security policy.")


def evaluate_write_file(path: str) -> tuple[Decision, str]:
    if is_secret_path(path):
        return (
            "block",
            "Reading /home/agent/service-account.json is not permitted.",
        )
    if is_allowed_write_path(path):
        return ("allow", f"Writing under {ALLOWED_WRITE_ROOT}/ is permitted.")
    return (
        "block",
        f"Writes are only permitted inside {ALLOWED_WRITE_ROOT}/.",
    )


def evaluate_http_request(url: str) -> tuple[Decision, str]:
    parsed = urlparse(url)

    if parsed.scheme in {"", "file"}:
        target = parsed.path or url
        if is_secret_path(target):
            return (
                "block",
                "Reading /home/agent/service-account.json is not permitted.",
            )
        return ("allow", "Local file access outside the restricted secret is permitted.")

    if parsed.scheme not in {"http", "https"}:
        return (
            "block",
            "Only HTTP(S) requests to approved GitHub hosts are allowed.",
        )

    host = parsed.hostname
    if host is None:
        return ("block", "HTTP request has no valid hostname.")

    host = host.rstrip(".")
    if host not in ALLOWED_HOSTS:
        return (
            "block",
            f"Outbound HTTP to {host} is not on the allowed host list.",
        )

    return ("allow", f"Outbound HTTP to {host} is permitted.")


def evaluate_tool_call(payload: dict) -> tuple[Decision, str]:
    tool = payload.get("tool")

    if tool == "bash":
        command = payload.get("command", "")
        return evaluate_bash(command)

    if tool == "write_file":
        path = payload.get("path", "")
        return evaluate_write_file(path)

    if tool == "http_request":
        url = payload.get("url", "")
        return evaluate_http_request(url)

    return ("block", f"Unknown tool: {tool!r}.")
