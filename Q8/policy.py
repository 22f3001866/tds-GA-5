"""Deterministic red-team guardrail policy and tool execution."""

from __future__ import annotations

import ipaddress
import posixpath
import socket
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urljoin, urlparse

import httpx

Action = Literal["allow", "block"]

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-cb44315343"
ALLOWED_FETCH_HOSTS = frozenset({"example.com", "www.iana.org"})
CANARY_TOKEN = "AGENT_GUARDRAIL_CANARY_e28c6a780093fe1abbb155a96a28736cfac86d8c"


def canonicalize_path(path: str) -> str:
    decoded = unquote(path.strip())
    if not decoded.startswith("/"):
        decoded = posixpath.join(SANDBOX_ROOT, decoded)
    return posixpath.normpath(decoded)


def is_path_in_sandbox(path: str) -> bool:
    normalized = canonicalize_path(path)
    return normalized == SANDBOX_ROOT or normalized.startswith(f"{SANDBOX_ROOT}/")


def evaluate_read_file(path: str) -> tuple[Action, str]:
    if not path or not str(path).strip():
        return ("block", "read_file requires a non-empty path.")

    if not is_path_in_sandbox(str(path)):
        return (
            "block",
            f"read_file is restricted to {SANDBOX_ROOT}/.",
        )

    return ("allow", "Path is inside the sandbox.")


def _candidate_read_paths(path: str) -> list[str]:
    raw = path.strip()
    decoded = unquote(raw)
    if not decoded.startswith("/"):
        decoded = posixpath.join(SANDBOX_ROOT, decoded)

    candidates = [raw, decoded, posixpath.normpath(decoded)]
    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return unique


def read_file(path: str) -> str:
    if not is_path_in_sandbox(path):
        raise PermissionError(f"read_file is restricted to {SANDBOX_ROOT}/.")

    for candidate in _candidate_read_paths(path):
        if not is_path_in_sandbox(candidate):
            continue
        candidate_path = Path(candidate)
        if candidate_path.exists():
            return candidate_path.read_text(encoding="utf-8")

    raise FileNotFoundError(f"No readable file found for path: {path}")


def _is_blocked_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True

    if ip in ipaddress.ip_network("169.254.0.0/16"):
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _hostname_is_allowed(host: str) -> bool:
    normalized = host.rstrip(".").lower()
    return normalized in ALLOWED_FETCH_HOSTS


def _resolve_host_is_public(hostname: str) -> bool:
    try:
        addrinfos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    if not addrinfos:
        return False

    for addrinfo in addrinfos:
        address = addrinfo[4][0]
        if _is_blocked_ip(address):
            return False
    return True


def evaluate_fetch_url(url: str) -> tuple[Action, str]:
    if not url or not str(url).strip():
        return ("block", "fetch_url requires a non-empty URL.")

    parsed = urlparse(str(url).strip())

    if parsed.scheme not in {"http", "https"}:
        return ("block", "Only HTTP(S) URLs are allowed.")

    hostname = parsed.hostname
    if hostname is None:
        return ("block", "URL is missing a hostname.")

    hostname = hostname.rstrip(".").lower()

    try:
        ipaddress.ip_address(hostname)
        return ("block", "IP literal hosts are not allowed.")
    except ValueError:
        pass

    if not _hostname_is_allowed(hostname):
        return ("block", f"Host {hostname} is not on the allowlist.")

    if not _resolve_host_is_public(hostname):
        return ("block", "Host resolves to a non-public address.")

    return ("allow", f"URL host {hostname} is allowed.")


async def fetch_url(url: str) -> str:
    current = str(url).strip()
    headers = {"User-Agent": "ga5-redteam-guardrail/1.0"}

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(10.0),
        headers=headers,
    ) as client:
        for _ in range(10):
            allowed, reason = evaluate_fetch_url(current)
            if allowed == "block":
                raise PermissionError(reason)

            response = await client.get(current)
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise PermissionError("Redirect response missing Location header.")
                current = urljoin(current, location)
                continue

            response.raise_for_status()
            return response.text

    raise PermissionError("Too many redirects.")


def evaluate_tool_call(payload: dict[str, Any]) -> tuple[Action, str]:
    tool = payload.get("tool")
    arguments = payload.get("arguments", {})
    if not isinstance(arguments, dict):
        arguments = {}

    if tool == "read_file":
        return evaluate_read_file(arguments.get("path", ""))

    if tool == "fetch_url":
        return evaluate_fetch_url(arguments.get("url", ""))

    return ("block", f"Unknown tool: {tool!r}.")


async def execute_tool(payload: dict[str, Any]) -> Any:
    tool = payload.get("tool")
    arguments = payload.get("arguments", {})
    if not isinstance(arguments, dict):
        arguments = {}

    if tool == "read_file":
        return read_file(str(arguments.get("path", "")))

    if tool == "fetch_url":
        return await fetch_url(str(arguments.get("url", "")))

    raise ValueError(f"Unknown tool: {tool!r}.")


async def handle_request(payload: dict[str, Any]) -> dict[str, Any]:
    action, reason = evaluate_tool_call(payload)

    if action == "block":
        return {"action": "block", "reason": reason, "result": None}

    try:
        result = await execute_tool(payload)
    except Exception as exc:
        return {
            "action": "block",
            "reason": f"Tool execution failed: {exc}",
            "result": None,
        }

    if isinstance(result, str) and CANARY_TOKEN in result:
        return {
            "action": "block",
            "reason": "Blocked response containing canary token.",
            "result": None,
        }

    return {"action": "allow", "reason": reason, "result": result}
