"""Deterministic agent skill safety scanner."""

from __future__ import annotations

import re
from typing import Any

import yaml

CATEGORY_HARDCODED_SECRET = "hardcoded_secret"
CATEGORY_PROMPT_INJECTION = "prompt_injection"
CATEGORY_EXCESSIVE_PERMISSIONS = "excessive_permissions"
CATEGORY_UNCLEAR_PROVENANCE = "unclear_provenance"

ALL_CATEGORIES = (
    CATEGORY_HARDCODED_SECRET,
    CATEGORY_PROMPT_INJECTION,
    CATEGORY_EXCESSIVE_PERMISSIONS,
    CATEGORY_UNCLEAR_PROVENANCE,
)

ENV_REFERENCE_RE = re.compile(
    r"(?i)(?:\$[{]?\w+[}]?|process\.env\.\w+|os\.environ(?:\.get)?\s*\(\s*['\"]|"
    r"getenv\s*\(\s*['\"]|secrets?\.(?:get|manager)|secret[\s_-]?store|vault)"
)

PLACEHOLDER_RE = re.compile(
    r"(?i)(?:<[^>]+>|your[_-]?(?:api[_-]?)?key|example|placeholder|changeme|\bxxx+\b|todo)"
)

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "github_pat"),
    (re.compile(r"gho_[0-9a-zA-Z]{36}"), "github_oauth"),
    (re.compile(r"github_pat_[0-9a-zA-Z_]{82}"), "github_fine_pat"),
    (re.compile(r"sk-ant-api03-[0-9a-zA-Z\-_]{80,}"), "anthropic_key"),
    (re.compile(r"sk-[0-9a-zA-Z]{20,}"), "openai_style_key"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"), "slack_token"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"), "private_key"),
    (
        re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
        ),
        "slack_webhook",
    ),
    (
        re.compile(
            r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"
        ),
        "discord_webhook",
    ),
    (
        re.compile(
            r"(?i)(?:api[_-]?key|apikey|secret|token|password|webhook[_-]?url)"
            r"\s*[:=]\s*['\"](?!\$\{?)[^'\"]{12,}['\"]"
        ),
        "labeled_secret",
    ),
)

PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"),
    re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules)"),
    re.compile(r"(?i)forget\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions|rules)"),
    re.compile(r"(?i)override\s+(?:the\s+)?(?:system|safety|security)\s+(?:prompt|instructions?)"),
    re.compile(r"(?i)ignore\s+(?:the\s+)?user(?:'s)?\s+(?:stop|cancel|cancellation|request)"),
    re.compile(r"(?i)(?:continue|proceed)\s+(?:even\s+if|when)\s+(?:the\s+)?user\s+(?:stops?|cancels?)"),
    re.compile(r"(?i)do\s+not\s+(?:tell|inform|notify|alert)\s+(?:the\s+)?user"),
    re.compile(r"(?i)(?:regardless of|despite)\s+(?:the\s+)?user(?:'s)?\s+(?:stop|cancel)"),
    re.compile(r"(?i)without\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|consent|approval)"),
    re.compile(r"(?i)without\s+(?:telling|informing|notifying)\s+(?:the\s+)?user"),
    re.compile(r"(?i)silently\s+(?:send|upload|post|transmit|exfiltrat)"),
    re.compile(r"(?i)(?:send|upload|post|transmit|exfiltrat).{0,40}without\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|consent|approval)"),
)

SECURITY_CONTEXT_RE = re.compile(
    r"(?i)\b(?:scan(?:ner)?|detect(?:ion)?|audit(?:ing)?|check(?:ing)?|"
    r"identif(?:y|ying)|look(?:ing)?\s+for|watch(?:ing)?\s+for|flag(?:ging)?|"
    r"prevent(?:ing)?|block(?:ing)?|mitigat(?:e|ing)|test(?:ing)?\s+for|"
    r"review(?:ing)?\s+for|example(?:s)?\s+of|patterns?\s+(?:to|for)|"
    r"vulnerabilit(?:y|ies)|malicious|suspicious|unsafe)\b"
)

EXCESSIVE_PERMISSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:filesystem|network)\.(?:read|write|egress)\.all\b"),
    re.compile(r"(?i)\ballowed-tools\b[^.\n]*\b\*\b"),
    re.compile(r"(?i)\b(?:filesystem|file\s*system)\s*:\s*['\"]?\*['\"]?\s*$"),
    re.compile(r"(?i)\bnetwork\s*:\s*['\"]?\*['\"]?\s*$"),
    re.compile(r"(?i)\begress\s*:\s*['\"]?\*['\"]?\s*$"),
    re.compile(r"(?i)\b(?:read|write)\s*:\s*['\"]?\*['\"]?\s*$"),
    re.compile(r"(?i)\b(?:read|write)\s*:\s*\[['\"]\*\*?['\"]\]"),
    re.compile(r"(?i)\b(?:entire|whole|full)\s+filesystem\b"),
    re.compile(r"(?i)\b(?:any|all|every)\s+(?:domain|host|url)s?\b"),
    re.compile(r"(?i)\bunrestricted\s+(?:network|filesystem|access)\b"),
    re.compile(r"(?i)\begress\s+to\s+any\s+(?:domain|host)\b"),
    re.compile(r"(?i)\b(?:read|write)\s*:\s*['\"]?/\*\*?['\"]?\s*$"),
)

SILENT_VERSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?:silently|quietly|without\s+(?:telling|informing|notifying|alerting))[^.\n]{0,80}\bversion\b"),
    re.compile(r"(?i)\bupdate\s+(?:the\s+)?(?:yaml\s+)?frontmatter[^.\n]{0,80}\bversion\b"),
    re.compile(r"(?i)\brewrite\s+(?:its\s+)?(?:own\s+)?version\s+metadata\b"),
    re.compile(r"(?i)\bchange\s+the\s+version\s+field[^.\n]{0,80}without\b"),
)

AUTHOR_KEYS = ("author", "authors", "maintainer", "maintainers", "created-by")
VERSION_KEYS = ("version",)
CHANGELOG_KEYS = ("changelog", "change-log", "changes", "history")


def parse_skill(skill_text: str) -> tuple[dict[str, Any], str, str]:
    text = skill_text.strip()
    if not text.startswith("---"):
        return {}, text, text

    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text, text

    try:
        frontmatter = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        frontmatter = {}

    if not isinstance(frontmatter, dict):
        frontmatter = {}

    body = parts[2]
    return frontmatter, body, text


def _has_metadata_value(frontmatter: dict[str, Any], keys: tuple[str, ...]) -> bool:
    for key in keys:
        value = frontmatter.get(key)
        if value is None:
            continue
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, (list, dict, tuple, set)) and value:
            return True
        if not isinstance(value, str):
            return True
    return False


def _line_has_security_context(line: str) -> bool:
    return bool(SECURITY_CONTEXT_RE.search(line))


def _is_env_backed(line: str, match: re.Match[str]) -> bool:
    window = line[max(0, match.start() - 40) : match.end() + 40]
    return bool(ENV_REFERENCE_RE.search(window))


def _is_placeholder_secret(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value))


def check_hardcoded_secret(text: str) -> bool:
    for line in text.splitlines():
        if ENV_REFERENCE_RE.search(line):
            continue
        for pattern, _label in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            if _is_env_backed(line, match):
                continue
            matched = match.group(0)
            if _is_placeholder_secret(matched):
                continue
            if _label == "labeled_secret":
                value_match = re.search(r"['\"]([^'\"]+)['\"]", matched)
                if value_match and _is_placeholder_secret(value_match.group(1)):
                    continue
            return True
    return False


def check_prompt_injection(text: str) -> bool:
    for line in text.splitlines():
        if _line_has_security_context(line):
            continue
        if any(pattern.search(line) for pattern in PROMPT_INJECTION_PATTERNS):
            return True
    return False


def _yaml_contains_wildcard_permissions(value: Any) -> bool:
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized in {"*", "**", "all", "any", "unrestricted"}
    if isinstance(value, list):
        return any(_yaml_contains_wildcard_permissions(item) for item in value)
    if isinstance(value, dict):
        return any(_yaml_contains_wildcard_permissions(item) for item in value.values())
    return False


def _frontmatter_has_excessive_permissions(frontmatter: dict[str, Any]) -> bool:
    permission_keys = (
        "permissions",
        "allowed-tools",
        "allowed_tools",
        "tools",
        "filesystem",
        "filesystem-access",
        "network",
        "network-access",
        "egress",
        "capabilities",
    )
    for key in permission_keys:
        if key not in frontmatter:
            continue
        if _yaml_contains_wildcard_permissions(frontmatter[key]):
            return True
    return False


def check_excessive_permissions(frontmatter: dict[str, Any], text: str) -> bool:
    if _frontmatter_has_excessive_permissions(frontmatter):
        return True

    for line in text.splitlines():
        if _line_has_security_context(line):
            continue
        if any(pattern.search(line) for pattern in EXCESSIVE_PERMISSION_PATTERNS):
            return True
    return False


def check_unclear_provenance(frontmatter: dict[str, Any], body: str) -> bool:
    has_author = _has_metadata_value(frontmatter, AUTHOR_KEYS)
    has_version = _has_metadata_value(frontmatter, VERSION_KEYS)
    has_changelog = _has_metadata_value(frontmatter, CHANGELOG_KEYS)

    if not has_author and not has_version and not has_changelog:
        return True

    for line in body.splitlines():
        if any(pattern.search(line) for pattern in SILENT_VERSION_PATTERNS):
            return True
    return False


def scan_skill(skill_text: str) -> list[str]:
    frontmatter, body, full_text = parse_skill(skill_text)
    categories: list[str] = []

    if check_hardcoded_secret(full_text):
        categories.append(CATEGORY_HARDCODED_SECRET)
    if check_prompt_injection(body):
        categories.append(CATEGORY_PROMPT_INJECTION)
    if check_excessive_permissions(frontmatter, full_text):
        categories.append(CATEGORY_EXCESSIVE_PERMISSIONS)
    if check_unclear_provenance(frontmatter, body):
        categories.append(CATEGORY_UNCLEAR_PROVENANCE)

    return categories
