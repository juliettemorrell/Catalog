"""Safe parsing and redaction helpers shared by every analyzer.

Everything a repository contains is untrusted input: YAML may hold alias bombs, JSON may
carry comments or a BOM, and configs may embed credentials. These helpers make the
common case easy to get right.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

# ---------------------------------------------------------------------------------- YAML


MAX_YAML_NODES = 100_000


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that allows anchors/aliases (real configs use them) but rejects documents
    whose alias-expanded size is huge ("billion laughs") or recursive."""

    def compose_document(self) -> Any:
        node = super().compose_document()
        if node is not None and self.anchors_seen and _expanded_size(node) > MAX_YAML_NODES:
            raise yaml.YAMLError("YAML aliases expand beyond the size limit")
        return node

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            self.anchors_seen = True
        return super().compose_node(parent, index)

    anchors_seen = False


def _expanded_size(root: yaml.Node) -> int:
    """Node count after alias expansion, computed on the shared graph without expanding."""
    memo: dict[int, int] = {}
    active: set[int] = set()

    def size(node: yaml.Node) -> int:
        key = id(node)
        if key in memo:
            return memo[key]
        if key in active:
            raise yaml.YAMLError("recursive YAML aliases are not supported")
        active.add(key)
        total = 1
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                total += size(k) + size(v)
                if total > MAX_YAML_NODES:
                    break
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                total += size(item)
                if total > MAX_YAML_NODES:
                    break
        active.discard(key)
        memo[key] = total
        return total

    try:
        return size(root)
    except RecursionError:
        raise yaml.YAMLError("YAML nesting too deep") from None


def load_yaml(text: str) -> Any:
    """Parse one YAML document safely. Raises ``yaml.YAMLError`` on bad input."""
    return yaml.load(text, Loader=_NoAliasLoader)


def load_yaml_all(text: str) -> list[Any]:
    return list(yaml.load_all(text, Loader=_NoAliasLoader))


# ---------------------------------------------------------------------------------- JSON


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments (outside strings) and trailing commas."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_json(text: str) -> Any:
    """Parse JSON or JSONC (comments, trailing commas, BOM). Raises ``ValueError``."""
    text = text.lstrip("﻿")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(strip_jsonc(text))


# ------------------------------------------------------------------------------ secrets

SECRET_PATTERNS = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-[A-Za-z0-9_\-]{20,}|"
    r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}|sk-ak-[A-Za-z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|"
    r"xox[abposr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35}|glpat-[A-Za-z0-9_\-]{20,}|"
    r"tvly-[A-Za-z0-9_\-]{16,}|hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{30,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)"
)
_BEARER = re.compile(
    r"(?i)((?:bearer|basic)\s+|(?:api[_-]?key|token|secret|password|passwd|pwd)[\"']?\s*[:=]\s*[\"']?)"
    r"([A-Za-z0-9._~+/\-]{16,}=*)"
)
SECRET_NAME = re.compile(r"(?i)(key|token|secret|password|passwd|pwd|credential|auth)")
_SENSITIVE_KEYS = {"env", "headers", "http_headers", "environment", "secrets", "requestinit"}


def redact_secrets(text: str) -> str:
    text = SECRET_PATTERNS.sub("[REDACTED]", text)
    return _BEARER.sub(lambda m: m.group(1) + "[REDACTED]", text)


def redact_url(url: str) -> str:
    """Drop credentials and query strings; mask long random-looking path segments."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[REDACTED]"
    if not parts.scheme:
        return redact_secrets(url)
    try:
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
    except ValueError:  # not a network URL, e.g. promptfoo's file://prompts.py:fn
        host = parts.netloc.rpartition("@")[2]
    path = "/".join(
        "[REDACTED]" if _secretish_segment(seg) else seg for seg in parts.path.split("/")
    )
    return urlunsplit((parts.scheme, host, path, "", ""))


def _secretish_segment(seg: str) -> bool:
    """URL path segments that are really credentials (webhook tokens, key-in-path APIs)."""
    if re.match(r"(?i)(sk|pk|rk|ak|key|api|tok|token|secret)[-_]", seg):
        return True
    return len(seg) >= 24 and bool(re.search(r"\d", seg)) and bool(re.search(r"[A-Za-z]", seg))


def redact_args(args: list[Any]) -> list[str]:
    """Command-line args with secret values masked (``--api-key X``, ``TOKEN=X``)."""
    out: list[str] = []
    mask_next = False
    for raw in args:
        a = str(raw)
        if mask_next:
            out.append("[REDACTED]")
            mask_next = False
            continue
        if a.startswith("-") and SECRET_NAME.search(a):
            if "=" in a:
                out.append(a.split("=", 1)[0] + "=[REDACTED]")
            else:
                out.append(a)
                mask_next = True
            continue
        key, eq, _ = a.partition("=")
        if eq and SECRET_NAME.search(key) and not key.startswith(("http", "/")):
            out.append(f"{key}=[REDACTED]")
        elif re.match(r"^[a-z]+://", a):
            out.append(redact_url(a))
        else:
            out.append(redact_secrets(a))
    return out


def sanitize_config(obj: Any, depth: int = 0) -> Any:
    """Deep copy of a JSON-like config with env/header blocks reduced to their key names
    and secret-looking strings, args and URLs redacted."""
    if depth > 20:
        return "…"
    if isinstance(obj, dict):
        clean: dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).lower() in _SENSITIVE_KEYS and isinstance(v, dict):
                clean[str(k)] = sorted(str(x) for x in v)  # names only
            elif str(k).lower() == "args" and isinstance(v, list):
                clean[str(k)] = redact_args(v)
            elif isinstance(v, str) and SECRET_NAME.search(str(k)) and len(v) >= 8:
                clean[str(k)] = "[REDACTED]"
            else:
                clean[str(k)] = sanitize_config(v, depth + 1)
        return clean
    if isinstance(obj, list):
        return [sanitize_config(v, depth + 1) for v in obj[:500]]
    if isinstance(obj, str):
        return redact_url(obj) if re.match(r"^[a-z][a-z0-9+.-]*://", obj) else redact_secrets(obj)
    return obj
