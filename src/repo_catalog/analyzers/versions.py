"""Just enough version-range logic to pick the locked version a range refers to.

Covers the operator syntax of npm/Composer (``^ ~ x || - >= <``), Cargo (bare ``1.2`` means
``^1.2``), PEP 440 (``== != ~= >= ,`` and ``1.2.*``) and RubyGems (``~>``). Anything it cannot
read returns ``None`` ("can't tell"), never a guess.
"""

from __future__ import annotations

import re

Version = tuple[int, int, int, int]  # major, minor, patch, 0 if prerelease else 1

_NUM = re.compile(
    r"^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:\.\d+)*([-+.]?[0-9A-Za-z.\-+]*)?$"
)


def parse_version(text: str) -> Version | None:
    m = _NUM.match(text.strip())
    if not m:
        return None
    parts = [int(p) if p and p.isdigit() else 0 for p in m.group(1, 2, 3)]
    pre = m.group(4) or ""
    is_pre = bool(re.match(r"^[-.]?(alpha|beta|rc|pre|dev|a|b|c)\d*", pre, re.I)) or (
        pre.startswith("-") and not pre.startswith("-+")
    )
    return parts[0], parts[1], parts[2], 0 if is_pre else 1


def _partial(text: str) -> tuple[list[int], bool]:
    """``1.2.x`` -> ([1, 2], True): the numeric prefix and whether it was a wildcard/partial."""
    text = text.strip().lstrip("v=")
    parts = re.split(r"[.]", text.split("-")[0].split("+")[0])
    nums: list[int] = []
    for p in parts[:3]:
        if p.isdigit():
            nums.append(int(p))
        else:
            break
    return nums, len(nums) < 3


def _bump(nums: list[int], index: int) -> Version:
    head = [*nums[:index], (nums[index] if index < len(nums) else 0) + 1]
    head += [0] * (3 - len(head))
    return head[0], head[1], head[2], 0  # lowest prerelease of the next version


def _floor(nums: list[int]) -> Version:
    padded = [*nums, 0, 0, 0][:3]
    return padded[0], padded[1], padded[2], 0


def _caret(nums: list[int]) -> tuple[Version, Version]:
    first_nonzero = next((i for i, n in enumerate(nums) if n != 0), len(nums) - 1)
    index = min(first_nonzero, len(nums) - 1) if nums else 0
    return _floor(nums), _bump(nums, index)


def _comparator(token: str, ecosystem: str) -> list[tuple[str, Version]] | None:
    m = re.match(r"^(\^|~>|~=|~|>=|<=|>|<|===|==|=|!=)?\s*(.+)$", token.strip())
    if not m:
        return None
    op, rest = m.group(1) or "", m.group(2).strip()
    if rest in ("*", "x", "X", ""):
        return []
    nums, partial = _partial(rest)
    if not nums:
        return None
    exact = parse_version(rest.replace("*", "0").replace("x", "0").replace("X", "0"))
    if exact is None:
        return None
    if op == "" and ecosystem == "cargo":
        op = "^"
    if op == "^":
        low, high = _caret(nums)
        return [(">=", low), ("<", high)]
    if op == "~":  # npm/Composer tilde: patch-level changes (Cargo: same)
        return [(">=", _floor(nums)), ("<", _bump(nums, 1 if len(nums) > 1 else 0))]
    if op in ("~>", "~="):  # RubyGems / PEP 440: last given component may grow
        if len(nums) < 2:
            return None
        return [(">=", exact), ("<", _bump(nums, len(nums) - 2))]
    if op in ("", "=", "==", "==="):
        if partial or rest.endswith((".*", ".x")):
            return [(">=", _floor(nums)), ("<", _bump(nums, len(nums) - 1))]
        return [("==", exact)]
    if op == "!=":
        return [("!=", exact)]
    return [(op, exact)]


def _check(version: Version, op: str, bound: Version) -> bool:
    core, bound_core = version[:3], bound[:3]
    return {
        ">=": version >= bound,
        ">": core > bound_core,
        "<=": core <= bound_core,
        "<": version < bound,
        "==": core == bound_core,
        "!=": core != bound_core,
    }[op]


def satisfies(version: str, spec: str, ecosystem: str) -> bool | None:
    """Does ``version`` fall in ``spec``? None when either cannot be read."""
    v = parse_version(version)
    spec = spec.strip()
    if v is None or not spec or spec.startswith(("git", "http", "file:", "link:", "workspace:")):
        return None
    spec = re.sub(r"^npm:(?:@?[^@]+@)?", "", spec)  # aliases: npm:real@^1
    alternatives = re.split(r"\s*\|\|?\s*", spec)
    any_readable = False
    for alt in alternatives:
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hyphen:
            low, _ = _partial(hyphen.group(1))
            high, high_partial = _partial(hyphen.group(2))
            if not low or not high:
                continue
            checks = [(">=", _floor(low))] + (
                [("<", _bump(high, len(high) - 1))] if high_partial else [("<=", _floor(high))]
            )
        else:
            tokens = [t for t in re.split(r"\s*,\s*|\s+(?![\d*xX])", alt) if t]
            checks = []
            readable = True
            for token in tokens:
                parsed = _comparator(token, ecosystem)
                if parsed is None:
                    readable = False
                    break
                checks += parsed
            if not readable:
                continue
        any_readable = True
        if all(_check(v, op, bound) for op, bound in checks):
            # prereleases only match when the range names that exact version
            named = any(b[3] == 1 and b[:3] == v[:3] for _, b in checks)
            if v[3] == 0 and not named and not any(op == "==" for op, _ in checks):
                continue
            return True
    return False if any_readable else None


def best_match(versions: list[str], spec: str | None, ecosystem: str) -> str | None:
    """The highest locked version satisfying ``spec``; the only one if there is one and
    the range is unreadable; otherwise None (never a guess between several)."""
    if not versions:
        return None
    if spec:
        verdicts = [(satisfies(v, spec, ecosystem), v) for v in versions]
        matching = [v for ok, v in verdicts if ok]
        if matching:
            return max(matching, key=lambda v: parse_version(v) or (0, 0, 0, 0))
        if any(ok is False for ok, _ in verdicts) and all(ok is not None for ok, _ in verdicts):
            return None
    return versions[0] if len(versions) == 1 else None
