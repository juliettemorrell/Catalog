"""Just enough version-range logic to pick the locked version a range refers to.

Covers the operator syntax of npm/Composer (``^ ~ x || - >= <``), Cargo (bare ``1.2`` means
``^1.2``), PEP 440 (``== != ~= >= ,`` and ``1.2.*``) and RubyGems (``~>``). Anything it cannot
read returns ``None`` ("can't tell"), never a guess.
"""

from __future__ import annotations

import re

# (release with trailing zeros dropped, phase, tag identifiers); comparable as a tuple.
# phase: 0 dev release (PEP 440), 1 prerelease, 2 release, 3 post release
Version = tuple[tuple[int, ...], int, tuple[tuple[int, int, str], ...]]
_ZERO: Version = ((0,), 0, ())

_SPEC_VERSION = re.compile(r"^[vV]?(\d+(?:\.\d+)*)((?:\.[xX*])*)(.*)$")
# normalised so plain string order matches release order: a < b < m < rc < snapshot
_PRE_WORDS = {
    "a": "a",
    "alpha": "a",
    "b": "b",
    "beta": "b",
    "m": "m",
    "milestone": "m",
    "c": "rc",
    "cr": "rc",
    "rc": "rc",
    "pre": "rc",
    "preview": "rc",
    "ea": "rc",
    "snapshot": "snapshot",
    "dev": "dev",
}
_MAVEN_RELEASE = {"ga", "final", "release"}  # same as no qualifier
_MAVEN = {"maven", "gradle", "sbt"}
# ecosystems where a bare "1.2" names exactly 1.2.0 rather than "any 1.2.x"
_PARTIAL_EXACT = {"pypi", "gem", "nuget", "maven", "gradle", "composer", "hex", "pub"}


def _strip(nums: list[int] | tuple[int, ...]) -> tuple[int, ...]:
    out = list(nums)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return tuple(out)


def _rel(nums: list[int]) -> Version:
    return _strip(nums), 2, ()


def _key(nums: list[int], rest: str, ecosystem: str) -> Version | None:
    rest = rest.split("+", 1)[0]  # build metadata / PEP 440 local versions
    if re.search(r"[^\w.\-]", rest):
        return None  # epochs (1!2.0), operators, anything not a plain version
    tag = rest.lstrip("-._")
    ids = re.findall(r"[A-Za-z]+|\d+", tag)
    if tag and not ids:
        return None
    parts = tuple(
        (0, int(i), "") if i.isdigit() else (1, 0, _PRE_WORDS.get(i.lower(), i.lower()))
        for i in ids
    )
    if not ids:
        return _strip(nums), 2, ()
    first = ids[0].lower()
    if ecosystem in _MAVEN:
        if first in _MAVEN_RELEASE:
            return _strip(nums), 2, parts[1:]
        if first not in _PRE_WORDS:
            return _strip(nums), 2, parts  # a variant such as 31.1-jre, not a prerelease
    if first in ("post", "rev", "r") and ecosystem == "pypi":
        return _strip(nums), 3, parts[1:]
    if first == "dev" and ecosystem == "pypi":
        return _strip(nums), 0, parts[1:]
    return _strip(nums), 1, parts


def parse_version(text: str, ecosystem: str = "") -> Version | None:
    """A comparable key for a concrete version; None when it is not one (ranges, tags)."""
    m = _SPEC_VERSION.match(text.strip())
    if not m or m.group(2):
        return None
    return _key([int(p) for p in m.group(1).split(".")], m.group(3), ecosystem)


def version_sort_key(text: str, ecosystem: str = "") -> tuple[int, Version, str]:
    """Sort key for mixed lists: parsed versions in version order, the rest after them."""
    v = parse_version(text, ecosystem)
    return (0, v, "") if v is not None else (1, _ZERO, text)


def _spec(text: str, ecosystem: str) -> tuple[list[int], bool, bool, Version] | None:
    """``1.2.x`` -> ([1, 2], wildcard, tagged, key)."""
    m = _SPEC_VERSION.match(text.strip())
    if not m:
        return None
    nums = [int(p) for p in m.group(1).split(".")]
    wild, rest = bool(m.group(2)), m.group(3)
    tagged = bool(rest.split("+", 1)[0].strip())
    if wild and tagged:
        return None
    key = _key(nums, rest, ecosystem)
    return None if key is None else (nums, wild, tagged, key)


def _bump(nums: list[int], index: int) -> Version:
    index = max(0, min(index, len(nums)))
    head = [*nums[:index], (nums[index] if index < len(nums) else 0) + 1]
    return _rel(head)


def _caret(nums: list[int]) -> Version:
    first_nonzero = next((i for i, n in enumerate(nums) if n != 0), len(nums) - 1)
    return _bump(nums, min(first_nonzero, len(nums) - 1) if nums else 0)


Check = tuple[str, Version, Version | None]


def _comparator(token: str, ecosystem: str) -> list[Check] | None:
    m = re.match(r"^(\^|~>|~=|~|>=|<=|>|<|===|==|=|!=)?\s*(.+)$", token.strip())
    if not m:
        return None
    op, rest = m.group(1) or "", m.group(2).strip()
    if rest in ("*", "x", "X", ""):
        return []
    parsed = _spec(rest, ecosystem)
    if parsed is None:
        return None
    nums, wild, tagged, bound = parsed
    # npm/Cargo read a short version as a range: "1.2" is 1.2.x, ">1.2" is >=1.3.0
    loose = wild or (len(nums) < 3 and not tagged and ecosystem not in _PARTIAL_EXACT)
    low = _rel(nums) if wild else bound
    if op == "" and ecosystem == "cargo":
        op = "^"
    if op == "~" and ecosystem == "composer":
        op = "~>"  # Composer: ~1.2 is >=1.2 <2.0, ~1.2.3 is >=1.2.3 <1.3.0
    if op == "^":
        return [(">=", low, None), ("<", _caret(nums), None)]
    if op == "~":  # npm/Cargo tilde: patch-level changes
        return [(">=", low, None), ("<", _bump(nums, 1 if len(nums) > 1 else 0), None)]
    if op in ("~>", "~="):  # RubyGems / PEP 440 / Composer: last given component may grow
        if len(nums) < 2 and op == "~=":
            return None
        return [(">=", low, None), ("<", _bump(nums, max(len(nums) - 2, 0)), None)]
    if op in ("", "=", "==", "==="):
        if loose:
            return [(">=", low, None), ("<", _bump(nums, len(nums) - 1), None)]
        return [("==", bound, None)]
    if op == "!=":
        if loose:
            return [("!in", low, _bump(nums, len(nums) - 1))]
        return [("!=", bound, None)]
    if loose and op == ">":
        return [(">=", _bump(nums, len(nums) - 1), None)]
    if loose and op == "<=":
        return [("<", _bump(nums, len(nums) - 1), None)]
    return [(op, low, None)]


def _check(v: Version, op: str, bound: Version, high: Version | None) -> bool:
    if op == "!in":
        return not (bound <= v < (high or bound))
    return {
        ">=": v >= bound,
        ">": v > bound,
        "<=": v <= bound,
        "<": v < bound,
        "==": v == bound,
        "!=": v != bound,
    }[op]


def _prerelease_allowed(v: Version, checks: list[Check], ecosystem: str) -> bool:
    """npm: a prerelease matches only when a bound carrying a prerelease tag names the
    same release (``<2.0.0`` never admits 2.0.0-beta). PEP 440: when the specifier names
    any prerelease, but ``<V`` still excludes V's own prereleases."""
    bounds = [b for _, b, _ in checks]
    if ecosystem == "pypi":
        if any(op == "<" and b[1] == 2 and b[0] == v[0] for op, b, _ in checks):
            return False
        return any(b[1] < 2 for b in bounds)
    return any(b[1] < 2 and b[0] == v[0] for b in bounds)


def satisfies(version: str, spec: str, ecosystem: str) -> bool | None:
    """Does ``version`` fall in ``spec``? None when either cannot be read."""
    v = parse_version(version, ecosystem)
    spec = spec.strip()
    if v is None or not spec or spec.startswith(("git", "http", "file:", "link:", "workspace:")):
        return None
    spec = re.sub(r"^npm:(?:@?[^@]+@)?", "", spec)  # aliases: npm:real@^1
    if ecosystem == "composer":
        spec = re.sub(r"@[A-Za-z]+", "", spec)  # stability flags: ^1.2@dev
    alternatives = re.split(r"\s*\|\|?\s*", spec)
    any_readable = False
    for alt in alternatives:
        hyphen = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        checks: list[Check] = []
        if hyphen:
            low = _spec(hyphen.group(1), ecosystem)
            high = _spec(hyphen.group(2), ecosystem)
            if not low or not high:
                continue
            checks = [(">=", _rel(low[0]) if low[1] else low[3], None)]
            if high[1] or (len(high[0]) < 3 and not high[2]):
                checks.append(("<", _bump(high[0], len(high[0]) - 1), None))
            else:
                checks.append(("<=", high[3], None))
        else:
            tokens = [t for t in re.split(r"\s*,\s*|\s+(?![\d*xX])", alt) if t]
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
        if all(_check(v, op, bound, high) for op, bound, high in checks):
            if v[1] < 2 and not _prerelease_allowed(v, checks, ecosystem):
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
            return max(matching, key=lambda v: parse_version(v, ecosystem) or _ZERO)
        if any(ok is False for ok, _ in verdicts) and all(ok is not None for ok, _ in verdicts):
            return None
    return versions[0] if len(versions) == 1 else None
