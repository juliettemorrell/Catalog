"""Known vulnerabilities for locked dependency versions, from OSV.dev (opt-in: ``--osv``).

Only exact versions (lockfiles or pins) are checked, so every hit is real for what the
repo ships. Results are cached for a day; advisories for longer. Network problems never
fail a build: the catalog is written without vulnerability data and a warning is logged.

API: https://google.github.io/osv.dev/api/ (querybatch + vulns/{id}).
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .analyzers.purls import summarize
from .analyzers.versions import version_sort_key
from .models import Dependency, Flag, Repo, Severity

log = logging.getLogger(__name__)

OSV_API = "https://api.osv.dev/v1"
BATCH = 1000
QUERY_TTL = 24 * 3600
ADVISORY_TTL = 7 * 24 * 3600
MAX_ADVISORIES = 5000
MAX_FLAGS_PER_REPO = 50

OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "gem": "RubyGems",
    "composer": "Packagist",
    "nuget": "NuGet",
    "pub": "Pub",
    "hex": "Hex",
    "swift": "SwiftURL",
    "cran": "CRAN",
    "github-actions": "GitHub Actions",
}
_SEVERITY: dict[str, Severity] = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
_RANK = {"high": 0, "medium": 1, "low": 2}

Key = tuple[str, str, str]  # (osv ecosystem, name, version)


def _key(dep: Dependency) -> Key | None:
    eco = OSV_ECOSYSTEM.get(dep.ecosystem)
    version = dep.resolved
    if not eco or not version:
        return None
    # only plain registry coordinates leave the machine: never URLs, paths or anything
    # that could carry an internal host name or credential
    if not re.fullmatch(r"v?\d[\w.+\-]*", version) or re.search(r"://|[?#\s]", dep.name):
        return None
    if re.search(r"(?:^|[.\-])[xX*](?:[.\-]|$)", version):
        return None  # 1.x is a range, not a version OSV can match
    if "@" in dep.name.lstrip("@") or (":" in dep.name and dep.ecosystem != "maven"):
        return None
    if dep.ecosystem == "github-actions" and not re.match(r"v?\d+\.\d+", version):
        return None  # branch or major-only refs cannot be matched to affected ranges
    name = dep.name
    if dep.ecosystem == "swift":
        name = f"https://{name}"
    if dep.ecosystem == "go":
        version = version.lstrip("v")
    return eco, name, version


class OsvClient:
    def __init__(self, cache_dir: Path, transport: httpx.BaseTransport | None = None) -> None:
        self.cache_dir = cache_dir
        (cache_dir / "advisories").mkdir(parents=True, exist_ok=True)
        self.http = httpx.Client(
            timeout=30, transport=transport, headers={"User-Agent": "repo-catalog"}
        )
        self.queries: dict[str, dict[str, Any]] = self._load(cache_dir / "queries.json") or {}

    @staticmethod
    def _load(path: Path) -> Any:
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return None

    def _save(self, path: Path, data: Any) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, path)  # atomic: a crash never leaves a corrupt cache

    def vulns_for(self, keys: Iterable[Key]) -> dict[Key, list[str]]:
        now = time.time()
        out: dict[Key, list[str]] = {}
        todo: list[Key] = []
        for key in dict.fromkeys(keys):
            cached = self.queries.get("|".join(key))
            if cached and now - float(cached.get("at", 0)) < QUERY_TTL:
                out[key] = list(cached.get("ids", []))
            else:
                todo.append(key)
        pending: list[tuple[Key, str | None]] = [(k, None) for k in todo]
        found: dict[Key, set[str]] = {k: set() for k in todo}
        complete: set[Key] = set(todo)
        rounds = 0
        while pending and rounds < 20:  # querybatch pages long result lists per query
            rounds += 1
            next_round: list[tuple[Key, str | None]] = []
            for i in range(0, len(pending), BATCH):
                chunk = pending[i : i + BATCH]
                body = {
                    "queries": [
                        {
                            "package": {"ecosystem": eco, "name": name},
                            "version": version,
                            **({"page_token": token} if token else {}),
                        }
                        for (eco, name, version), token in chunk
                    ]
                }
                resp = self.http.post(f"{OSV_API}/querybatch", json=body)
                resp.raise_for_status()
                results = resp.json().get("results", [])
                for (key, _), result in zip(chunk, results, strict=False):
                    result = result or {}
                    found[key] |= {v["id"] for v in result.get("vulns", []) if v.get("id")}
                    if result.get("next_page_token"):
                        next_round.append((key, str(result["next_page_token"])))
            pending = next_round
        for key, _ in pending:
            complete.discard(key)  # never cache a partial list
        for key in todo:
            out[key] = sorted(found[key])
            if key in complete:
                self.queries["|".join(key)] = {"ids": out[key], "at": now}
        self._save(self.cache_dir / "queries.json", self.queries)
        return out

    def advisory(self, vuln_id: str) -> dict[str, Any] | None:
        """The advisory, or None when it cannot be fetched (withdrawn, 5xx): one bad id
        must not drop every other finding."""
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", vuln_id)
        path = self.cache_dir / "advisories" / f"{safe}.json"
        cached = self._load(path)
        if cached and time.time() - float(cached.get("_at", 0)) < ADVISORY_TTL:
            return dict(cached)
        try:
            resp = self.http.get(f"{OSV_API}/vulns/{vuln_id}")
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.info("OSV advisory %s unavailable (%s)", vuln_id, exc)
            return None
        data["_at"] = time.time()
        self._save(path, data)
        return data


# CVSS v3.x base metrics (https://www.first.org/cvss/v3.1/specification-document)
_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_base_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3["C"][m["C"]]) * (1 - _CVSS3["I"][m["I"]]) * (1 - _CVSS3["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + exploit), 10) if changed else min(impact + exploit, 10)
    return math.ceil(raw * 10 - 1e-9) / 10  # "round up" to one decimal


def _severity(advisory: dict[str, Any]) -> Severity:
    label = str((advisory.get("database_specific") or {}).get("severity") or "").upper()
    if label in _SEVERITY:
        return _SEVERITY[label]
    scores = []
    for sev in advisory.get("severity") or []:
        score = str(sev.get("score", ""))
        value = cvss3_base_score(score) if score.startswith("CVSS:") else None
        if value is None and re.fullmatch(r"\d+(?:\.\d+)?", score):
            value = float(score)  # some feeds give a bare base score
        if value is not None:
            scores.append(value)
    if scores:
        top = max(scores)
        return "high" if top >= 7 else "medium" if top >= 4 else "low"
    return "medium"  # unknown (e.g. only a CVSS v4 vector): don't under-state it


def _fixed(advisory: dict[str, Any], ecosystem: str, name: str) -> list[str]:
    def same(a: str) -> bool:
        if ecosystem == "PyPI":
            return re.sub(r"[-_.]+", "-", a.lower()) == re.sub(r"[-_.]+", "-", name.lower())
        return a.lower() == name.lower()

    fixed = []
    for affected in advisory.get("affected") or []:
        pkg = affected.get("package") or {}
        if (
            not same(str(pkg.get("name", "")))
            or str(pkg.get("ecosystem", ecosystem)).split(":")[0] != ecosystem
        ):
            continue
        for rng in affected.get("ranges") or []:
            if str(rng.get("type") or "ECOSYSTEM").upper() not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges list commit SHAs, not versions anyone can upgrade to
            fixed += [str(e["fixed"]) for e in rng.get("events") or [] if e.get("fixed")]
    return list(dict.fromkeys(fixed))


def _distinct(ids: list[str], advisories: dict[str, dict[str, Any]]) -> list[list[str]]:
    """Group ids that describe the same issue (GHSA-x and PYSEC-y aliasing one CVE), so it
    is counted once. The first id of each group (GHSA preferred) is the one shown."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    ordered = sorted(dict.fromkeys(ids), key=lambda i: (not i.startswith("GHSA-"), i))
    for vid in ordered:  # union-find: A~B and B~C put A, B and C in one group
        aliases = advisories.get(vid, {}).get("aliases") or []
        for alias in [vid, *(str(a) for a in aliases if a)]:
            parent[find(alias)] = find(vid)
    groups: dict[str, list[str]] = {}
    for vid in ordered:
        groups.setdefault(find(vid), []).append(vid)
    return list(groups.values())


@dataclass
class OsvFindings:
    """What OSV reported for a set of locked versions, applied one repo at a time
    (``annotate``) so a large catalog never needs every dependency in memory at once.
    ``ok`` is False when there was nothing to look up or OSV was unreachable: advisory ids
    and flags are then cleared and the dependency summaries left as they were."""

    found: dict[Key, list[str]] = field(default_factory=dict)
    advisories: dict[str, dict[str, Any]] = field(default_factory=dict)
    ok: bool = False
    _groups: dict[Key, list[list[str]]] = field(default_factory=dict, repr=False)

    def groups(self, key: Key) -> list[list[str]]:
        """Distinct advisories (aliases merged) for a package version."""
        ids = [i for i in self.found.get(key, []) if i in self.advisories]
        if not ids:
            return []
        if key not in self._groups:
            self._groups[key] = _distinct(ids, self.advisories)
        return self._groups[key]

    def vulns_for(self, dep: Dependency) -> list[str]:
        key = _key(dep) if self.ok else None
        return [g[0] for g in self.groups(key)] if key is not None else []


def dependency_keys(deps: Iterable[Dependency]) -> Iterable[Key]:
    return (key for dep in deps if (key := _key(dep)) is not None)


def lookup_vulnerabilities(
    keys: Iterable[Key], cache_dir: Path, transport: httpx.BaseTransport | None = None
) -> OsvFindings:
    unique = list(dict.fromkeys(keys))
    if not unique:
        return OsvFindings()
    try:
        client = OsvClient(cache_dir, transport)
        found = client.vulns_for(unique)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        log.warning("OSV lookup skipped (%s): vulnerability data not included", exc)
        return OsvFindings()
    ids = sorted({i for v in found.values() for i in v})[:MAX_ADVISORIES]
    with ThreadPoolExecutor(max_workers=8) as pool:
        fetched = dict(zip(ids, pool.map(client.advisory, ids), strict=True))
    # an advisory that could not be fetched still counts: OSV said this version is affected
    advisories = {i: a if a is not None else {"id": i} for i, a in fetched.items()}
    return OsvFindings(found={k: v for k, v in found.items() if v}, advisories=advisories, ok=True)


def annotate(repo: Repo, findings: OsvFindings) -> int:
    """Set advisory ids on ``repo``'s dependencies (all of them, transitive included) and
    its `vulnerable-dependency` flags. Returns the number of vulnerable package versions."""
    repo.flags = [f for f in repo.flags if f.id != "vulnerable-dependency"]
    for dep in repo.dependencies:
        dep.vulns = []
    if not findings.ok:
        return 0
    hits = 0
    flags: list[Flag] = []
    flagged: set[Key] = set()
    for dep in repo.dependencies:
        key = _key(dep)
        groups = findings.groups(key) if key is not None else []
        if key is None or not groups:
            continue
        advisories = findings.advisories
        vuln_ids = [g[0] for g in groups]
        members = [i for g in groups for i in g]
        dep.vulns = vuln_ids
        if key in flagged:
            continue  # same package@version from another manifest in this repo
        flagged.add(key)
        hits += 1
        # sources can disagree on severity (GHSA label vs a PYSEC CVSS vector): take the worst
        worst = min((_severity(advisories[i]) for i in members), key=lambda s: _RANK[s])
        fixed = sorted(
            {f for i in members for f in _fixed(advisories[i], key[0], key[1])},
            key=lambda f: version_sort_key(f, dep.ecosystem),
        )
        shown = ", ".join(vuln_ids[:3]) + ("..." if len(vuln_ids) > 3 else "")
        message = (
            f"{dep.name}@{key[2]}{' (transitive)' if dep.scope == 'transitive' else ''}: "
            f"{len(vuln_ids)} known advisor{'y' if len(vuln_ids) == 1 else 'ies'} ({shown})"
            + (f"; fixed in {', '.join(fixed[:3])}" if fixed else "; no fixed version listed")
        )
        flags.append(
            Flag(
                id="vulnerable-dependency",
                category="security",
                severity=worst,
                message=message,
                path=dep.manifest,
            )
        )
    flags.sort(key=lambda f: _RANK[f.severity])
    repo.flags += flags[:MAX_FLAGS_PER_REPO]
    repo.dependency_summary = summarize(repo.dependencies)
    return hits


def apply_vulnerabilities(
    repos: list[Repo], cache_dir: Path, transport: httpx.BaseTransport | None = None
) -> int:
    """Annotate deps with advisory ids and add `vulnerable-dependency` flags. Returns the
    number of vulnerable (repo, dependency) pairs; 0 when OSV is unreachable."""
    keys = dependency_keys(d for repo in repos for d in repo.dependencies)
    findings = lookup_vulnerabilities(keys, cache_dir, transport)
    return sum(annotate(repo, findings) for repo in repos)
