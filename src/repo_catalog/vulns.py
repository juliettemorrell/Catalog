"""Known vulnerabilities for locked dependency versions, from OSV.dev (opt-in: ``--osv``).

Only exact versions (lockfiles or pins) are checked, so every hit is real for what the
repo ships. Results are cached for a day; advisories for longer. Network problems never
fail a build: the catalog is written without vulnerability data and a warning is logged.

API: https://google.github.io/osv.dev/api/ (querybatch + vulns/{id}).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

from .analyzers.purls import summarize
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
        for i in range(0, len(todo), BATCH):
            chunk = todo[i : i + BATCH]
            body = {
                "queries": [
                    {"package": {"ecosystem": eco, "name": name}, "version": version}
                    for eco, name, version in chunk
                ]
            }
            resp = self.http.post(f"{OSV_API}/querybatch", json=body)
            resp.raise_for_status()
            results = resp.json().get("results", [])
            for key, result in zip(chunk, results, strict=False):
                ids = sorted({v["id"] for v in (result or {}).get("vulns", []) if v.get("id")})
                out[key] = ids
                self.queries["|".join(key)] = {"ids": ids, "at": now}
        self._save(self.cache_dir / "queries.json", self.queries)
        return out

    def advisory(self, vuln_id: str) -> dict[str, Any]:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", vuln_id)
        path = self.cache_dir / "advisories" / f"{safe}.json"
        cached = self._load(path)
        if cached and time.time() - float(cached.get("_at", 0)) < ADVISORY_TTL:
            return dict(cached)
        resp = self.http.get(f"{OSV_API}/vulns/{vuln_id}")
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        data["_at"] = time.time()
        self._save(path, data)
        return data


def _severity(advisory: dict[str, Any]) -> Severity:
    label = str((advisory.get("database_specific") or {}).get("severity") or "").upper()
    if label in _SEVERITY:
        return _SEVERITY[label]
    for sev in advisory.get("severity") or []:
        score = str(sev.get("score", ""))
        m = re.match(r"^\d+(?:\.\d+)?$", score)  # some feeds give a bare base score
        if m:
            value = float(score)
            return "high" if value >= 7 else "medium" if value >= 4 else "low"
    return "medium"


def _fixed(advisory: dict[str, Any], name: str) -> list[str]:
    fixed = []
    for affected in advisory.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name", "")
        if pkg.lower() != name.lower():
            continue
        for rng in affected.get("ranges") or []:
            fixed += [e["fixed"] for e in rng.get("events") or [] if e.get("fixed")]
    return list(dict.fromkeys(fixed))


def apply_vulnerabilities(
    repos: list[Repo], cache_dir: Path, transport: httpx.BaseTransport | None = None
) -> int:
    """Annotate deps with advisory ids and add `vulnerable-dependency` flags. Returns the
    number of vulnerable (repo, dependency) pairs; 0 when OSV is unreachable."""
    for repo in repos:
        repo.flags = [f for f in repo.flags if f.id != "vulnerable-dependency"]
        for dep in repo.dependencies:
            dep.vulns = []
    keyed = [
        (repo, dep, key)
        for repo in repos
        for dep in repo.dependencies
        if (key := _key(dep)) is not None
    ]
    if not keyed:
        return 0
    try:
        client = OsvClient(cache_dir, transport)
        found = client.vulns_for(key for _, _, key in keyed)
        ids = sorted({i for v in found.values() for i in v})[:MAX_ADVISORIES]
        with ThreadPoolExecutor(max_workers=8) as pool:
            advisories = dict(zip(ids, pool.map(client.advisory, ids), strict=True))
    except (httpx.HTTPError, OSError, ValueError) as exc:
        log.warning("OSV lookup skipped (%s): vulnerability data not included", exc)
        return 0

    hits = 0
    per_repo: dict[str, list[Flag]] = {}
    flagged: set[tuple[str, Key]] = set()
    for repo, dep, key in keyed:
        vuln_ids = [i for i in found.get(key, []) if i in advisories]
        if not vuln_ids:
            continue
        dep.vulns = vuln_ids
        if (repo.id, key) in flagged:
            continue  # same package@version from another manifest in this repo
        flagged.add((repo.id, key))
        hits += 1
        worst = min((_severity(advisories[i]) for i in vuln_ids), key=lambda s: _RANK[s])
        fixed = sorted({f for i in vuln_ids for f in _fixed(advisories[i], key[1])})
        shown = ", ".join(vuln_ids[:3]) + ("..." if len(vuln_ids) > 3 else "")
        message = (
            f"{dep.name}@{key[2]}{' (transitive)' if dep.scope == 'transitive' else ''}: "
            f"{len(vuln_ids)} known advisor{'y' if len(vuln_ids) == 1 else 'ies'} ({shown})"
            + (f"; fixed in {', '.join(fixed[:3])}" if fixed else "; no fixed version yet")
        )
        per_repo.setdefault(repo.id, []).append(
            Flag(
                id="vulnerable-dependency",
                category="security",
                severity=worst,
                message=message,
                path=dep.manifest,
            )
        )
    for repo in repos:
        flags = sorted(per_repo.get(repo.id, []), key=lambda f: _RANK[f.severity])
        repo.flags += flags[:MAX_FLAGS_PER_REPO]
        repo.dependency_summary = summarize(repo.dependencies)
    return hits
