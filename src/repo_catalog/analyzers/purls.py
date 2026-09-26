"""Package URLs and exact versions, so dependencies line up with SBOM and vulnerability tools.

purl spec: https://github.com/package-url/purl-spec (types npm, pypi, golang, cargo, maven,
gem, composer, nuget, pub, swift, cocoapods, hex, cran, conda, docker, github, bazel,
conan).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import quote

from ..models import Dependency, DependencySummary

# ecosystems whose deps are code packages (vs images, actions, tooling hooks)
PACKAGE_ECOSYSTEMS = frozenset(
    {
        "npm",
        "pypi",
        "go",
        "cargo",
        "maven",
        "gem",
        "composer",
        "nuget",
        "pub",
        "swift",
        "cocoapods",
        "hex",
        "cran",
        "conda",
        "bazel",
        "vcpkg",
        "conan",
        "jsr",
        "deno",
    }
)
_EXACT = re.compile(r"^(?:==|=|v)?(\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.\-+]*)?)$")
# a bare "1.2.3" means ^1.2.3 in Cargo and ~> in Terraform/Helm; only locks make it exact
_BARE_IS_RANGE = {"cargo", "terraform", "helm", "conda"}
_PURL_TYPE = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "golang",
    "cargo": "cargo",
    "maven": "maven",
    "gem": "gem",
    "composer": "composer",
    "nuget": "nuget",
    "pub": "pub",
    "swift": "swift",
    "cocoapods": "cocoapods",
    "hex": "hex",
    "cran": "cran",
    "conda": "conda",
    "docker": "docker",
    "github-actions": "github",
    "bazel": "bazel",
    "conan": "conan",
}


def exact_version(ecosystem: str, version: str | None) -> str | None:
    if not version or ecosystem in _BARE_IS_RANGE:
        return None
    m = _EXACT.match(version.strip())
    if not m:
        return None
    if ecosystem == "docker" and version in ("latest", "stable"):
        return None
    return m.group(1)


def purl(dep: Dependency) -> str | None:
    kind = _PURL_TYPE.get(dep.ecosystem)
    if not kind:
        return None
    version = dep.resolved or (
        dep.version if dep.ecosystem in ("docker", "github-actions") else None
    )
    name = dep.name
    namespace = ""
    qualifiers = ""
    if kind == "npm" and name.startswith("@") and "/" in name:
        scope, _, name = name.partition("/")
        namespace = quote(scope, safe="")
    elif kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name.lower())
    elif kind == "maven" and ":" in name:
        namespace, _, name = name.partition(":")
    elif kind in ("golang", "swift", "composer", "github") and "/" in name:
        namespace, _, name = name.rpartition("/")
    elif kind == "docker":
        registry, _, rest = name.partition("/") if "." in name.split("/")[0] else ("", "", name)
        if registry:
            qualifiers = f"?repository_url={quote(registry, safe='')}"
        namespace, _, name = rest.rpartition("/")
        namespace = namespace or ("library" if not registry else "")
    parts = [f"pkg:{kind}"]
    if namespace:
        parts.append("/".join(quote(p, safe="%") for p in namespace.split("/")))
    parts.append(quote(name, safe=""))
    out = "/".join(parts)
    if version:
        out += "@" + quote(version, safe="")
    return out + qualifiers


def finalize_dependencies(deps: list[Dependency]) -> None:
    """Exact pins count as resolved; every dependency gets a purl where one exists."""
    for dep in deps:
        if not dep.resolved:
            dep.resolved = exact_version(dep.ecosystem, dep.version)
        dep.purl = purl(dep)


def summarize(deps: list[Dependency]) -> DependencySummary:
    direct = [d for d in deps if d.scope != "transitive"]
    packages = [d for d in direct if d.ecosystem in PACKAGE_ECOSYSTEMS]
    resolved = sum(1 for d in packages if d.resolved)
    return DependencySummary(
        direct=len(direct),
        transitive=len(deps) - len(direct),
        ecosystems=dict(Counter(d.ecosystem for d in direct).most_common()),
        lockfile_coverage=round(resolved / len(packages), 3) if packages else 0.0,
        vulnerable=sum(1 for d in deps if d.vulns),
    )


_ECOSYSTEM_BY_TYPE = {v: k for k, v in _PURL_TYPE.items()}


def parse_purl(value: str) -> tuple[str, str, str | None] | None:
    """``pkg:npm/%40acme/ui@2.0.0`` -> (``npm``, ``@acme/ui``, ``2.0.0``)."""
    from urllib.parse import unquote

    m = re.match(r"^pkg:([a-z0-9.+-]+)/([^?#]+?)(?:@([^?#]+))?(?:[?#].*)?$", value.strip())
    if not m:
        return None
    ecosystem = _ECOSYSTEM_BY_TYPE.get(m.group(1).lower())
    if not ecosystem:
        return None
    path = [unquote(p) for p in m.group(2).split("/")]
    maven = ecosystem == "maven" and len(path) == 2
    name = f"{path[0]}:{path[1]}" if maven else "/".join(path)
    version = unquote(m.group(3)) if m.group(3) else None
    return ecosystem, name, version


def merge_github_sbom(deps: list[Dependency], sbom: dict[str, Any]) -> int:
    """Add packages from GitHub's dependency graph that the manifest parsers did not see
    (ecosystems or files we don't parse). Returns how many were added."""
    have = {(d.ecosystem, d.name.lower()) for d in deps}
    root_targets = {
        r.get("relatedSpdxElement")
        for r in sbom.get("relationships") or []
        if isinstance(r, dict)
        and r.get("relationshipType") == "DEPENDS_ON"
        and str(r.get("spdxElementId", "")).startswith("SPDXRef-com.github")
    }
    added = 0
    for pkg in sbom.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        refs = pkg.get("externalRefs") or []
        locator = next(
            (
                r.get("referenceLocator")
                for r in refs
                if isinstance(r, dict) and r.get("referenceType") == "purl"
            ),
            None,
        )
        parsed = parse_purl(str(locator)) if locator else None
        if not parsed or (parsed[0], parsed[1].lower()) in have:
            continue
        ecosystem, name, version = parsed
        have.add((ecosystem, name.lower()))
        dep = Dependency(
            name=name,
            version=version,
            ecosystem=ecosystem,
            scope="runtime" if pkg.get("SPDXID") in root_targets else "transitive",
            manifest="github-dependency-graph",
            resolved=exact_version(ecosystem, version) if version else None,
        )
        dep.purl = purl(dep)
        deps.append(dep)
        added += 1
    return added
