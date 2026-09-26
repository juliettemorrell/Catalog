"""Lockfiles: the exact versions a repo installs, including transitive dependencies.

Manifests say what a team asked for (``^1.2``); lockfiles say what actually ships
(``1.4.7`` plus everything it pulls in). That is what matters for "which repos run the
vulnerable version of X?". Each parser returns (name, version) pairs; ``apply_lockfiles``
fills ``resolved`` on direct dependencies and adds the rest as ``transitive``.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath
from typing import Any

from ..fs import RepoFiles
from ..models import Dependency
from ..textutil import load_json, load_yaml

MAX_TRANSITIVE_PER_LOCKFILE = 5000
MAX_LOCKFILE_BYTES = 30_000_000

Locked = list[tuple[str, str]]


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _split_at(spec: str) -> tuple[str, str]:
    """``@scope/name@1.2.3`` -> (``@scope/name``, ``1.2.3``)."""
    at = spec.rfind("@")
    if at <= 0:
        return spec, ""
    return spec[:at], spec[at + 1 :]


# ------------------------------------------------------------------------------ JavaScript


def _package_lock(text: str) -> Locked:
    data = _d(json.loads(text))
    out: Locked = []
    packages = _d(data.get("packages"))
    if packages:  # lockfileVersion 2 and 3
        for key, meta in packages.items():
            meta = _d(meta)
            if "node_modules/" not in key or meta.get("link") or not meta.get("version"):
                continue  # root, workspace members and links are the repo's own code
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            out.append((str(name), str(meta["version"])))
        return out

    def walk(deps: dict[str, Any]) -> None:  # lockfileVersion 1: nested tree
        for name, meta in deps.items():
            meta = _d(meta)
            if meta.get("version"):
                out.append((name, str(meta["version"])))
            walk(_d(meta.get("dependencies")))

    walk(_d(data.get("dependencies")))
    return out


_YARN_HEADER = re.compile(r'^"?(?P<specs>[^\s#][^:]*?)"?:\s*$')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _yarn_lock(text: str) -> Locked:
    """Yarn v1 and Berry: header lines list the requested specs, then a version line."""
    out: Locked = []
    names: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            m = _YARN_HEADER.match(line)
            names = []
            if m and "__metadata" not in line:
                for spec in m.group("specs").split(","):
                    spec = spec.strip().strip('"')
                    name, rest = _split_at(spec)
                    if "workspace:" in rest or "link:" in rest or "portal:" in rest:
                        continue  # the repo's own packages
                    names.append(name)
            continue
        if names and (m := _YARN_VERSION.match(line)):
            for name in dict.fromkeys(names):
                out.append((name, m.group(1)))
            names = []
    return out


_PNPM_KEY = re.compile(r"^  ['\"]?/?(?P<key>[^'\"\s]+?)['\"]?:\s*$")


def _pnpm_lock(text: str) -> Locked:
    """pnpm v5 (``/name/1.0.0``), v6 (``/name@1.0.0``) and v9 (``name@1.0.0``)."""
    out: Locked = []
    section = ""
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section = line.rstrip(":").strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        m = _PNPM_KEY.match(line)
        if not m:
            continue
        key = re.split(r"[(_]", m.group("key"), maxsplit=1)[0]  # peer suffixes
        name, version = _split_at(key)
        if not version:  # v5: /@scope/name/1.0.0
            head, _, version = key.rpartition("/")
            name = head
        if name and re.match(r"\d", version):
            out.append((name, version))
    return list(dict.fromkeys(out))


def _bun_lock(text: str) -> Locked:
    data = _d(load_json(text))
    out: Locked = []
    for entry in _d(data.get("packages")).values():
        spec = str(_l(entry)[0]) if _l(entry) else ""
        name, version = _split_at(spec)
        if name and version and not version.startswith("workspace:"):
            out.append((name, version))
    return out


# ---------------------------------------------------------------------------------- Python


def _toml_packages(text: str, *, skip_local: bool = False) -> Locked:
    """poetry.lock, uv.lock, pdm.lock, Cargo.lock: ``[[package]] name/version``."""
    out: Locked = []
    for pkg in _l(tomllib.loads(text).get("package")):
        pkg = _d(pkg)
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source")
        if skip_local and (
            source is None
            or (isinstance(source, dict) and {"editable", "virtual", "workspace"} & set(source))
        ):
            continue  # the repo's own crates / packages
        if isinstance(name, str) and isinstance(version, str):
            out.append((name, version))
    return out


def _pipfile_lock(text: str) -> Locked:
    data = _d(json.loads(text))
    out: Locked = []
    for section in ("default", "develop"):
        for name, meta in _d(data.get(section)).items():
            version = str(_d(meta).get("version") or "").lstrip("=")
            if version:
                out.append((name, version))
    return out


# ------------------------------------------------------------------------------- the rest


def _gemfile_lock(text: str) -> Locked:
    out: Locked = []
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if in_specs and (m := re.match(r"^    ([^\s(]+) \(([^)]+)\)", line)):
            out.append((m.group(1), m.group(2).split("-")[0]))
    return out


def _composer_lock(text: str) -> Locked:
    data = _d(json.loads(text))
    return [
        (str(p["name"]), str(p["version"]).lstrip("v"))
        for key in ("packages", "packages-dev")
        for p in _l(data.get(key))
        if isinstance(p, dict) and p.get("name") and p.get("version")
    ]


def _nuget_lock(text: str) -> Locked:
    out: Locked = []
    for framework in _d(json.loads(text).get("dependencies")).values():
        for name, meta in _d(framework).items():
            meta = _d(meta)
            if meta.get("type") != "Project" and meta.get("resolved"):
                out.append((name, str(meta["resolved"])))
    return list(dict.fromkeys(out))


def _pubspec_lock(text: str) -> Locked:
    packages = _d(_d(load_yaml(text)).get("packages"))
    return [
        (name, str(_d(meta).get("version")))
        for name, meta in packages.items()
        if _d(meta).get("version") and _d(meta).get("source") != "path"
    ]


def _gradle_lock(text: str) -> Locked:
    out: Locked = []
    for line in text.splitlines():
        coords = line.split("=", 1)[0].strip()
        parts = coords.split(":")
        if len(parts) == 3 and not line.startswith("#"):
            out.append((f"{parts[0]}:{parts[1]}", parts[2]))
    return out


def _mix_lock(text: str) -> Locked:
    return re.findall(r'^\s*"([\w-]+)":\s*\{:hex,\s*:[\w-]+,\s*"([^"]+)"', text, re.M)


def _swift_resolved(text: str) -> Locked:
    data = _d(json.loads(text))
    pins = _l(data.get("pins")) or _l(_d(data.get("object")).get("pins"))
    out: Locked = []
    for pin in pins:
        pin = _d(pin)
        url = str(pin.get("location") or pin.get("repositoryURL") or "")
        version = _d(pin.get("state")).get("version")
        if url and version:
            out.append((swift_name(url), str(version)))
    return out


def swift_name(url: str) -> str:
    """Swift packages are identified by repository: ``github.com/apple/swift-nio``."""
    url = re.sub(r"^(?:https?://|git@|ssh://git@)", "", url.strip())
    return url.replace(":", "/", 1).removesuffix(".git").removesuffix("/").lower()


def _podfile_lock(text: str) -> Locked:
    out: Locked = []
    in_pods = False
    for line in text.splitlines():
        if line.startswith("PODS:"):
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        if in_pods and (m := re.match(r"^  - ([^\s(/]+)(?:/\S+)? \(([^)]+)\)", line)):
            out.append((m.group(1), m.group(2)))
    return list(dict.fromkeys(out))


def _renv_lock(text: str) -> Locked:
    packages = _d(json.loads(text).get("Packages"))
    return [(n, str(_d(m).get("Version"))) for n, m in packages.items() if _d(m).get("Version")]


def _terraform_lock(text: str) -> Locked:
    return [
        (name.split("/", 1)[1] if name.count("/") >= 2 else name, version)
        for name, version in re.findall(
            r'provider\s+"([^"]+)"\s*\{[^}]*?\bversion\s*=\s*"([^"]+)"', text, re.S
        )
    ]


# lowercase file name -> (ecosystem, parser)
PARSERS: dict[str, tuple[str, Callable[[str], Locked]]] = {
    "package-lock.json": ("npm", _package_lock),
    "npm-shrinkwrap.json": ("npm", _package_lock),
    "yarn.lock": ("npm", _yarn_lock),
    "pnpm-lock.yaml": ("npm", _pnpm_lock),
    "bun.lock": ("npm", _bun_lock),
    "poetry.lock": ("pypi", _toml_packages),
    "pdm.lock": ("pypi", _toml_packages),
    "uv.lock": ("pypi", lambda t: _toml_packages(t, skip_local=True)),
    "pipfile.lock": ("pypi", _pipfile_lock),
    "cargo.lock": ("cargo", lambda t: _toml_packages(t, skip_local=True)),
    "gemfile.lock": ("gem", _gemfile_lock),
    "composer.lock": ("composer", _composer_lock),
    "packages.lock.json": ("nuget", _nuget_lock),
    "pubspec.lock": ("pub", _pubspec_lock),
    "gradle.lockfile": ("maven", _gradle_lock),
    "mix.lock": ("hex", _mix_lock),
    "package.resolved": ("swift", _swift_resolved),
    "podfile.lock": ("cocoapods", _podfile_lock),
    "renv.lock": ("cran", _renv_lock),
    ".terraform.lock.hcl": ("terraform", _terraform_lock),
}


def norm(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _dir(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def _covers(lock_dir: str, manifest: str) -> bool:
    return lock_dir == "" or manifest == lock_dir or manifest.startswith(lock_dir + "/")


def apply_lockfiles(
    files: RepoFiles,
    lockfile_paths: Iterable[str],
    dependencies: list[Dependency],
    errors: list[str],
) -> None:
    """Resolve direct deps to locked versions and append locked transitive deps."""
    # (path, ecosystem, normalized name -> (name as written, versions))
    parsed: list[tuple[str, str, dict[str, tuple[str, list[str]]]]] = []
    for path in lockfile_paths:
        spec = PARSERS.get(PurePosixPath(path).name.lower())
        if not spec:
            continue
        text = files.read(path, MAX_LOCKFILE_BYTES + 1, cache=False)
        if not text or len(text) > MAX_LOCKFILE_BYTES:
            continue
        ecosystem, parser = spec
        try:
            locked = parser(text)
        except Exception as exc:  # a malformed lockfile must not lose the manifests
            errors.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        versions: dict[str, tuple[str, list[str]]] = {}
        for name, version in locked:
            _, bucket = versions.setdefault(norm(ecosystem, name), (name, []))
            if version not in bucket:
                bucket.append(version)
        parsed.append((path, ecosystem, versions))

    # nearest lockfile wins: deeper directories first
    parsed.sort(key=lambda p: -len(_dir(p[0])))
    direct_by_lock: dict[str, set[str]] = {p[0]: set() for p in parsed}
    for dep in dependencies:
        dep_dir = _dir(dep.manifest)
        for path, ecosystem, versions in parsed:
            if dep.ecosystem != ecosystem or not _covers(_dir(path), dep_dir):
                continue
            key = norm(ecosystem, dep.name)
            direct_by_lock[path].add(key)
            if key in versions and not dep.resolved:
                dep.resolved = versions[key][1][0]
            break

    seen = {(d.ecosystem, norm(d.ecosystem, d.name), d.resolved) for d in dependencies}
    for path, ecosystem, versions in parsed:
        added = 0
        for key, (written, found) in versions.items():
            if key in direct_by_lock[path]:
                continue
            for version in found:
                if (ecosystem, key, version) in seen or added >= MAX_TRANSITIVE_PER_LOCKFILE:
                    continue
                seen.add((ecosystem, key, version))
                added += 1
                dependencies.append(
                    Dependency(
                        name=written,
                        version=version,
                        resolved=version,
                        ecosystem=ecosystem,
                        scope="transitive",
                        manifest=path,
                    )
                )
