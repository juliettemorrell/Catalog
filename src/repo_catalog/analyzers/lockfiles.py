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
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from ..fs import RepoFiles
from ..models import Dependency
from ..textutil import clean_ref, load_json, load_yaml
from .versions import best_match, satisfies

MAX_TRANSITIVE_PER_LOCKFILE = 5000
MAX_LOCKFILE_BYTES = 30_000_000

Locked = list[tuple[str, str]]


@dataclass
class LockData:
    """Every (name, version) a lockfile pins, plus what the format says directly about
    which version each project's direct dependency got (npm/pnpm importers, yarn specs)."""

    entries: Locked = field(default_factory=list)
    # (importer dir relative to the lockfile, normalized name) -> version; "" is the root
    direct: dict[tuple[str, str], str] = field(default_factory=dict)
    # "name@range" as written in a manifest -> version (yarn)
    specs: dict[str, str] = field(default_factory=dict)
    # npm workspace member dirs: their deps are hoisted to the root, so a member missing
    # from ``direct`` may fall back to the root's record; nothing else may (pnpm never)
    workspaces: set[str] = field(default_factory=set)


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def split_at(spec: str) -> tuple[str, str]:
    """``@scope/name@1.2.3`` -> (``@scope/name``, ``1.2.3``): split at the first ``@``
    after the scope, so protocol specs (``npm:x@1``, ``patch:x@..``) stay in the range."""
    at = spec.find("@", 1)
    if at <= 0:
        return spec, ""
    return spec[:at], spec[at + 1 :]


def _npm_alias(name: str, version: str) -> tuple[str, str]:
    """package-lock v1 aliases: ``"version": "npm:left-pad@1.3.0"`` -> (left-pad, 1.3.0)."""
    if version.startswith("npm:"):
        real, ver = split_at(version[4:])
        if real and ver:
            return real, ver
    return name, version


# ------------------------------------------------------------------------------ JavaScript


def _package_lock(text: str) -> LockData:
    data = _d(json.loads(text))
    out = LockData()
    packages = _d(data.get("packages"))
    if packages:  # lockfileVersion 2 and 3: keys are install paths
        for key, meta in packages.items():
            meta = _d(meta)
            if key and "node_modules/" not in key:
                out.workspaces.add(key.strip("/"))
            if "node_modules/" not in key or meta.get("link") or not meta.get("version"):
                continue  # root, workspace members and links are the repo's own code
            installed = key.rsplit("node_modules/", 1)[1]
            name, version = _npm_alias(str(meta.get("name") or installed), str(meta["version"]))
            out.entries.append((name, version))
            owner = key.rsplit("node_modules/", 1)[0].rstrip("/")
            if "node_modules" not in owner:  # "" (root) or a workspace dir, not a nested dep
                out.direct[(owner, norm("npm", name))] = version
        return out

    def walk(deps: dict[str, Any], depth: int) -> None:  # lockfileVersion 1: nested tree
        if depth > 200:
            return
        for key, meta in deps.items():
            meta = _d(meta)
            if meta.get("version"):
                name, version = _npm_alias(str(key), str(meta["version"]))
                out.entries.append((name, version))
                if depth == 0:
                    out.direct[("", norm("npm", name))] = version
            walk(_d(meta.get("dependencies")), depth + 1)

    walk(_d(data.get("dependencies")), 0)
    return out


_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _yarn_lock(text: str) -> LockData:
    """Yarn v1 (``foo@^1.0.0, foo@^1.1.0:``) and Berry (``"foo@npm:^1.0.0":``)."""
    out = LockData()
    specs: list[tuple[str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            specs = []
            header = line.rstrip()
            if (
                not header.endswith(":")
                or header.startswith('"__metadata')
                or header.startswith("__metadata")
            ):
                continue
            for spec in header[:-1].split(","):
                spec = spec.strip().strip('"')
                name, rng = split_at(spec)
                if not name or rng.startswith(("workspace:", "link:", "portal:", "file:")):
                    continue  # the repo's own packages
                specs.append((name, rng))
            continue
        if specs and (m := _YARN_VERSION.match(line)):
            real_names: list[str] = []
            for name, rng in specs:
                out.specs[f"{name}@{rng}"] = m.group(1)
                real = name
                if rng.startswith("npm:"):
                    target, target_rng = split_at(rng[4:])
                    if target_rng and not re.match(r"^[\d^~<>=*xX]", target):
                        # alias: "myalias@npm:left-pad@^1.3.0" installs left-pad
                        real = target
                        out.specs[f"{target}@{target_rng}"] = m.group(1)
                    else:
                        out.specs[f"{name}@{rng[4:]}"] = m.group(1)
                real_names.append(real)
            for name in dict.fromkeys(real_names):
                out.entries.append((name, m.group(1)))
            specs = []
    return out


_PNPM_KEY = re.compile(r"^  ['\"]?(?P<key>[^'\"\s]+?)['\"]?:\s*$")
_TOP_KEY = re.compile(r"^([A-Za-z]\w*):")


def _pnpm_key(key: str, v5: bool) -> tuple[str, str] | None:
    key = key.lstrip("/")
    if v5:  # /name/1.0.0 or /@scope/name/1.0.0_peer@1.0.0
        name, _, version = key.rpartition("/")
        version = version.split("_", 1)[0]
    else:  # name@1.0.0(peer@1.0.0)
        name, version = split_at(key.split("(", 1)[0])
    if name and re.match(r"\d", version):
        return name, version
    return None


def _pnpm_version(value: Any, v5: bool) -> str | None:
    if isinstance(value, dict):
        value = value.get("version")
    if not isinstance(value, str | int | float):
        return None
    text = str(value)
    if text.startswith(("link:", "file:", "workspace:")):
        return None
    text = text.split("(", 1)[0]
    if v5:
        text = text.split("_", 1)[0]
    if "@" in text.lstrip("/"):  # aliased or v6 "/name@1.0.0" style
        text = split_at(text.lstrip("/"))[1]
    return text or None


def _pnpm_lock(text: str) -> LockData:
    """pnpm v5 (``/name/1.0.0``), v6 (``/name@1.0.0``) and v9 (``name@1.0.0``), with the
    versions each importer (workspace project) resolved its direct deps to."""
    out = LockData()
    version_line = re.search(r"^lockfileVersion:\s*['\"]?(\d+)", text, re.M)
    v5 = bool(version_line) and int(version_line.group(1)) < 6  # type: ignore[union-attr]
    sections: dict[str, list[str]] = {}
    current = ""
    for line in text.splitlines():
        if line and not line.startswith(" "):
            m = _TOP_KEY.match(line)
            current = m.group(1) if m else ""
            continue
        if current:
            sections.setdefault(current, []).append(line)
    for section in ("packages", "snapshots"):
        for line in sections.get(section, []):
            m = _PNPM_KEY.match(line)
            parsed = _pnpm_key(m.group("key"), v5) if m else None
            if parsed:
                out.entries.append(parsed)
    out.entries = list(dict.fromkeys(out.entries))

    importers: dict[str, Any] = {}
    if "importers" in sections:
        importers = _d(load_yaml("\n".join(sections["importers"])))
    elif any(k in sections for k in ("dependencies", "devDependencies")):  # single project
        importers = {
            ".": {
                k: load_yaml("\n".join(sections[k]))
                for k in ("dependencies", "devDependencies", "optionalDependencies")
                if k in sections
            }
        }
    for importer, groups in importers.items():
        where = "" if importer in (".", "") else str(importer).strip("/")
        for group in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, value in _d(_d(groups).get(group)).items():
                version = _pnpm_version(value, v5)
                if version:
                    out.direct[(where, norm("npm", str(name)))] = version
    return out


def _bun_lock(text: str) -> Locked:
    data = _d(load_json(text))
    out: Locked = []
    for entry in _d(data.get("packages")).values():
        spec = str(_l(entry)[0]) if _l(entry) else ""
        name, version = split_at(spec)
        if name and version and not version.startswith(("workspace:", "link:", "file:")):
            out.append((name, version))
    return out


# ---------------------------------------------------------------------------------- Python

_LOCAL_SOURCE = {"editable", "virtual", "workspace", "directory", "path"}


def _toml_packages(text: str, *, registry_only: bool = False) -> Locked:
    """poetry.lock, uv.lock, pdm.lock, Cargo.lock: ``[[package]] name/version``, skipping
    the repo's own packages (path, directory, editable and workspace sources)."""
    out: Locked = []
    for pkg in _l(tomllib.loads(text).get("package")):
        pkg = _d(pkg)
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source")
        if registry_only and source is None:
            continue  # Cargo: crates without a source are workspace members / path deps
        if isinstance(source, dict) and (
            _LOCAL_SOURCE & set(source) or source.get("type") in ("directory", "file")
        ):
            continue
        if pkg.get("path") or pkg.get("editable"):
            continue  # pdm local packages
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
    section = ""
    in_specs = False
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section, in_specs = line.strip(), False
            continue
        if line.strip() == "specs:":
            in_specs = section in ("GEM", "GIT")  # PATH gems are the repo's own code
            continue
        if in_specs and (m := re.match(r"^    ([^\s(]+) \(([^)]+)\)", line)):
            out.append(
                (
                    m.group(1),
                    re.sub(
                        r"-(x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux|musl).*$",
                        "",
                        m.group(2),
                    ),
                )
            )
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
    return re.findall(r'^[ \t]*"([\w-]+)":\s*\{:hex,\s*:[\w-]+,\s*"([^"]+)"', text, re.M)


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
    url = re.sub(r"^(?:[a-z+]+://)?", "", url.strip()).split("?", 1)[0].split("#", 1)[0]
    host, sep, rest = url.partition("/")
    host = host.rsplit("@", 1)[-1]  # drop userinfo: user:token@github.com
    if ":" in host and not re.search(r":\d+$", host):  # scp-like git@github.com:owner/repo
        host, _, first = host.partition(":")
        rest = f"{first}/{rest}" if rest else first
    return f"{host}{sep or '/'}{rest}".removesuffix("/").removesuffix(".git").lower()


def _podfile_lock(text: str) -> Locked:
    out: Locked = []
    in_pods = False
    for line in text.splitlines():
        if line.startswith("PODS:"):
            in_pods = True
            continue
        if in_pods and line and not line.startswith(" "):
            break
        if in_pods and (m := re.match(r"^  - \"?([^\s(/\"]+)(?:/[^\s\"]+)? \(([^)]+)\)", line)):
            out.append((m.group(1), m.group(2)))
    return list(dict.fromkeys(out))


def _renv_lock(text: str) -> Locked:
    packages = _d(json.loads(text).get("Packages"))
    return [(n, str(_d(m).get("Version"))) for n, m in packages.items() if _d(m).get("Version")]


def _terraform_lock(text: str) -> Locked:
    return [
        (name.split("/", 1)[1] if name.count("/") >= 2 else name, version)
        for name, version in re.findall(
            r'provider\s+"([^"]+)"\s*\{[^{}]{0,4000}?\bversion\s*=\s*"([^"]+)"', text
        )
    ]


# lowercase file name -> (ecosystem, parser)
PARSERS: dict[str, tuple[str, Callable[[str], Locked | LockData]]] = {
    "package-lock.json": ("npm", _package_lock),
    "npm-shrinkwrap.json": ("npm", _package_lock),
    "yarn.lock": ("npm", _yarn_lock),
    "pnpm-lock.yaml": ("npm", _pnpm_lock),
    "bun.lock": ("npm", _bun_lock),
    "poetry.lock": ("pypi", _toml_packages),
    "pdm.lock": ("pypi", _toml_packages),
    "uv.lock": ("pypi", _toml_packages),
    "pipfile.lock": ("pypi", _pipfile_lock),
    "cargo.lock": ("cargo", lambda t: _toml_packages(t, registry_only=True)),
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


def norm(ecosystem: str, name: object) -> str:
    name = str(name).strip().lower()
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
    """Resolve direct deps to their locked versions and append every other locked version
    as a transitive dependency. Never raises: problems go to ``errors``."""
    parsed: list[tuple[str, str, LockData]] = []
    for path in lockfile_paths:
        spec = PARSERS.get(PurePosixPath(path).name.lower())
        if not spec:
            continue
        text = files.read(path, MAX_LOCKFILE_BYTES + 1, cache=False)
        if not text or len(text) > MAX_LOCKFILE_BYTES:
            continue
        ecosystem, parser = spec
        try:
            result = parser(text)
            data = result if isinstance(result, LockData) else LockData(entries=result)
            # lockfile versions can be git/tarball URLs carrying deploy tokens
            data.entries = [
                (clean_ref(str(n)), clean_ref(str(v))) for n, v in data.entries if n and v
            ]
            data.direct = {k: clean_ref(str(v)) for k, v in data.direct.items()}
            data.specs = {k: clean_ref(str(v)) for k, v in data.specs.items()}
        except Exception as exc:  # a malformed lockfile must not lose the manifests
            errors.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        parsed.append((path, ecosystem, data))

    # nearest lockfile wins: deeper directories first
    parsed.sort(key=lambda p: -len(_dir(p[0])))
    claimed: dict[str, set[tuple[str, str]]] = {p[0]: set() for p in parsed}
    for dep in dependencies:
        dep_dir = _dir(dep.manifest)
        for path, ecosystem, data in parsed:
            lock_dir = _dir(path)
            if dep.ecosystem != ecosystem or not _covers(lock_dir, dep_dir):
                continue
            if not dep.resolved:
                dep.resolved = _resolve(dep, data, _relative(lock_dir, dep_dir))
            if dep.resolved:
                claimed[path].add((norm(ecosystem, dep.name), dep.resolved))
            break

    seen = {(d.ecosystem, norm(d.ecosystem, d.name), d.resolved) for d in dependencies}
    for path, ecosystem, data in parsed:
        added = 0
        for name, version in data.entries:
            key = norm(ecosystem, name)
            if (key, version) in claimed[path] or (ecosystem, key, version) in seen:
                continue
            if added >= MAX_TRANSITIVE_PER_LOCKFILE:
                errors.append(f"{path}: more than {MAX_TRANSITIVE_PER_LOCKFILE} locked packages")
                break
            seen.add((ecosystem, key, version))
            added += 1
            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    resolved=version,
                    ecosystem=ecosystem,
                    scope="transitive",
                    manifest=path,
                )
            )


def _relative(lock_dir: str, dep_dir: str) -> str:
    if not lock_dir:
        return dep_dir
    return "" if dep_dir == lock_dir else dep_dir[len(lock_dir) + 1 :]


def _resolve(dep: Dependency, data: LockData, importer: str) -> str | None:
    """The locked version of a direct dependency: the lockfile's own record for this
    project first, then the version satisfying the declared range. Never a guess."""
    key = norm(dep.ecosystem, dep.name)
    # the root's record only stands in for a declared npm workspace member (hoisted deps)
    places = [importer, ""] if importer == "" or importer in data.workspaces else [importer]
    for where in dict.fromkeys(places):
        found = data.direct.get((where, key))
        if found is not None:
            if dep.version and satisfies(found, dep.version, dep.ecosystem) is False:
                break  # the lockfile records something else than this manifest asks for
            return found
    if dep.version and f"{dep.name}@{dep.version}" in data.specs:
        return data.specs[f"{dep.name}@{dep.version}"]
    candidates = list(dict.fromkeys(v for n, v in data.entries if norm(dep.ecosystem, n) == key))
    return best_match(candidates, dep.version, dep.ecosystem)
