"""Parse package manifests from every mainstream ecosystem into Dependencies and Packages."""

from __future__ import annotations

import json
import logging
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import yaml

from ..fs import RepoFiles
from ..models import Dependency, Package

log = logging.getLogger(__name__)

LOCKFILES = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "bun.lockb": "bun",
    "bun.lock": "bun",
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "pipfile.lock": "pipenv",
    "pdm.lock": "pdm",
    "cargo.lock": "cargo",
    "go.sum": "go modules",
    "gemfile.lock": "bundler",
    "composer.lock": "composer",
    "packages.lock.json": "nuget",
    "pubspec.lock": "pub",
    "gradle.lockfile": "gradle",
    "mix.lock": "mix",
}


@dataclass
class ManifestResult:
    dependencies: list[Dependency] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    runtimes: dict[str, str] = field(default_factory=dict)
    package_managers: set[str] = field(default_factory=set)
    lockfiles: list[str] = field(default_factory=list)
    workspaces: bool = False
    scripts: dict[str, dict[str, str]] = field(default_factory=dict)  # manifest -> scripts
    bins: list[str] = field(default_factory=list)
    descriptions: list[tuple[int, str]] = field(default_factory=list)  # (depth, description)
    errors: list[str] = field(default_factory=list)

    def add_dep(self, name: str, version: Any, ecosystem: str, scope: str, manifest: str) -> None:
        if not name:
            return
        ver = version if isinstance(version, str) else None
        self.dependencies.append(
            Dependency(
                name=name,
                version=ver,
                ecosystem=ecosystem,
                scope=scope,  # type: ignore[arg-type]
                manifest=manifest,
            )
        )


MAX_MANIFESTS_PER_KIND = 200


def parse_manifests(files: RepoFiles) -> ManifestResult:
    res = ManifestResult()
    parsers = [
        (("package.json",), _package_json),
        (("pyproject.toml",), _pyproject),
        (("pipfile",), _pipfile),
        (("go.mod",), _go_mod),
        (("cargo.toml",), _cargo),
        (("pom.xml",), _pom),
        (("build.gradle", "build.gradle.kts"), _gradle),
        (("gemfile",), _gemfile),
        (("composer.json",), _composer),
        (("pubspec.yaml",), _pubspec),
        (("setup.py",), _setup_py),
    ]
    for names, parser in parsers:
        for entry in files.named(*names)[:MAX_MANIFESTS_PER_KIND]:
            text = files.read(entry.path)
            if text is None:
                continue
            try:
                parser(entry.path, text, res)
            except Exception as exc:  # manifests in the wild are messy; never fail the scan
                res.errors.append(f"{entry.path}: {type(exc).__name__}: {exc}"[:300])
    for entry in files.files:
        name = entry.name.lower()
        if name.startswith("requirements") and name.endswith((".txt", ".in")):
            text = files.read(entry.path)
            if text:
                _requirements(entry.path, text, res)
        elif name.endswith(".csproj") or name.endswith(".fsproj"):
            text = files.read(entry.path)
            if text:
                try:
                    _csproj(entry.path, text, res)
                except ET.ParseError as exc:
                    res.errors.append(f"{entry.path}: {exc}")
        if name in LOCKFILES:
            res.package_managers.add(LOCKFILES[name])
            res.lockfiles.append(entry.path)
    _runtime_files(files, res)
    return res


# -- JavaScript ---------------------------------------------------------------------------


def _package_json(path: str, text: str, res: ManifestResult) -> None:
    data = json.loads(text)
    if not isinstance(data, dict):
        return
    scopes = (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    )
    for key, scope in scopes:
        for name, ver in (data.get(key) or {}).items():
            res.add_dep(name, ver, "npm", scope, path)
    if data.get("name"):
        res.packages.append(
            Package(
                name=data["name"],
                path=_dir(path),
                ecosystem="npm",
                version=data.get("version"),
                description=data.get("description"),
                private=data.get("private"),
            )
        )
    if data.get("description"):
        res.descriptions.append((path.count("/"), data["description"]))
    if data.get("workspaces"):
        res.workspaces = True
    if isinstance(data.get("engines"), dict) and data["engines"].get("node"):
        res.runtimes.setdefault("node", str(data["engines"]["node"]))
    pm = data.get("packageManager")
    if isinstance(pm, str):
        res.package_managers.add(pm.split("@", 1)[0])
    if isinstance(data.get("scripts"), dict):
        res.scripts[path] = {k: str(v) for k, v in data["scripts"].items()}
    bins = data.get("bin")
    if isinstance(bins, str):
        res.bins.append(data.get("name") or path)
    elif isinstance(bins, dict):
        res.bins.extend(bins.keys())


# -- Python -------------------------------------------------------------------------------

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def _split_req(req: str) -> tuple[str, str | None]:
    req = req.split(";", 1)[0].split("#", 1)[0].strip()
    m = _REQ_NAME.match(req)
    if not m:
        return "", None
    return m.group(1), (m.group(3).strip() or None)


def _requirements(path: str, text: str, res: ManifestResult) -> None:
    scope = (
        "dev" if re.search(r"(dev|test|lint|docs)", PurePosixPath(path).name, re.I) else "runtime"
    )
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        name, ver = _split_req(line)
        res.add_dep(name, ver, "pypi", scope, path)
    res.package_managers.add("pip")


def _pyproject(path: str, text: str, res: ManifestResult) -> None:
    data = tomllib.loads(text)
    project = data.get("project") or {}
    for req in project.get("dependencies") or []:
        name, ver = _split_req(req)
        res.add_dep(name, ver, "pypi", "runtime", path)
    for group, reqs in (project.get("optional-dependencies") or {}).items():
        scope = "dev" if group in {"dev", "test", "tests", "lint", "docs", "typing"} else "optional"
        for req in reqs:
            name, ver = _split_req(req)
            res.add_dep(name, ver, "pypi", scope, path)
    for reqs in (data.get("dependency-groups") or {}).values():
        for req in reqs:
            if isinstance(req, str):
                name, ver = _split_req(req)
                res.add_dep(name, ver, "pypi", "dev", path)
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    for name, ver in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python":
            res.runtimes.setdefault("python", str(ver))
        else:
            res.add_dep(name, ver, "pypi", "runtime", path)
    for grp in (poetry.get("group") or {}).values():
        for name, ver in (grp.get("dependencies") or {}).items():
            res.add_dep(name, ver, "pypi", "dev", path)
    for name, ver in (poetry.get("dev-dependencies") or {}).items():
        res.add_dep(name, ver, "pypi", "dev", path)
    for req in (data.get("build-system") or {}).get("requires") or []:
        name, ver = _split_req(req)
        res.add_dep(name, ver, "pypi", "build", path)
    for req in (tool.get("uv") or {}).get("dev-dependencies") or []:
        name, ver = _split_req(req)
        res.add_dep(name, ver, "pypi", "dev", path)
    pkg_name = project.get("name") or poetry.get("name")
    if pkg_name:
        res.packages.append(
            Package(
                name=pkg_name,
                path=_dir(path),
                ecosystem="pypi",
                version=project.get("version") or poetry.get("version"),
                description=project.get("description") or poetry.get("description"),
            )
        )
    desc = project.get("description") or poetry.get("description")
    if desc:
        res.descriptions.append((path.count("/"), desc))
    if project.get("requires-python"):
        res.runtimes.setdefault("python", project["requires-python"])
    scripts = project.get("scripts") or poetry.get("scripts") or {}
    res.bins.extend(scripts.keys())
    if "uv" in tool:
        res.package_managers.add("uv")
    if poetry:
        res.package_managers.add("poetry")
    if "workspace" in (tool.get("uv") or {}):
        res.workspaces = True
    # tool configs double as linting/testing signals; recorded by the stack analyzer


def _pipfile(path: str, text: str, res: ManifestResult) -> None:
    data = tomllib.loads(text)
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, ver in (data.get(section) or {}).items():
            res.add_dep(name, ver, "pypi", scope, path)
    py = (data.get("requires") or {}).get("python_version")
    if py:
        res.runtimes.setdefault("python", str(py))
    res.package_managers.add("pipenv")


def _setup_py(path: str, text: str, res: ManifestResult) -> None:
    block = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
    if block:
        for req in re.findall(r"['\"]([^'\"]+)['\"]", block.group(1)):
            name, ver = _split_req(req)
            res.add_dep(name, ver, "pypi", "runtime", path)
    m = re.search(r"\bname\s*=\s*['\"]([^'\"]+)['\"]", text)
    if m:
        res.packages.append(Package(name=m.group(1), path=_dir(path), ecosystem="pypi"))


# -- Go / Rust / JVM / Ruby / PHP / .NET / Dart --------------------------------------------


def _go_mod(path: str, text: str, res: ManifestResult) -> None:
    module = re.search(r"^module\s+(\S+)", text, re.M)
    if module:
        res.packages.append(Package(name=module.group(1), path=_dir(path), ecosystem="go"))
    go = re.search(r"^go\s+(\S+)", text, re.M)
    if go:
        res.runtimes.setdefault("go", go.group(1))
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        parts = line.split()
        if in_block and len(parts) >= 2:
            scope = "runtime" if "// indirect" not in raw else "optional"
            res.add_dep(parts[0], parts[1], "go", scope, path)
        elif line.startswith("require ") and len(parts) >= 3:
            res.add_dep(parts[1], parts[2], "go", "runtime", path)
    res.package_managers.add("go modules")


def _cargo(path: str, text: str, res: ManifestResult) -> None:
    data = tomllib.loads(text)
    for section, scope in (
        ("dependencies", "runtime"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    ):
        for name, spec in (data.get(section) or {}).items():
            ver = spec if isinstance(spec, str) else (spec or {}).get("version")
            res.add_dep(name, ver, "cargo", scope, path)
    pkg = data.get("package") or {}
    if pkg.get("name"):
        res.packages.append(
            Package(
                name=pkg["name"],
                path=_dir(path),
                ecosystem="cargo",
                version=_str(pkg.get("version")),
                description=pkg.get("description"),
            )
        )
    if "workspace" in data:
        res.workspaces = True
    res.package_managers.add("cargo")


def _pom(path: str, text: str, res: ManifestResult) -> None:
    root = ET.fromstring(text)
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    p = "m:" if ns else ""

    def find(el: ET.Element, tag: str) -> str | None:
        found = el.find(f"{p}{tag}", ns)
        return found.text.strip() if found is not None and found.text else None

    for dep in root.iterfind(f".//{p}dependencies/{p}dependency", ns):
        group, artifact = find(dep, "groupId"), find(dep, "artifactId")
        if group and artifact:
            scope = "dev" if find(dep, "scope") == "test" else "runtime"
            res.add_dep(f"{group}:{artifact}", find(dep, "version"), "maven", scope, path)
    parent = root.find(f"{p}parent", ns)
    if parent is not None:
        group, artifact = find(parent, "groupId"), find(parent, "artifactId")
        if group and artifact:
            res.add_dep(f"{group}:{artifact}", find(parent, "version"), "maven", "build", path)
    artifact = find(root, "artifactId")
    if artifact:
        res.packages.append(
            Package(
                name=artifact,
                path=_dir(path),
                ecosystem="maven",
                version=find(root, "version"),
                description=find(root, "description"),
            )
        )
    java = root.find(f".//{p}properties/{p}java.version", ns)
    if java is not None and java.text:
        res.runtimes.setdefault("java", java.text.strip())
    res.package_managers.add("maven")


_GRADLE_DEP = re.compile(
    r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|kapt|ksp|"
    r"annotationProcessor|classpath)\s*\(?\s*['\"]([^'\":]+):([^'\":]+)(?::([^'\"]+))?['\"]"
)


def _gradle(path: str, text: str, res: ManifestResult) -> None:
    for conf, group, artifact, ver in _GRADLE_DEP.findall(text):
        scope = "dev" if conf.startswith("test") else "runtime"
        res.add_dep(f"{group}:{artifact}", ver or None, "maven", scope, path)
    for plugin in re.findall(
        r"id\s*\(?\s*['\"](org\.springframework\.boot|io\.quarkus|"
        r"io\.micronaut[\w.]*|com\.android\.application)['\"]",
        text,
    ):
        res.add_dep(f"{plugin}:plugin", None, "maven", "build", path)
    res.package_managers.add("gradle")


def _gemfile(path: str, text: str, res: ManifestResult) -> None:
    group_dev = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("group") and re.search(r":(development|test)", s):
            group_dev = True
        elif s == "end":
            group_dev = False
        m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", s)
        if m:
            res.add_dep(m.group(1), m.group(2), "gem", "dev" if group_dev else "runtime", path)
    ruby = re.search(r"^ruby\s+['\"]([^'\"]+)['\"]", text, re.M)
    if ruby:
        res.runtimes.setdefault("ruby", ruby.group(1))
    res.package_managers.add("bundler")


def _composer(path: str, text: str, res: ManifestResult) -> None:
    data = json.loads(text)
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, ver in (data.get(section) or {}).items():
            if name == "php":
                res.runtimes.setdefault("php", str(ver))
            elif not name.startswith("ext-"):
                res.add_dep(name, ver, "composer", scope, path)
    if data.get("name"):
        res.packages.append(
            Package(
                name=data["name"],
                path=_dir(path),
                ecosystem="composer",
                description=data.get("description"),
            )
        )
    res.package_managers.add("composer")


def _csproj(path: str, text: str, res: ManifestResult) -> None:
    root = ET.fromstring(text)
    for ref in root.iter():
        if ref.tag.endswith("PackageReference"):
            name = ref.attrib.get("Include")
            ver = ref.attrib.get("Version")
            if ver is None:
                child = next((c for c in ref if c.tag.endswith("Version")), None)
                ver = child.text if child is not None else None
            if name:
                res.add_dep(name, ver, "nuget", "runtime", path)
        elif ref.tag.endswith("TargetFramework") and ref.text:
            res.runtimes.setdefault("dotnet", ref.text.strip())
    res.packages.append(Package(name=PurePosixPath(path).stem, path=_dir(path), ecosystem="nuget"))
    res.package_managers.add("nuget")


def _pubspec(path: str, text: str, res: ManifestResult) -> None:
    data = yaml.safe_load(text) or {}
    for section, scope in (("dependencies", "runtime"), ("dev_dependencies", "dev")):
        for name, ver in (data.get(section) or {}).items():
            res.add_dep(name, ver if isinstance(ver, str) else None, "pub", scope, path)
    if data.get("name"):
        res.packages.append(
            Package(
                name=data["name"],
                path=_dir(path),
                ecosystem="pub",
                description=data.get("description"),
            )
        )
    res.package_managers.add("pub")


# -- runtime version files -----------------------------------------------------------------

_RUNTIME_FILES = {
    ".nvmrc": "node",
    ".node-version": "node",
    ".python-version": "python",
    ".ruby-version": "ruby",
    ".java-version": "java",
    ".go-version": "go",
    "rust-toolchain": "rust",
    ".terraform-version": "terraform",
    ".bun-version": "bun",
}


def _runtime_files(files: RepoFiles, res: ManifestResult) -> None:
    for fname, runtime in _RUNTIME_FILES.items():
        if files.exists(fname):
            val = (files.read(fname) or "").strip().splitlines()
            if val:
                res.runtimes.setdefault(runtime, val[0].strip())
    if files.exists("rust-toolchain.toml"):
        try:
            data = tomllib.loads(files.read("rust-toolchain.toml") or "")
            res.runtimes.setdefault("rust", str((data.get("toolchain") or {}).get("channel", "")))
        except tomllib.TOMLDecodeError:
            pass
    if files.exists(".tool-versions"):
        for line in (files.read(".tool-versions") or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("#"):
                res.runtimes.setdefault(parts[0].replace("nodejs", "node"), parts[1])


def _dir(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def _str(v: Any) -> str | None:
    return v if isinstance(v, str) else None
