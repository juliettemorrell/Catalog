"""Parse package manifests from every mainstream ecosystem into Dependencies and Packages.

Manifests in the wild are messy: every field is type-checked, every file is parsed in
isolation (errors are recorded, never raised) and manifests that only exist as examples
or test fixtures are ignored so they do not distort the repo's stack.
"""

from __future__ import annotations

import ast
import logging
import re
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from ..fs import RepoFiles
from ..models import Dependency, Package
from ..textutil import load_json, load_yaml

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
    "conda-lock.yml": "conda",
    "pixi.lock": "pixi",
}

# Manifests below these folders describe examples/fixtures, not the repo's own stack.
NON_PRODUCT_DIR = re.compile(
    r"(^|/)(examples?|samples?|fixtures?|__fixtures__|testdata|test[-_]?data|tests?|"
    r"__tests__|e2e|benchmarks?|playground|\.devcontainer)/",
    re.I,
)
_DEV_FILE = re.compile(
    r"(^|[-_./])(dev|develop|test|tests|testing|lint|docs?|ci|typing)"
    r"([-_.]|$)",
    re.I,
)

Scope = str  # runtime | dev | optional | peer | build | transitive


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
    test_projects: int = 0
    skipped_manifests: int = 0
    errors: list[str] = field(default_factory=list)

    def add_dep(self, name: Any, version: Any, ecosystem: str, scope: Scope, manifest: str) -> None:
        name = _str(name)
        if not name:
            return
        ver = version if isinstance(version, str) else None
        if isinstance(version, dict):
            ver = _str(version.get("version"))
        self.dependencies.append(
            Dependency(
                name=name,
                version=ver,
                ecosystem=ecosystem,
                scope=scope,  # type: ignore[arg-type]
                manifest=manifest,
            )
        )

    def add_package(
        self,
        name: Any,
        path: str,
        ecosystem: str,
        *,
        version: Any = None,
        description: Any = None,
        private: Any = None,
    ) -> None:
        pkg_name = _str(name)
        if not pkg_name:
            return
        desc = _str(description)
        self.packages.append(
            Package(
                name=pkg_name,
                path=_dir(path),
                ecosystem=ecosystem,
                version=_str(version),
                description=desc,
                private=private if isinstance(private, bool) else None,
            )
        )
        if desc:
            self.descriptions.append((path.count("/"), desc))


MAX_MANIFESTS_PER_KIND = 200
Parser = Callable[[str, str, "ManifestResult", RepoFiles], None]


def parse_manifests(files: RepoFiles) -> ManifestResult:
    res = ManifestResult()
    by_name: list[tuple[tuple[str, ...], Parser]] = [
        (("package.json",), _package_json),
        (("pyproject.toml",), _pyproject),
        (("pipfile",), _pipfile),
        (("setup.py",), _setup_py),
        (("go.mod",), _go_mod),
        (("cargo.toml",), _cargo),
        (("pom.xml",), _pom),
        (("build.gradle", "build.gradle.kts"), _gradle),
        (("libs.versions.toml",), _gradle_catalog),
        (("gemfile",), _gemfile),
        (("composer.json",), _composer),
        (("pubspec.yaml",), _pubspec),
    ]
    jobs: list[tuple[str, Parser]] = []
    for names, parser in by_name:
        jobs += [(e.path, parser) for e in files.named(*names)[:MAX_MANIFESTS_PER_KIND]]
    for entry in files.files:
        name = entry.name.lower()
        is_req = (name.startswith("requirements") and name.endswith((".txt", ".in"))) or (
            entry.parts[-2:-1] == ("requirements",) and name.endswith((".txt", ".in"))
        )
        if is_req:
            jobs.append((entry.path, _requirements))
        elif name.endswith((".csproj", ".fsproj", ".vbproj")):
            jobs.append((entry.path, _csproj))
        if name in LOCKFILES and not NON_PRODUCT_DIR.search(entry.path):
            res.package_managers.add(LOCKFILES[name])
            res.lockfiles.append(entry.path)
    for path, parser in jobs:
        if NON_PRODUCT_DIR.search(path):
            res.skipped_manifests += 1
            continue
        text = files.read(path)
        if text is None:
            continue
        try:
            parser(path, text, res, files)
        except Exception as exc:  # never fail the scan on a bad manifest
            res.errors.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
    try:
        _runtime_files(files, res)
    except Exception as exc:
        res.errors.append(f"runtime version files: {type(exc).__name__}: {exc}")
    return res


# -- JavaScript ---------------------------------------------------------------------------


def _package_json(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = load_json(text)
    if not isinstance(data, dict):
        return
    for key, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ):
        deps = data.get(key)
        for name, ver in deps.items() if isinstance(deps, dict) else []:
            res.add_dep(name, ver, "npm", scope, path)
    res.add_package(
        data.get("name"),
        path,
        "npm",
        version=data.get("version"),
        description=data.get("description"),
        private=data.get("private"),
    )
    if data.get("workspaces"):
        res.workspaces = True
    engines = data.get("engines")
    if isinstance(engines, dict) and _str(engines.get("node")):
        res.runtimes.setdefault("node", str(engines["node"]))
    pm = data.get("packageManager")
    if isinstance(pm, str):
        res.package_managers.add(pm.split("@", 1)[0])
    if isinstance(data.get("scripts"), dict):
        res.scripts[path] = {str(k): str(v) for k, v in data["scripts"].items()}
    bins = data.get("bin")
    if isinstance(bins, str):
        res.bins.append(_str(data.get("name")) or path)
    elif isinstance(bins, dict):
        res.bins.extend(str(b) for b in bins)


# -- Python -------------------------------------------------------------------------------

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


def _split_req(req: Any) -> tuple[str, str | None]:
    if not isinstance(req, str):
        return "", None
    req = req.split(";", 1)[0].split(" #", 1)[0].split("--hash", 1)[0].strip()
    if req.startswith(("#", "-", "git+", "http", ".", "/")) or "@" in req.split("[")[0]:
        # URL / path / VCS installs: keep the name of "pkg @ url" forms
        if " @ " in req:
            req = req.split(" @ ", 1)[0]
        else:
            return "", None
    m = _REQ_NAME.match(req)
    if not m:
        return "", None
    return m.group(1), (m.group(3).strip() or None)


def _requirements(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    scope = "dev" if _DEV_FILE.search(PurePosixPath(path).stem) else "runtime"
    logical = re.sub(r"\\\r?\n", " ", text)  # join backslash continuations
    reqs = 0
    pinned = 0
    for line in logical.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-r", "-c", "--", "-e", "-i")):
            continue
        name, ver = _split_req(line)
        if name:
            reqs += 1
            pinned += bool(ver and ver.startswith("=="))
            res.add_dep(name, ver, "pypi", scope, path)
    res.package_managers.add("pip")
    if reqs and pinned == reqs and scope == "runtime":
        res.lockfiles.append(path)  # fully pinned (e.g. pip-compile output) acts as a lock


def _pyproject(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = tomllib.loads(text)
    project = _dict(data.get("project"))
    for req in _list(project.get("dependencies")):
        name, ver = _split_req(req)
        res.add_dep(name, ver, "pypi", "runtime", path)
    for group, reqs in _dict(project.get("optional-dependencies")).items():
        scope = "dev" if _DEV_FILE.search(str(group)) else "optional"
        for req in _list(reqs):
            name, ver = _split_req(req)
            res.add_dep(name, ver, "pypi", scope, path)
    for reqs in _dict(data.get("dependency-groups")).values():
        for req in _list(reqs):
            name, ver = _split_req(req)  # include-group tables are skipped
            res.add_dep(name, ver, "pypi", "dev", path)
    tool = _dict(data.get("tool"))
    poetry = _dict(tool.get("poetry"))
    for name, ver in _dict(poetry.get("dependencies")).items():
        if str(name).lower() == "python":
            res.runtimes.setdefault("python", str(ver))
        else:
            res.add_dep(name, ver, "pypi", "runtime", path)
    for grp_name, grp in _dict(poetry.get("group")).items():
        scope = "runtime" if grp_name == "main" else "dev"
        for name, ver in _dict(_dict(grp).get("dependencies")).items():
            res.add_dep(name, ver, "pypi", scope, path)
    for name, ver in _dict(poetry.get("dev-dependencies")).items():
        res.add_dep(name, ver, "pypi", "dev", path)
    for reqs in _dict(_dict(tool.get("pdm")).get("dev-dependencies")).values():
        for req in _list(reqs):
            name, ver = _split_req(req)
            res.add_dep(name, ver, "pypi", "dev", path)
    for req in _list(_dict(data.get("build-system")).get("requires")):
        name, ver = _split_req(req)
        res.add_dep(name, ver, "pypi", "build", path)
    for req in _list(_dict(tool.get("uv")).get("dev-dependencies")):
        name, ver = _split_req(req)
        res.add_dep(name, ver, "pypi", "dev", path)
    res.add_package(
        project.get("name") or poetry.get("name"),
        path,
        "pypi",
        version=project.get("version") or poetry.get("version"),
        description=project.get("description") or poetry.get("description"),
    )
    if _str(project.get("requires-python")):
        res.runtimes.setdefault("python", str(project["requires-python"]))
    scripts = _dict(project.get("scripts")) or _dict(poetry.get("scripts"))
    res.bins.extend(str(s) for s in scripts)
    if "uv" in tool:
        res.package_managers.add("uv")
    if poetry:
        res.package_managers.add("poetry")
    if "pdm" in tool:
        res.package_managers.add("pdm")
    if "workspace" in _dict(tool.get("uv")):
        res.workspaces = True


def _pipfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = tomllib.loads(text)
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, ver in _dict(data.get(section)).items():
            res.add_dep(name, ver, "pypi", scope, path)
    py = _dict(data.get("requires")).get("python_version")
    if py:
        res.runtimes.setdefault("python", str(py))
    res.package_managers.add("pipenv")


def _setup_py(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    """Read ``setup(...)`` keyword arguments with ``ast`` (literal values only)."""
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", getattr(node.func, "attr", "")) == "setup"
        ):
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            for req in _literal_list(kw.get("install_requires")):
                name, ver = _split_req(req)
                res.add_dep(name, ver, "pypi", "runtime", path)
            extras = kw.get("extras_require")
            if isinstance(extras, ast.Dict):
                for key, value in zip(extras.keys, extras.values, strict=False):
                    group = key.value if isinstance(key, ast.Constant) else ""
                    scope = "dev" if _DEV_FILE.search(str(group)) else "optional"
                    for req in _literal_list(value):
                        name, ver = _split_req(req)
                        res.add_dep(name, ver, "pypi", scope, path)
            name_node = kw.get("name")
            if isinstance(name_node, ast.Constant):
                desc = kw.get("description")
                res.add_package(
                    name_node.value,
                    path,
                    "pypi",
                    description=desc.value if isinstance(desc, ast.Constant) else None,
                )
            return


def _literal_list(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.List | ast.Tuple):
        return [
            e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
    return []


# -- Go / Rust / JVM / Ruby / PHP / .NET / Dart --------------------------------------------


def _go_mod(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    module = re.search(r"^module\s+(\S+)", text, re.M)
    if module:
        res.add_package(module.group(1), path, "go")
    go = re.search(r"^go\s+(\S+)", text, re.M)
    if go:
        res.runtimes.setdefault("go", go.group(1))
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if re.match(r"^require\s*\(", line):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        parts = line.split()
        scope = "transitive" if "// indirect" in raw else "runtime"
        if in_block and len(parts) >= 2:
            res.add_dep(parts[0], parts[1], "go", scope, path)
        elif line.startswith("require ") and len(parts) >= 3:
            res.add_dep(parts[1], parts[2], "go", scope, path)
    res.package_managers.add("go modules")


def _cargo(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = tomllib.loads(text)
    sections: list[tuple[dict[str, Any], str]] = [
        (_dict(data.get("dependencies")), "runtime"),
        (_dict(data.get("dev-dependencies")), "dev"),
        (_dict(data.get("build-dependencies")), "build"),
        (_dict(_dict(data.get("workspace")).get("dependencies")), "runtime"),
    ]
    for target in _dict(data.get("target")).values():
        t = _dict(target)
        sections += [
            (_dict(t.get("dependencies")), "runtime"),
            (_dict(t.get("dev-dependencies")), "dev"),
        ]
    for deps, scope in sections:
        for name, spec in deps.items():
            res.add_dep(name, spec, "cargo", scope, path)
    pkg = _dict(data.get("package"))
    res.add_package(
        pkg.get("name"),
        path,
        "cargo",
        version=pkg.get("version"),
        description=pkg.get("description"),
    )  # `x.workspace = true` -> None
    if "workspace" in data:
        res.workspaces = True
    for b in _list(data.get("bin")):
        if isinstance(b, dict) and _str(b.get("name")):
            res.bins.append(str(b["name"]))
    res.package_managers.add("cargo")


def _pom(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    root = ET.fromstring(text)
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    p = "m:" if ns else ""

    def find(el: ET.Element, tag: str) -> str | None:
        found = el.find(f"{p}{tag}", ns)
        return found.text.strip() if found is not None and found.text else None

    def deps(container: str, default_scope: str) -> None:
        for dep in root.iterfind(f"{container}{p}dependency", ns):
            group, artifact = find(dep, "groupId"), find(dep, "artifactId")
            if group and artifact:
                scope = "dev" if find(dep, "scope") == "test" else default_scope
                if find(dep, "scope") == "import":
                    scope = "build"
                res.add_dep(f"{group}:{artifact}", find(dep, "version"), "maven", scope, path)

    deps(f"{p}dependencies/", "runtime")  # direct dependencies only
    deps(f"{p}dependencyManagement/{p}dependencies/", "build")  # BOMs / version pins
    for plugin in root.iterfind(f"{p}build/{p}plugins/{p}plugin", ns):
        group = find(plugin, "groupId") or "org.apache.maven.plugins"
        artifact = find(plugin, "artifactId")
        if artifact:
            res.add_dep(f"{group}:{artifact}", find(plugin, "version"), "maven", "build", path)
    parent = root.find(f"{p}parent", ns)
    if parent is not None:
        pgroup, partifact = find(parent, "groupId"), find(parent, "artifactId")
        if pgroup and partifact:
            res.add_dep(f"{pgroup}:{partifact}", find(parent, "version"), "maven", "build", path)
    res.add_package(
        find(root, "artifactId"),
        path,
        "maven",
        version=find(root, "version"),
        description=find(root, "description"),
    )
    java = root.find(f"{p}properties/{p}java.version", ns)
    if java is not None and java.text:
        res.runtimes.setdefault("java", java.text.strip())
    res.package_managers.add("maven")


_GRADLE_DEP = re.compile(
    r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|kapt|ksp|"
    r"annotationProcessor|classpath|developmentOnly)\s*\(?\s*(?:platform\(\s*)?"
    r"['\"]([^'\":\s]+):([^'\":\s]+)(?::([^'\"\s]+))?['\"]"
)
_GRADLE_CATALOG_REF = re.compile(
    r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|kapt|ksp|"
    r"annotationProcessor|developmentOnly)\s*\(?\s*(?:platform\(\s*)?libs\.([\w.]+)"
)


def _gradle(path: str, text: str, res: ManifestResult, files: RepoFiles) -> None:
    for conf, group, artifact, ver in _GRADLE_DEP.findall(text):
        scope = "dev" if conf.startswith("test") else "runtime"
        res.add_dep(f"{group}:{artifact}", ver or None, "maven", scope, path)
    catalog = _load_catalog(files)
    for conf, alias in _GRADLE_CATALOG_REF.findall(text):
        module = catalog.get(alias.replace(".", "-").lower())
        if module:
            scope = "dev" if conf.startswith("test") else "runtime"
            res.add_dep(module[0], module[1], "maven", scope, path)
    plugins = re.findall(
        r"id\s*\(?\s*['\"](org\.springframework\.boot|io\.quarkus|io\.micronaut[\w.]*|"
        r"com\.android\.application)['\"]|alias\(\s*libs\.plugins\.([\w.]+)",
        text,
    )
    for plugin_id, alias in plugins:
        pid = plugin_id or (catalog.get("plugin:" + alias.replace(".", "-").lower(), ("",))[0])
        if pid:
            res.add_dep(f"{pid}:plugin", None, "maven", "build", path)
    res.package_managers.add("gradle")


def _load_catalog(files: RepoFiles) -> dict[str, tuple[str, str | None]]:
    """alias -> (group:artifact, version) from gradle/libs.versions.toml."""
    text = files.read("gradle/libs.versions.toml")
    if not text:
        return {}
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    versions = _dict(data.get("versions"))
    out: dict[str, tuple[str, str | None]] = {}
    for alias, spec in _dict(data.get("libraries")).items():
        module: str | None = None
        version: str | None = None
        if isinstance(spec, str):
            parts = spec.split(":")
            module, version = ":".join(parts[:2]), (parts[2] if len(parts) > 2 else None)
        elif isinstance(spec, dict):
            module = _str(spec.get("module")) or (
                f"{spec.get('group')}:{spec.get('name')}" if spec.get("group") else None
            )
            v = spec.get("version")
            version = _str(v) if not isinstance(v, dict) else _str(versions.get(str(v.get("ref"))))
        if module:
            out[str(alias).replace(".", "-").replace("_", "-").lower()] = (module, version)
    for alias, spec in _dict(data.get("plugins")).items():
        pid = spec.split(":")[0] if isinstance(spec, str) else _str(_dict(spec).get("id"))
        if pid:
            out["plugin:" + str(alias).replace(".", "-").lower()] = (pid, None)
    return out


def _gradle_catalog(path: str, text: str, res: ManifestResult, files: RepoFiles) -> None:
    """Catalog entries are only *declared*; they count once a build file references them.
    Recorded here only when no build.gradle file exists to reference them."""
    if files.named("build.gradle", "build.gradle.kts"):
        return
    for module, version in (
        v for k, v in _load_catalog(files).items() if not k.startswith("plugin:")
    ):
        res.add_dep(module, version, "maven", "runtime", path)


def _gemfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    stack: list[bool] = []  # one entry per open `do` block: True if it is a dev/test group
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        if re.match(r"^(group|platforms?|source|install_if|git|path|gemspec)\b.*\bdo\b", s):
            stack.append(s.startswith("group") and bool(re.search(r":(development|test)", s)))
            continue
        if s == "end" and stack:
            stack.pop()
            continue
        m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", s)
        if m:
            inline_dev = bool(re.search(r"group[s]?:\s*\[?[^\]]*:(development|test)", s))
            dev = inline_dev or any(stack)
            res.add_dep(m.group(1), m.group(2), "gem", "dev" if dev else "runtime", path)
    ruby = re.search(r"^ruby\s+['\"]([^'\"]+)['\"]", text, re.M)
    if ruby:
        res.runtimes.setdefault("ruby", ruby.group(1))
    res.package_managers.add("bundler")


def _composer(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = load_json(text)
    if not isinstance(data, dict):
        return
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, ver in _dict(data.get(section)).items():
            if name == "php":
                res.runtimes.setdefault("php", str(ver))
            elif not str(name).startswith("ext-"):
                res.add_dep(name, ver, "composer", scope, path)
    res.add_package(data.get("name"), path, "composer", description=data.get("description"))
    res.package_managers.add("composer")


_TEST_PROJECT = re.compile(r"(\.|^)(Unit|Integration|Functional|E2E)?Tests?$", re.I)


def _csproj(path: str, text: str, res: ManifestResult, files: RepoFiles) -> None:
    root = ET.fromstring(text)
    stem = PurePosixPath(path).stem
    refs = [(r.attrib.get("Include"), r) for r in root.iter() if r.tag.endswith("PackageReference")]
    is_test = (
        bool(_TEST_PROJECT.search(stem))
        or any(
            el.tag.endswith("IsTestProject") and (el.text or "").strip().lower() == "true"
            for el in root.iter()
        )
        or any(
            (n or "").lower()
            in {"xunit", "nunit", "mstest.testframework", "microsoft.net.test.sdk"}
            for n, _ in refs
        )
    )
    central = _central_versions(files, path)
    scope = "dev" if is_test else "runtime"
    for name, ref in refs:
        ver = ref.attrib.get("Version")
        if ver is None:
            child = next((c for c in ref if c.tag.endswith("Version")), None)
            ver = child.text if child is not None else central.get((name or "").lower())
        res.add_dep(name, ver, "nuget", scope, path)
    sdk = root.attrib.get("Sdk", "")
    if sdk.startswith("Microsoft.NET.Sdk.") and not is_test:
        flavor = sdk.rsplit(".", 1)[-1]
        implied = {
            "Web": "Microsoft.AspNetCore.App",
            "BlazorWebAssembly": "Microsoft.AspNetCore.Components.WebAssembly",
            "Worker": "Microsoft.Extensions.Hosting",
        }.get(flavor)
        if implied:
            res.add_dep(implied, None, "nuget", "runtime", path)
    for el in root.iter():
        if el.tag.endswith(("TargetFramework", "TargetFrameworks")) and el.text:
            res.runtimes.setdefault("dotnet", el.text.strip().split(";")[0])
    if is_test:
        res.test_projects += 1
    else:
        res.add_package(stem, path, "nuget")
    res.package_managers.add("nuget")


def _central_versions(files: RepoFiles, project: str) -> dict[str, str]:
    """Central Package Management: nearest Directory.Packages.props up the tree."""
    folder = PurePosixPath(project).parent
    while True:
        candidate = (folder / "Directory.Packages.props").as_posix().removeprefix("./")
        text = files.read(candidate)
        if text:
            try:
                root = ET.fromstring(text)
            except ET.ParseError:
                return {}
            return {
                (el.attrib.get("Include") or "").lower(): el.attrib.get("Version", "")
                for el in root.iter()
                if el.tag.endswith("PackageVersion")
            }
        if str(folder) in (".", ""):
            return {}
        folder = folder.parent


def _pubspec(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = load_yaml(text)
    if not isinstance(data, dict):
        return
    for section, scope in (("dependencies", "runtime"), ("dev_dependencies", "dev")):
        for name, ver in _dict(data.get(section)).items():
            res.add_dep(name, ver if isinstance(ver, str) else None, "pub", scope, path)
    res.add_package(data.get("name"), path, "pub", description=data.get("description"))
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
        lines = (files.read(fname) or "").strip().splitlines()
        if lines and lines[0].strip():
            res.runtimes.setdefault(runtime, lines[0].strip()[:40])
    if files.exists("rust-toolchain.toml"):
        try:
            data = tomllib.loads(files.read("rust-toolchain.toml") or "")
            channel = _str(_dict(data.get("toolchain")).get("channel"))
            if channel:
                res.runtimes.setdefault("rust", channel)
        except tomllib.TOMLDecodeError:
            pass
    for line in (files.read(".tool-versions") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("#"):
            res.runtimes.setdefault(parts[0].replace("nodejs", "node"), parts[1])


# -- helpers --------------------------------------------------------------------------------


def _dir(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "" if parent == "." else parent


def _str(v: Any) -> str | None:
    """Scalar -> str; containers/None/bools (e.g. ``description.workspace = true``) -> None."""
    if isinstance(v, bool) or v is None or isinstance(v, dict | list | tuple):
        return None
    s = str(v).strip()
    return s or None


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []
