"""Dependencies beyond the main language package managers.

Swift, CocoaPods, Elixir, R, Conda, sbt, Bazel, vcpkg, Conan, Deno and ``setup.cfg``;
plus what a repo runs on or builds with: container images (Dockerfiles, Compose,
Kubernetes manifests), Terraform providers and modules, Helm chart dependencies, GitHub
Actions, pre-commit hooks and Ansible Galaxy content.
"""

from __future__ import annotations

import configparser
import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..fs import RepoFiles
from ..textutil import load_json, load_yaml, load_yaml_all
from .lockfiles import swift_name

if TYPE_CHECKING:
    from .manifests import ManifestResult


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


# ------------------------------------------------------------------------ language managers


def swift_package(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(r"\.package\s*\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)", text):
        args = m.group("args")
        url = re.search(r'url:\s*"([^"]+)"', args)
        if not url:
            continue
        ver = re.search(r'(?:from|exact|branch|revision):\s*"([^"]+)"', args) or re.search(
            r'"(\d+\.\d+(?:\.\d+)?)"', args
        )
        res.add_dep(
            swift_name(url.group(1)), ver.group(1) if ver else None, "swift", "runtime", path
        )


def podfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(
        r"^\s*pod\s+['\"]([^'\"/]+)(?:/[^'\"]+)?['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?", text, re.M
    ):
        res.add_dep(m.group(1), m.group(2), "cocoapods", "runtime", path)


def mix_exs(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(r"\{:(\w+),\s*(?:\"([^\"]+)\")?([^}]*)\}", text):
        name, version, rest = m.group(1), m.group(2), m.group(3)
        if not version and "github:" not in rest and "git:" not in rest and "path:" not in rest:
            continue
        if "path:" in rest:
            continue
        dev = re.search(r"only:\s*(?:\[[^\]]*\]|:\w+)", rest)
        scope = "dev" if dev and ":prod" not in dev.group(0) else "runtime"
        res.add_dep(name, version, "hex", scope, path)


def r_description(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    if not re.search(r"^Package:", text, re.M):
        return  # only R package metadata uses this file name
    fields: dict[str, str] = {}
    current = ""
    for line in text.splitlines():
        if re.match(r"^[A-Za-z][\w.]*:", line):
            current, _sep, value = line.partition(":")
            fields[current] = value
        elif current and line[:1].isspace():
            fields[current] += " " + line.strip()
    for key, scope in (
        ("Depends", "runtime"),
        ("Imports", "runtime"),
        ("LinkingTo", "build"),
        ("Suggests", "dev"),
    ):
        for item in fields.get(key, "").split(","):
            m = re.match(r"\s*([A-Za-z][\w.]*)\s*(?:\(([^)]*)\))?", item)
            if m and m.group(1) != "R":
                res.add_dep(m.group(1), (m.group(2) or "").strip() or None, "cran", scope, path)


def conda_env(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = _d(load_yaml(text))
    for dep in _l(data.get("dependencies")):
        if isinstance(dep, str):
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*([=<>!~].*)?$", dep.split("::")[-1].strip())
            if m and m.group(1) not in ("python", "pip"):
                res.add_dep(
                    m.group(1), (m.group(2) or "").lstrip("=") or None, "conda", "runtime", path
                )
        elif isinstance(dep, dict):
            for req in _l(dep.get("pip")):
                m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(.*)$", str(req).strip())
                if m and not str(req).startswith("-"):
                    res.add_dep(
                        m.group(1).split("[")[0], m.group(2) or None, "pypi", "runtime", path
                    )
    if "python" in text:
        m = re.search(r"^\s*-\s*python\s*=+\s*([\d.]+)", text, re.M)
        if m:
            res.runtimes.setdefault("python", m.group(1))


def sbt(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(
        r'"([\w.\-]+)"\s*%%?%?\s*"([\w.\-]+)"\s*%\s*"([^"]+)"(?:\s*%\s*"?(\w+)"?)?', text
    ):
        group, artifact, version, config = m.groups()
        scope = "dev" if config and config.lower() in ("test", "it") else "runtime"
        res.add_dep(f"{group}:{artifact}", version, "maven", scope, path)


def bazel_module(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(r"bazel_dep\s*\(([^)]*)\)", text):
        name = re.search(r'name\s*=\s*"([^"]+)"', m.group(1))
        version = re.search(r'version\s*=\s*"([^"]+)"', m.group(1))
        dev = re.search(r"dev_dependency\s*=\s*True", m.group(1))
        if name:
            res.add_dep(
                name.group(1),
                version.group(1) if version else None,
                "bazel",
                "dev" if dev else "runtime",
                path,
            )


def vcpkg(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for dep in _l(_d(load_json(text)).get("dependencies")):
        name = dep if isinstance(dep, str) else _d(dep).get("name")
        version = _d(dep).get("version>=") if isinstance(dep, dict) else None
        res.add_dep(name, version, "vcpkg", "runtime", path)


def conanfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for name, version in re.findall(
        r'(?:^|["\'\s])([\w.+-]+)/(\d[\w.+-]*)(?:@[\w./-]+)?(?=["\'\s,\]]|$)', text, re.M
    ):
        res.add_dep(name, version, "conan", "runtime", path)


def deno_json(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for alias, spec in _d(_d(load_json(text)).get("imports")).items():
        m = re.match(r"(npm|jsr):(@?[^@]+)(?:@(.+))?$", str(spec))
        if m:
            res.add_dep(m.group(2), m.group(3), m.group(1), "runtime", path)
        elif str(alias) and str(spec).startswith("https://deno.land/"):
            res.add_dep(
                str(spec).split("/")[4 if "/x/" in str(spec) else 3].split("@")[0],
                None,
                "deno",
                "runtime",
                path,
            )


def setup_cfg(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_string(text)
    if not cfg.has_section("options"):
        return
    sections = [
        ("install_requires", "runtime", cfg.get("options", "install_requires", fallback=""))
    ]
    if cfg.has_section("options.extras_require"):
        for extra, reqs in cfg.items("options.extras_require"):
            sections.append(
                (extra, "dev" if re.search(r"dev|test|lint|doc", extra) else "optional", reqs)
            )
    for _extra, scope, block in sections:
        for line in block.splitlines():
            line = line.split("#")[0].strip()
            m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$", line)
            if m and line:
                res.add_dep(
                    m.group(1), m.group(3).split(";")[0].strip() or None, "pypi", scope, path
                )


# -------------------------------------------------------------------- infrastructure deps

_TF_REQUIRED = re.compile(r"required_providers\s*\{(?P<body>(?:[^{}]|\{[^{}]*\})*)\}", re.S)
_TF_PROVIDER = re.compile(r"(\w[\w-]*)\s*=\s*\{(?P<body>[^{}]*)\}", re.S)
_TF_MODULE = re.compile(r'module\s+"[^"]+"\s*\{(?P<body>(?:[^{}]|\{[^{}]*\})*)\}', re.S)


def terraform(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for block in _TF_REQUIRED.finditer(text):
        for m in _TF_PROVIDER.finditer(block.group("body")):
            source = re.search(r'source\s*=\s*"([^"]+)"', m.group("body"))
            version = re.search(r'version\s*=\s*"([^"]+)"', m.group("body"))
            name = source.group(1) if source else f"hashicorp/{m.group(1)}"
            name = name.split("/", 1)[1] if name.count("/") >= 2 else name  # drop registry host
            res.add_dep(name, version.group(1) if version else None, "terraform", "runtime", path)
    for m in _TF_MODULE.finditer(text):
        source = re.search(r'source\s*=\s*"([^"]+)"', m.group("body"))
        if not source or source.group(1).startswith((".", "/")):
            continue  # local modules are the repo's own code
        version = re.search(r'version\s*=\s*"([^"]+)"', m.group("body"))
        src = source.group(1)
        ref = re.search(r"[?&]ref=([^&\"]+)", src)
        git = re.search(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git)?(?://|\?|$)", src)
        name = f"github.com/{git.group(1)}" if git else src.split("//")[0]
        res.add_dep(
            name,
            (version.group(1) if version else ref.group(1) if ref else None),
            "terraform",
            "runtime",
            path,
        )


def helm_chart(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for dep in _l(_d(load_yaml(text)).get("dependencies")):
        dep = _d(dep)
        res.add_dep(dep.get("name"), dep.get("version"), "helm", "runtime", path)


_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)


def split_image(image: str) -> tuple[str, str | None]:
    """``ghcr.io/acme/api:1.2@sha256:..`` -> (``ghcr.io/acme/api``, ``1.2``)."""
    ref = None
    if "@" in image:
        image, ref = image.split("@", 1)
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        image, tag = image.rsplit(":", 1)
        ref = tag
    name = image.lower()
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/"):
        name = name.removeprefix(prefix)
    return name, ref


def dockerfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    stages: set[str] = set()
    froms = list(_FROM.finditer(text))
    for i, m in enumerate(froms):
        image, alias = m.group(1), m.group(2)
        if alias:
            stages.add(alias.lower())
        if image.lower() in stages or image == "scratch" or "$" in image:
            continue
        name, ref = split_image(image)
        res.add_dep(name, ref, "docker", "runtime" if i == len(froms) - 1 else "build", path)


def compose(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for svc in _d(_d(load_yaml(text)).get("services")).values():
        image = _d(svc).get("image")
        if isinstance(image, str) and "$" not in image:
            name, ref = split_image(image)
            res.add_dep(name, ref, "docker", "runtime", path)


_WORKLOAD = re.compile(
    r"^kind:\s*(Deployment|StatefulSet|DaemonSet|Job|CronJob|Pod|ReplicaSet)\b", re.M
)


def kubernetes(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    if not _WORKLOAD.search(text) or "{{" in text:
        return  # not a workload, or a Helm template (values are resolved at deploy time)
    for doc in load_yaml_all(text):
        for image in _images(doc):
            name, ref = split_image(image)
            res.add_dep(name, ref, "docker", "runtime", path)


def _images(node: Any, depth: int = 0) -> list[str]:
    if depth > 12:
        return []
    if isinstance(node, dict):
        out = [node["image"]] if isinstance(node.get("image"), str) else []
        for key, value in node.items():
            if key != "image":
                out += _images(value, depth + 1)
        return out
    if isinstance(node, list):
        return [img for item in node for img in _images(item, depth + 1)]
    return []


_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s'\"#]+)", re.M)


def github_actions(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for name, ref in _USES.findall(text):
        res.add_dep(name, ref, "github-actions", "build", path)


def pre_commit(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for repo in _l(_d(load_yaml(text)).get("repos")):
        url = str(_d(repo).get("repo") or "")
        if url.startswith("http") or url.startswith("git@"):
            res.add_dep(swift_name(url), _d(repo).get("rev"), "pre-commit", "dev", path)


def ansible_requirements(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    data = load_yaml(text)
    items = _l(data) + _l(_d(data).get("roles")) + _l(_d(data).get("collections"))
    for item in items:
        name = item if isinstance(item, str) else _d(item).get("name") or _d(item).get("src")
        version = _d(item).get("version") if isinstance(item, dict) else None
        res.add_dep(name, version, "ansible-galaxy", "runtime", path)


Parser = Callable[[str, str, "ManifestResult", RepoFiles], None]

# exact lowercase file names
BY_NAME: list[tuple[tuple[str, ...], Parser]] = [
    (("package.swift",), swift_package),
    (("podfile",), podfile),
    (("mix.exs",), mix_exs),
    (("description",), r_description),
    (("environment.yml", "environment.yaml"), conda_env),
    (("build.sbt",), sbt),
    (("module.bazel",), bazel_module),
    (("vcpkg.json",), vcpkg),
    (("conanfile.txt", "conanfile.py"), conanfile),
    (("deno.json", "deno.jsonc"), deno_json),
    (("setup.cfg",), setup_cfg),
    (("chart.yaml",), helm_chart),
    (("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"), compose),
    ((".pre-commit-config.yaml",), pre_commit),
    (("action.yml", "action.yaml"), github_actions),
]


def extra_jobs(files: RepoFiles, limit: int) -> list[tuple[str, Parser]]:
    """(path, parser) pairs for every extra manifest in the repo."""
    jobs: list[tuple[str, Parser]] = []
    for names, parser in BY_NAME:
        jobs += [(e.path, parser) for e in files.named(*names)[:limit]]
    queued = {p for p, _ in jobs}
    for entry in files.files:
        name = entry.name.lower()
        if entry.suffix == ".tf":
            jobs.append((entry.path, terraform))
        elif name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            jobs.append((entry.path, dockerfile))
        elif entry.path.startswith(".github/workflows/") and entry.suffix in (".yml", ".yaml"):
            jobs.append((entry.path, github_actions))
        elif (
            name.startswith("docker-compose.")
            and entry.suffix in (".yml", ".yaml")
            and entry.path not in queued
        ):
            jobs.append((entry.path, compose))
        elif entry.suffix in (".yml", ".yaml") and re.search(
            r"(^|/)(k8s|kubernetes|deploy|deployments?|manifests|kustomize|overlays|base)/",
            entry.path,
        ):
            jobs.append((entry.path, kubernetes))
        elif name == "requirements.yml" and (
            "roles" in entry.path or "ansible" in entry.path or entry.depth == 0
        ):
            jobs.append((entry.path, ansible_requirements))
    return jobs[: limit * 10]
