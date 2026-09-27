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
from pathlib import PurePosixPath
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
        res.add_dep(swift_name(url.group(1)), _swift_requirement(args), "swift", "runtime", path)


def _swift_requirement(args: str) -> str | None:
    """SwiftPM requirement as a range: ``from: "2.0.0"`` means up to the next major."""
    if m := re.search(r'exact:\s*"([^"]+)"', args):
        return m.group(1)
    if m := re.search(r'\.upToNextMinor\s*\(\s*from:\s*"([^"]+)"', args):
        return f"~{m.group(1)}"
    if m := re.search(r'(?:from|upToNextMajor\s*\(\s*from):\s*"([^"]+)"', args):
        return f"^{m.group(1)}"
    if m := re.search(r'"([^"]+)"\s*\.\.<\s*"([^"]+)"', args):
        return f">={m.group(1)} <{m.group(2)}"
    if m := re.search(r'"([^"]+)"\s*\.\.\.\s*"([^"]+)"', args):
        return f">={m.group(1)} <={m.group(2)}"
    if m := re.search(r'(?:branch|revision):\s*"([^"]+)"', args):
        return m.group(1)
    return None


def podfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(
        r"^[ \t]*pod\s+['\"]([^'\"/]+)(?:/[^'\"]+)?['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?", text, re.M
    ):
        if not any(
            d.ecosystem == "cocoapods" and d.name == m.group(1) and d.manifest == path
            for d in res.dependencies
        ):  # Firebase/Analytics + Firebase/Crashlytics
            res.add_dep(m.group(1), m.group(2), "cocoapods", "runtime", path)


def mix_exs(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    # bounded: an unclosed "{:a," must not rescan the rest of the file from every start
    for m in re.finditer(r"\{:(\w+),\s*(?:\"([^\"]+)\")?([^{}]{0,400})\}", text):
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
            # "numpy=1.26", "numpy >=1.26", "numpy 1.26.*", "conda-forge::numpy"
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*([=<>!~]?.*)$", dep.split("::")[-1].strip())
            if m and m.group(1) not in ("python", "pip"):
                spec = m.group(2).strip()
                spec = spec[1:] if spec.startswith("=") and not spec.startswith("==") else spec
                res.add_dep(m.group(1), spec or None, "conda", "runtime", path)
        elif isinstance(dep, dict):
            for req in _l(dep.get("pip")):
                name, version = pip_requirement(str(req))
                if name:
                    res.add_dep(name, version, "pypi", "runtime", path)
    if "python" in text:
        m = re.search(r"^[ \t]*-[ \t]*python\s*=+\s*([\d.]+)", text, re.M)
        if m:
            res.runtimes.setdefault("python", m.group(1))


def pip_requirement(line: str) -> tuple[str | None, str | None]:
    """``requests[socks]>=2 ; python_version>"3"`` -> (requests, >=2). URL/VCS requirements
    keep only the name: their URL may carry credentials and is not a version."""
    line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("git+") else line.strip()
    if not line or line.startswith(("-", "git+", "http:", "https:", "file:", ".", "/")):
        egg = re.search(r"#egg=([A-Za-z0-9_.\-]+)", line)
        return (egg.group(1), None) if egg else (None, None)
    m = re.match(r"([A-Za-z0-9_.\-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
    if not m:
        return None, None
    rest = m.group(3).split(";", 1)[0].strip()
    return m.group(1), (None if rest.startswith("@") else rest or None)


_SBT_VAL = re.compile(r'\b(?:lazy\s+)?val\s+(\w+)\s*(?::\s*String\s*)?=\s*"([^"\s]+)"')


def _sbt_values(path: str, text: str, files: RepoFiles) -> dict[str, str]:
    """Simple ``val circeV = "0.14.1"`` definitions in build.sbt and project/*.scala."""
    values: dict[str, str] = {}
    parent = str(PurePosixPath(path).parent)
    project = "project" if parent == "." else f"{parent}/project"
    texts = []
    for entry in files.under(project)[:50]:
        if entry.path.endswith(".scala") and entry.path.count("/") == project.count("/") + 1:
            texts.append(files.read(entry.path) or "")
    for source in [*texts, text]:  # the build file's own definitions win
        for name, value in _SBT_VAL.findall(source):
            values[name] = value
    return values


def sbt(path: str, text: str, res: ManifestResult, files: RepoFiles) -> None:
    scala = re.search(r'scalaVersion\s*:?=\s*"(\d+)\.(\d+)', text)
    suffix = (
        ("_3" if scala.group(1) == "3" else f"_{scala.group(1)}.{scala.group(2)}") if scala else ""
    )
    values: dict[str, str] | None = None
    for m in re.finditer(
        r'"([\w.\-]+)"\s*(%%%|%%|%)\s*"([\w.\-]+)"\s*%\s*(?:"([^"]+)"|([A-Za-z_][\w.]*))'
        r'(?:\s*%\s*"?(\w+)"?)?',
        text,
    ):
        group, op, artifact, version, variable, config = m.groups()
        if variable and version is None:
            if values is None:
                try:
                    values = _sbt_values(path, text, files)
                except Exception:  # an unreadable project/ file just leaves it unresolved
                    values = {}
            version = values.get(variable) or values.get(variable.rsplit(".", 1)[-1])
        # %% appends the Scala binary version to the artifact id
        artifact = artifact + suffix if op != "%" and suffix else artifact
        scope = "dev" if config and config.lower() in ("test", "it") else "runtime"
        res.add_dep(f"{group}:{artifact}", version, "maven", scope, path)


def bazel_module(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for m in re.finditer(r"bazel_dep\s*\(([^)]*)\)", text):
        name = re.search(r'name\s*=\s*"([^"]+)"', m.group(1))
        version = re.search(r'version\s*=\s*"([^"]+)"', m.group(1))
        dev = re.search(r"dev_dependency\s*=\s*True", m.group(1))
        if name:  # Bzlmod picks the highest requested version (MVS): this is a minimum
            res.add_dep(
                name.group(1),
                f">={version.group(1)}" if version else None,
                "bazel",
                "dev" if dev else "runtime",
                path,
            )


def vcpkg(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for dep in _l(_d(load_json(text)).get("dependencies")):
        name = dep if isinstance(dep, str) else _d(dep).get("name")
        minimum = _d(dep).get("version>=") if isinstance(dep, dict) else None
        res.add_dep(name, f">={minimum}" if minimum else None, "vcpkg", "runtime", path)


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
            name, version = pip_requirement(line)
            if name:
                res.add_dep(name, version, "pypi", scope, path)


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
        name = terraform_source_name(src)
        res.add_dep(
            name,
            (version.group(1) if version else ref.group(1) if ref else None),
            "terraform",
            "runtime",
            path,
        )


def terraform_source_name(src: str) -> str:
    """Module source -> a stable, credential-free name. Registry sources stay as written
    (``terraform-aws-modules/vpc/aws``); git/http/s3 sources become ``host/path``."""
    rest = re.sub(r"^[a-z0-9]+::", "", src.strip())  # forced getters: git::, s3::, gcs::
    rest = re.sub(r"^(?:[a-z0-9+.-]+://|git@)", "", rest)
    rest = rest.split("?", 1)[0]
    host_path, _, _subdir = rest.partition("//")
    host_path = host_path.rsplit("@", 1)[-1]  # drop userinfo (user:token@host)
    host_path = (
        host_path.replace(":", "/", 1) if src.startswith(("git@", "git::git@")) else host_path
    )
    return host_path.removesuffix(".git").strip("/")


def helm_chart(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    for dep in _l(_d(load_yaml(text)).get("dependencies")):
        dep = _d(dep)
        res.add_dep(dep.get("name"), dep.get("version"), "helm", "runtime", path)


_FROM = re.compile(r"^[ \t]*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)


def has_registry(name: str) -> bool:
    """``ghcr.io/x``, ``localhost:5000/x`` and ``registry:5000/x`` name a registry host."""
    first, sep, _ = name.partition("/")
    return bool(sep) and ("." in first or ":" in first or first == "localhost")


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


_ARG = re.compile(r"^[ \t]*ARG\s+([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|\S+)", re.I | re.M)


def dockerfile(path: str, text: str, res: ManifestResult, _: RepoFiles) -> None:
    args = {k: v.strip("\"'") for k, v in _ARG.findall(text)}

    def expand(image: str) -> str:
        return re.sub(
            r"\$\{?([A-Za-z_]\w*)(?::?-([^}]*))?\}?",
            lambda m: str(args.get(m.group(1), m.group(2) or m.group(0))),
            image,
        )

    stages: dict[str, str] = {}  # alias -> the external image it builds on
    froms = [(expand(m.group(1)), (m.group(2) or "").lower()) for m in _FROM.finditer(text)]
    # a FROM names an earlier stage only when that alias was defined above it:
    # "FROM nginx AS nginx" still pulls the nginx image
    external: list[str] = []
    base = ""
    for image, alias in froms:
        if image.lower() in stages:
            base = stages[image.lower()]
        else:
            base = image
            external.append(image)
        if alias:
            stages[alias] = base
    # the final stage (and everything it builds FROM, through aliases) is the runtime
    runtime_images = {base} if froms else set()
    for image in external:
        if image == "scratch" or "$" in image:
            continue
        name, ref = split_image(image)
        scope = "runtime" if image in runtime_images else "build"
        if not any(
            d.ecosystem == "docker" and d.name == name and d.version == ref and d.manifest == path
            for d in res.dependencies
        ):
            res.add_dep(name, ref, "docker", scope, path)


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


_USES = re.compile(
    r"^[ \t]*-?[ \t]*uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s'\"#]+)", re.M
)


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
