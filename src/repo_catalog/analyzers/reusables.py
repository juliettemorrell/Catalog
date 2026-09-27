"""Building blocks other teams can adopt, and references to code in other repositories.

Reusables answer "does the org already have a GitHub Action / Terraform module / Helm
chart / template / API for this?". Cross-references (``uses: acme/setup@v2``, Terraform
``source = "github.com/acme/..."``, ``FROM ghcr.io/acme/base``, submodules) are resolved
org-wide in ``org.py`` into depends-on / used-by links.
"""

from __future__ import annotations

import bisect
import re
from collections import defaultdict
from collections.abc import Callable
from pathlib import PurePosixPath
from typing import Any

from ..fs import FileEntry, RepoFiles
from ..models import CrossRef, Package, Reusable
from ..textutil import load_json, load_yaml
from .docs import first_sentence
from .manifests import NON_PRODUCT_DIR

MAX_REUSABLES = 300
MAX_REFS = 500
_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head")


def _d(value: Any) -> dict[Any, Any]:
    return value if isinstance(value, dict) else {}


def _s(value: Any, limit: int = 300) -> str | None:
    if isinstance(value, str | int | float) and not isinstance(value, bool):
        text = str(value).strip()
        return text[:limit] or None
    return None


def _dir(path: str) -> str:
    parent = str(PurePosixPath(path).parent)
    return "." if parent in ("", ".") else parent


def _readme_blurb(files: RepoFiles, folder: str) -> str | None:
    prefix = "" if folder == "." else f"{folder}/"
    for name in ("README.md", "readme.md", "README.rst"):
        text = files.read(prefix + name, 20_000)
        if text:
            body = re.sub(r"(?m)^[ \t]*(#.*|!\[.*|\[!\[.*|<.*>|```.*|\|.*)$", "", text)
            para = next((p.strip() for p in re.split(r"\n\s*\n", body) if len(p.strip()) > 20), "")
            return first_sentence(" ".join(para.split())) if para else None
    return None


# -------------------------------------------------------------------------- detectors


def _actions(files: RepoFiles, out: list[Reusable]) -> None:
    for entry in files.named("action.yml", "action.yaml"):
        if NON_PRODUCT_DIR.search(entry.path) or entry.path.startswith(".github/workflows/"):
            continue
        data = _d(load_yaml(files.read(entry.path) or ""))
        if not data.get("runs"):
            continue
        folder = _dir(entry.path)
        out.append(
            Reusable(
                kind="action",
                name=_s(data.get("name"), 120) or (folder if folder != "." else "action"),
                path=folder,
                description=_s(data.get("description")),
                details={
                    "using": _s(_d(data.get("runs")).get("using")),
                    "inputs": sorted(str(k) for k in _d(data.get("inputs")))[:40],
                    "outputs": sorted(str(k) for k in _d(data.get("outputs")))[:40],
                },
            )
        )


def _reusable_workflows(workflow_texts: dict[str, str], out: list[Reusable]) -> None:
    for path, text in workflow_texts.items():
        if "workflow_call" not in text:
            continue
        data = _d(load_yaml(text))
        on = data.get("on", data.get(True))
        call = on.get("workflow_call") if isinstance(on, dict) else None
        if call is None and not (isinstance(on, list | str) and "workflow_call" in on):
            continue
        call = _d(call)
        out.append(
            Reusable(
                kind="reusable-workflow",
                name=_s(data.get("name"), 120) or PurePosixPath(path).stem,
                path=path,
                details={
                    "inputs": sorted(str(k) for k in _d(call.get("inputs")))[:40],
                    "secrets": sorted(str(k) for k in _d(call.get("secrets")))[:40],
                    "jobs": sorted(str(k) for k in _d(data.get("jobs")))[:20],
                },
            )
        )


_TF_VAR = re.compile(r'^[ \t]*variable\s+"([\w-]+)"', re.M)
_TF_OUT = re.compile(r'^[ \t]*output\s+"([\w-]+)"', re.M)
_TF_RES = re.compile(r'^[ \t]*(?:resource|data)\s+"([a-z0-9]+)_', re.M)
_TF_BACKEND = re.compile(r'^[ \t]*backend\s+"', re.M)


def _terraform_modules(files: RepoFiles, repo_name: str, out: list[Reusable]) -> None:
    by_dir: dict[str, list[FileEntry]] = defaultdict(list)
    for entry in files.by_suffix.get(".tf", []):
        if not NON_PRODUCT_DIR.search(entry.path) and "/.terraform/" not in f"/{entry.path}":
            by_dir[_dir(entry.path)].append(entry)
    for folder, entries in sorted(by_dir.items()):
        text = "\n".join(files.read(e.path) or "" for e in entries[:40])
        variables, outputs = _TF_VAR.findall(text), _TF_OUT.findall(text)
        # a module takes inputs and returns outputs; live stacks configure a backend
        in_modules = "modules/" in f"{folder}/" or (
            folder == "." and re.match(r"(terraform|tf)-", repo_name, re.I) is not None
        )
        if not variables or _TF_BACKEND.search(text) or not (in_modules or outputs):
            continue
        if not in_modules and folder != ".":
            continue
        providers = sorted(set(_TF_RES.findall(text)))[:10]
        out.append(
            Reusable(
                kind="terraform-module",
                name=repo_name if folder == "." else PurePosixPath(folder).name,
                path=folder,
                description=_readme_blurb(files, folder),
                details={
                    "variables": len(set(variables)),
                    "outputs": len(set(outputs)),
                    "providers": providers,
                },
            )
        )


def _helm_charts(files: RepoFiles, out: list[Reusable]) -> None:
    entries = [e for e in files.named("Chart.yaml") if not NON_PRODUCT_DIR.search(e.path)]
    chart_dirs = {_dir(e.path) for e in entries}
    for entry in entries:
        folder = _dir(entry.path)
        # sub-charts vendored under another chart are dependencies, not building blocks
        if any(folder != d and (d == "." or folder.startswith(d + "/")) for d in chart_dirs):
            continue
        data = _d(load_yaml(files.read(entry.path) or ""))
        name = _s(data.get("name"), 120)
        if not name:
            continue
        out.append(
            Reusable(
                kind="helm-chart",
                name=name,
                path=folder,
                description=_s(data.get("description")),
                details={
                    "version": _s(data.get("version"), 40),
                    "app_version": _s(data.get("appVersion"), 40),
                    "type": _s(data.get("type"), 20) or "application",
                },
            )
        )


def _templates(files: RepoFiles, is_template: bool, repo_name: str, out: list[Reusable]) -> None:
    for entry in files.named("cookiecutter.json"):
        data = _d(load_json(files.read(entry.path) or "{}"))
        folder = _dir(entry.path)
        out.append(
            Reusable(
                kind="template",
                name=_s(data.get("project_name"), 120) or (repo_name if folder == "." else folder),
                path=folder,
                description=_readme_blurb(files, folder),
                details={"engine": "cookiecutter", "variables": sorted(map(str, data))[:30]},
            )
        )
    for entry in files.named("copier.yml", "copier.yaml"):
        data = _d(load_yaml(files.read(entry.path) or ""))
        folder = _dir(entry.path)
        out.append(
            Reusable(
                kind="template",
                name=repo_name if folder == "." else PurePosixPath(folder).name,
                path=folder,
                description=_readme_blurb(files, folder),
                details={
                    "engine": "copier",
                    "variables": sorted(str(k) for k in data if not str(k).startswith("_"))[:30],
                },
            )
        )
    candidates = files.glob("**/template.yaml", "**/template.yml", "**/templates/**/*.yaml")
    for entry in candidates[:200]:
        text = files.read(entry.path) or ""
        if "scaffolder.backstage.io" not in text:
            continue
        data = _d(load_yaml(text))
        meta = _d(data.get("metadata"))
        if data.get("kind") != "Template":
            continue
        out.append(
            Reusable(
                kind="template",
                name=_s(meta.get("title"), 120) or _s(meta.get("name"), 120) or entry.path,
                path=entry.path,
                description=_s(meta.get("description")),
                details={"engine": "backstage", "type": _s(_d(data.get("spec")).get("type"), 40)},
            )
        )
    if is_template:
        out.append(
            Reusable(
                kind="template",
                name=repo_name,
                path=".",
                description=None,
                details={"engine": "github-template-repo"},
            )
        )


_PROTO_SERVICE = re.compile(r"^[ \t]*service\s+(\w+)\s*\{", re.M)
_PROTO_RPC = re.compile(r"^[ \t]*rpc\s+(\w+)\s*\(", re.M)
_PROTO_PKG = re.compile(r"^[ \t]*package\s+([\w.]+)\s*;", re.M)
_GQL_ROOT = re.compile(r"\btype\s+(Query|Mutation|Subscription)\b[^{}]{0,200}\{")


def _graphql_roots(text: str) -> list[tuple[str, str]]:
    """(root type, body) pairs. Linear: each opening brace is paired with the next closing
    brace by bisecting a precomputed index instead of scanning ahead from every match."""
    closes = [i for i, c in enumerate(text) if c == "}"]
    out = []
    for m in _GQL_ROOT.finditer(text):
        k = bisect.bisect_left(closes, m.end())
        if k < len(closes):
            out.append((m.group(1), text[m.end() : closes[k]]))
    return out


def _apis(files: RepoFiles, api_specs: list[str], out: list[Reusable]) -> None:
    protos: dict[str, dict[str, Any]] = {}
    for path in api_specs:
        if NON_PRODUCT_DIR.search(path):
            continue
        text = files.read(path) or ""
        if not text:
            continue
        if path.endswith(".proto"):
            services = _PROTO_SERVICE.findall(text)
            if services:  # message-only protos are types, not APIs
                pkg = _PROTO_PKG.search(text)
                protos[path] = {
                    "format": "grpc",
                    "package": pkg.group(1) if pkg else None,
                    "services": services[:20],
                    "operations": len(_PROTO_RPC.findall(text)),
                    "sample": _PROTO_RPC.findall(text)[:25],
                }
            continue
        if path.endswith((".graphql", ".graphqls")):
            fields = [
                f"{root}.{m}"
                for root, body in _graphql_roots(text)
                for m in re.findall(r"^[ \t]*(\w+)\s*[(:]", body, re.M)
            ]
            if fields:
                out.append(
                    Reusable(
                        kind="api",
                        name=PurePosixPath(path).stem,
                        path=path,
                        details={
                            "format": "graphql",
                            "operations": len(fields),
                            "sample": fields[:25],
                        },
                    )
                )
            continue
        data = _d(load_json(text) if path.endswith(".json") else load_yaml(text))
        info = _d(data.get("info"))
        if "asyncapi" in data:
            channels = _d(data.get("channels"))
            out.append(
                Reusable(
                    kind="api",
                    name=_s(info.get("title"), 120) or PurePosixPath(path).stem,
                    path=path,
                    description=_s(info.get("description")),
                    details={
                        "format": f"asyncapi {data.get('asyncapi')}",
                        "version": _s(info.get("version"), 40),
                        "operations": len(channels),
                        "sample": sorted(map(str, channels))[:25],
                    },
                )
            )
            continue
        if not ("openapi" in data or "swagger" in data):
            continue
        ops = [
            f"{method.upper()} {route}"
            for route, item in _d(data.get("paths")).items()
            for method in _d(item)
            if method in _HTTP_METHODS
        ]
        out.append(
            Reusable(
                kind="api",
                name=_s(info.get("title"), 120) or PurePosixPath(path).stem,
                path=path,
                description=first_sentence(_s(info.get("description"), 2000)),
                details={
                    "format": f"openapi {data.get('openapi') or data.get('swagger')}",
                    "version": _s(info.get("version"), 40),
                    "operations": len(ops),
                    "sample": ops[:25],
                },
            )
        )
    seen_services: set[tuple[object, ...]] = set()
    for path, details in sorted(protos.items(), key=lambda kv: ("client" in kv[0].lower(), kv[0])):
        signature = (details["package"], tuple(details["services"]), tuple(details["sample"]))
        if signature in seen_services:
            continue  # a client's copy of a proto it consumes is not a second API
        seen_services.add(signature)
        out.append(
            Reusable(
                kind="api",
                name=", ".join(details["services"][:3]),
                path=path,
                details=details,
            )
        )


_CONFIG_PKG = re.compile(
    r"(?:^|[/-])(?:eslint|prettier|stylelint|commitlint|tsconfig|renovate|biome|oxlint|"
    r"lint-staged|semantic-release|jest|vitest|tailwind)-?(?:config|preset|plugin)?$|"
    r"(?:^|[/-])(?:eslint|prettier|stylelint)-(?:config|plugin)-",
    re.I,
)


def _config_packages(packages: list[Package], out: list[Reusable]) -> None:
    for pkg in packages:
        if pkg.private or NON_PRODUCT_DIR.search(pkg.path):
            continue
        if pkg.ecosystem == "npm" and _CONFIG_PKG.search(pkg.name):
            out.append(
                Reusable(
                    kind="config-package",
                    name=pkg.name,
                    path=pkg.path,
                    description=pkg.description,
                    details={"ecosystem": pkg.ecosystem, "version": pkg.version},
                )
            )


def find_reusables(
    files: RepoFiles,
    workflow_texts: dict[str, str],
    api_specs: list[str],
    packages: list[Package],
    repo_name: str,
    is_template: bool,
    errors: list[str],
) -> list[Reusable]:
    out: list[Reusable] = []
    steps: list[tuple[str, Callable[[], None]]] = [
        ("actions", lambda: _actions(files, out)),
        ("reusable workflows", lambda: _reusable_workflows(workflow_texts, out)),
        ("terraform", lambda: _terraform_modules(files, repo_name, out)),
        ("helm", lambda: _helm_charts(files, out)),
        ("templates", lambda: _templates(files, is_template, repo_name, out)),
        ("apis", lambda: _apis(files, api_specs, out)),
        ("config packages", lambda: _config_packages(packages, out)),
    ]
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # one bad file must not hide the other building blocks
            errors.append(f"reusables/{label}: {type(exc).__name__}: {str(exc)[:200]}")
    return out[:MAX_REUSABLES]


# --------------------------------------------------------------------- cross references

_USES = re.compile(
    r"^[ \t]*-?[ \t]*uses:\s*['\"]?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)((?:/[^@\s'\"]+)?)@", re.M
)
_TF_SOURCE = re.compile(
    r"^[ \t]*source\s*=\s*\"(?:git::)?(?:https://|ssh://git@|git@)?github\.com[/:]"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?://|\?|\"|/)",
    re.M,
)
_GHCR_FROM = re.compile(r"^[ \t]*FROM\s+(?:--\S+\s+)*ghcr\.io/([\w.-]+)/([\w.-]+)", re.I | re.M)
_SUBMODULE = re.compile(
    r"url\s*=\s*(?:https://|git@)github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?\s*$", re.M
)


def find_references(files: RepoFiles, workflow_texts: dict[str, str]) -> list[CrossRef]:
    refs: dict[tuple[str, str, str], CrossRef] = {}

    def add(kind: str, owner: str, repo: str, path: str) -> None:
        target = f"{owner}/{repo}".lower()
        key = (kind, target, path)
        if len(refs) < MAX_REFS and key not in refs:
            refs[key] = CrossRef(kind=kind, target=target, path=path)  # type: ignore[arg-type]

    action_files = {
        e.path: files.read(e.path) or "" for e in files.named("action.yml", "action.yaml")[:50]
    }
    for path, text in {**workflow_texts, **action_files}.items():
        for owner, repo, sub in _USES.findall(text):
            if owner in (".", "..") or owner.lower() == "docker":
                continue
            kind = "reusable-workflow" if "/.github/workflows/" in f"{sub}/" else "action"
            add(kind, owner, repo, path)
    for entry, text in files.iter_text(files.by_suffix.get(".tf", [])[:500], 300_000):
        for owner, repo in _TF_SOURCE.findall(text):
            add("terraform", owner, repo, entry.path)
    for entry in files.glob("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile")[:50]:
        for owner, repo in _GHCR_FROM.findall(files.read(entry.path) or ""):
            add("container", owner, repo.split(":")[0].split("@")[0], entry.path)
    for owner, repo in _SUBMODULE.findall(files.read(".gitmodules") or ""):
        add("git", owner, repo, ".gitmodules")
    return list(refs.values())
