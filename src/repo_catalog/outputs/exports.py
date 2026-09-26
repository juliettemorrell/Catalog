"""Interop exports: Backstage entities and a CycloneDX 1.6 AI-BOM."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

from .. import __version__
from ..models import AIAsset, Repo

_BACKSTAGE_TYPE = {
    "service": "service",
    "full-stack-app": "website",
    "web-app": "website",
    "library": "library",
    "cli": "tool",
    "mcp-server": "service",
    "infrastructure": "resource",
    "monorepo": "service",
    "data-app": "website",
    "mobile-app": "mobile-app",
    "docs": "documentation",
}
_BACKSTAGE_LIFECYCLE = {
    "active": "production",
    "maintained": "production",
    "stale": "deprecated",
    "archived": "deprecated",
}


def _bs_name(s: str) -> str:
    """Backstage name: ``^([A-Za-z0-9][-_.]?)*[A-Za-z0-9]$``, max 63 chars."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", s)
    name = re.sub(r"[-_.]{2,}", "-", name)  # separators may not repeat
    name = name[:63].strip("-_.")
    return name or "unnamed"


def _bs_tag(s: str) -> str:
    """Backstage tag: ``^[a-z0-9:+#]+(-[a-z0-9:+#]+)*$``, max 63 chars."""
    tag = re.sub(r"[^a-z0-9:+#]+", "-", s.lower())
    return re.sub(r"-{2,}", "-", tag)[:63].strip("-")


def _bs_owner(raw: str) -> str:
    """CODEOWNERS / declared owner -> Backstage entity ref."""
    raw = raw.strip()
    if ":" in raw and "/" in raw.split(":", 1)[1]:
        return raw  # already a full ref like group:default/payments
    if raw.startswith("@") and "/" in raw:
        return f"group:default/{_bs_name(raw.split('/', 1)[1])}"
    if raw.startswith("@"):
        return f"user:default/{_bs_name(raw[1:])}"
    if "@" in raw:  # e-mail address
        return f"user:default/{_bs_name(raw.split('@', 1)[0])}"
    return _bs_name(raw)


def backstage_entities(repos: list[Repo]) -> list[dict[str, object]]:
    """One Component per repo. Values a team declared themselves always win."""
    out = []
    base_names = [_bs_name(r.declared.name or r.name) for r in repos]
    clashes = {n for n in base_names if base_names.count(n) > 1}
    names = {
        r.id: _bs_name(f"{r.owner}-{base}") if base in clashes else base
        for r, base in zip(repos, base_names, strict=True)
    }
    for r in repos:
        d = r.declared
        name = names[r.id]
        # declared dependencies win; otherwise the links resolved from code
        depends = d.depends_on or sorted(
            {f"component:default/{names[ln.repo]}" for ln in r.depends_on if ln.repo in names}
        )
        branch = r.default_branch or "main"
        tags = sorted(
            {
                _bs_tag(t)
                for t in [
                    *(r.topics or []),
                    *(lang.name for lang in r.stack.languages[:3]),
                    *r.stack.frameworks[:5],
                ]
                if _bs_tag(t)
            }
        )[:20]
        entity: dict[str, object] = {
            "apiVersion": "backstage.io/v1alpha1",
            "kind": "Component",
            "metadata": {
                "name": name,
                "title": r.summary.readme_title or r.name,
                "description": r.summary.purpose or r.summary.one_liner or "",
                "tags": tags,
                "annotations": {
                    "github.com/project-slug": r.id,
                    "backstage.io/source-location": f"url:{r.url}/tree/{branch}/",
                    "repo-catalog/practices-score": str(r.practices.score),
                    "repo-catalog/ai-assets": str(r.ai.asset_count),
                    "repo-catalog/high-severity-flags": str(
                        sum(f.severity == "high" for f in r.flags)
                    ),
                },
                "links": [{"url": r.url, "title": "Repository"}]
                + ([{"url": r.homepage, "title": "Homepage"}] if r.homepage else [])
                + [link for link in d.links if link.get("url")],
            },
            "spec": {
                "type": d.type or _BACKSTAGE_TYPE.get(r.structure.repo_type, "other"),
                "lifecycle": d.lifecycle or _BACKSTAGE_LIFECYCLE[r.lifecycle],
                "owner": _bs_owner(
                    d.owner or (r.ownership.codeowners[0] if r.ownership.codeowners else "unknown")
                ),
                **({"system": d.system} if d.system else {}),
                **({"providesApis": d.provides_apis} if d.provides_apis else {}),
                **({"consumesApis": d.consumes_apis} if d.consumes_apis else {}),
                **({"dependsOn": depends} if depends else {}),
            },
        }
        out.append(entity)
    return out


def write_backstage(path: Path, repos: list[Repo]) -> None:
    path.write_text(
        yaml.safe_dump_all(backstage_entities(repos), sort_keys=False, allow_unicode=True)
    )


def aibom(repos: list[Repo], assets: list[AIAsset], source: str) -> dict[str, object]:
    """CycloneDX 1.6 BOM: models as ``machine-learning-model``, SDKs as ``library``,
    MCP servers as ``application`` and prompts/skills/agents/rules as ``data``."""
    components: list[dict[str, object]] = []
    seen: set[str] = set()

    def add(ref: str, comp: dict[str, object]) -> None:
        if ref not in seen:
            seen.add(ref)
            components.append({"bom-ref": ref, **comp})

    for r in repos:
        for model in r.ai.models:
            add(
                f"model:{model}",
                {
                    "type": "machine-learning-model",
                    "name": model,
                    "properties": [{"name": "repo-catalog:seen-in", "value": r.id}],
                },
            )
        for sdk in r.ai.sdks:
            add(f"sdk:{sdk}", {"type": "library", "name": sdk})
    for a in assets:
        comp_type = {"mcp-server": "application", "sdk-usage": "library"}.get(a.kind, "data")
        comp: dict[str, object] = {
            "type": comp_type,
            "name": a.name,
            "description": a.description or a.summary or "",
            "externalReferences": [{"type": "vcs", "url": a.url}],
            "properties": [
                {"name": "repo-catalog:kind", "value": a.kind},
                {"name": "repo-catalog:ecosystem", "value": a.ecosystem},
                {"name": "repo-catalog:repo", "value": a.repo},
                {"name": "repo-catalog:path", "value": a.path},
                *({"name": "repo-catalog:model", "value": m} for m in a.models),
                *({"name": "repo-catalog:tool", "value": t} for t in a.tools[:30]),
            ],
        }
        if comp_type == "data":
            comp["data"] = [
                {
                    "type": "other",
                    "name": a.kind,
                    "contents": {
                        "attachment": {
                            "contentType": "text/markdown",
                            "content": (a.content or "")[:2000],
                        }
                    },
                }
            ]
        if a.content_sha:
            comp["hashes"] = [{"alg": "SHA-256", "content": a.content_sha}]
        add(f"asset:{a.id}", comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "repo-catalog", "version": __version__}
                ]
            },
            "component": {"type": "application", "name": source, "bom-ref": "root"},
        },
        "components": components,
    }


def write_aibom(path: Path, repos: list[Repo], assets: list[AIAsset], source: str) -> None:
    path.write_text(json.dumps(aibom(repos, assets, source), indent=1))


_CDX_SCOPE = {"dev": "optional", "build": "excluded", "optional": "optional"}


def repo_sbom(r: Repo) -> dict[str, object]:
    """CycloneDX 1.6 SBOM for one repo: every direct and locked transitive dependency with
    its purl, plus known advisories when the catalog was built with ``--osv``."""
    root = f"repo:{r.id}"
    components: list[dict[str, object]] = []
    refs: dict[tuple[str, str, str | None], str] = {}
    direct: list[str] = []
    vulns: dict[str, list[str]] = {}
    for d in r.dependencies:
        key = (d.ecosystem, d.name, d.resolved or d.version)
        if key in refs:
            ref = refs[key]
        else:
            ref = d.purl or f"{d.ecosystem}:{d.name}@{d.resolved or d.version or ''}"
            if ref in refs.values():
                ref = f"{ref}#{len(refs)}"
            refs[key] = ref
            comp: dict[str, object] = {
                "bom-ref": ref,
                "type": "container" if d.ecosystem == "docker" else "library",
                "name": d.name,
                "properties": [
                    {"name": "repo-catalog:ecosystem", "value": d.ecosystem},
                    {"name": "repo-catalog:manifest", "value": d.manifest},
                    {"name": "repo-catalog:scope", "value": d.scope},
                    *(
                        [{"name": "repo-catalog:declared", "value": d.version}]
                        if d.version and d.version != d.resolved
                        else []
                    ),
                ],
            }
            if d.resolved or d.version:
                comp["version"] = d.resolved or d.version
            if d.purl:
                comp["purl"] = d.purl
            if d.scope in _CDX_SCOPE:
                comp["scope"] = _CDX_SCOPE[d.scope]
            components.append(comp)
        if d.scope != "transitive" and ref not in direct:
            direct.append(ref)
        for vuln in d.vulns:
            vulns.setdefault(vuln, [])
            if ref not in vulns[vuln]:
                vulns[vuln].append(ref)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{r.url}@{r.head_sha}')}",
        "version": 1,
        "metadata": {
            "timestamp": r.scanned_at.isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "repo-catalog", "version": __version__}
                ]
            },
            "component": {
                "bom-ref": root,
                "type": "application",
                "name": r.name,
                "group": r.owner,
                **({"version": r.head_sha} if r.head_sha else {}),
                "purl": f"pkg:github/{r.owner}/{r.name}" + (f"@{r.head_sha}" if r.head_sha else ""),
                "externalReferences": [{"type": "vcs", "url": r.url}],
            },
        },
        "components": components,
        "dependencies": [{"ref": root, "dependsOn": direct}],
        **(
            {
                "vulnerabilities": [
                    {
                        "id": vuln,
                        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln}"},
                        "affects": [{"ref": ref} for ref in affected],
                    }
                    for vuln, affected in sorted(vulns.items())
                ]
            }
            if vulns
            else {}
        ),
    }


def write_sboms(folder: Path, repos: list[Repo]) -> None:
    """One ``<owner>__<name>.cdx.json`` per repo; stale files from removed repos are dropped."""
    folder.mkdir(parents=True, exist_ok=True)
    wanted = set()
    for r in repos:
        name = re.sub(r"[^A-Za-z0-9._-]+", "__", r.id) + ".cdx.json"
        wanted.add(name)
        (folder / name).write_text(json.dumps(repo_sbom(r), indent=1))
    for old in folder.glob("*.cdx.json"):
        if old.name not in wanted:
            old.unlink()
