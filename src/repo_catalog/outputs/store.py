"""JSON outputs. One file per repo (small, diffable in git) plus aggregated files that the
frontend, SQLite builder and MCP server read."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from .. import __version__
from ..models import AIAsset, CatalogMeta, Repo

log = logging.getLogger(__name__)

REPOS_DIR = "repos"
CATALOG_FILE = "catalog.json"
ASSETS_FILE = "ai-assets.json"


def _slug(repo_id: str) -> str:
    return repo_id.replace("/", "__")


def load_previous(out_dir: Path) -> dict[str, tuple[Repo, list[AIAsset]]]:
    prev: dict[str, tuple[Repo, list[AIAsset]]] = {}
    folder = out_dir / REPOS_DIR
    if not folder.is_dir():
        return prev
    for path in folder.glob("*.json"):
        try:
            data = json.loads(path.read_text())
            repo = Repo.model_validate(data["repo"])
            assets = [AIAsset.model_validate(a) for a in data.get("assets", [])]
            prev[repo.id] = (repo, assets)
        except Exception as exc:  # schema drift: just rescan that repo
            log.info("ignoring stale %s: %s", path.name, exc)
    return prev


def write_repo(out_dir: Path, repo: Repo, assets: list[AIAsset]) -> None:
    folder = out_dir / REPOS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    payload = {
        "repo": repo.model_dump(mode="json"),
        "assets": [a.model_dump(mode="json") for a in assets],
    }
    (folder / f"{_slug(repo.id)}.json").write_text(json.dumps(payload, indent=1) + "\n")


def prune(out_dir: Path, keep: set[str], owners: set[str]) -> list[str]:
    """Remove records of repos under ``owners`` that were not seen in this run (deleted,
    renamed or filtered out). Records of other owners and of local scans are left alone."""
    removed: list[str] = []
    folder = out_dir / REPOS_DIR
    if not owners or not folder.is_dir():
        return removed
    wanted = {_slug(k) for k in keep}
    for path in folder.glob("*.json"):
        owner = path.stem.split("__", 1)[0].lower()
        if owner in owners and path.stem not in wanted:
            path.unlink()
            removed.append(path.stem)
    return removed


def write_aggregates(
    out_dir: Path, repos: list[Repo], assets: list[AIAsset], source: str, llm: bool
) -> CatalogMeta:
    meta = CatalogMeta(
        generated_at=datetime.now(UTC),
        scanner_version=__version__,
        source=source,
        repo_count=len(repos),
        asset_count=len(assets),
        llm_enriched=llm,
    )
    meta_json = meta.model_dump(mode="json")
    (out_dir / CATALOG_FILE).write_text(
        json.dumps(
            {"meta": meta_json, "repos": [r.model_dump(mode="json") for r in repos]}, indent=1
        )
    )
    (out_dir / ASSETS_FILE).write_text(
        json.dumps(
            {"meta": meta_json, "assets": [a.model_dump(mode="json") for a in assets]}, indent=1
        )
    )
    return meta


def load_aggregates(out_dir: Path) -> tuple[list[Repo], list[AIAsset]]:
    repos = [
        Repo.model_validate(r) for r in json.loads((out_dir / CATALOG_FILE).read_text())["repos"]
    ]
    assets = [
        AIAsset.model_validate(a) for a in json.loads((out_dir / ASSETS_FILE).read_text())["assets"]
    ]
    return repos, assets


def write_schemas(schema_dir: Path) -> None:
    schema_dir.mkdir(parents=True, exist_ok=True)
    for name, model in (("repo", Repo), ("ai-asset", AIAsset), ("catalog-meta", CatalogMeta)):
        (schema_dir / f"{name}.schema.json").write_text(
            json.dumps(model.model_json_schema(), indent=2) + "\n"
        )
