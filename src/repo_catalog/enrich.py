"""Optional Claude enrichment: plain-language repo summaries and AI asset classification.

Heuristic scanning answers *what is in* a repo; this answers *what it is for* and *what
another team could reuse*. Results are cached on disk keyed by a hash of the exact input,
so re-runs only pay for repos/assets whose content changed. Every generated field is
marked with ``summary.source = "llm"`` so consumers can tell it apart from facts.
"""

from __future__ import annotations

import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar, cast

from pydantic import BaseModel, Field

from .models import AIAsset, Repo

if TYPE_CHECKING:
    from anthropic.types.beta import BetaOutputConfigParam

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-5"
PROMPT_VERSION = "2"
MAX_README_CHARS = 60_000
MAX_ASSET_CHARS = 40_000

T = TypeVar("T", bound=BaseModel)


class RepoInsight(BaseModel):
    purpose: str = Field(
        description="2-4 sentences: what the repo is and what it does, for an "
        "engineer deciding whether it is relevant to them."
    )
    key_features: list[str] = Field(description="Up to 8 concrete capabilities or features.")
    domains: list[str] = Field(
        description="Business/technical domain tags, lowercase-hyphenated,"
        " e.g. 'billing', 'patient-intake', 'etl'."
    )
    capabilities: list[str] = Field(
        description="Reusable capability tags, lowercase-hyphenated, "
        "e.g. 'pdf-generation', 'oauth-login'."
    )
    reuse_notes: str = Field(
        description="1-3 sentences on which parts other teams could borrow "
        "(modules, patterns, components) and caveats. Say "
        "'Nothing notable' if so."
    )


class AssetInsight(BaseModel):
    summary: str = Field(description="1-2 sentences: what this AI asset does and when to use it.")
    category: str = Field(
        description="One lowercase-hyphenated category, e.g. code-review, "
        "testing, documentation, data-analysis, devops, security, "
        "customer-support, content-generation, research, "
        "project-management, domain-knowledge, coding-standards."
    )
    use_cases: list[str] = Field(description="Up to 5 short example situations it helps with.")
    tags: list[str] = Field(description="Up to 8 lowercase-hyphenated tags.")


_REPO_SYSTEM = (
    "You write entries for an internal engineering catalog. Engineers and AI coding agents "
    "search it to find existing code to reuse and to learn how the organization builds "
    "software. Be specific and factual; use only the evidence provided. If the evidence is "
    "thin, say so briefly rather than guessing."
)
_ASSET_SYSTEM = (
    "You catalog AI assets (agent skills, subagents, prompts, rules files, MCP servers, "
    "hooks, LLM integrations) for an internal AI asset library. Describe what the asset does "
    "and when someone would reuse it. Use only the evidence provided."
)


class Enricher:
    def __init__(
        self, cache_dir: Path, model: str = DEFAULT_MODEL, workers: int = 4, effort: str = "medium"
    ):
        import anthropic  # optional dependency: pip install 'repo-catalog[llm]'

        self.client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.workers = workers
        self.cache_dir = cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)

    # -- public ---------------------------------------------------------------------------

    def enrich_repos(self, repos: list[Repo], readmes: dict[str, str]) -> None:
        def work(repo: Repo) -> None:
            prompt = _repo_prompt(repo, readmes.get(repo.id, ""))
            insight = self._call(RepoInsight, _REPO_SYSTEM, prompt)
            if insight is None:
                return
            repo.summary.purpose = insight.purpose
            repo.summary.key_features = insight.key_features or repo.summary.key_features
            repo.summary.domains = sorted(set(insight.domains))
            repo.summary.reuse_notes = insight.reuse_notes
            repo.summary.source = "llm"
            repo.capabilities = sorted(set(repo.capabilities) | set(insight.capabilities))

        self._map(work, repos)

    def enrich_assets(self, assets: list[AIAsset]) -> None:
        targets = [a for a in assets if a.kind != "sdk-usage" or a.content]

        def work(asset: AIAsset) -> None:
            insight = self._call(AssetInsight, _ASSET_SYSTEM, _asset_prompt(asset))
            if insight is None:
                return
            asset.summary = insight.summary
            asset.category = insight.category
            asset.use_cases = insight.use_cases
            asset.tags = sorted(set(asset.tags) | set(insight.tags))

        self._map(work, targets)

    # -- internals ------------------------------------------------------------------------

    def _map(self, fn: Any, items: list[Any]) -> None:
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for _ in pool.map(fn, items):
                pass

    def _call(self, schema: type[T], system: str, prompt: str) -> T | None:
        import anthropic

        key = hashlib.sha256(
            f"{PROMPT_VERSION}|{self.model}|{schema.__name__}|{system}|{prompt}".encode()
        ).hexdigest()
        cached = self.cache_dir / f"{key}.json"
        if cached.exists():
            return schema.model_validate_json(cached.read_text())
        try:
            response = self.client.beta.messages.parse(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": prompt}],
                output_format=schema,
                output_config=cast("BetaOutputConfigParam", {"effort": self.effort}),
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.RateLimitError as exc:
            log.warning("LLM rate limited (after SDK retries): %s", exc)
            return None
        except anthropic.APIStatusError as exc:
            log.warning("LLM request failed (%s): %s", exc.status_code, exc.message)
            return None
        except anthropic.APIConnectionError as exc:
            log.warning("LLM connection error: %s", exc)
            return None
        if response.stop_reason == "refusal" or response.parsed_output is None:
            log.warning("LLM returned no structured output (stop_reason=%s)", response.stop_reason)
            return None
        result: T = response.parsed_output
        cached.write_text(result.model_dump_json())
        return result


def _repo_prompt(repo: Repo, readme: str) -> str:
    readme_note = ""
    if len(readme) > MAX_README_CHARS:
        readme_note = f"\n(README truncated to the first {MAX_README_CHARS} characters.)"
        readme = readme[:MAX_README_CHARS]
    facts = {
        "repo": repo.id,
        "github_description": repo.description,
        "topics": repo.topics,
        "type": repo.structure.repo_type,
        "languages": [f"{lang.name} {lang.percent}%" for lang in repo.stack.languages[:6]],
        "frameworks": repo.stack.frameworks,
        "libraries": repo.stack.libraries,
        "databases": repo.stack.databases,
        "cloud_and_infra": repo.stack.cloud + repo.stack.infrastructure,
        "ai": repo.stack.ai,
        "packages": [p.name for p in repo.structure.packages[:20]],
        "entrypoints": repo.structure.entrypoints[:15],
        "api_specs": repo.structure.api_specs[:10],
        "top_level_files": repo.structure.top_level[:60],
        "detected_capabilities": repo.capabilities,
        "ai_assets": repo.ai.asset_kinds,
    }
    return (
        "<facts>\n" + json.dumps(facts, indent=1, default=str) + "\n</facts>\n\n"
        f"<readme>{readme_note}\n{readme or '(no README)'}\n</readme>\n\n"
        "Write the catalog entry for this repository."
    )


def _asset_prompt(asset: AIAsset) -> str:
    content = asset.content or ""
    note = ""
    if len(content) > MAX_ASSET_CHARS:
        note = f" (truncated to the first {MAX_ASSET_CHARS} characters)"
        content = content[:MAX_ASSET_CHARS]
    meta = {
        "kind": asset.kind,
        "ecosystem": asset.ecosystem,
        "name": asset.name,
        "description": asset.description,
        "path": asset.path,
        "repo": asset.repo,
        "tools": asset.tools,
        "models": asset.models,
        "frontmatter": asset.frontmatter,
    }
    return (
        "<asset_metadata>\n"
        + json.dumps(meta, indent=1, default=str)[:8000]
        + "\n</asset_metadata>\n\n"
        f"<asset_content{note}>\n{content}\n</asset_content>\n\nCatalog this AI asset."
    )
