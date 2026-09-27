"""GitHub discovery: list repositories and their metadata with as few API calls as possible.

One GraphQL query per 50 repos returns everything the catalog needs from GitHub itself
(topics, license, languages, default-branch HEAD SHA, ...). Org custom properties come
from a single paginated REST call. Everything else is read from a local clone.
"""

from __future__ import annotations

import email.utils
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

log = logging.getLogger(__name__)

API = "https://api.github.com"

_REPO_FIELDS = """
  nameWithOwner name url description homepageUrl visibility
  isArchived isFork isTemplate createdAt pushedAt stargazerCount
  owner { login }
  licenseInfo { spdxId }
  repositoryTopics(first: 25) { nodes { topic { name } } }
  defaultBranchRef { name target { oid } }
  issues(states: OPEN) { totalCount }
  languages(first: 25, orderBy: {field: SIZE, direction: DESC}) { edges { size node { name } } }
"""

_OWNER_QUERY = """
query($login: String!, $cursor: String) {
  repositoryOwner(login: $login) {
    login
    repositories(first: 50, after: $cursor, orderBy: {field: NAME, direction: ASC}) {
      pageInfo { hasNextPage endCursor }
      nodes { __FIELDS__ }
    }
  }
}
""".replace("__FIELDS__", _REPO_FIELDS)

_REPO_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) { __FIELDS__ }
}
""".replace("__FIELDS__", _REPO_FIELDS)


@dataclass
class RepoRef:
    """Minimal description of a repository to scan."""

    full_name: str
    clone_url: str
    html_url: str
    default_branch: str | None = None
    head_sha: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)
    custom_properties: dict[str, Any] = field(default_factory=dict)
    properties_known: bool = True  # False when the custom-properties call failed

    @property
    def owner(self) -> str:
        return self.full_name.split("/", 1)[0]

    @property
    def name(self) -> str:
        return self.full_name.split("/", 1)[1]


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _parse_retry_after(value: str | None) -> float | None:
    """Retry-After is either delta-seconds or an HTTP date."""
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return float(min(max((when - datetime.now(UTC)).total_seconds(), 1), 3600))


class GitHubClient:
    """Small GitHub API client with primary and secondary rate-limit handling."""

    def __init__(
        self,
        token: str | None,
        *,
        max_retries: int = 5,
        timeout: float = 30.0,
        api_url: str = API,
        transport: httpx.BaseTransport | None = None,
    ):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repo-catalog",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            base_url=api_url, headers=headers, timeout=timeout, transport=transport
        )
        self._max_retries = max_retries
        self.has_token = bool(token)
        self._graphql_ok = bool(token)  # GraphQL requires authentication
        # owners whose listing came back incomplete: never prune their records
        self.incomplete: set[str] = set()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- transport --------------------------------------------------------- #

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            try:
                resp = self._http.request(method, url, **kwargs)
            except httpx.TransportError as exc:  # timeouts, resets, DNS hiccups
                if attempt >= self._max_retries:
                    raise GitHubError(f"network error calling GitHub: {exc}") from None
                wait = float(2**attempt)
                log.warning("GitHub %s %s failed (%s), retrying in %.0fs", method, url, exc, wait)
                time.sleep(wait)
                continue
            delay = self._retry_delay(resp, attempt)
            if delay is None:
                return resp
            log.warning(
                "GitHub %s %s -> %s, retrying in %.0fs", method, url, resp.status_code, delay
            )
            time.sleep(delay)
        raise AssertionError("unreachable")

    def _retry_delay(self, resp: httpx.Response, attempt: int) -> float | None:
        if attempt >= self._max_retries:
            return None
        if resp.status_code in (403, 429):
            retry_after = _parse_retry_after(resp.headers.get("retry-after"))
            if retry_after is not None:
                return retry_after
            if resp.headers.get("x-ratelimit-remaining") == "0":
                reset = int(resp.headers.get("x-ratelimit-reset", "0") or 0)
                return float(min(max(reset - time.time(), 1), 3600))
            if resp.status_code == 429 or "rate limit" in resp.text.lower():
                return 60.0 * (attempt + 1)  # GitHub: wait at least a minute
            return None
        if resp.status_code in (500, 502, 503, 504):
            return float(2**attempt)
        return None

    def graphql(self, query: str, variables: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Returns (data, complete). ``complete`` is False when GitHub answered with partial
        errors (e.g. SAML on one repo), so callers never treat the result as exhaustive."""
        for attempt in range(self._max_retries + 1):
            resp = self._request("POST", "/graphql", json={"query": query, "variables": variables})
            if resp.status_code != 200:
                raise GitHubError(
                    f"GraphQL HTTP {resp.status_code}: {resp.text[:300]}", status=resp.status_code
                )
            body = resp.json()
            errors = body.get("errors") or []
            # GraphQL reports rate limiting as HTTP 200 with a RATE_LIMITED error
            if any(e.get("type") == "RATE_LIMITED" for e in errors if isinstance(e, dict)):
                if attempt >= self._max_retries:
                    raise GitHubError("GraphQL rate limit exceeded", status=429)
                reset = int(resp.headers.get("x-ratelimit-reset", "0") or 0)
                wait = float(min(max(reset - time.time(), 60 * (attempt + 1)), 3600))
                log.warning("GraphQL rate limited, retrying in %.0fs", wait)
                time.sleep(wait)
                continue
            if errors and not body.get("data"):
                raise GitHubError(f"GraphQL errors: {errors}")
            for err in errors:
                log.warning("GraphQL partial error: %s", err.get("message"))
            data: dict[str, Any] = body["data"]
            return data, not errors
        raise AssertionError("unreachable")

    def paginate(self, url: str, params: dict[str, Any] | None = None) -> list[Any]:
        items: list[Any] = []
        next_url: str | None = url
        query: dict[str, Any] | None = {"per_page": 100, **(params or {})}
        while next_url:
            # the `next` link already carries its query string; passing params would drop it
            resp = self._request("GET", next_url, params=query)
            if resp.status_code != 200:
                raise GitHubError(
                    f"GET {next_url} -> {resp.status_code}: {resp.text[:300]}",
                    status=resp.status_code,
                )
            items.extend(resp.json())
            next_url = resp.links.get("next", {}).get("url")
            query = None
        return items

    # -- discovery --------------------------------------------------------- #

    def _use_graphql(self, fn: Any, *args: Any) -> Any:
        """Prefer GraphQL (1 call per 50 repos); fall back to REST where it is blocked
        (some proxies, GHES configs and sandboxes only allow REST)."""
        if self._graphql_ok:
            try:
                return fn(*args)
            except GitHubError as exc:
                if exc.status is None:
                    raise  # GraphQL answered with errors: a real problem, not an outage
                if exc.status in (401, 403, 404, 410, 501):
                    log.info("GraphQL unavailable (%s); using REST", str(exc)[:120])
                    self._graphql_ok = False  # blocked/disabled: stop trying for this run
                else:
                    log.warning("GraphQL failed (%s); using REST for this call", str(exc)[:120])
        return None

    def list_owner_repos(self, login: str) -> list[RepoRef]:
        """All repos owned by an org or user (repos they merely collaborate on are dropped)."""
        refs = self._use_graphql(self._list_owner_graphql, login)
        return refs if refs is not None else self._list_owner_rest(login)

    def get_repo(self, full_name: str) -> RepoRef:
        ref = self._use_graphql(self._get_repo_graphql, full_name)
        return ref if ref is not None else self._get_repo_rest(full_name)

    def _list_owner_rest(self, login: str) -> list[RepoRef]:
        try:
            rows = self.paginate(f"/orgs/{login}/repos", {"type": "all"})
        except GitHubError as exc:
            if exc.status != 404:  # e.g. 403 SAML enforcement: report it, don't mask it
                raise
            rows = self.paginate(f"/users/{login}/repos", {"type": "owner"})
        return [
            self._ref_from_rest(r) for r in rows if r["owner"]["login"].lower() == login.lower()
        ]

    def _get_repo_rest(self, full_name: str) -> RepoRef:
        resp = self._request("GET", f"/repos/{full_name}")
        if resp.status_code != 200:
            raise GitHubError(f"Repository {full_name}: HTTP {resp.status_code}")
        return self._ref_from_rest(resp.json())

    @staticmethod
    def _ref_from_rest(r: dict[str, Any]) -> RepoRef:
        # the primary language only: a /languages call per repo would cost one request each
        meta = {
            "description": r.get("description"),
            "homepage": r.get("homepage") or None,
            "visibility": r.get("visibility"),
            "archived": r.get("archived", False),
            "fork": r.get("fork", False),
            "is_template": r.get("is_template", False),
            "created_at": _dt(r.get("created_at")),
            "pushed_at": _dt(r.get("pushed_at")),
            "stars": r.get("stargazers_count"),
            "open_issues": r.get("open_issues_count"),
            "license": (r.get("license") or {}).get("spdx_id"),
            "topics": r.get("topics") or [],
            "languages": {r["language"]: 1} if r.get("language") else {},
            "languages_partial": True,
        }
        return RepoRef(
            full_name=r["full_name"],
            clone_url=r["clone_url"],
            html_url=r["html_url"],
            default_branch=r.get("default_branch") if r.get("size", 1) else None,
            head_sha=None,  # resolved with `git ls-remote` by the scanner
            meta=meta,
        )

    def _list_owner_graphql(self, login: str) -> list[RepoRef]:
        refs: list[RepoRef] = []
        cursor: str | None = None
        while True:
            data, complete = self.graphql(_OWNER_QUERY, {"login": login, "cursor": cursor})
            if not complete:
                self.incomplete.add(login.lower())
            owner = data.get("repositoryOwner")
            if owner is None:
                raise GitHubError(f"No GitHub user or organization named {login!r}")
            conn = owner["repositories"]
            for node in conn["nodes"]:
                if not node:  # a repo GitHub could not return: the listing is incomplete
                    self.incomplete.add(login.lower())
                elif node["owner"]["login"].lower() == login.lower():
                    refs.append(_ref_from_node(node))
            if not conn["pageInfo"]["hasNextPage"]:
                break
            cursor = conn["pageInfo"]["endCursor"]
        return refs

    def _get_repo_graphql(self, full_name: str) -> RepoRef:
        owner, name = full_name.split("/", 1)
        data, _ = self.graphql(_REPO_QUERY, {"owner": owner, "name": name})
        if not data.get("repository"):
            raise GitHubError(f"Repository {full_name} not found or not accessible")
        return _ref_from_node(data["repository"])

    def org_custom_properties(self, org: str) -> dict[str, dict[str, Any]] | None:
        """Map of full_name -> {property: value}; empty for users. None when the call failed,
        so callers keep the values they already have instead of wiping them."""
        try:
            rows = self.paginate(f"/orgs/{org}/properties/values")
        except GitHubError as exc:
            if exc.status == 404:  # a user account, or properties not enabled
                return {}
            log.warning("Custom properties unavailable for %s (%s)", org, exc)
            return None
        try:
            return {
                row["repository_full_name"]: {
                    p["property_name"]: p["value"] for p in row.get("properties") or []
                }
                for row in rows
            }
        except (TypeError, KeyError, AttributeError):
            log.warning("Custom properties for %s had an unexpected shape; ignoring", org)
            return None

    def dependency_sbom(self, full_name: str) -> dict[str, Any] | None:
        """GitHub's dependency graph as SPDX JSON (needs the dependency graph enabled and
        `contents: read`). None when unavailable, so scans never depend on it."""
        try:
            resp = self._request("GET", f"/repos/{full_name}/dependency-graph/sbom")
        except GitHubError as exc:
            log.info("Dependency graph unavailable for %s (%s)", full_name, exc)
            return None
        if resp.status_code != 200:
            log.info("Dependency graph unavailable for %s (HTTP %s)", full_name, resp.status_code)
            return None
        sbom = resp.json().get("sbom")
        return sbom if isinstance(sbom, dict) else None


def _ref_from_node(node: dict[str, Any]) -> RepoRef:
    branch = node.get("defaultBranchRef") or {}
    meta = {
        "description": node.get("description"),
        "homepage": node.get("homepageUrl") or None,
        "visibility": (node.get("visibility") or "").lower() or None,
        "archived": node.get("isArchived", False),
        "fork": node.get("isFork", False),
        "is_template": node.get("isTemplate", False),
        "created_at": _dt(node.get("createdAt")),
        "pushed_at": _dt(node.get("pushedAt")),
        "stars": node.get("stargazerCount"),
        "open_issues": (node.get("issues") or {}).get("totalCount"),
        "license": (node.get("licenseInfo") or {}).get("spdxId"),
        "topics": [
            n["topic"]["name"] for n in (node.get("repositoryTopics") or {}).get("nodes", [])
        ],
        "languages": {
            e["node"]["name"]: e["size"] for e in (node.get("languages") or {}).get("edges", [])
        },
    }
    return RepoRef(
        full_name=node["nameWithOwner"],
        clone_url=f"{node['url']}.git",
        html_url=node["url"],
        default_branch=branch.get("name"),
        head_sha=(branch.get("target") or {}).get("oid"),
        meta=meta,
    )


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
