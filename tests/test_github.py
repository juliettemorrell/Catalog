from __future__ import annotations

import httpx
import pytest

from repo_catalog import github
from repo_catalog.github import GitHubClient


def _rest_repo(name: str, owner: str = "acme") -> dict[str, object]:
    return {
        "full_name": f"{owner}/{name}",
        "owner": {"login": owner},
        "clone_url": f"https://github.com/{owner}/{name}.git",
        "html_url": f"https://github.com/{owner}/{name}",
        "default_branch": "main",
        "size": 10,
        "description": "d",
        "topics": ["x"],
        "license": {"spdx_id": "MIT"},
        "archived": False,
        "fork": False,
        "visibility": "private",
        "pushed_at": "2026-01-01T00:00:00Z",
        "stargazers_count": 3,
    }


def test_rest_fallback_and_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(f"{req.method} {req.url.path}")
        if req.url.path == "/graphql":
            return httpx.Response(403, json={"message": "GraphQL disabled"})
        if req.url.path == "/orgs/acme/repos":
            if req.url.params.get("page") == "2":
                return httpx.Response(200, json=[_rest_repo("b"), _rest_repo("c", owner="other")])
            return httpx.Response(
                200,
                json=[_rest_repo("a")],
                headers={"link": '<https://api.github.com/orgs/acme/repos?page=2>; rel="next"'},
            )
        if req.url.path.endswith("/languages"):
            return httpx.Response(200, json={"Python": 1000})
        return httpx.Response(404)

    gh = GitHubClient("t", transport=httpx.MockTransport(handler))
    refs = gh.list_owner_repos("acme")
    assert [r.full_name for r in refs] == ["acme/a", "acme/b"]  # other owner dropped
    assert refs[0].meta["license"] == "MIT" and refs[0].meta["languages"] == {"Python": 1000}
    assert refs[0].head_sha is None and refs[0].default_branch == "main"
    gh.list_owner_repos("acme")  # GraphQL is not retried once known to be unavailable
    assert calls.count("POST /graphql") == 1


def test_graphql_path() -> None:
    node = {
        "nameWithOwner": "acme/a",
        "name": "a",
        "url": "https://github.com/acme/a",
        "owner": {"login": "acme"},
        "isArchived": False,
        "isFork": False,
        "defaultBranchRef": {"name": "main", "target": {"oid": "deadbeef"}},
        "repositoryTopics": {"nodes": [{"topic": {"name": "api"}}]},
        "languages": {"edges": [{"size": 5, "node": {"name": "Go"}}]},
        "licenseInfo": {"spdxId": "Apache-2.0"},
        "pushedAt": "2026-02-01T00:00:00Z",
    }

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": {
                    "repositoryOwner": {
                        "login": "acme",
                        "repositories": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [node],
                        },
                    }
                }
            },
        )

    refs = GitHubClient("t", transport=httpx.MockTransport(handler)).list_owner_repos("acme")
    assert refs[0].head_sha == "deadbeef" and refs[0].meta["topics"] == ["api"]
    assert refs[0].meta["languages"] == {"Go": 5}


def test_rate_limit_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(github.time, "sleep", sleeps.append)
    responses = iter(
        [
            httpx.Response(429, headers={"retry-after": "7"}),
            httpx.Response(502),
            httpx.Response(200, json=[]),
        ]
    )
    gh = GitHubClient(None, transport=httpx.MockTransport(lambda req: next(responses)))
    assert gh.paginate("/orgs/acme/properties/values") == []
    assert sleeps == [7.0, 2.0]


def test_custom_properties_missing_is_empty() -> None:
    gh = GitHubClient("t", transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    assert gh.org_custom_properties("someuser") == {}
