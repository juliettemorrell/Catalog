"""Regression tests for the final review: dependency accuracy, credential hygiene,
regex performance, OSV handling, org-wide links, queries and SBOM output."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from repo_catalog.analyzers.manifests import parse_manifests
from repo_catalog.fs import RepoFiles
from repo_catalog.models import Dependency, Package, Repo
from repo_catalog.outputs import exports
from repo_catalog.outputs.sqlite import build_sqlite

TOKEN = "gh" + "p_" + "Q7xZk2Lm9Vb4Nc8Rt1Yw6Ps3Hd5Jf0Ga2Ke4"
PASSWORD = "hunter2" + "password"


def deps_of(tmp_path: Path, files: dict[str, str]) -> dict[tuple[str, str], list[Dependency]]:
    for rel, content in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(content)
    res = parse_manifests(RepoFiles.scan(tmp_path))
    out: dict[tuple[str, str], list[Dependency]] = {}
    for d in res.dependencies:
        out.setdefault((d.ecosystem, d.name), []).append(d)
    return out


def only(
    found: dict[tuple[str, str], list[Dependency]], eco: str, name: str, scope: str
) -> Dependency:
    rows = [d for d in found[(eco, name)] if d.scope == scope]
    assert len(rows) == 1, rows
    return rows[0]


# ------------------------------------------------------------------------- JavaScript locks


def test_yarn_berry_and_versions_by_range(tmp_path: Path) -> None:
    found = deps_of(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"lodash": "^4.17.21", "foo": "^2.0.0"}}),
            "yarn.lock": '__metadata:\n  version: 8\n\n"lodash@npm:^4.17.21":\n  version: 4.17.21\n'
            '  resolution: "lodash@npm:4.17.21"\n\n"foo@npm:^1.0.0":\n  version: 1.5.0\n\n'
            '"foo@npm:^2.0.0":\n  version: 2.3.0\n\n"left-pad@npm:1.3.0":\n  version: 1.3.0\n',
        },
    )
    assert only(found, "npm", "lodash", "runtime").resolved == "4.17.21"
    assert only(found, "npm", "foo", "runtime").resolved == "2.3.0"  # not the first seen
    assert only(found, "npm", "foo", "transitive").resolved == "1.5.0"  # nothing is lost
    assert only(found, "npm", "left-pad", "transitive").resolved == "1.3.0"


def test_package_lock_nested_workspaces_and_aliases(tmp_path: Path) -> None:
    found = deps_of(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "workspaces": ["packages/*"],
                    "dependencies": {"debug": "^4.3.0", "pad": "npm:left-pad@^1.3.0"},
                }
            ),
            "packages/web/package.json": json.dumps({"dependencies": {"react": "^17"}}),
            "package-lock.json": json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {},
                        "node_modules/a/node_modules/debug": {"version": "2.6.9"},
                        "node_modules/debug": {"version": "4.3.4"},
                        "node_modules/pad": {"name": "left-pad", "version": "1.3.0"},
                        "node_modules/react": {"version": "18.2.0"},
                        "packages/web/node_modules/react": {"version": "17.0.2"},
                        "node_modules/web": {"resolved": "packages/web", "link": True},
                    },
                }
            ),
        },
    )
    assert only(found, "npm", "debug", "runtime").resolved == "4.3.4"
    assert only(found, "npm", "debug", "transitive").resolved == "2.6.9"
    assert only(found, "npm", "left-pad", "runtime").resolved == "1.3.0"  # alias -> real name
    assert only(found, "npm", "react", "runtime").resolved == "17.0.2"  # its own workspace copy
    assert only(found, "npm", "react", "transitive").resolved == "18.2.0"


@pytest.mark.parametrize(
    "lock",
    [
        "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      string_decoder:\n"
        "        specifier: ^1.3.0\n        version: 1.3.0\npackages:\n  string_decoder@1.3.0:\n"
        "    resolution: {integrity: x}\n",
        "lockfileVersion: 5.4\nspecifiers:\n  string_decoder: ^1.3.0\ndependencies:\n"
        "  string_decoder: 1.3.0\npackages:\n  /string_decoder/1.3.0:\n    resolution: {integrity: x}\n",
    ],
)
def test_pnpm_names_with_underscores(tmp_path: Path, lock: str) -> None:
    found = deps_of(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"string_decoder": "^1.3.0"}}),
            "pnpm-lock.yaml": lock,
        },
    )
    assert only(found, "npm", "string_decoder", "runtime").resolved == "1.3.0"


def test_malformed_lockfile_values_never_raise(tmp_path: Path) -> None:
    found = deps_of(
        tmp_path,
        {
            "pubspec.yaml": "name: app\ndependencies:\n  http: ^1.0.0\n",
            "pubspec.lock": "packages:\n  http:\n    version: 1.2.0\n  2048:\n    version: 1.0.0\n",
        },
    )
    assert only(found, "pub", "http", "runtime").resolved == "1.2.0"


# ------------------------------------------------------------------------ other ecosystems


def test_ranges_are_not_pins_and_versions_keep_their_form(tmp_path: Path) -> None:
    found = deps_of(
        tmp_path,
        {
            "Package.swift": '.package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),\n',
            "MODULE.bazel": 'bazel_dep(name = "rules_go", version = "0.41.0")\n',
            "vcpkg.json": json.dumps({"dependencies": [{"name": "fmt", "version>=": "10.0.0"}]}),
            "go.mod": "module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n\n"
            "replace github.com/foo/bar => github.com/fork/bar v1.5.0\n",
            ".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/cache/restore@v4\n"
            "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n",
            "App.csproj": '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.3]" />'
            '<PackageReference Include="Serilog" Version="3.0.0" VersionOverride="3.1.1" /></ItemGroup></Project>',
        },
    )
    assert only(found, "swift", "github.com/apple/swift-nio", "runtime").resolved is None
    assert only(found, "bazel", "rules_go", "runtime").resolved is None
    assert only(found, "vcpkg", "fmt", "runtime").resolved is None
    fork = only(found, "go", "github.com/fork/bar", "runtime")
    assert fork.purl == "pkg:golang/github.com/fork/bar@v1.5.0"
    cache = only(found, "github-actions", "actions/cache/restore", "build")
    assert cache.resolved is None and cache.purl == "pkg:github/actions/cache@v4#restore"
    checkout = only(found, "github-actions", "actions/checkout", "build")
    assert checkout.resolved == "b4ffde65f46336ab88eb53be808477a3936bae11"
    assert only(found, "nuget", "Newtonsoft.Json", "runtime").resolved == "13.0.3"
    assert only(found, "nuget", "Serilog", "runtime").version == "3.1.1"


def test_dockerfile_args_stages_and_registries(tmp_path: Path) -> None:
    found = deps_of(
        tmp_path,
        {
            "Dockerfile": "ARG PY=3.12\nFROM python:${PY}-slim AS build\nFROM node:20-alpine AS base\n"
            "FROM base AS final\nFROM localhost:5000/team/app:1.0 AS tools\nFROM final\n",
        },
    )
    assert only(found, "docker", "python", "build").version == "3.12-slim"
    assert only(found, "docker", "node", "runtime").version == "20-alpine"  # through aliases
    app = only(found, "docker", "localhost:5000/team/app", "build")
    assert app.purl == "pkg:docker/team/app@1.0?repository_url=localhost%3A5000"


def test_repo_own_packages_are_not_dependencies(tmp_path: Path) -> None:
    found = deps_of(
        tmp_path,
        {
            "Cargo.toml": '[package]\nname = "app"\n[dependencies]\nmylib = { path = "../mylib" }\n'
            'rq = { package = "reqwest", version = "0.12" }\n',
            "Gemfile": "group :development do\n  if ENV['X']\n    gem 'x'\n  end\n  gem 'pry'\nend\n",
            "Gemfile.lock": "PATH\n  remote: .\n  specs:\n    myapp (0.1.0)\n\nGEM\n  specs:\n    pry (0.14.2)\n",
        },
    )
    assert ("cargo", "mylib") not in found and ("cargo", "rq") not in found
    assert only(found, "cargo", "reqwest", "runtime").version == "0.12"
    assert only(found, "gem", "pry", "dev").resolved == "0.14.2"  # still in the dev group
    assert ("gem", "myapp") not in found


# ---------------------------------------------------------------------- credential hygiene


def test_credentials_never_reach_any_output(tmp_path: Path) -> None:
    from repo_catalog.cli import main

    repo = tmp_path / "clones" / "canary"
    files = {
        "package.json": json.dumps(
            {
                "dependencies": {
                    "privx": f"git+https://user:{TOKEN}@github.com/acme/x.git",
                    "privy": f"https://deploy:{PASSWORD}@npm.acme.com/y-1.0.0.tgz",
                }
            }
        ),
        "Package.swift": f'.package(url: "https://deploy:{PASSWORD}@github.com/acme/q.git", from: "1.0.0"),\n',
        ".pre-commit-config.yaml": f"repos:\n  - repo: https://deploy:{PASSWORD}@github.com/acme/hooks\n    rev: v1\n",
        "main.tf": f'module "m" {{\n  source = "app.terraform.io/acme/mod/aws?token={TOKEN}"\n}}\n',
        "setup.cfg": f"[options]\ninstall_requires =\n    pkgb @ git+https://deploy:{PASSWORD}@github.com/acme/b\n",
        "environment.yml": f"dependencies:\n  - pip:\n    - git+https://deploy:{PASSWORD}@github.com/acme/c#egg=pkgc\n",
    }
    for rel, content in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(content)
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        ["-c", "user.name=T", "-c", "user.email=t@e", "commit", "-qm", "x"],
    ):
        subprocess.run(["git", *args], cwd=repo, check=True)
    out = tmp_path / "data"
    assert main(["scan", "--local", str(tmp_path / "clones"), "--out", str(out)]) == 0
    for path in out.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert TOKEN.encode() not in data and PASSWORD.encode() not in data, path

    from repo_catalog.vulns import apply_vulnerabilities

    scanned = Repo.model_validate(
        json.loads(next((out / "repos").glob("*.json")).read_text())["repo"]
    )
    sent: list[str] = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(request.content.decode())
        return httpx.Response(
            200, json={"results": [{} for _ in json.loads(request.content)["queries"]]}
        )

    apply_vulnerabilities([scanned], tmp_path / "osv", httpx.MockTransport(record))
    assert PASSWORD not in "".join(sent) and TOKEN not in "".join(sent)


# ------------------------------------------------------------------------ regex performance


@pytest.mark.parametrize(
    "files",
    [
        {".github/workflows/ci.yml": "on: push\n" + "\n" * 20000},
        {"Dockerfile": "\n" * 200000},
        {"mix.exs": "{:a, \n" * 20000},
        {".terraform.lock.hcl": 'provider "a/b" {\n' * 20000},
        {"schema.graphql": "type Query {" * 20000},
    ],
)
def test_pathological_files_scan_quickly(
    make_repo,
    tmp_path: Path,
    files: dict[str, str],  # type: ignore[no-untyped-def]
) -> None:
    from repo_catalog.scanner import ScanOptions, analyze_checkout

    ref, root = make_repo(files)
    start = time.time()
    analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w"))
    assert time.time() - start < 10


# ----------------------------------------------------------------------------------- OSV


def test_osv_aliases_pagination_and_partial_failures(tmp_path: Path) -> None:
    from repo_catalog.vulns import apply_vulnerabilities, cvss3_base_score

    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    repo = Repo(
        id="acme/a",
        name="a",
        owner="acme",
        url="https://github.com/acme/a",
        scanned_at="2026-01-01T00:00:00Z",
        scanner_version="t",  # type: ignore[arg-type]
        dependencies=[
            Dependency(
                name="Jinja2", version="2.10", resolved="2.10", ecosystem="pypi", manifest="r.txt"
            ),
            Dependency(
                name="left-pad",
                version="1.0.0",
                resolved="1.0.0",
                ecosystem="npm",
                manifest="p.json",
            ),
        ],
    )
    advisories = {
        "GHSA-aaaa": {
            "id": "GHSA-aaaa",
            "aliases": ["CVE-1"],
            "database_specific": {"severity": "LOW"},
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "jinja2"},
                    "ranges": [{"events": [{"fixed": "2.11.3"}]}],
                }
            ],
        },
        "PYSEC-1": {
            "id": "PYSEC-1",
            "aliases": ["CVE-1"],
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/querybatch"):
            results = []
            for q in json.loads(request.content)["queries"]:
                if q["package"]["name"] == "Jinja2" and "page_token" not in q:
                    results.append({"vulns": [{"id": "GHSA-aaaa"}], "next_page_token": "p2"})
                elif q["package"]["name"] == "Jinja2":
                    results.append({"vulns": [{"id": "PYSEC-1"}]})
                else:
                    results.append({"vulns": [{"id": "GHSA-gone"}]})
            return httpx.Response(200, json={"results": results})
        vid = request.url.path.rsplit("/", 1)[-1]
        return (
            httpx.Response(200, json=advisories[vid]) if vid in advisories else httpx.Response(404)
        )

    assert apply_vulnerabilities([repo], tmp_path, httpx.MockTransport(handler)) == 2
    flags = {f.message.split("@")[0]: f for f in repo.flags}
    jinja = flags["Jinja2"]
    assert jinja.severity == "high"  # aliased issue: the worst of GHSA LOW and CVSS 9.8
    assert "1 known advisory" in jinja.message and "fixed in 2.11.3" in jinja.message
    assert flags["left-pad"].severity == "medium"  # withdrawn advisory still reported


# ---------------------------------------------------------------------------- org links


def _repo(rid: str, **kw: object) -> Repo:
    owner, name = rid.split("/")
    return Repo(
        id=rid,
        name=name,
        owner=owner,
        url=f"https://github.com/{rid}",
        scanned_at="2026-01-01T00:00:00Z",
        scanner_version="t",
        **kw,
    )  # type: ignore[arg-type]


def _pkgs(*specs: tuple[str, str]) -> dict[str, object]:
    from repo_catalog.models import Structure

    return {
        "structure": Structure(packages=[Package(name=n, path=".", ecosystem=e) for e, n in specs])
    }


def test_links_prefer_live_unique_publishers_and_scale(tmp_path: Path) -> None:
    from repo_catalog.analyzers.org import link_org

    legacy = _repo("acme/ui-legacy", archived=True, **_pkgs(("npm", "@acme/ui")))
    live = _repo("acme/web-ui", **_pkgs(("npm", "@acme/ui")))
    twin_a = _repo("acme/alpha", **_pkgs(("pypi", "shared")))
    twin_b = _repo("acme/beta", **_pkgs(("pypi", "shared")))
    mono = _repo(
        "acme/mono",
        **_pkgs(*[("npm", f"@acme/p{i}") for i in range(250)]),
    )
    consumer = _repo(
        "acme/shop",
        dependencies=[
            Dependency(name="@acme/ui", version="^1", ecosystem="npm", manifest="package.json"),
            Dependency(name="shared", version="1", ecosystem="pypi", manifest="r.txt"),
            Dependency(
                name="@acme/eslint-config",
                version="1",
                ecosystem="npm",
                scope="dev",
                manifest="p.json",
            ),
            *[
                Dependency(
                    name=f"@acme/p{i}",
                    version="1",
                    resolved="1",
                    ecosystem="npm",
                    scope="transitive",
                    manifest="package-lock.json",
                )
                for i in range(250)
            ],
        ],
    )
    lint = _repo("acme/lint", **_pkgs(("npm", "@acme/eslint-config")))
    link_org([legacy, live, twin_a, twin_b, mono, consumer, lint], [])
    targets = {ln.repo: ln.via for ln in consumer.depends_on}
    assert targets.get("acme/web-ui") == "npm @acme/ui"  # the live publisher
    assert "acme/ui-legacy" not in targets and not any(
        f.id == "depends-on-archived" for f in consumer.flags
    )
    assert "acme/alpha" not in targets and "acme/beta" not in targets  # ambiguous: no link
    assert targets.get("acme/lint") == "npm @acme/eslint-config (dev)"
    assert sum(ln.repo == "acme/mono" for ln in consumer.depends_on) == 5  # routes capped per repo


def test_retired_model_spellings() -> None:
    from repo_catalog.analyzers.org import lookup_model

    for spelling, canonical in (
        ("vertex_ai/claude-3-opus@20240229", "claude-3-opus-20240229"),
        ("bedrock/anthropic.claude-v2:1", "claude-2.1"),
        ("anthropic.claude-v2", "claude-2.0"),
        ("us.anthropic.claude-3-haiku-20240307-v1:0", "claude-3-haiku-20240307"),
        ("claude-3-5-sonnet-latest", "claude-3-5-sonnet-20241022"),
    ):
        hit = lookup_model(spelling)
        assert hit and hit[0] == canonical, spelling


# ----------------------------------------------------------------------- queries and SBOM


def test_queries_normalize_escape_and_disambiguate(tmp_path: Path) -> None:
    from repo_catalog.models import Flag
    from repo_catalog.query import dependency_usage, get_repo, list_flags

    a = _repo(
        "one/skills",
        dependencies=[
            Dependency(name="typing-extensions", version="4", ecosystem="pypi", manifest="r")
        ],
        flags=[Flag(id="no-owner", category="ownership", severity="low", message="m")],
    )
    b = _repo("two/skills")
    c = _repo(
        "two/other", flags=[Flag(id="no-owner", category="ownership", severity="low", message="m")]
    )
    db = tmp_path / "c.db"
    build_sqlite(db, [a, b, c], [], {})
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    assert len(dependency_usage(con, "typing_extensions")) == 1  # PEP 503
    assert list_flags(con, repo="%") == [] and list_flags(con, repo="sk_lls") == []
    assert len(list_flags(con, repo="skills")) == 1
    ambiguous = get_repo(con, "skills")
    assert ambiguous and ambiguous["candidates"] == ["one/skills", "two/skills"]
    assert get_repo(con, "one/skills")["id"] == "one/skills"  # type: ignore[index]


def test_sbom_one_component_per_package_with_strongest_scope() -> None:
    repo = _repo(
        "acme/a",
        dependencies=[
            Dependency(
                name="lodash",
                version="4.17.21",
                resolved="4.17.21",
                ecosystem="npm",
                scope="dev",
                manifest="tools/package.json",
                purl="pkg:npm/lodash@4.17.21",
            ),
            Dependency(
                name="lodash",
                version="^4.17.0",
                resolved="4.17.21",
                ecosystem="npm",
                manifest="package.json",
                purl="pkg:npm/lodash@4.17.21",
            ),
            Dependency(
                name="requests",
                version=">=2,<3",
                ecosystem="pypi",
                manifest="r.txt",
                purl="pkg:pypi/requests",
            ),
        ],
    )
    sbom = exports.repo_sbom(repo)
    comps = {c["bom-ref"]: c for c in sbom["components"]}  # type: ignore[union-attr, index]
    assert list(comps) == ["pkg:npm/lodash@4.17.21", "pkg:pypi/requests"]
    assert "scope" not in comps["pkg:npm/lodash@4.17.21"]  # required: runtime use wins
    assert "version" not in comps["pkg:pypi/requests"]  # a range is not a version


def test_github_sbom_merge_skips_the_repo_and_normalized_duplicates() -> None:
    from repo_catalog.analyzers.purls import merge_github_sbom

    sbom = {
        "packages": [
            {
                "SPDXID": "SPDXRef-com.github.acme-app",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:github/acme/app@main"}
                ],
            },
            {
                "SPDXID": "SPDXRef-pip-1",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/typing-extensions@4.12.2",
                    }
                ],
            },
            {
                "SPDXID": "SPDXRef-docker-1",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:docker/library/nginx@1.25"}
                ],
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-com.github.acme-app",
            }
        ],
    }
    deps = [
        Dependency(
            name="typing_extensions", version=">=4", ecosystem="pypi", manifest="pyproject.toml"
        ),
        Dependency(name="nginx", version="1.25", ecosystem="docker", manifest="compose.yml"),
    ]
    assert merge_github_sbom(deps, sbom) == 0


def test_go_packages_link_to_the_module_that_publishes_them() -> None:
    from repo_catalog.analyzers.org import link_org

    lib = _repo("acme/lib", **_pkgs(("go", "github.com/acme/lib")))
    app = _repo(
        "acme/app",
        dependencies=[
            Dependency(
                name="github.com/acme/lib/pkg/client",
                version="v1.2.0",
                ecosystem="go",
                manifest="go.mod",
            ),
        ],
    )
    link_org([lib, app], [])
    assert [(ln.repo, ln.via) for ln in app.depends_on] == [
        ("acme/lib", "go github.com/acme/lib/pkg/client")
    ]
