"""Second review sweep: version ranges, lockfile resolution, purls, OSV, Dockerfile stages,
sbt variables and credential cleaning of dependency references."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_catalog.analyzers.manifests import parse_manifests
from repo_catalog.analyzers.purls import exact_version
from repo_catalog.analyzers.versions import best_match, satisfies
from repo_catalog.fs import RepoFiles
from repo_catalog.models import Dependency
from repo_catalog.textutil import clean_ref
from repo_catalog.vulns import _distinct, _fixed, _key


def scan_deps(tmp_path: Path, files: dict[str, str]) -> list[Dependency]:
    for rel, content in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(content)
    res = parse_manifests(RepoFiles.scan(tmp_path))
    assert not res.errors, res.errors
    return res.dependencies


def rows(deps: list[Dependency], eco: str, name: str) -> list[Dependency]:
    return [d for d in deps if d.ecosystem == eco and d.name == name]


# ------------------------------------------------------------------------------- versions


@pytest.mark.parametrize(
    ("version", "spec", "eco", "expected"),
    [
        # an upper bound never admits prereleases of that version
        ("2.0.0-beta.1", ">=1.0.0 <2.0.0", "npm", False),
        ("2.0.0-beta.1", "^1.2.0", "npm", False),
        ("3.0.0rc1", ">=2,<3", "pypi", False),
        ("2.1.0-rc.1", "1.2.x || >=2.0.0 <2.1", "npm", False),
        # a bound carrying a prerelease tag on the same release does
        ("1.2.3-beta.2", ">=1.2.3-beta", "npm", True),
        ("1.2.3", ">1.2.3-beta", "npm", True),
        # pinned versions match themselves, and only themselves
        ("31.1-jre", "31.1-jre", "maven", True),
        ("31.1-android", "31.1-jre", "maven", False),
        ("31.1-jre", ">=30.0", "maven", True),
        ("2.0b3", "==2.0b3", "pypi", True),
        ("1.0.0rc1", "==1.0.0rc1", "pypi", True),
        ("1.2.3rc1", "==1.2.3", "pypi", False),
        ("1.2.3-alpha", "=1.2.3", "npm", False),
        ("1.2.5", "==1.2", "pypi", False),
        ("1.2.0", "==1.2", "pypi", True),
        ("1.5.3", "!=1.5.*", "pypi", False),
        ("4.7.2.2", "4.7.2.1", "nuget", False),
        ("4.7.2.1", "4.7.2.1", "nuget", True),
        # Composer tilde: the last given component may grow
        ("1.5.0", "~1.2", "composer", True),
        ("2.0.0", "~1.2", "composer", False),
        ("1.2.9", "~1.2.3", "composer", True),
        ("1.3.0", "~1.2.3", "composer", False),
        ("1.4.0", "^1.2@dev", "composer", True),
        # npm tilde / partial versions
        ("1.3.0", "~1.2", "npm", False),
        ("1.2.9", ">1.2", "npm", False),
        ("1.3.0", ">1.2", "npm", True),
        ("2.5.0", "~> 2", "gem", True),
    ],
)
def test_satisfies(version: str, spec: str, eco: str, expected: bool) -> None:
    assert satisfies(version, spec, eco) is expected


def test_best_match_orders_prereleases_numerically() -> None:
    assert best_match(["1.9.0", "2.0.0-beta.1"], ">=1.0.0 <2.0.0", "npm") == "1.9.0"
    assert best_match(["2.28.0", "3.0.0rc1"], ">=2,<3", "pypi") == "2.28.0"
    assert best_match(["1.0.0-rc.10", "1.0.0-rc.9"], ">=1.0.0-rc.1", "npm") == "1.0.0-rc.10"
    assert best_match(["4.7.2.2", "4.7.2.1"], "4.7.2.1", "nuget") == "4.7.2.1"


def test_exact_version_rejects_npm_ranges() -> None:
    assert exact_version("npm", "1.x") is None
    assert exact_version("npm", "1.2") is None  # npm: 1.2.x
    assert exact_version("npm", "1.2.*") is None
    assert exact_version("npm", "1.2.3") == "1.2.3"
    assert exact_version("pypi", "==1.2") == "1.2"
    assert exact_version("maven", "31.1-jre") == "31.1-jre"
    dep = Dependency(name="x", version="1.x", resolved="1.x", ecosystem="npm", manifest="p")
    assert _key(dep) is None


# ----------------------------------------------------------------------------- manifests


def test_packages_starting_with_http_are_kept(tmp_path: Path) -> None:
    deps = scan_deps(
        tmp_path,
        {
            "requirements.txt": "httpx==0.27.0\nhttpcore==1.0.5\nhttps://example.com/p.whl\n",
            "pyproject.toml": '[project]\nname="app"\nversion="0.1"\n'
            'dependencies=["httptools"]\n[dependency-groups]\ndev=["httpx-sse"]\n',
        },
    )
    names = {d.name for d in deps if d.ecosystem == "pypi"}
    assert {"httpx", "httpcore", "httptools", "httpx-sse"} <= names
    assert not any("example.com" in n for n in names)


def test_dockerfile_stage_alias_equal_to_image(tmp_path: Path) -> None:
    deps = scan_deps(
        tmp_path,
        {
            "Dockerfile": "FROM node:20 AS build\nRUN x\n"
            "FROM nginx AS nginx\nCOPY --from=build /a /b\n"
        },
    )
    assert rows(deps, "docker", "node")[0].scope == "build"
    assert rows(deps, "docker", "nginx")[0].scope == "runtime"


def test_sbt_version_variables(tmp_path: Path) -> None:
    deps = scan_deps(
        tmp_path,
        {
            "build.sbt": 'scalaVersion := "2.13.12"\nval circeV = "0.14.6"\n'
            'libraryDependencies ++= Seq(\n  "io.circe" %% "circe-core" % circeV,\n'
            '  "org.typelevel" %% "cats-core" % Versions.cats\n)\n',
            "project/Versions.scala": 'object Versions {\n  val cats = "2.10.0"\n}\n',
        },
    )
    assert rows(deps, "maven", "io.circe:circe-core_2.13")[0].version == "0.14.6"
    assert rows(deps, "maven", "org.typelevel:cats-core_2.13")[0].version == "2.10.0"


# ----------------------------------------------------------------------------- lockfiles


def test_non_workspace_package_does_not_borrow_root_lock(tmp_path: Path) -> None:
    lock = {
        "name": "root",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root", "dependencies": {"react": "^18.2.0"}},
            "node_modules/react": {"version": "18.2.0"},
        },
    }
    deps = scan_deps(
        tmp_path,
        {
            "package.json": json.dumps({"name": "root", "dependencies": {"react": "^18.2.0"}}),
            "package-lock.json": json.dumps(lock),
            "services/legacy/package.json": json.dumps({"dependencies": {"react": "^16.14.0"}}),
        },
    )
    react = {d.manifest: d for d in rows(deps, "npm", "react") if d.scope == "runtime"}
    assert react["package.json"].resolved == "18.2.0"
    assert react["services/legacy/package.json"].resolved is None


def test_npm_workspace_member_uses_hoisted_root_record(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root", "workspaces": ["packages/*"]},
            "packages/a": {"name": "a", "dependencies": {"lodash": "^4.17.0"}},
            "node_modules/a": {"resolved": "packages/a", "link": True},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }
    deps = scan_deps(
        tmp_path,
        {
            "package.json": json.dumps({"name": "root", "workspaces": ["packages/*"]}),
            "package-lock.json": json.dumps(lock),
            "packages/a/package.json": json.dumps(
                {"name": "a", "dependencies": {"lodash": "^4.17.0"}}
            ),
        },
    )
    assert rows(deps, "npm", "lodash")[0].resolved == "4.17.21"


def test_pnpm_never_falls_back_to_another_importer(tmp_path: Path) -> None:
    pnpm = (
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n"
        "        specifier: ^18.2.0\n        version: 18.2.0\n\npackages:\n\n"
        "  react@18.2.0:\n    resolution: {integrity: sha512-x}\n"
    )
    deps = scan_deps(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"react": "^18.2.0"}}),
            "pnpm-lock.yaml": pnpm,
            "tools/old/package.json": json.dumps({"dependencies": {"react": "^16.0.0"}}),
        },
    )
    by_manifest = {d.manifest: d.resolved for d in rows(deps, "npm", "react")}
    assert by_manifest == {"package.json": "18.2.0", "tools/old/package.json": None}


def test_pinned_and_aliased_deps_are_not_repeated_as_transitive(tmp_path: Path) -> None:
    deps = scan_deps(
        tmp_path,
        {
            "build.gradle": "dependencies {\n"
            " implementation 'com.google.guava:guava:31.1-jre'\n}\n",
            "gradle.lockfile": "com.google.guava:guava:31.1-jre=compileClasspath\nempty=\n",
            "composer.json": json.dumps({"require": {"monolog/monolog": "~1.2"}}),
            "composer.lock": json.dumps(
                {"packages": [{"name": "monolog/monolog", "version": "1.5.0"}]}
            ),
            "package.json": json.dumps({"dependencies": {"myalias": "npm:left-pad@^1.3.0"}}),
            "yarn.lock": '# yarn lockfile v1\n\n\n"myalias@npm:left-pad@^1.3.0":\n'
            '  version "1.3.0"\n'
            '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc"\n',
            "pyproject.toml": '[project]\nname="app"\nversion="0.1"\n'
            'dependencies=["pydantic==2.0b3"]\n',
            "uv.lock": 'version = 1\n\n[[package]]\nname = "pydantic"\nversion = "2.0b3"\n'
            'source = { registry = "https://pypi.org/simple" }\n',
        },
    )
    for eco, name, version in [
        ("maven", "com.google.guava:guava", "31.1-jre"),
        ("composer", "monolog/monolog", "1.5.0"),
        ("npm", "left-pad", "1.3.0"),
        ("pypi", "pydantic", "2.0b3"),
    ]:
        found = rows(deps, eco, name)
        assert [(d.scope, d.resolved) for d in found] == [("runtime", version)], found
    assert not rows(deps, "npm", "myalias")


# ---------------------------------------------------------------------------------- OSV


def test_osv_fixed_versions_distinct_groups() -> None:
    adv = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "jinja2"},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "7" * 40}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]},
                ],
            }
        ]
    }
    assert _fixed(adv, "PyPI", "Jinja2") == ["3.1.3"]
    advisories = {
        "GHSA-1111": {"aliases": ["CVE-2024-1"]},
        "GHSA-2222": {"id": "GHSA-2222"},
        "PYSEC-2024-3": {"aliases": ["CVE-2024-1", "GHSA-2222"]},
        "PYSEC-2024-9": {"aliases": ["CVE-2024-9"]},
    }
    assert _distinct(list(advisories), advisories) == [
        ["GHSA-1111", "GHSA-2222", "PYSEC-2024-3"],
        ["PYSEC-2024-9"],
    ]


# ------------------------------------------------------------------------------ clean_ref


@pytest.mark.parametrize(
    ("raw", "cleaned"),
    [
        (
            "git+ssh://git@github.com/acme/lib.git#v1.2.3",
            "git+ssh://github.com/acme/lib.git#v1.2.3",
        ),
        (
            "git::https://example.com/vpc.git?ref=v1.2.0",
            "git::https://example.com/vpc.git?ref=v1.2.0",
        ),
        ("com.foo:bar:1.0@aar", "com.foo:bar:1.0@aar"),
        ("npm:lodash@^4", "npm:lodash@^4"),
        ("@scope/name@1.2.3", "@scope/name@1.2.3"),
        ("user:p@ss@host/x", "host/x"),
        ("https://codeload.github.com/a/b/tar.gz/" + "ab12" * 10, None),
        ("https://u:pw@h.io/p?k=v&token=x&X-Amz-Signature=abc", "https://h.io/p?k=v"),
        ("app.terraform.io/acme/mod/aws?token=abc", "app.terraform.io/acme/mod/aws"),
        ("https://h.io/x#access_token=abc", "https://h.io/x"),
    ],
)
def test_clean_ref(raw: str, cleaned: str | None) -> None:
    assert clean_ref(raw) == (raw if cleaned is None else cleaned)
