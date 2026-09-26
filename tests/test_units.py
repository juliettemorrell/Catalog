from __future__ import annotations

from pathlib import Path

import pytest

from repo_catalog.analyzers.ai_common import as_list, parse_frontmatter
from repo_catalog.analyzers.manifests import parse_manifests
from repo_catalog.analyzers.rules import match_dependency
from repo_catalog.fs import RepoFiles, _glob_to_regex
from repo_catalog.query import fts_query, read_only_sql


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("**/SKILL.md", "SKILL.md", True),
        ("**/SKILL.md", ".claude/skills/pdf/SKILL.md", True),
        ("*.md", "docs/a.md", False),
        ("docs/*.md", "docs/a.md", True),
        ("**/.cursor/rules/**/*.{mdc,md}", ".cursor/rules/ts.mdc", True),
        ("**/.cursor/rules/**/*.{mdc,md}", "pkg/.cursor/rules/sub/x.md", True),
        ("**/.cursor/rules/**/*.{mdc,md}", ".cursor/rules/x.txt", False),
        (".github/workflows/*.yml", ".github/workflows/ci.yml", True),
        ("**/Dockerfile.*", "svc/Dockerfile.prod", True),
    ],
)
def test_glob(pattern: str, path: str, expected: bool) -> None:
    assert bool(_glob_to_regex(pattern).match(path)) is expected


def test_frontmatter_valid_and_invalid_yaml() -> None:
    fm, body = parse_frontmatter("---\nname: x\ntools: [Read, Grep]\n---\nBody")
    assert fm == {"name": "x", "tools": ["Read", "Grep"]} and body == "Body"
    # Cursor rules often contain YAML-invalid globs; the line parser must still recover them.
    fm, _ = parse_frontmatter(
        "---\ndescription: TS rules\nglobs: *.ts,*.tsx\nalwaysApply: false\n---\nx"
    )
    assert fm["globs"] == "*.ts,*.tsx" and fm["description"] == "TS rules"
    assert parse_frontmatter("no frontmatter") == ({}, "no frontmatter")


def test_as_list() -> None:
    assert as_list("Read, Grep, Bash(git:*)") == ["Read", "Grep", "Bash(git:*)"]
    assert as_list("Read Grep") == ["Read", "Grep"]
    assert as_list(["a", ""]) == ["a"]
    assert as_list(None) == []


def test_dependency_rules() -> None:
    labels = {r.label for r in match_dependency("@anthropic-ai/sdk")}
    assert labels == {"Anthropic SDK"}
    assert "Stripe" in {r.label for r in match_dependency("stripe")}
    assert "AWS" in {r.label for r in match_dependency("@aws-sdk/client-s3")}  # prefix rule
    assert "Spring Boot" in {r.label for r in match_dependency("org.springframework.boot:starter")}
    assert match_dependency("Scikit_Learn")  # case and _/- insensitive


def test_manifests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name": "web", "description": "Web app", "dependencies": {"react": "^19"},'
        ' "devDependencies": {"vitest": "^3"}, "engines": {"node": ">=22"},'
        ' "packageManager": "pnpm@9.0.0", "workspaces": ["packages/*"]}'
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "svc"\nrequires-python = ">=3.12"\n'
        'dependencies = ["fastapi>=0.110", "anthropic[bedrock]>=1.0; python_version>\'3.9\'"]\n'
        '[project.optional-dependencies]\ndev = ["pytest"]\n'
    )
    (tmp_path / "go.mod").write_text(
        "module github.com/acme/tool\n\ngo 1.23\n\nrequire (\n\tgithub.com/spf13/cobra v1.8.0\n"
        "\tgolang.org/x/sys v0.20.0 // indirect\n)\n"
    )
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n# comment\n-e .\n")
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>api</artifactId>'
        "<dependencies><dependency><groupId>org.junit.jupiter</groupId>"
        "<artifactId>junit-jupiter</artifactId><scope>test</scope></dependency>"
        "</dependencies></project>"
    )
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n")
    res = parse_manifests(RepoFiles.scan(tmp_path))
    deps = {(d.ecosystem, d.name): d for d in res.dependencies}
    assert deps[("npm", "vitest")].scope == "dev"
    assert deps[("pypi", "anthropic")].version == ">=1.0"
    assert deps[("pypi", "pytest")].scope == "dev"
    assert deps[("go", "golang.org/x/sys")].scope == "optional"
    assert deps[("maven", "org.junit.jupiter:junit-jupiter")].scope == "dev"
    assert deps[("pypi", "requests")].version == "==2.32.0"
    assert res.runtimes == {"node": ">=22", "python": ">=3.12", "go": "1.23"}
    assert {"pnpm", "pip", "go modules", "maven"} <= res.package_managers
    assert res.workspaces and res.lockfiles == ["pnpm-lock.yaml"]
    assert {p.name for p in res.packages} >= {"web", "svc", "github.com/acme/tool", "api"}
    assert not res.errors


def test_bad_manifest_is_reported_not_raised(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json")
    res = parse_manifests(RepoFiles.scan(tmp_path))
    assert res.errors and "package.json" in res.errors[0]


def test_fts_query_is_safe() -> None:
    assert fts_query('pdf "gen" OR drop') == '"pdf"* AND "gen"* AND "or"* AND "drop"*'
    assert fts_query("") == ""


def test_read_only_sql_rejects_writes() -> None:
    import sqlite3

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE t (x)")
    with pytest.raises(ValueError):
        read_only_sql(con, "DELETE FROM t")
    with pytest.raises(ValueError):
        read_only_sql(con, "SELECT 1; DROP TABLE t")
    assert read_only_sql(con, "SELECT 1 AS one") == [{"one": 1}]
