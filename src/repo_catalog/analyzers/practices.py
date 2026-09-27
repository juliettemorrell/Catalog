"""Engineering best-practice checks, loosely modelled on OpenSSF Scorecard and common
"repo health" rubrics, restricted to what can be verified from the checkout alone."""

from __future__ import annotations

import re
from typing import Literal

from ..fs import RepoFiles
from ..models import PracticeCheck, Practices, Stack, Structure
from .docs import find_readme

_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|e2e|integration[-_]tests?|src/test)/[^/]+\.[a-z0-9]+$|"
    r"(^|/)[^/]*\.(Unit|Integration|Functional)?Tests?/[^/]+\.(cs|fs|vb)$|"  # .NET test projects
    r"(^|/)[^/]*Tests/[^/]+\.swift$|"  # Xcode/SwiftPM test targets
    r"(_test\.(go|py|exs?)|\.(test|spec)\.[cm]?[jt]sx?|_spec\.rb|(^|/)test_[^/]+\.py|"
    r"Tests?\.(cs|java|kt|swift|php))$",
    re.IGNORECASE,
)
_NOT_TEST = re.compile(r"\.(md|mdx|rst|txt|ya?ml|json|lock|svg|png|jpe?g)$", re.I)
# a test is source code: fixtures and data files (test/fixture.bin, test/data.csv) are not
_TEST_SOURCE = re.compile(
    r"\.(py|pyi|[cm]?[jt]sx?|go|rs|java|kt|kts|scala|groovy|rb|php|cs|fs|vb|swift|dart|exs?|"
    r"erl|clj[sc]?|hs|ml|c|cc|cpp|cxx|h|hpp|m|mm|lua|r|jl|sh|bats|ps1|pl|t|zig|nim|vue|"
    r"svelte|feature|robot|sql)$",
    re.I,
)
_TEST_CMD = re.compile(
    r"\b(pytest|tox|nox|jest|vitest|mocha|go test|cargo test|cargo nextest|"
    r"mvnw?(?:\.cmd)?\s[^\n]*\b(?:test|verify|install|package)|"
    r"gradlew?(?:\.bat)?\s[^\n]*\b(?:test|check|build)|"
    r"npm (run )?test|pnpm (run )?test|yarn test|bun test|rspec|phpunit|pest|artisan test|"
    r"dotnet test|make test|playwright test|cypress run|ctest|swift test|mix test|flutter test)\b|"
    r"\}\}\s+(?:test|nextest)\b",  # ${{ env.CARGO }} test
    re.IGNORECASE,
)
_USES = re.compile(r"uses:\s*['\"]?([\w.-]+/[\w./-]+)@([\w.-]+)")
_WRITE_ALL = re.compile(r"^[ \t]*permissions:\s*['\"]?write-all", re.M)


def assess_practices(
    files: RepoFiles,
    stack: Stack,
    structure: Structure,
    lockfiles: list[str],
    workflows: dict[str, str],
    dependencies: int = 1,
    *,
    description: str | None,
    topics: list[str],
    has_descriptor: bool,
) -> Practices:
    checks: list[PracticeCheck] = []

    def check(
        id_: str,
        category: str,
        label: str,
        passed: bool,
        weight: int = 1,
        evidence: str | None = None,
    ) -> None:
        checks.append(
            PracticeCheck(
                id=id_,
                category=category,
                label=label,
                passed=passed,
                weight=weight,
                evidence=evidence,
            )
        )

    def first(*patterns: str) -> str | None:
        hit = files.first(*patterns)
        return hit.path if hit else None

    readme = find_readme(files)
    readme_len = len(files.read(readme) or "") if readme else 0
    check("readme", "docs", "Has a README", bool(readme), 3, readme)
    check(
        "readme-substantial",
        "docs",
        "README is substantial (>= 800 chars)",
        readme_len >= 800,
        1,
        f"{readme_len} chars" if readme else None,
    )
    lic = first(
        "LICENSE",
        "LICENSE.*",
        "LICENCE",
        "LICENCE.*",
        "COPYING",
        "COPYING.*",
        "LICENSE-*",
        "UNLICENSE",
    )
    check("license", "governance", "Has a LICENSE file", bool(lic), 2, lic)
    contributing = first("CONTRIBUTING.*", ".github/CONTRIBUTING.*", "docs/CONTRIBUTING.*")
    check(
        "contributing", "docs", "Has contribution guidelines", bool(contributing), 1, contributing
    )
    changelog = first("CHANGELOG*", "HISTORY*", "RELEASES*", ".changeset/config.json")
    check(
        "changelog", "docs", "Maintains a changelog or release notes", bool(changelog), 1, changelog
    )
    check(
        "docs",
        "docs",
        "Has a docs folder or ADRs",
        any(d.rstrip("/").lower() in {"docs", "doc", "adr", "adrs"} for d in structure.docs),
        1,
    )

    codeowners = first("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
    check(
        "codeowners",
        "governance",
        "Declares code owners (CODEOWNERS)",
        bool(codeowners),
        2,
        codeowners,
    )
    check(
        "descriptor",
        "governance",
        "Has a catalog descriptor (catalog-info.yaml etc.)",
        has_descriptor,
        1,
    )
    check("description", "governance", "GitHub description is set", bool(description), 1)
    check(
        "topics",
        "governance",
        "GitHub topics are set",
        bool(topics),
        1,
        ", ".join(topics[:5]) or None,
    )

    security = first("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
    check(
        "security-policy",
        "security",
        "Has a security policy (SECURITY.md)",
        bool(security),
        1,
        security,
    )
    dep_updates = "Dependabot" in stack.ci_cd or "Renovate" in stack.ci_cd
    check(
        "dependency-updates",
        "security",
        "Automated dependency updates (Dependabot/Renovate)",
        dep_updates,
        2,
    )
    # repos whose manifests declare no external dependencies have nothing to lock
    has_manifest = bool(dependencies) and bool(structure.packages or stack.package_managers)
    check(
        "lockfile",
        "security",
        "Dependencies are locked (lockfile committed)",
        bool(lockfiles) or not has_manifest,
        2,
        lockfiles[0] if lockfiles else None,
    )
    env_files = [
        f.path
        for f in files.files
        if re.search(r"(^|/)\.env(\.[\w.-]+)?$", f.path)
        and not re.search(
            r"\.(example|sample|template|dist|vault|schema|defaults|tpl)$|"
            r"\.(example|sample|template)\.",
            f.name,
            re.I,
        )
    ]
    check(
        "no-env-files",
        "security",
        "No .env files committed",
        not env_files,
        2,
        ", ".join(env_files[:3]) or None,
    )
    all_wf = "\n".join(workflows.values())
    if workflows:
        refs = [ref for _, ref in _USES.findall(all_wf)]
        pinned = sum(bool(re.fullmatch(r"[0-9a-f]{40}", r)) for r in refs)
        unpinned = len(refs) - pinned
        check(
            "actions-pinned",
            "security",
            "GitHub Actions pinned to commit SHAs",
            unpinned == 0 and pinned > 0,
            1,
            f"{pinned} pinned / {unpinned} unpinned",
        )
        check(
            "workflow-permissions",
            "security",
            "Workflows declare least-privilege permissions",
            all(
                re.search(r"^[ \t]*permissions:", t, re.M) and not _WRITE_ALL.search(t)
                for t in workflows.values()
            ),
            1,
        )

    test_files = [
        f.path
        for f in files.files
        if _TEST_PATH.search(f.path)
        and not _NOT_TEST.search(f.path)
        and _TEST_SOURCE.search(f.path)
    ]
    check(
        "tests",
        "quality",
        "Has automated tests",
        bool(test_files),
        3,
        f"{len(test_files)} test files" if test_files else None,
    )
    linters = [
        t
        for t in stack.linting
        if t
        not in {"EditorConfig", "Codecov", "pre-commit", "Husky", "TypeScript", "mypy", "Pyright"}
    ]
    check(
        "linter",
        "quality",
        "Linter/formatter configured",
        bool(linters),
        2,
        ", ".join(linters[:4]) or None,
    )
    typed = any(t in stack.linting for t in ("TypeScript", "mypy", "Pyright")) or (
        stack.primary_language in {"Go", "Rust", "Java", "Kotlin", "C#", "Scala", "Swift", "Dart"}
    )
    check("type-checking", "quality", "Static typing / type checking", typed, 1)
    check("editorconfig", "quality", "Has .editorconfig", "EditorConfig" in stack.linting, 1)
    check(
        "pre-commit",
        "quality",
        "Pre-commit hooks configured",
        "pre-commit" in stack.linting or "Husky" in stack.linting,
        1,
    )

    has_ci = bool(
        stack.ci_cd
        and set(stack.ci_cd) - {"Dependabot", "Renovate", "release-please", "GoReleaser"}
    )
    check(
        "ci",
        "delivery",
        "Has CI pipelines",
        has_ci,
        3,
        ", ".join(stack.ci_cd[:3]) or None,
    )
    ci_texts = all_wf + "".join(
        files.read(p) or ""
        for p in (
            ".gitlab-ci.yml",
            "Jenkinsfile",
            ".circleci/config.yml",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
            ".buildkite/pipeline.yml",
        )
    )
    if has_ci and re.search(r"\bmake\s+\w*|\bjust\s+\w+|\btask\s+\w+", ci_texts):
        # CI delegating to a task runner: the runner's recipes count too
        ci_texts += "".join(files.read(p) or "" for p in ("Makefile", "justfile", "Taskfile.yml"))
    ran = has_ci and bool(_TEST_CMD.search(ci_texts))
    check("ci-runs-tests", "delivery", "CI runs the test suite", ran, 2)
    release = any(t in stack.ci_cd for t in ("release-please", "GoReleaser")) or any(
        t in stack.build_tools for t in ("Changesets", "semantic-release")
    )
    check("release-automation", "delivery", "Automated releases", release, 1)
    check("gitignore", "delivery", "Has .gitignore", files.exists(".gitignore"), 1)

    total = sum(c.weight for c in checks)
    earned = sum(c.weight for c in checks if c.passed)
    score = round(100 * earned / total) if total else 0
    return Practices(score=score, grade=_grade(score), checks=checks)


Grade = Literal["A", "B", "C", "D", "F"]
_GRADES: tuple[tuple[int, Grade], ...] = ((85, "A"), (70, "B"), (55, "C"), (40, "D"))


def _grade(score: int) -> Grade:
    return next((grade for threshold, grade in _GRADES if score >= threshold), "F")
