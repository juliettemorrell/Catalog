"""Review sweep 2 (repo records): one-liners, repo types, stack recall, workflow and secret
findings, CI test detection, ownership counts, API specs and runtime versions."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path

from repo_catalog.analyzers.flags import _satisfies, _workflow_flags
from repo_catalog.github import RepoRef
from repo_catalog.models import Contributor, Declared, Ownership, Repo
from repo_catalog.scanner import ScanOptions, analyze_checkout

MakeRepo = Callable[..., tuple[RepoRef, Path]]


def _scan(make_repo: MakeRepo, tmp_path: Path, files: dict[str, str], name: str = "demo") -> Repo:
    ref, root = make_repo(files, name=name)
    ref.meta = {}  # no GitHub description: exercise the local fallbacks
    return analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w")).repo


# ------------------------------------------------------------------------- one-liner


def test_one_liner_prefers_descriptor_then_root_manifest(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    repo = _scan(
        make_repo,
        tmp_path,
        {
            "catalog-info.yaml": "apiVersion: backstage.io/v1alpha1\nkind: Component\n"
            "metadata:\n  name: pay\n  description: Authorizes card payments.\n"
            "spec:\n  type: service\n  owner: team-a\n",
            "package.json": '{"name": "pay", "description": "Root package"}',
            "README.md": "# Pay\n\nSome readme text that describes things.\n",
        },
        name="pay",
    )
    assert repo.summary.one_liner == "Authorizes card payments."

    repo = _scan(
        make_repo,
        tmp_path,
        {
            # a nested package's description describes itself, not the repo
            "packages/ide/package.json": '{"name": "ide", "description": "IDE companion."}',
            "pyproject.toml": '[project]\nname = "tool"\ndescription = "Add your description here"\n',
            "README.md": "> **Note:** this is a note about something else entirely.\n\n"
            "[![ci](https://x/badge.svg)](https://x)\n\n# Tool\n"
            "Tool turns logs into dashboards for on-call engineers.\n\n"
            "## Setup\n\nClick the Use this template button to create a repository.\n",
        },
        name="tool",
    )
    assert repo.summary.one_liner == "Tool turns logs into dashboards for on-call engineers."
    assert repo.summary.source == "readme"

    repo = _scan(
        make_repo,
        tmp_path,
        {
            "README.md": "# Spring PetClinic Sample Application\n\n## Slides\n\n"
            "See the presentation here:\n[slides](https://x)\n\n> Note: legacy slides.\n",
        },
        name="petclinic",
    )
    assert repo.summary.one_liner == "Spring PetClinic Sample Application"


# ------------------------------------------------------------------------- repo type


def test_repo_type_follows_the_product_not_the_workspace(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    uv_ws = _scan(
        make_repo,
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "agents"\ndependencies = ["httpx"]\n'
            '[tool.uv.workspace]\nmembers = ["examples/demo"]\n',
            "src/agents/__init__.py": "x = 1\n",
            "examples/demo/pyproject.toml": '[project]\nname = "demo"\n',
        },
        name="agents",
    )
    assert not uv_ws.structure.is_monorepo and uv_ws.structure.repo_type == "library"

    cli = _scan(
        make_repo,
        tmp_path,
        {
            "Cargo.toml": '[package]\nname = "rg"\n[[bin]]\nname = "rg"\npath = "crates/core/main.rs"\n'
            '[workspace]\nmembers = ["crates/*"]\n',
            "crates/core/main.rs": "fn main() {}\n",
            "crates/grep/Cargo.toml": '[package]\nname = "grep"\n',
            "crates/grep/src/lib.rs": "pub fn f() {}\n",
            "crates/ignore/Cargo.toml": '[package]\nname = "ignore"\n',
            "crates/ignore/src/lib.rs": "pub fn g() {}\n",
        },
        name="rg",
    )
    assert cli.structure.is_monorepo and cli.structure.repo_type == "cli"

    lib = _scan(
        make_repo,
        tmp_path,
        {
            "go.mod": "module github.com/acme/lib\n\ngo 1.22\n",
            "lib.go": "package lib\n",
            "otel/go.mod": "module github.com/acme/lib/otel\n\ngo 1.22\n",
            "otel/otel.go": "package otel\n",
            "www/package.json": '{"name": "docs", "private": true, "dependencies": {"react": "18"}}',
        },
        name="lib",
    )
    assert not lib.structure.is_monorepo and lib.structure.repo_type == "library"

    mono = _scan(
        make_repo,
        tmp_path,
        {
            "package.json": '{"name": "mono", "private": true, "workspaces": ["apps/*"]}',
            "turbo.json": "{}",
            "apps/web/package.json": '{"name": "web", "dependencies": {"next": "14"}}',
            "apps/api/package.json": '{"name": "api", "dependencies": {"@nestjs/core": "10"}}',
        },
        name="mono",
    )
    assert mono.structure.is_monorepo and mono.structure.repo_type == "monorepo"

    examples = _scan(
        make_repo,
        tmp_path,
        {
            "crews/a/pyproject.toml": '[project]\nname = "a"\n',
            "crews/a/main.py": "print(1)\n",
            "crews/b/pyproject.toml": '[project]\nname = "b"\n',
            "crews/b/main.py": "print(2)\n",
        },
        name="acme-examples",
    )
    assert examples.structure.repo_type == "examples"

    solution = _scan(
        make_repo,
        tmp_path,
        {
            "Shop.slnx": "<Solution />\n",
            "src/Catalog.API/Catalog.API.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />\n',
            "src/Catalog.API/Program.cs": "var app = 1;\n",
            "src/Basket.API/Basket.API.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />\n',
            "src/Basket.API/Program.cs": "var app = 1;\n",
            "src/EventBus/EventBus.csproj": '<Project Sdk="Microsoft.NET.Sdk" />\n',
        },
        name="shop",
    )
    assert not solution.structure.is_monorepo and solution.structure.repo_type == "service"


def test_mobile_and_data_pipeline_types(make_repo: MakeRepo, tmp_path: Path) -> None:
    android = _scan(
        make_repo,
        tmp_path,
        {
            "settings.gradle.kts": 'include(":app")\n',
            "app/build.gradle.kts": 'plugins { id("com.android.application") }\ndependencies {\n'
            '    implementation("androidx.compose.material3:material3:1.3.0")\n'
            '    implementation("androidx.room:room-runtime:2.6.1")\n'
            '    implementation("com.squareup.retrofit2:retrofit:2.11.0")\n}\n',
            "app/src/main/AndroidManifest.xml": "<manifest />\n",
            "app/src/main/java/com/acme/MainActivity.kt": "class MainActivity\n",
        },
        name="android",
    )
    assert android.structure.repo_type == "mobile-app"
    assert {"Android", "Jetpack Compose"} <= set(android.stack.frameworks)
    assert "Room" in android.stack.databases and "Retrofit" in android.stack.libraries

    pipeline = _scan(
        make_repo,
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "pipe"\n'
            'dependencies = ["apache-airflow", "dbt-snowflake"]\n',
            "dags/daily.py": "from airflow import DAG\n",
            "dbt/dbt_project.yml": "name: warehouse\n",
        },
        name="pipe",
    )
    assert pipeline.structure.repo_type == "data-pipeline"
    assert "Snowflake" in pipeline.stack.databases


# ----------------------------------------------------------------------------- stack


def test_stack_recall_dotnet_spring_terraform_prisma(make_repo: MakeRepo, tmp_path: Path) -> None:
    dotnet = _scan(
        make_repo,
        tmp_path,
        {
            "src/Api/Api.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup>'
            '<PackageReference Include="Npgsql.EntityFrameworkCore.PostgreSQL" Version="8.0.0" />'
            '<PackageReference Include="MassTransit.RabbitMQ" Version="8.0.0" />'
            '<PackageReference Include="Serilog.AspNetCore" Version="8.0.0" />'
            '<PackageReference Include="OpenTelemetry.Extensions.Hosting" Version="1.9.0" />'
            '<PackageReference Include="Grpc.AspNetCore" Version="2.60.0" />'
            '<PackageReference Include="Aspire.Npgsql" Version="9.0.0" />'
            "</ItemGroup></Project>\n",
            "tests/Api.Tests/Api.Tests.csproj": '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
            '<PackageReference Include="xunit.v3" Version="1.0.0" />'
            '<PackageReference Include="MSTest.TestFramework" Version="3.0.0" />'
            "</ItemGroup></Project>\n",
        },
        name="dotnet",
    )
    st = dotnet.stack
    assert "PostgreSQL" in st.databases and "RabbitMQ" in st.messaging
    assert {"Serilog", "OpenTelemetry"} <= set(st.observability)
    assert "gRPC" in st.frameworks and ".NET Aspire" in st.infrastructure
    assert {"xUnit", "MSTest"} <= set(st.testing)  # from the test project
    assert not any(d.name == "xunit.v3" and d.scope == "runtime" for d in dotnet.dependencies)

    spring = _scan(
        make_repo,
        tmp_path,
        {
            "build.gradle.kts": "plugins { java }\ndependencies {\n"
            '    implementation("org.springframework.boot:spring-boot-starter-web")\n'
            '    implementation("org.springframework.kafka:spring-kafka")\n'
            '    testImplementation("org.springframework.boot:spring-boot-starter-test")\n}\n',
            "settings.gradle.kts": 'rootProject.name = "orders"\n',
            "src/main/java/com/acme/App.java": "class App {}\n",
            "src/main/java/com/acme/Orders.java": "class Orders {}\n",
        },
        name="orders",
    )
    assert "Kafka" in spring.stack.messaging and "JUnit" in spring.stack.testing
    assert spring.stack.primary_language == "Java"  # build.gradle.kts is not Kotlin code

    infra = _scan(
        make_repo,
        tmp_path,
        {
            "main.tf": "terraform {\n  required_providers {\n    aws = {\n"
            '      source = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n  }\n}\n',
            "rustfmt.toml": "edition = '2021'\n",
            "prisma/schema.prisma": 'datasource db {\n  provider = "postgresql"\n'
            '  url = env("DATABASE_URL")\n}\n',
        },
        name="infra",
    )
    assert "AWS" in infra.stack.cloud
    assert "PostgreSQL" in infra.stack.databases and "rustfmt" in infra.stack.linting


def test_client_libs_and_vendored_protos_are_not_apis(make_repo: MakeRepo, tmp_path: Path) -> None:
    repo = _scan(
        make_repo,
        tmp_path,
        {
            "package.json": '{"name": "cli", "dependencies": {"@grpc/grpc-js": "1.14.3"}}',
            "src/tracing/proto/opentelemetry/proto/collector/trace/v1/trace_service.proto": (
                'syntax = "proto3";\npackage opentelemetry.proto.collector.trace.v1;\n'
                "service TraceService {\n  rpc Export(Req) returns (Resp) {}\n}\n"
            ),
            "src/Catalog.API/Catalog.API.json": json.dumps(
                {
                    "openapi": "3.1.1",
                    "info": {"title": "Catalog HTTP API", "version": "1.0"},
                    "paths": {"/api/items": {"get": {"responses": {}}}},
                },
                indent=2,
            ),
        },
        name="cli",
    )
    assert "gRPC" not in repo.stack.frameworks and "rpc-api" not in repo.capabilities
    assert not any(r.name == "TraceService" for r in repo.reusables)
    assert "src/Catalog.API/Catalog.API.json" in repo.structure.api_specs
    api = next(r for r in repo.reusables if r.kind == "api")
    assert api.name == "Catalog HTTP API" and api.details["operations"] == 1


# ------------------------------------------------------------------------- workflows

_PWN = {
    "merge-ref.yml": "on: pull_request_target\njobs:\n  b:\n    runs-on: x\n    steps:\n"
    "      - uses: actions/checkout@v4\n        with:\n"
    "          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n"
    "      - run: npm ci && npm test\n        env:\n          T: ${{ secrets.NPM_TOKEN }}\n",
    "gh-checkout.yml": "on: pull_request_target\njobs:\n  b:\n    runs-on: x\n    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - run: gh pr checkout ${{ github.event.pull_request.number }} && make build\n",
    "workflow-run.yml": "on:\n  workflow_run:\n    workflows: [ci]\njobs:\n  d:\n"
    "    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
    "          ref: ${{ github.event.workflow_run.head_sha }}\n      - run: ./deploy.sh\n"
    "        env:\n          TOKEN: ${{ secrets.DEPLOY }}\n",
    "env-ref.yml": "on: pull_request_target\nenv:\n  HEAD: ${{ github.event.pull_request.head.sha }}\n"
    "jobs:\n  x:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n"
    "        with:\n          ref: ${{ env.HEAD }}\n      - run: npm install\n",
}
_SAFE = {
    "safe.yml": "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  x:\n"
    "    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
    "          ref: ${{ github.event.pull_request.base.ref }}\n          path: .trusted\n"
    "      - uses: actions/checkout@v4\n        with:\n"
    "          ref: ${{ github.event.pull_request.head.sha }}\n          path: pr\n"
    "          persist-credentials: false\n"
    "      - run: |\n          git -C pr diff --name-only > pr/.changed\n"
    '          node .trusted/check.mjs --root "$GITHUB_WORKSPACE/pr"\n',
    "fetch-only.yml": "on: pull_request_target\njobs:\n  x:\n    runs-on: x\n    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - run: |\n          git fetch origin pull/${{ github.event.pull_request.number }}/head:pr\n"
    "          node scripts/changed.js\n",
}


def test_pwn_request_forms_and_safe_pattern() -> None:
    for name, text in _PWN.items():
        flags = [f for f in _workflow_flags({name: text}, []) if f.id == "workflow-pwn-request"]
        assert flags and flags[0].severity == "high", name
    for name, text in _SAFE.items():
        flags = [f for f in _workflow_flags({name: text}, []) if f.id == "workflow-pwn-request"]
        assert not flags, name
    # running the PR's code from its folder is still a finding
    exec_from = _SAFE["safe.yml"] + "      - run: cd pr && npm install\n"
    flags = _workflow_flags({"w.yml": exec_from}, [])
    assert [f.severity for f in flags if f.id == "workflow-pwn-request"] == ["medium"]


def test_ci_runs_tests_and_test_sources(make_repo: MakeRepo, tmp_path: Path) -> None:
    for cmd in ("./mvnw -B verify", "./gradlew build", "${{ env.CARGO }} test", "php artisan test"):
        repo = _scan(
            make_repo,
            tmp_path,
            {
                ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n"
                f"    steps:\n      - run: {cmd}\n",
                "test/fixture.bin": "\x00\x01",
                "test/data.csv": "a,b\n",
            },
            name=f"ci{abs(hash(cmd)) % 10_000}",
        )
        checks = {c.id: c.passed for c in repo.practices.checks}
        assert checks["ci-runs-tests"], cmd
        assert not checks["tests"]  # fixtures alone are not automated tests


def test_workflow_versions_outside_engines_are_dropped(make_repo: MakeRepo, tmp_path: Path) -> None:
    repo = _scan(
        make_repo,
        tmp_path,
        {
            "package.json": '{"name": "pf", "engines": {"node": ">=22.22.0"}}',
            ".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n"
            "      - uses: actions/setup-node@v4\n        with:\n          node-version: 20.20.0\n"
            "      - uses: actions/setup-node@v4\n        with:\n          node-version: 24\n",
        },
        name="pf",
    )
    versions = {v.version for v in repo.stack.runtime_versions if v.runtime == "node"}
    assert versions == {"24"}
    assert _satisfies("3.9", ">=3.10") is False and _satisfies("22", "^20 || ^22") is True
    assert _satisfies("lts/*", ">=18") is None


# ---------------------------------------------------------------------------- secrets

DSN = "postgresql://admin:" + "Pr0dP4ssw0rd9x" + "@db.internal.acme.com:5432/orders"
NPM = "3f9a1c2e-7b4d-4e8a-9c1f-2d6b8e0a4f7c"
TWILIO = "SK" + "2a8e9c7f1b3d4e5f" + "60718293a4b5c6d7"  # split so push protection sees no key


def test_secret_recall_without_values(make_repo: MakeRepo, tmp_path: Path) -> None:
    repo = _scan(
        make_repo,
        tmp_path,
        {
            "src/config.py": f'DATABASE_URL = "{DSN}"\nTWILIO_KEY = "{TWILIO}"\n',
            ".npmrc": f"//registry.npmjs.org/:_authToken={NPM}\n",
            # precision: dev DSNs, templated passwords and env-var tokens are not leaks
            "docker-compose.yml": "x: postgres://postgres:postgres@db:5432/app\n"
            "y: postgresql://app:s3cretPassw0rd@localhost/app\n",
            "src/settings.py": 'URL = f"mysql://{user}:${DB_PASSWORD}@db.acme.com/x"\n',
            ".yarnrc.yml": 'npmAuthToken: "${NPM_TOKEN}"\n',
        },
        name="secrets",
    )
    found = {
        (f.path, f.message.split(" committed")[0]) for f in repo.flags if f.id == "committed-secret"
    }
    assert found == {
        ("src/config.py", "Database URL with password"),
        ("src/config.py", "Twilio API key"),
        (".npmrc", "npm auth token"),
    }
    dumped = repo.model_dump_json()
    assert "Pr0dP4ssw0rd9x" not in dumped and NPM not in dumped and TWILIO not in dumped


# -------------------------------------------------------------------------- ownership


def _git(cwd: Path, *args: str, author: str = "Test Author") -> None:
    subprocess.run(
        ["git", "-c", f"user.name={author}", "-c", "user.email=a@example.com", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_contributor_count_and_bus_factor(make_repo: MakeRepo, tmp_path: Path) -> None:
    ref, root = make_repo({"README.md": "# x\n"}, name="owned")
    authors = ["Lead"] * 30 + [f"Dev {i}" for i in range(14)] + ["GitHub Actions"] * 5
    for i, author in enumerate(authors):
        (root / f"f{i}.txt").write_text(str(i))
        _git(root, "add", "-A", author=author)
        _git(root, "commit", "-q", "-m", f"c{i}", author=author)
    repo = analyze_checkout(ref, root, ScanOptions(workdir=tmp_path / "w")).repo
    own = repo.ownership
    assert own.commit_count == 50 and own.contributor_count == 17  # not capped at 10
    assert len(own.top_contributors) == 10
    assert not any(f.id == "single-maintainer" for f in repo.flags)  # 30 of 45 human commits

    from repo_catalog.analyzers.flags import _ownership_flags

    skewed = Ownership(
        codeowners=["@a"],
        commit_count=100,
        top_contributors=[
            Contributor(name="Lead", commits=92),
            Contributor(name="GitHub Actions", commits=5),
        ],
    )
    msg = [f.message for f in _ownership_flags(skewed, Declared(), False)]
    assert msg == ["Bus factor 1: 97% of commits come from one person"]  # 92 of 95 humans
    skewed.commit_count = 400  # the rest of history is spread over other people
    assert not _ownership_flags(skewed, Declared(), False)


# ------------------------------------------------------------------------- type overrides


def test_sdk_with_asgi_dep_and_doc_servers_stays_a_library(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    server = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('Demo')\n\n@mcp.tool()\ndef add(a: int, b: int) -> int:\n    return a + b\n"
    repo = _scan(
        make_repo,
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "sdk"\ndependencies = ["starlette>=0.40", "httpx"]\n',
            "src/sdk/__init__.py": "def client():\n    return 1\n",
            "docs_src/first_steps/tutorial001.py": server,
            "examples/servers/demo.py": server,
        },
        name="sdk",
    )
    assert repo.structure.repo_type == "library"
    assert repo.ai.mcp_servers_provided  # still cataloged, just not the product


def test_cli_with_mcp_mode_stays_a_cli(make_repo: MakeRepo, tmp_path: Path) -> None:
    repo = _scan(
        make_repo,
        tmp_path,
        {
            "package.json": '{"name": "tool", "bin": {"tool": "dist/cli.js"}, "dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}',
            "src/commands/mcp/server.ts": "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\nconst server = new McpServer({ name: 'Tool MCP', version: '1' });\n",
            "src/cli.ts": "console.log('hi')\n",
        },
        name="tool",
    )
    assert repo.structure.repo_type == "cli"
