"""Risk and maintenance flags found while scanning one repository.

Flags point a human at something worth fixing. They never carry secret values:
only the kind of finding and where it is. Findings whose meaning changes with the
calendar (end-of-life runtimes, retired models) are computed at build time in
``org.py`` from the pinned versions collected here, so they never go stale.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from typing import Any

from ..fs import FileEntry, RepoFiles
from ..models import Declared, Flag, Ownership, RuntimeVersion
from ..textutil import load_yaml
from .manifests import NON_PRODUCT_DIR

# ---------------------------------------------------------------------------- secrets

# High-precision patterns only: a flag must be worth a human's time.
_SECRETS: dict[str, str] = {
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
    "GitHub fine-grained token": r"\bgithub_pat_[A-Za-z0-9_]{80,}",
    "Anthropic API key": r"\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_\-]{80,}",
    "OpenAI API key": r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,}",
    "AWS access key": r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])",
    "Slack token": r"\bxox[baprs]-\d{6,}-[A-Za-z0-9-]{10,}",
    "Slack webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}",
    "Google API key": r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "GitLab token": r"\bglpat-[A-Za-z0-9_\-]{20}\b",
    "Stripe live key": r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}",
    "npm token": r"\bnpm_[A-Za-z0-9]{36}\b",
    "Hugging Face token": r"\bhf_[A-Za-z0-9]{34}\b",
    "SendGrid key": r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
    "Azure storage key": r"AccountKey=[A-Za-z0-9+/]{80,}={0,2}",
    "Twilio API key": r"\bSK[0-9a-f]{32}\b",
    "npm auth token": r"(?:_authToken|npmAuthToken)[ \t]*[=:][ \t]*['\"]?(?!\$)[A-Za-z0-9_\-.+/=]{20,}",
    # a connection string with an inline password (checked further in _dsn_ok)
    "Database URL with password": r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|"
    r"amqps?|mssql|sqlserver|oracle)(?:\+\w+)?://([^:@/\s'\"]{1,64}):([^@\s'\"]{8,128})@"
    r"([A-Za-z0-9.-]{3,253})",
    # header plus a real base64 body (code that only parses PEM headers is not a leak)
    "Private key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:\\[nr]|\s)+(?:[A-Za-z0-9+/=]{40,}(?:\\[nr]|\s)+){2,}",
}
# literal(s) each pattern must contain: `in` checks run at C speed, so a pattern's regex
# only runs on the rare file that could match it
_HINTS: dict[str, tuple[str, ...]] = {
    "GitHub token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "GitHub fine-grained token": ("github_pat_",),
    "Anthropic API key": ("sk-ant-",),
    "OpenAI API key": ("T3BlbkFJ",),
    "AWS access key": ("AKIA", "ASIA"),
    "Slack token": ("xox",),
    "Slack webhook": ("hooks.slack.com",),
    "Google API key": ("AIza",),
    "GitLab token": ("glpat-",),
    "Stripe live key": ("_live_",),
    "npm token": ("npm_",),
    "Hugging Face token": ("hf_",),
    "SendGrid key": ("SG.",),
    "Azure storage key": ("AccountKey=",),
    "Twilio API key": ("SK",),
    "npm auth token": ("uthToken",),
    "Database URL with password": ("://",),
    "Private key": ("PRIVATE KEY",),
}
_SECRET_RXS = [(label, _HINTS[label], re.compile(rx)) for label, rx in _SECRETS.items()]
_PLACEHOLDER = re.compile(
    r"(?i)example|x{4,}|dummy|fake|sample|placeholder|redacted|your|test(?:ing)?key|0{8,}|1234567"
)
_SKIP_SUFFIX = frozenset(
    [
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".webp",
        ".pdf",
        ".zip",
        ".gz",
        ".tgz",
        ".jar",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".mp3",
        ".lock",
        ".map",
        ".min.js",
        ".snap",
        ".svg",
        ".bin",
        ".onnx",
        ".pt",
        ".parquet",
    ]
)
_SKIP_NAMES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "go.sum",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
        "Pipfile.lock",
        "bun.lockb",
    }
)
MAX_SECRET_BYTES = 150_000_000  # per repo
MAX_SECRET_FLAGS = 25
_TESTISH = re.compile(
    r"(^|/)(docs?|spec|__mocks__|mocks?|certs?-?test)/|[._-](test|spec)\.[a-z]+$|(^|/)test_[^/]+$",
    re.I,
)


_WEAK_PASSWORDS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "secret",
        "changeme",
        "change_me",
        "admin",
        "root",
        "postgres",
        "mysql",
        "redis",
        "guest",
        "user",
        "test",
        "example",
        "default",
        "letmein",
        "12345678",
        "password123",
    }
)


def _dsn_ok(m: re.Match[str]) -> bool:
    """A real-looking inline password on a real host, not a local/dev or templated one."""
    user, password, host = m.group(1), m.group(2), m.group(3).lower()
    if re.search(r"[${}<>%*]", password) or password.lower() in _WEAK_PASSWORDS:
        return False
    if password.lower() == user.lower() or "." not in host or host.startswith("127."):
        return False  # docker-compose service names (db, postgres) and localhost
    if host in ("localhost", "0.0.0.0", "host.docker.internal"):
        return False
    # letters and digits both: dictionary words are almost always documentation
    return bool(re.search(r"\d", password) and re.search(r"[A-Za-z]", password))


def find_secrets(text: str) -> Iterable[tuple[str, int]]:
    """(kind, offset) for each credential-shaped string that is not a placeholder."""
    for label, hints, rx in _SECRET_RXS:
        if not any(h in text for h in hints):
            continue
        for m in rx.finditer(text):
            value = m.group(0)
            if _PLACEHOLDER.search(value) or len(set(value)) < 10:
                continue
            if label == "Database URL with password" and not _dsn_ok(m):
                continue
            if label == "Twilio API key" and not (
                re.search(r"\d", value[2:]) and re.search(r"[a-f]", value[2:])
            ):
                continue
            yield label, m.start()


def _secret_flags(files: RepoFiles) -> list[Flag]:
    flags: list[Flag] = []
    budget = MAX_SECRET_BYTES
    seen: set[tuple[str, str]] = set()
    for entry in files.files:
        if (
            entry.suffix in _SKIP_SUFFIX
            or entry.name in _SKIP_NAMES
            or entry.name.endswith(".min.js")
            or entry.size > 1_000_000
        ):
            continue
        budget -= entry.size
        if budget < 0 or len(flags) >= MAX_SECRET_FLAGS:
            break
        text = files.read(entry.path, cache=False)
        if not text:
            continue
        for kind, offset in find_secrets(text):
            if (kind, entry.path) in seen:
                continue
            seen.add((kind, entry.path))
            testish = bool(NON_PRODUCT_DIR.search(entry.path) or _TESTISH.search(entry.path))
            flags.append(
                Flag(
                    id="committed-secret",
                    category="security",
                    severity="low" if testish else "high",
                    message=f"{kind} committed"
                    + (" (test/example/docs path)" if testish else "; rotate it and purge history"),
                    path=entry.path,
                    line=text.count("\n", 0, offset) + 1,
                )
            )
    return flags


# ------------------------------------------------------------------- runtime versions

_VERSION_FILES = {
    ".nvmrc": "node",
    ".node-version": "node",
    ".python-version": "python",
    ".ruby-version": "ruby",
    ".go-version": "go",
    ".java-version": "java",
}
_TOOL_VERSIONS = {
    "nodejs": "node",
    "node": "node",
    "python": "python",
    "ruby": "ruby",
    "golang": "go",
    "go": "go",
    "java": "java",
    "php": "php",
    "dotnet": "dotnet",
    "dotnet-core": "dotnet",
}
_IMAGES = {
    "python": "python",
    "node": "node",
    "ruby": "ruby",
    "golang": "go",
    "php": "php",
    "openjdk": "java",
    "eclipse-temurin": "java",
    "amazoncorretto": "java",
    "adoptopenjdk": "java",
    "sapmachine": "java",
    "ibm-semeru-runtimes": "java",
}
_WORKFLOW_VERSION = re.compile(
    r"^[ \t]*-?[ \t]*(node|python|java|go|dotnet|ruby|php)-version:\s*['\"]?([0-9][\w.+\-]*)['\"]?\s*$",
    re.M,
)
_FROM = re.compile(r"^[ \t]*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", re.I | re.M)


def _add(out: list[RuntimeVersion], runtime: str, version: str, path: str) -> None:
    version = version.strip().strip("'\"")[:40]
    if version and not any(
        v.runtime == runtime and v.version == version and v.path == path for v in out
    ):
        out.append(RuntimeVersion(runtime=runtime, version=version, path=path))


def runtime_versions(
    files: RepoFiles, workflow_texts: dict[str, str], manifest_runtimes: dict[str, str]
) -> list[RuntimeVersion]:
    """Concrete runtime versions the repo runs on (ranges like ">=3.8" are ignored)."""
    out: list[RuntimeVersion] = []
    for name, runtime in _VERSION_FILES.items():
        first = (files.read(name) or "").strip().splitlines()
        if first:
            _add(out, runtime, first[0], name)
    for line in (files.read(".tool-versions") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in _TOOL_VERSIONS:
            _add(out, _TOOL_VERSIONS[parts[0]], parts[1], ".tool-versions")
    runtime_txt = (files.read("runtime.txt") or "").strip()
    if m := re.match(r"python-(\d+\.\d+)", runtime_txt):
        _add(out, "python", m.group(1), "runtime.txt")
    try:
        sdk = json.loads(files.read("global.json") or "{}").get("sdk", {}).get("version")
        if isinstance(sdk, str):
            _add(out, "dotnet", sdk, "global.json")
    except (ValueError, AttributeError):
        pass
    for entry in _product(files.glob("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile")):
        for image, _alias in _FROM.findall(files.read(entry.path) or ""):
            hit = _image_runtime(image)
            if hit:
                _add(out, hit[0], hit[1], entry.path)
    for path, text in workflow_texts.items():
        for runtime, version in _WORKFLOW_VERSION.findall(text):
            # a CI matrix may test versions the project no longer supports (engines >=22
            # while the matrix still has 20): only versions inside the declared range count
            spec = manifest_runtimes.get(runtime)
            if spec and not _exactish(spec) and _satisfies(version, spec) is False:
                continue
            _add(out, runtime, version, path)
    # go.mod's `go` line and ranges like engines/requires-python state compatibility,
    # not what the service runs on, so only pins that choose a runtime count
    manifest_files = {
        "ruby": "Gemfile",
        "java": "pom.xml",
        "dotnet": "**/*.csproj",
        "php": "composer.json",
        "node": "package.json",
    }
    for runtime, pattern in manifest_files.items():
        spec = manifest_runtimes.get(runtime)
        if spec and _exactish(spec):
            found = files.first(pattern)
            _add(out, runtime, spec, found.path if found else pattern)
    return out[:50]


def _vtuple(text: str) -> tuple[int, ...] | None:
    m = re.match(r"v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", text.strip())
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None and g.isdigit())


def _satisfies(version: str, spec: str) -> bool | None:
    """Whether ``version`` falls inside a range such as ">=22.22.0", ">=3.10,<4",
    "^20 || ^22" or "~3.11". A partial version ("22") stands for its whole line. None when
    the range cannot be read (then nothing is dropped)."""
    v = _vtuple(version)
    if v is None:
        return None
    alternatives = []
    for alt in spec.split("||"):
        ok: bool | None = True
        for part in re.split(r"[,\s]+(?=[<>=!^~])|,", alt.strip()):
            part = part.strip()
            if not part or part in ("*", "x"):
                continue
            m = re.match(r"(>=|<=|>|<|==|=|!=|\^|~=|~)?\s*(.+)", part)
            want = _vtuple(m.group(2)) if m else None
            if not m or want is None:
                return None
            op, n = m.group(1) or "=", len(want)
            head = v[:n] + (0,) * (n - len(v[:n]))
            if op == ">=":
                ok = ok and v >= want[: len(v)]
            elif op == ">":
                ok = ok and head > want
            elif op == "<=":
                ok = ok and head <= want
            elif op == "<":
                ok = ok and v + (0,) * 3 < want + (0,) * 3
            elif op == "!=":
                ok = ok and head != want
            elif op == "^":
                ok = ok and v[:1] == want[:1] and v >= want[: len(v)]
            elif op in ("~", "~="):
                keep = max(1, n - 1) if op == "~=" else min(2, n)
                ok = ok and head[:keep] == want[:keep] and v >= want[: len(v)]
            else:
                ok = ok and head == want
        alternatives.append(bool(ok))
    return any(alternatives) if alternatives else None


def _exactish(spec: str) -> bool:
    """ "1.21", "^7.4", "~2.7", "18.x", "net6.0" pin a line; ">=3.8" or "*" do not."""
    return not re.search(r"[<>*|,]", spec) and bool(re.search(r"\d", spec))


def _image_runtime(image: str) -> tuple[str, str] | None:
    if "$" in image or ":" not in image.rsplit("/", 1)[-1]:
        return None
    name, _, tag = image.rpartition(":")
    tag = tag.split("@")[0]
    repo = name.lower()
    base = repo.rsplit("/", 1)[-1]
    if repo.startswith("mcr.microsoft.com/dotnet/"):
        return ("dotnet", tag) if re.match(r"\d+\.\d+", tag) else None
    if base in ("maven", "gradle"):
        m = re.search(r"(?:jdk|openjdk|temurin|corretto)-?(\d+)", tag)
        return ("java", m.group(1)) if m else None
    runtime = _IMAGES.get(base)
    if runtime and re.match(r"\d", tag):
        return runtime, tag
    return None


def _product(entries: list[FileEntry]) -> list[FileEntry]:
    return [e for e in entries if not NON_PRODUCT_DIR.search(e.path)]


def release_cycle(runtime: str, version: str) -> str | None:
    """Normalise a version as written to an endoflife.date release cycle key."""
    v = version.strip().lower()
    if runtime == "dotnet":
        m = re.match(r"(?:net(?:coreapp)?)?(\d+)\.(\d+)", v)
        if not m or (v.startswith("net") and not v.startswith("netcoreapp") and "." not in v):
            return None
        return f"{m.group(1)}.{m.group(2)}"
    v = re.sub(r"^[a-z_-]*?(?=\d)", "", v)  # v18, temurin-17, python-3.8
    v = v.lstrip("^~=")
    m = re.match(r"(\d+)(?:\.(\d+))?", v)
    if not m:
        return None
    major, minor = m.group(1), m.group(2)
    if runtime == "java":
        return minor if major == "1" and minor else major  # 1.8 -> 8
    if runtime == "node":
        return major
    return f"{major}.{minor}" if minor is not None else None


# ------------------------------------------------------------------------- Dockerfiles


def _docker_flags(files: RepoFiles) -> list[Flag]:
    flags: list[Flag] = []
    for entry in _product(files.glob("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile"))[:30]:
        text = files.read(entry.path) or ""
        stages: set[str] = set()
        last_image = ""
        for m in _FROM.finditer(text):
            image, alias = m.group(1), m.group(2)
            last_image = image
            if alias:
                stages.add(alias.lower())
            if image.lower() in stages or image == "scratch" or "$" in image:
                continue
            last = image.rsplit("/", 1)[-1]
            if "@" not in image and (":" not in last or last.endswith(":latest")):
                flags.append(
                    Flag(
                        id="docker-unpinned-base",
                        category="security",
                        severity="medium",
                        message=f"Base image {image} is not pinned to a version tag or digest",
                        path=entry.path,
                        line=text.count("\n", 0, m.start()) + 1,
                    )
                )
        if not last_image or last_image == "scratch" or "nonroot" in last_image:
            continue
        final = text[text.rfind(last_image) :]
        users = re.findall(r"^[ \t]*USER\s+(\S+)", final, re.I | re.M)
        if not users or users[-1].split(":")[0] in ("root", "0"):
            flags.append(
                Flag(
                    id="docker-runs-as-root",
                    category="security",
                    severity="low",
                    message="Final image runs as root (no USER instruction)",
                    path=entry.path,
                )
            )
    return flags


# -------------------------------------------------------------------- GitHub workflows

_UNTRUSTED = re.compile(
    r"\$\{\{[^}]{0,300}?\b(github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\."
    r"(?:ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|"
    r"discussion\.(?:title|body)|pages\.[^}]{0,200}?page_name|commits\.[^}]{0,200}?(?:message|author\."
    r"(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|workflow_run\."
    r"(?:head_branch|head_commit\.message|display_title))|github\.head_ref)\b"
)
# refs that resolve to code from the pull request (or the run that built it)
_HEAD_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.(?:head\.(?:sha|ref)|merge_commit_sha)|github\.head_ref|"
    r"refs/pull/|github\.event\.(?:pull_request\.)?number|github\.event\.workflow_run\."
    r"(?:head_sha|head_branch|pull_requests)|github\.event\.issue\.number"
)
_ENV_REF = re.compile(r"\$\{\{\s*env\.(\w+)\s*\}\}")
# shell commands that fetch the PR's code into the workspace
_PR_FETCH = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bgit\s+(?:checkout|switch|merge|pull|reset\s+--hard)\b[^\n]*"
    r"(?:pull/|FETCH_HEAD|pull_request\.head|head_ref|pr-head)"
)
_PRIVILEGED_EVENTS = {"pull_request_target", "workflow_run"}


def _expand_env(value: str, env: dict[Any, Any]) -> str:
    return _ENV_REF.sub(lambda m: str(env.get(m.group(1), "")), value)


def _read_only(perms: Any) -> bool:
    if perms in ("read-all", {}) or perms == "{}":
        return True
    return isinstance(perms, dict) and all(v in ("read", "none") for v in perms.values())


def _uses_secrets(job: dict[str, Any]) -> bool:
    """Secrets other than a (read-only) GITHUB_TOKEN reach the job."""
    text = json.dumps(job, default=str)
    return bool(re.search(r"secrets\.(?!GITHUB_TOKEN\b)\w+|secrets\[", text))


def _executes_from(path: str, steps: list[dict[str, Any]]) -> bool:
    """Whether later steps run code from a checkout placed at ``path`` (not only read it)."""
    p = re.escape(path.strip("./") or ".")
    in_dir = re.compile(
        rf"(?:^|[\s;&|(])(?:cd|pushd)\s+['\"]?(?:\$\{{?GITHUB_WORKSPACE\}}?/)?{p}\b|"
        rf"(?:^|[;&|(]|\bthen|\bdo)\s*\.?/?{p}/\S+|"  # pr/build.sh in command position
        rf"\b(?:bash|sh|node|python3?|ruby|perl|npx|tsx|deno|bun|source)\s+['\"]?"
        rf"(?:\$\{{?GITHUB_WORKSPACE\}}?/)?\.?/?{p}/\S+|"
        rf"(?:-C|--prefix|--dir|--cwd|--project|--manifest-path)[\s=]+['\"]?{p}\b",
        re.M,
    )
    for step in steps:
        wd = str(step.get("working-directory") or "")
        if wd.strip("./").startswith(path.strip("./")) and step.get("run"):
            return True
        uses = str(step.get("uses") or "")
        if uses.startswith(("./" + path.strip("./") + "/", path.strip("./") + "/")):
            return True
        run = step.get("run")
        if isinstance(run, str):
            # arguments like `--root pr` or `git -C pr diff` only read the tree
            cleaned = re.sub(r"\bgit\s+-C\s+\S+", "git", run)
            if in_dir.search(cleaned):
                return True
    return False


def _pwn_request_flags(path: str, text: str, data: dict[str, Any], events: set[Any]) -> list[Flag]:
    """Privileged triggers (pull_request_target, workflow_run) that check out and run the
    PR's code. A read-only job without secrets that only reads the PR from a separate
    folder is the documented safe pattern and is not flagged."""
    if not events & _PRIVILEGED_EVENTS:
        return []
    flags: list[Flag] = []
    wf_env = _d(data.get("env"))
    for job in _d(data.get("jobs")).values():
        job = _d(job)
        env = {**wf_env, **_d(job.get("env"))}
        steps = [s for s in _l(job.get("steps")) if isinstance(s, dict)]
        perms = job.get("permissions", data.get("permissions"))
        safe_token = perms is not None and _read_only(perms)
        secrets = _uses_secrets(job)
        for i, step in enumerate(steps):
            with_ = _d(step.get("with"))
            uses = str(step.get("uses") or "")
            ref = str(with_.get("ref") or "")
            # follow ${{ env.X }} one level: env: HEAD: ${{ github.event.pull_request.head.sha }}
            step_env = {**env, **_d(step.get("env"))}
            ref = _expand_env(ref, step_env)
            repo_ref = str(with_.get("repository") or "")
            run = step.get("run") if isinstance(step.get("run"), str) else ""
            if uses.startswith("actions/checkout") and (
                _HEAD_CHECKOUT.search(ref) or "pull_request.head.repo" in repo_ref
            ):
                where = str(with_.get("path") or "")
                needle = with_.get("ref") or "pull_request.head"
            elif run and (fetch := _PR_FETCH.search(str(run))):
                where, needle = "", fetch.group(0)
            else:
                continue
            later = steps[i + 1 :] if uses else steps[i:]
            separate = bool(where.strip("./"))
            if separate and not _executes_from(where, later):
                if safe_token and not secrets:
                    continue  # PR files are only read, with nothing worth stealing
                severity = "low"
                why = "checks out untrusted PR code into a separate folder while secrets are available"
            else:
                severity = (
                    "medium" if (job.get("environment") or (safe_token and not secrets)) else "high"
                )
                why = "runs untrusted PR code while secrets or a write token are available"
                if job.get("environment"):
                    why += " (behind an environment approval)"
                elif safe_token and not secrets:
                    why = "runs untrusted PR code with a read-only token (cache poisoning risk)"
            trigger = "pull_request_target" if "pull_request_target" in events else "workflow_run"
            flags.append(
                Flag(
                    id="workflow-pwn-request",
                    category="security",
                    severity=severity,  # type: ignore[arg-type]
                    message=f"{trigger} {why}",
                    path=path,
                    line=_line_of_ref(text, str(needle)),
                )
            )
    return flags


def _line_of_ref(text: str, needle: str) -> int | None:
    """Line of ``needle``, preferring an occurrence on a ``ref:``/``run:`` line."""
    first = None
    for m in re.finditer(re.escape(needle), text):
        start = text.rfind("\n", 0, m.start()) + 1
        line = text[start : m.start()]
        if first is None:
            first = m.start()
        if re.search(r"\b(ref|run):|^\s*[^:#]*$", line):
            return text.count("\n", 0, m.start()) + 1
    return text.count("\n", 0, first) + 1 if first is not None else None


def _steps(data: dict[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for job in _d(data.get("jobs")).values():
        for step in _l(_d(job).get("steps")):
            if isinstance(step, dict):
                yield _d(job), step


def _workflow_flags(workflow_texts: dict[str, str], errors: list[str]) -> list[Flag]:
    flags: list[Flag] = []
    for path, text in workflow_texts.items():
        try:
            data = load_yaml(text)
        except Exception as exc:
            errors.append(f"{path}: {type(exc).__name__}: {str(exc)[:200]}")
            continue
        if not isinstance(data, dict):
            continue
        on = data.get("on", data.get(True))  # YAML 1.1 reads a bare `on` key as True
        events = set(on) if isinstance(on, dict | list) else {on} if isinstance(on, str) else set()
        for _job, step in _steps(data):
            with_ = _d(step.get("with"))
            scripts = [step.get("run"), with_.get("script")]
            for script in scripts:
                if isinstance(script, str) and (m := _UNTRUSTED.search(script)):
                    flags.append(
                        Flag(
                            id="workflow-script-injection",
                            category="security",
                            severity="high",
                            message=f"Untrusted `{m.group(1)}` interpolated into a script; "
                            "pass it through env instead",
                            path=path,
                            line=_line_of(text, m.group(0)),
                        )
                    )
        flags += _pwn_request_flags(path, text, data, events)
    return _dedupe(flags)


def _d(value: Any) -> dict[Any, Any]:
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _line_of(text: str, needle: str) -> int | None:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else None


# --------------------------------------------------------------- AI agent permissions


def _ai_settings_flags(files: RepoFiles) -> list[Flag]:
    flags: list[Flag] = []

    def flag(fid: str, sev: str, msg: str, path: str) -> None:
        flags.append(Flag(id=fid, category="ai-governance", severity=sev, message=msg, path=path))  # type: ignore[arg-type]

    for entry in files.glob("**/.claude/settings.json", "**/.claude/settings.local.json"):
        try:
            data = json.loads(files.read(entry.path) or "{}")
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        if entry.name == "settings.local.json":
            flag(
                "ai-personal-settings-committed",
                "low",
                "Personal Claude Code settings committed (usually gitignored)",
                entry.path,
            )
        perms = _d(data.get("permissions"))
        if perms.get("defaultMode") == "bypassPermissions":
            flag(
                "ai-permissions-bypassed",
                "high",
                "Claude Code permission prompts disabled for everyone (bypassPermissions)",
                entry.path,
            )
        allow = _l(perms.get("allow"))
        if any(a in ("Bash", "Bash(*)", "Bash(:*)") for a in allow):
            flag(
                "ai-unrestricted-shell",
                "medium",
                "Claude Code may run any shell command without asking",
                entry.path,
            )
        if data.get("enableAllProjectMcpServers") is True:
            flag(
                "ai-mcp-auto-enabled",
                "low",
                "Every MCP server in .mcp.json is enabled without review",
                entry.path,
            )
    for entry in files.glob("**/.vscode/settings.json"):
        text = files.read(entry.path) or ""
        if re.search(r'"chat\.tools\.(?:global\.)?autoApprove"\s*:\s*true', text):
            flag(
                "ai-permissions-bypassed",
                "high",
                "Copilot agent tools auto-approved for everyone (chat.tools.autoApprove)",
                entry.path,
            )
    for entry in files.glob("**/.codex/config.toml"):
        try:
            data = tomllib.loads(files.read(entry.path) or "")
        except tomllib.TOMLDecodeError:
            continue
        if data.get("approval_policy") == "never" and data.get("sandbox_mode") == (
            "danger-full-access"
        ):
            flag(
                "ai-permissions-bypassed",
                "high",
                "Codex runs without approvals or sandbox",
                entry.path,
            )
    for entry in files.glob("**/.gemini/settings.json"):
        text = files.read(entry.path) or ""
        if re.search(r'"(?:autoAccept|yolo)"\s*:\s*true|"approvalMode"\s*:\s*"yolo"', text):
            flag(
                "ai-permissions-bypassed", "high", "Gemini CLI auto-approves tool calls", entry.path
            )
    return flags


# ------------------------------------------------------------------------- ownership

_BOT = re.compile(
    r"(?i)\[bot\]|dependabot|renovate|github[- ]actions|\bbot\b|actions-user|-bot$|"
    r"^(?:semantic-release|greenkeeper|snyk|web-flow|copilot|pre-commit-ci|mergify)\b"
)


def _ownership_flags(ownership: Ownership, declared: Declared, archived: bool) -> list[Flag]:
    flags: list[Flag] = []
    if archived:
        return flags
    if not ownership.codeowners and not declared.owner:
        flags.append(
            Flag(
                id="no-owner",
                category="ownership",
                severity="low",
                message="No CODEOWNERS or declared owner",
            )
        )
    humans = [c for c in ownership.top_contributors if not _BOT.search(c.name)]
    bots = sum(c.commits for c in ownership.top_contributors if _BOT.search(c.name))
    # share of ALL human commits, not of the top-10 list (that overstates a lead author)
    total = max(ownership.commit_count - bots, sum(c.commits for c in humans))
    if humans and total >= 30 and humans[0].commits / total >= 0.9:
        share = round(100 * humans[0].commits / total)
        flags.append(
            Flag(
                id="single-maintainer",
                category="ownership",
                severity="medium",
                message=f"Bus factor 1: {share}% of commits come from one person",
            )
        )
    return flags


def _dedupe(flags: list[Flag]) -> list[Flag]:
    seen: set[tuple[str, str | None, int | None]] = set()
    out = []
    for f in flags:
        key = (f.id, f.path, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def repo_flags(
    files: RepoFiles,
    workflow_texts: dict[str, str],
    ownership: Ownership,
    declared: Declared,
    archived: bool,
    errors: list[str],
) -> list[Flag]:
    flags: list[Flag] = []
    steps = (
        lambda: _secret_flags(files),
        lambda: _docker_flags(files),
        lambda: _workflow_flags(workflow_texts, errors),
        lambda: _ai_settings_flags(files),
        lambda: _ownership_flags(ownership, declared, archived),
    )
    for step in steps:
        try:
            flags += step()
        except Exception as exc:  # a detector bug must never lose the rest of the scan
            errors.append(f"flags: {type(exc).__name__}: {str(exc)[:200]}")
    return flags
