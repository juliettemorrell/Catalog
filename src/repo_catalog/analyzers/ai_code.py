"""Detect AI usage inside source code: provider SDK call sites, model identifiers,
embedded prompts, agents defined in code and MCP server implementations."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ..fs import FileEntry, RepoFiles
from . import ai_python
from .ai_common import AssetDraft

CODE_EXT = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".mts",
    ".go",
    ".java",
    ".kt",
    ".cs",
    ".rb",
    ".php",
    ".rs",
    ".ipynb",
}
CONFIG_EXT = {".yaml", ".yml", ".json", ".toml", ".env.example", ".properties", ".tf"}
MAX_FILE = 400_000
MAX_FILES = 6_000


def _py(module: str) -> str:
    """Python ``import x`` / ``from x import`` for a dotted module (regex-escaped here)."""
    return rf"^\s*(?:from|import)\s+{re.escape(module)}\b"


def _js(package: str) -> str:
    """JS/TS ``from 'pkg'`` / ``require('pkg')`` / ``import('pkg')``; ``package`` is a regex."""
    return rf"(?:\bfrom|\brequire\(|\bimport\(?)\s*['\"`]{package}['\"`]"


def _go(path: str) -> str:
    return rf"^\s*(?:import\s+)?(?:\w+\s+)?\"{re.escape(path)}"


def _any(*patterns: str) -> str:
    return "|".join(f"(?:{p})" for p in patterns)


# provider -> (display name, import regex, call-site regex). Import patterns require real
# import syntax so that documentation, rule tables and string literals are not counted.
SDKS: dict[str, tuple[str, str, str]] = {
    "anthropic": (
        "Anthropic SDK",
        _any(
            _py("anthropic"),
            _js("@anthropic-ai/sdk(?:/[\\w/-]*)?"),
            _go("github.com/anthropics/anthropic-sdk-go"),
            r"^\s*import\s+com\.anthropic\.",
        ),
        r"messages\.(?:create|stream|parse|batches)|Messages\.New|beta\.messages",
    ),
    "claude-agent-sdk": (
        "Claude Agent SDK",
        _any(
            _py("claude_agent_sdk"),
            _py("claude_code_sdk"),
            _js("@anthropic-ai/claude-(?:agent-sdk|code)"),
        ),
        r"\bquery\(|ClaudeSDKClient|ClaudeAgentOptions|AgentDefinition",
    ),
    "openai": (
        "OpenAI SDK",
        _any(
            _py("openai"),
            _js("openai(?:/[\\w/-]*)?"),
            _go("github.com/openai/openai-go"),
            _go("github.com/sashabaranov/go-openai"),
            r"^\s*import\s+com\.openai\.",
        ),
        r"chat\.completions\.create|responses\.create|embeddings\.create|"
        r"images\.generate|audio\.\w+\.create|\.beta\.\w+",
    ),
    "openai-agents": (
        "OpenAI Agents SDK",
        _any(r"^\s*from\s+agents\s+import\s+.*\b(?:Agent|Runner)\b", _js("@openai/agents")),
        r"\bRunner\.run|\brun\(|\bAgent\(",
    ),
    "google-genai": (
        "Google Gen AI",
        _any(
            r"^\s*from\s+google\s+import\s+genai",
            _py("google.generativeai"),
            _js("@google/genai"),
            _js("@google/generative-ai"),
        ),
        r"generate_content|generateContent|models\.generate",
    ),
    "vertex-ai": (
        "Vertex AI",
        _any(_py("vertexai"), _py("google.cloud.aiplatform"), _js("@google-cloud/vertexai")),
        r"GenerativeModel|generate_content",
    ),
    "google-adk": ("Google ADK", _py("google.adk"), r"LlmAgent|Agent\("),
    "bedrock": (
        "Amazon Bedrock",
        _any(
            r"""\.client\(\s*['"]bedrock(?:-agent)?-runtime['"]""",
            _js("@aws-sdk/client-bedrock(?:-agent)?-runtime"),
            r"\bnew\s+BedrockRuntimeClient\(",
        ),
        r"invoke_model|converse|InvokeModel|Converse",
    ),
    "azure-openai": (
        "Azure OpenAI",
        _any(r"\bAzureOpenAI\s*\(", _js("@azure/openai"), r"^\s*using\s+Azure\.AI\.OpenAI"),
        r"chat\.completions\.create|GetChatCompletions",
    ),
    "langchain": (
        "LangChain",
        _any(
            r"^\s*(?:from|import)\s+langchain",
            _js("(?:langchain|@langchain/(?!langgraph))[\\w/-]*"),
        ),
        r"\.invoke\(|\.stream\(|ChatPromptTemplate|create_\w+_agent",
    ),
    "langgraph": (
        "LangGraph",
        _any(_py("langgraph"), _js("@langchain/langgraph[\\w/-]*")),
        r"StateGraph|add_node|create_react_agent",
    ),
    "llamaindex": (
        "LlamaIndex",
        _any(_py("llama_index"), _js("llamaindex[\\w/-]*")),
        r"VectorStoreIndex|as_query_engine|as_chat_engine|FunctionAgent|ReActAgent",
    ),
    "crewai": ("CrewAI", _py("crewai"), r"\bCrew\(|\bAgent\(|\bTask\("),
    "autogen": ("AutoGen", r"^\s*(?:from|import)\s+autogen", r"AssistantAgent|UserProxyAgent"),
    "pydantic-ai": ("PydanticAI", _py("pydantic_ai"), r"\bAgent\("),
    "smolagents": ("smolagents", _py("smolagents"), r"CodeAgent|ToolCallingAgent"),
    "semantic-kernel": (
        "Semantic Kernel",
        _any(_py("semantic_kernel"), r"^\s*using\s+Microsoft\.SemanticKernel"),
        r"Kernel|ChatCompletionAgent",
    ),
    "vercel-ai": (
        "Vercel AI SDK",
        _any(_js("ai"), _js("@ai-sdk/[\\w-]+")),
        r"generateText|streamText|generateObject|streamObject|useChat",
    ),
    "mastra": ("Mastra", _js("@mastra/[\\w/-]+"), r"new Agent\(|createWorkflow|createTool"),
    "litellm": ("LiteLLM", _py("litellm"), r"completion\(|acompletion\("),
    "mistral": ("Mistral", _any(_py("mistralai"), _js("@mistralai/mistralai")), r"chat\.complete"),
    "cohere": ("Cohere", _any(_py("cohere"), _js("cohere-ai")), r"\.chat\(|embed"),
    "groq": ("Groq", _any(_py("groq"), _js("groq-sdk")), r"chat\.completions"),
    "ollama": ("Ollama", _any(_py("ollama"), _js("ollama(?:/browser)?")), r"\.chat\(|generate"),
    "dspy": ("DSPy", _py("dspy"), r"dspy\.\w+"),
    "instructor": ("Instructor", _py("instructor"), r"from_\w+|patch\("),
    "huggingface": (
        "Hugging Face",
        _any(r"^\s*from\s+transformers\s+import", _js("@huggingface/[\\w-]+")),
        r"pipeline\(|from_pretrained",
    ),
    "anthropic-http": (
        "Anthropic API (raw HTTP)",
        r"['\"`]https://api\.anthropic\.com",
        r"api\.anthropic\.com|/v1/messages",
    ),
    "openai-http": (
        "OpenAI API (raw HTTP)",
        r"['\"`]https://api\.openai\.com",
        r"api\.openai\.com|/v1/(?:chat/completions|responses)",
    ),
    "snowflake-cortex": (
        "Snowflake Cortex",
        _any(_py("snowflake.cortex"), r"(?i:\bcortex\.complete\s*\()", r"(?i:\bAI_COMPLETE\s*\()"),
        r"(?i)cortex\.complete|\bcomplete\(|AI_COMPLETE",
    ),
    "databricks": (
        "Databricks Model Serving",
        _any(
            _py("databricks.sdk"),
            _py("mlflow.deployments"),
            r"/serving-endpoints/[\w-]+/invocations",
        ),
        r"serving_endpoints\.query|predict\(|/invocations",
    ),
    "mcp-client": (
        "MCP client",
        _any(
            r"^\s*from\s+mcp\s+import\s+.*\bClientSession\b",
            _js("@modelcontextprotocol/sdk/client[\\w/.-]*"),
        ),
        r"call_tool|callTool|list_tools|listTools",
    ),
}

# One pass per file instead of one per SDK: named groups tell which SDKs matched.
_SDK_GROUP = {key: "g_" + re.sub(r"\W", "_", key) for key in SDKS}
SDK_IMPORT_RX = re.compile(
    "|".join(f"(?P<{_SDK_GROUP[k]}>{imp})" for k, (_, imp, _) in SDKS.items()), re.M
)
_SDK_BY_GROUP = {g: k for k, g in _SDK_GROUP.items()}


# Every alternative in SDKS import patterns contains one of these (lowercase); a unit test
# enforces it so a new pattern cannot be silently filtered out.
IMPORT_HINTS = (
    "import",
    "from",
    "require",
    "using",
    "://",
    "bedrock",
    "azureopenai",
    "cortex.complete",
    "ai_complete",
    "serving-endpoints",
)


def _import_lines(text: str, suffix: str) -> str:
    """Only lines that can match an SDK import pattern: running the big alternation over
    whole files dominated scan time. Go import blocks list bare quoted paths."""
    quoted = suffix == ".go"
    keep = []
    for line in text.split("\n"):
        low = line.lower()
        if any(h in low for h in IMPORT_HINTS) or (quoted and '"' in line):
            keep.append(line)
    return "\n".join(keep)


# Model identifiers. Kept deliberately specific to avoid false positives.
MODEL_PATTERNS = [
    r"(?:(?:us|eu|apac|global)\.)?(?:anthropic\.)?claude-(?:opus|sonnet|haiku|fable|mythos|instant|"
    r"[0-9])[a-z0-9.\-]*(?:@\d{8}|-v\d:\d)?",
    r"gpt-(?:3\.5|4|4o|4\.1|4\.5|5|oss)[a-z0-9.\-]*",
    r"(?<=['\"])o[1-9](?:-mini|-pro|-preview|-deep-research)?(?=['\"])",
    r"text-embedding-(?:3-small|3-large|ada-002)",
    r"whisper-1",
    r"dall-e-[23]",
    r"gpt-image-1",
    r"gemini-(?:[0-9][a-z0-9.\-]*|pro|ultra|flash)[a-z0-9.\-]*",
    r"text-bison|chat-bison",
    r"(?:meta-)?llama-?[0-9][a-z0-9.\-]*",
    r"(?:mistral|mixtral|codestral|ministral|pixtral|magistral|devstral)-(?:(?:large|medium|small|"
    r"tiny|nemo|embed|saba|ocr|latest)(?:-[a-z0-9.]+)*|[0-9][a-z0-9.\-]*)",
    r"command-(?:r(?:-plus)?|a)(?:-\d{2}-\d{4}|-[0-9]{2,})?(?![a-z])",
    r"deepseek-[a-z0-9.\-]+",
    r"qwen[0-9.]*-[a-z0-9.\-]+",
]
MODEL_RX = re.compile(r"\b(" + "|".join(MODEL_PATTERNS) + r")\b", re.I)

_MCP_SERVER_IMPORT = re.compile(
    r"from\s+mcp\.server|from\s+fastmcp|import\s+fastmcp|@modelcontextprotocol/sdk/server|"
    r"mark3labs/mcp-go/server|modelcontextprotocol/go-sdk/mcp|ModelContextProtocol\.Server|"
    r"io\.modelcontextprotocol\.server|rmcp::|from\s+['\"]fastmcp['\"]"
)
_MCP_SERVER_NAME = [
    re.compile(r"\b(?:FastMCP|MCPServer)\(\s*(?:name\s*=\s*)?['\"]([^'\"]+)['\"]"),
    re.compile(r"new\s+(?:Mcp|Fast)?(?:Server|MCP)\(\s*\{\s*name:\s*['\"`]([^'\"`]+)['\"`]"),
    re.compile(r"NewMCPServer\(\s*\"([^\"]+)\""),
    re.compile(r"mcp\.Implementation\{\s*Name:\s*\"([^\"]+)\""),
    re.compile(r"(?i)server_?info['\"]?\s*[=:]\s*\{[^}]*?['\"]name['\"]\s*:\s*['\"]([^'\"]+)"),
]
_MCP_SERVER_CTOR = re.compile(
    r"\b(FastMCP|MCPServer)\(|new\s+McpServer\(|new\s+Server\(\s*\{|NewMCPServer\(|mcp\.NewServer\(|"
    r"AddMcpServer\(|McpServer\.(?:sync|async)\(|new\s+FastMCP\("
)
_HANDWRITTEN_MCP = re.compile(
    r"(?:==|===|\bcase)\s*['\"]tools/call['\"]|['\"]tools/call['\"]\s*[:)]\s*(?!\s*['\"])"
)
# a server must publish tool schemas; clients and method tables only name the methods
_SERVES_SCHEMAS = re.compile(r"['\"](?:inputSchema|input_schema)['\"]")
_JSON_TOOL = re.compile(
    r"['\"]name['\"]\s*:\s*['\"]([\w\-.]+)['\"]\s*,\s*['\"]description['\"]\s*:\s*"
    r"['\"]([^'\"]{0,300})['\"](?=[^{}]{0,200}['\"]inputSchema['\"])"
)


def _handwritten_mcp(code: str) -> bool:
    return (
        "tools/list" in code
        and _HANDWRITTEN_MCP.search(code) is not None
        and _SERVES_SCHEMAS.search(code) is not None
    )


_PY_RESOURCE = re.compile(r"@\w+\.(resource|prompt)\s*\(")

_PROMPT_VAR = re.compile(r"(prompt|instruction|system|persona|template|guideline|preamble)", re.I)
_PY_ASSIGN = re.compile(
    r"^[ \t]*(?P<name>[A-Za-z_]\w*)\s*(?::\s*[\w\[\], |]+)?=\s*(?:[rRfFbBuU]{0,2})"
    r"(?P<q>\"\"\"|''')(?P<body>.*?)(?P=q)",
    re.S | re.M,
)
_PY_KWARG = re.compile(
    r"\b(?P<name>system|system_prompt|instructions|system_message|prompt|backstory|role|goal)"
    r"\s*=\s*(?:[rRfF]{0,2})(?P<q>\"\"\"|''')(?P<body>.*?)(?P=q)",
    re.S,
)
_JS_ASSIGN = re.compile(
    r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]| ]+)?=\s*"
    r"(?:\w+)?`(?P<body>(?:[^`\\]|\\.)*)`",
    re.S,
)
_JS_PROP = re.compile(
    r"\b(?P<name>system|systemPrompt|instructions|prompt)\s*:\s*`(?P<body>(?:[^`\\]|\\.)*)`", re.S
)
_MIN_PROMPT = 180

_AGENT_CTORS = re.compile(
    r"\b(?P<ctor>Agent|LlmAgent|AssistantAgent|CodeAgent|ToolCallingAgent|ChatCompletionAgent|"
    r"AgentDefinition|ClaudeAgentOptions|create_react_agent|createReactAgent|FunctionAgent|"
    r"ReActAgent)\s*\((?P<brace>\s*\{)?"
)


@dataclass
class CodeFindings:
    drafts: list[AssetDraft] = field(default_factory=list)
    sdks: set[str] = field(default_factory=set)
    models: dict[str, int] = field(default_factory=dict)
    mcp_provided: set[str] = field(default_factory=set)


def scan_code(files: RepoFiles, claimed: set[str]) -> CodeFindings:
    out = CodeFindings()
    candidates = [
        f
        for f in files.files
        if (f.suffix in CODE_EXT or f.suffix in CONFIG_EXT or f.name.startswith(".env."))
        and f.size <= MAX_FILE
        and not _is_test_fixture(f.path)
    ][:MAX_FILES]
    sdk_hits: dict[str, list[tuple[str, list[int]]]] = defaultdict(list)
    sdk_snippets: dict[str, list[str]] = defaultdict(list)
    sdk_models: dict[str, set[str]] = defaultdict(set)
    mcp_tools: list[tuple[str, str, str | None]] = []  # (path, tool, description)
    mcp_servers: list[AssetDraft] = []

    for entry, text in files.iter_text(candidates, MAX_FILE):
        is_code = entry.suffix in CODE_EXT
        file_models = _models(text)
        for m in file_models:
            out.models[m] = out.models.get(m, 0) + 1
        if not is_code:
            continue
        matched = {
            _SDK_BY_GROUP[g]
            for mt in SDK_IMPORT_RX.finditer(_import_lines(text, entry.suffix))
            for g, v in mt.groupdict().items()
            if v is not None
        }
        for key in sorted(matched):
            label, _, call = SDKS[key]
            call_rx = re.compile(call)
            lines = [i + 1 for i, ln in enumerate(text.splitlines()) if call_rx.search(ln)]
            sdk_hits[key].append((entry.path, lines[:20]))
            sdk_models[key].update(file_models)
            out.sdks.add(label)
            if len(sdk_snippets[key]) < 6 and lines:
                sdk_snippets[key].append(_snippet(entry.path, text, lines[0]))

        tree = ai_python.parse(text) if entry.suffix == ".py" else None
        if tree is not None:
            py = ai_python.analyze(tree, text, entry.path, want_prompts=entry.path not in claimed)
            out.drafts.extend(py.prompts + py.agents)
            mcp_servers.extend(py.servers)
            mcp_tools += [(entry.path, t, d) for t, d in py.tools]
            if not py.servers and _handwritten_mcp(text):
                server = _mcp_server(entry, text, detector="mcp-server-jsonrpc")
                server.confidence = "medium"
                mcp_servers.append(server)
                mcp_tools += [(entry.path, t, d) for t, d in _JSON_TOOL.findall(text)]
            continue
        if entry.suffix == ".ipynb":
            continue  # notebooks: SDK usage and models only
        code = strip_comments(text, entry.suffix)
        if entry.path not in claimed:
            out.drafts.extend(_inline_prompts(entry, code))
        out.drafts.extend(_code_agents(entry, code))
        if _MCP_SERVER_IMPORT.search(code):
            mcp_tools += [(entry.path, t, d) for t, d in _mcp_tools(entry, code)]
            if _MCP_SERVER_CTOR.search(code):
                mcp_servers.append(_mcp_server(entry, code))
        elif _handwritten_mcp(code):
            # MCP spoken directly over JSON-RPC (no SDK): common in quick internal servers
            server = _mcp_server(entry, code, detector="mcp-server-jsonrpc")
            server.confidence = "medium"
            mcp_servers.append(server)
            mcp_tools += [(entry.path, t, d) for t, d in _JSON_TOOL.findall(code)]

    for key, hits in sdk_hits.items():
        label = SDKS[key][0]
        call_sites = sum(len(lines) for _, lines in hits)
        body = "\n\n".join(sdk_snippets[key])
        paths = [p for p, _ in hits]
        out.drafts.append(
            AssetDraft(
                kind="sdk-usage",
                ecosystem=key,
                name=f"{label} usage",
                path=paths[0],
                detector="sdk-import",
                text=body or "\n".join(paths),
                providers=[label],
                models=sorted(sdk_models[key]),
                confidence="high",
                description=f"{label} used in {len(paths)} file(s), ~{call_sites} call site(s).",
                frontmatter={"files": paths[:100], "call_sites": call_sites},
                tags=["sdk"],
            )
        )

    if mcp_servers:
        for path, tool, desc in mcp_tools:
            server = _closest(mcp_servers, path)
            server.tools.append(tool)
            server.frontmatter.setdefault("tool_descriptions", {})[tool] = desc
        for s in mcp_servers:
            out.mcp_provided.add(s.name)
            s.description = s.description or (
                f"MCP server exposing {len(s.tools)} tool(s): " + ", ".join(s.tools[:12])
            )
            out.drafts.append(s)
    return out


def strip_comments(text: str, suffix: str) -> str:
    """Blank out // and /* */ comments (keeping newlines so line numbers stay right),
    respecting string, template and Go raw-string literals."""
    if suffix not in {
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".go",
        ".java",
        ".kt",
        ".cs",
        ".rs",
        ".php",
    }:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    quote: str | None = None
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and not (quote == "`" and suffix == ".go"):  # Go raw strings: no escapes
                if i + 1 < n:
                    out.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            elif c == "\n" and quote in "'\"":
                quote = None  # unterminated single-line string: recover
            i += 1
            continue
        if c in "'\"`":
            quote = c
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _models(text: str) -> set[str]:
    found = set()
    for m in MODEL_RX.finditer(text):
        val = m.group(1).rstrip(".-").lower()
        if len(val) > 3 and not val.endswith(("-", "-x", "-xx")):
            found.add(val)
    return found


def _is_test_fixture(path: str) -> bool:
    """Tests and fixtures often embed fake SDK calls, servers and prompts: not assets."""
    return bool(
        re.search(
            r"(^|/)(tests?|__tests__|spec|fixtures?|__snapshots__|testdata|mocks?|e2e|"
            r"integration[-_]tests?|test[-_]utils?|testing)/|"
            r"(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec|eval)\.[cm]?[jt]sx?$|"
            r"(^|/)conftest\.py$",
            path,
            re.I,
        )
    )


def _snippet(path: str, text: str, line: int, context: int = 4) -> str:
    lines = text.splitlines()
    lo, hi = max(0, line - 1 - context), min(len(lines), line + context + 2)
    lang = PurePosixPath(path).suffix.lstrip(".")
    return f"// {path}:{line}\n```{lang}\n" + "\n".join(lines[lo:hi]) + "\n```"


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _inline_prompts(entry: FileEntry, text: str) -> list[AssetDraft]:
    drafts: list[AssetDraft] = []
    used: dict[str, int] = {}
    seen: set[int] = set()
    patterns = (
        (_PY_ASSIGN, _PY_KWARG)
        if entry.suffix == ".py"
        else (
            (_JS_ASSIGN, _JS_PROP)
            if entry.suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts"}
            else ()
        )
    )
    for rx in patterns:
        for m in rx.finditer(text):
            name, body = m.group("name"), m.group("body")
            if m.start() in seen or not _PROMPT_VAR.search(name):
                continue
            if len(body.strip()) < _MIN_PROMPT or body.count(" ") < 20:
                continue
            seen.add(m.start())
            line = _line_of(text, m.start())
            variables = sorted(set(re.findall(r"\{(\w+)\}|\$\{(\w+)\}|\{\{\s*(\w+)\s*\}\}", body)))
            label = f"{PurePosixPath(entry.path).name}:{name}"
            used[label] = used.get(label, 0) + 1
            if used[label] > 1:
                label += f" #{used[label]}"
            drafts.append(
                AssetDraft(
                    kind="prompt",
                    ecosystem="inline",
                    name=label,
                    path=entry.path,
                    line=line,
                    detector="inline-prompt",
                    text=body.strip(),
                    confidence="medium",
                    arguments=[next(v for v in t if v) for t in variables][:20],
                    description=None,
                    tags=["embedded"],
                    frontmatter={"variable": name, "line": line},
                )
            )
    return drafts


def _balanced(text: str, start: int, limit: int = 8000) -> str:
    """Return text from ``start`` (just after an opening paren) to its matching close."""
    depth, i, n = 1, start, min(len(text), start + limit)
    quote: str | None = None
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif text.startswith(quote, i):
                i += len(quote) - 1
                quote = None
        elif text.startswith(('"""', "'''"), i):
            quote = text[i : i + 3]
            i += 2
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return text[start:n]


def _kw(args: str, *names: str) -> str | None:
    for name in names:
        m = re.search(rf"\b{name}\s*[=:]\s*(?:[rfRF]?)(\"\"\"|'''|\"|'|`)(.*?)\1", args, re.S)
        if m:
            return m.group(2).strip()
    return None


def _code_agents(entry: FileEntry, text: str) -> list[AssetDraft]:
    drafts: list[AssetDraft] = []
    if not re.search(
        r"agents|adk|autogen|smolagents|pydantic_ai|crewai|semantic_kernel|"
        r"claude_agent_sdk|claude-agent-sdk|langgraph|llama_index|@mastra|"
        r"@openai/agents|SemanticKernel|prebuilt",
        text,
    ):
        return drafts
    for m in list(_AGENT_CTORS.finditer(text))[:_MAX_CALLS]:
        args = _balanced(text, m.end())
        ctor = m.group("ctor")
        name = _kw(args, "name", "role") or (
            re.match(r"\s*['\"]([^'\"]+)['\"]", args).group(1)  # type: ignore[union-attr]
            if re.match(r"\s*['\"]([^'\"]+)['\"]", args)
            else None
        )
        instructions = _kw(
            args,
            "instructions",
            "system_prompt",
            "systemPrompt",
            "system_message",
            "prompt",
            "backstory",
            "goal",
            "description",
        )
        if not (name or instructions):
            continue
        model = _kw(args, "model", "llm")
        tools_m = re.search(r"\b(?:tools|allowed_tools|allowedTools)\s*[=:]\s*\[([^\]]*)\]", args)
        tools = (
            [t.strip().strip("'\"") for t in tools_m.group(1).split(",") if t.strip()]
            if tools_m
            else []
        )
        line = _line_of(text, m.start())
        kind = (
            "workflow"
            if ctor in ("create_react_agent", "createReactAgent") and not name
            else "agent"
        )
        drafts.append(
            AssetDraft(
                kind=kind,
                ecosystem=_agent_eco(text, ctor),
                name=name or f"{ctor}@{entry.path}:{line}",
                path=entry.path,
                line=line,
                detector=f"code-{ctor}",
                text=f"{ctor}({args})",
                body=instructions or "",
                description=(_kw(args, "description") or (instructions or "")[:300]) or None,
                models=[model] if model else [],
                tools=tools[:40],
                confidence="medium",
                frontmatter={"constructor": ctor, "line": line},
            )
        )
    for m in re.finditer(r"\bStateGraph\s*\(", text):
        nodes = re.findall(r"add_node\(\s*['\"]([\w\-]+)['\"]", text)
        line = _line_of(text, m.start())
        drafts.append(
            AssetDraft(
                kind="workflow",
                ecosystem="langgraph",
                name=f"{PurePosixPath(entry.path).stem} graph",
                path=entry.path,
                line=line,
                detector="code-StateGraph",
                text=_snippet(entry.path, text, line, 30),
                description=f"LangGraph StateGraph with nodes: {', '.join(nodes[:15])}"
                if nodes
                else "LangGraph StateGraph",
                confidence="medium",
                frontmatter={"nodes": nodes},
            )
        )
        break
    return drafts


def _agent_eco(text: str, ctor: str) -> str:
    checks = (
        ("claude_agent_sdk", "claude-agent-sdk"),
        ("claude-agent-sdk", "claude-agent-sdk"),
        ("google.adk", "google-adk"),
        ("from agents", "openai-agents"),
        ("@openai/agents", "openai-agents"),
        ("pydantic_ai", "pydantic-ai"),
        ("smolagents", "smolagents"),
        ("crewai", "crewai"),
        ("autogen", "autogen"),
        ("semantic_kernel", "semantic-kernel"),
        ("SemanticKernel", "semantic-kernel"),
        ("@mastra", "mastra"),
        ("langgraph", "langgraph"),
        ("llama_index", "llamaindex"),
    )
    for needle, eco in checks:
        if needle in text:
            return eco
    return "generic"


_TS_TOOL_CALL = re.compile(r"\.(?:tool|registerTool|addTool)\(")
_GO_NEWTOOL = re.compile(r"\bNewTool\(")
_GO_TOOL_STRUCT = re.compile(r"&?mcp\.Tool\{")
_STR = r"(?:\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'|`([^`]*)`)"
_FIRST_STR = re.compile(r"\s*" + _STR)
_MAX_CALLS = 500


def _str_at(text: str) -> str | None:
    m = _FIRST_STR.match(text)
    return next((g for g in m.groups() if g is not None), None) if m else None


def _mcp_tools(entry: FileEntry, text: str) -> list[tuple[str, str | None]]:
    """Tools registered in JS/TS or Go source (Python is handled by ``ai_python``)."""
    tools: list[tuple[str, str | None]] = []
    if entry.suffix == ".go":
        for m in list(_GO_NEWTOOL.finditer(text))[:_MAX_CALLS]:
            args = _balanced(text, m.end(), 4000)
            name = _str_at(args)
            desc = re.search(r"WithDescription\(\s*" + _STR, args)
            if name:
                tools.append((name, _group(desc)))
        for m in list(_GO_TOOL_STRUCT.finditer(text))[:_MAX_CALLS]:
            body = _balanced(text, m.end(), 4000)
            name_m = re.search(r"\bName:\s*" + _STR, body)
            desc = re.search(r"\bDescription:\s*" + _STR, body)
            if name_m and _group(name_m):
                tools.append((_group(name_m) or "", _group(desc)))
        return tools
    for m in list(_TS_TOOL_CALL.finditer(text))[:_MAX_CALLS]:
        args = _balanced(text, m.end(), 6000)
        first = _FIRST_STR.match(args)
        tool_name = _group(first)
        rest = args[first.end() :] if first else args
        if tool_name is None:  # addTool({ name: "x", description: "..." })
            tool_name = _group(re.search(r"\bname\s*:\s*" + _STR, args))
        if not tool_name or not re.fullmatch(r"[\w.\-/]{1,100}", tool_name):
            continue
        after = rest.lstrip()
        text_desc = _group(_FIRST_STR.match(after[1:])) if after.startswith(",") else None
        if text_desc is None:
            text_desc = _group(re.search(r"\bdescription\s*:\s*" + _STR, rest))
        tools.append((tool_name, text_desc[:300] if text_desc else None))
    return tools


def _group(m: re.Match[str] | None) -> str | None:
    if not m:
        return None
    return next((g for g in m.groups() if g is not None), None)


def _mcp_server(entry: FileEntry, text: str, detector: str = "mcp-server-code") -> AssetDraft:
    name = next((m.group(1) for rx in _MCP_SERVER_NAME if (m := rx.search(text))), None)
    ctor = re.search(r"new\s+(?:Mcp)?Server\(\s*\{", text)
    if not name and ctor:
        inner = re.search(r"\bname\s*:\s*['\"`]([^'\"`]+)['\"`]", _balanced(text, ctor.end()))
        name = inner.group(1) if inner else None
    lang = entry.suffix.lstrip(".")
    resources = len(_PY_RESOURCE.findall(text)) + len(
        re.findall(r"\.(?:resource|registerResource|prompt|registerPrompt)\(", text)
    )
    return AssetDraft(
        kind="mcp-server",
        ecosystem="mcp",
        name=name or ai_python._fallback_name(entry.path),
        path=entry.path,
        detector=detector,
        text=text,
        frontmatter={"language": lang, "resources_and_prompts": resources},
        tags=[f"lang:{lang}"],
    )


def _closest(servers: list[AssetDraft], path: str) -> AssetDraft:
    def shared(a: str, b: str) -> int:
        n = 0
        for x, y in zip(a.split("/"), b.split("/"), strict=False):
            if x != y:
                break
            n += 1
        return n

    return max(servers, key=lambda s: shared(s.path, path))
