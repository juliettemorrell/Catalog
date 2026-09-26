"""Detect AI usage inside source code: provider SDK call sites, model identifiers,
embedded prompts, agents defined in code and MCP server implementations."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from ..fs import FileEntry, RepoFiles
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
    r"(?:mistral|mixtral|codestral|ministral|pixtral)-"
    r"[a-z0-9.\-]+",
    r"command-r(?:-plus)?[a-z0-9\-]*",
    r"deepseek-[a-z0-9.\-]+",
    r"qwen[0-9.]*-[a-z0-9.\-]+",
]
MODEL_RX = re.compile(r"\b(" + "|".join(MODEL_PATTERNS) + r")\b", re.I)

_MCP_SERVER_IMPORT = re.compile(
    r"from\s+mcp\.server|from\s+fastmcp|import\s+fastmcp|@modelcontextprotocol/sdk/server|"
    r"mark3labs/mcp-go/server|modelcontextprotocol/go-sdk/mcp|ModelContextProtocol\.Server|"
    r"io\.modelcontextprotocol\.server|rmcp::"
)
_MCP_SERVER_NAME = [
    re.compile(r"\b(?:FastMCP|MCPServer)\(\s*(?:name\s*=\s*)?['\"]([^'\"]+)['\"]"),
    re.compile(r"new\s+(?:Mcp)?Server\(\s*\{\s*name:\s*['\"`]([^'\"`]+)['\"`]"),
    re.compile(r"NewMCPServer\(\s*\"([^\"]+)\""),
    re.compile(r"mcp\.Implementation\{\s*Name:\s*\"([^\"]+)\""),
    re.compile(r"(?i)server_?info['\"]?\s*[=:]\s*\{[^}]*?['\"]name['\"]\s*:\s*['\"]([^'\"]+)"),
]
_MCP_SERVER_CTOR = re.compile(
    r"\b(FastMCP|MCPServer)\(|new\s+McpServer\(|new\s+Server\(\s*\{|NewMCPServer\(|mcp\.NewServer\(|"
    r"AddMcpServer\(|McpServer\.(?:sync|async)\("
)
_PY_TOOL = re.compile(
    r"@\w+\.tool\s*\((?P<args>[^)]*)\)\s*\n(?:\s*@.*\n)*\s*(?:async\s+)?def\s+(?P<fn>\w+)\s*\("
    r"[^)]*\)[^:]*:\s*\n\s*(?:[rub]?(?P<q>\"\"\"|''')(?P<doc>.*?)(?P=q))?",
    re.S,
)
_TS_TOOL = re.compile(
    r"\.(?:tool|registerTool)\(\s*['\"`]([\w\-.]+)['\"`]\s*,\s*(?:\{[^}]*?description:\s*)?"
    r"['\"`]([^'\"`]{0,300})",
    re.S,
)
_GO_TOOL = re.compile(
    r"mcp\.NewTool\(\s*\"([^\"]+)\"(?:.*?mcp\.WithDescription\(\s*\"([^\"]*)\")?", re.S
)
_HANDWRITTEN_MCP = re.compile(r"['\"]tools/list['\"]")
_JSON_TOOL = re.compile(
    r"['\"]name['\"]\s*:\s*['\"]([\w\-.]+)['\"]\s*,\s*['\"]description['\"]\s*:\s*"
    r"['\"]([^'\"]{0,300})['\"](?=[^{}]{0,200}['\"]inputSchema['\"])"
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
        if (f.suffix in CODE_EXT or f.suffix in CONFIG_EXT)
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
        for key, (label, imp, call) in SDKS.items():
            if not re.search(imp, text, re.M):
                continue
            lines = [i + 1 for i, ln in enumerate(text.splitlines()) if re.search(call, ln)]
            sdk_hits[key].append((entry.path, lines[:20]))
            sdk_models[key].update(file_models)
            out.sdks.add(label)
            if len(sdk_snippets[key]) < 6 and lines:
                sdk_snippets[key].append(_snippet(entry.path, text, lines[0]))
        if entry.path not in claimed:
            out.drafts.extend(_inline_prompts(entry, text))
        out.drafts.extend(_code_agents(entry, text))
        if _MCP_SERVER_IMPORT.search(text):
            tools = _mcp_tools(entry, text)
            mcp_tools += [(entry.path, t, d) for t, d in tools]
            if _MCP_SERVER_CTOR.search(text):
                mcp_servers.append(_mcp_server(entry, text))
        elif _HANDWRITTEN_MCP.search(text) and "tools/call" in text:
            # MCP spoken directly over JSON-RPC (no SDK): common in quick internal servers
            server = _mcp_server(entry, text, detector="mcp-server-jsonrpc")
            server.confidence = "medium"
            mcp_servers.append(server)
            mcp_tools += [(entry.path, t, d) for t, d in _JSON_TOOL.findall(text)]

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
            r"(^|/)(tests?|__tests__|spec|fixtures?|__snapshots__|testdata|mocks?)/|"
            r"(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$",
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
            drafts.append(
                AssetDraft(
                    kind="prompt",
                    ecosystem="inline",
                    name=f"{PurePosixPath(entry.path).name}:{name}",
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
    for m in _AGENT_CTORS.finditer(text):
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


def _mcp_tools(entry: FileEntry, text: str) -> list[tuple[str, str | None]]:
    tools: list[tuple[str, str | None]] = []
    if entry.suffix == ".py":
        for m in _PY_TOOL.finditer(text):
            explicit = re.search(r"name\s*=\s*['\"]([^'\"]+)", m.group("args") or "")
            desc = re.search(r"description\s*=\s*['\"]([^'\"]+)", m.group("args") or "")
            doc = (m.group("doc") or "").strip().split("\n\n")[0].strip()
            tools.append(
                (
                    explicit.group(1) if explicit else m.group("fn"),
                    (desc.group(1) if desc else doc)[:300] or None,
                )
            )
    elif entry.suffix == ".go":
        tools += [(n, d or None) for n, d in _GO_TOOL.findall(text)]
    else:
        tools += [(n, d or None) for n, d in _TS_TOOL.findall(text)]
    return tools


def _mcp_server(entry: FileEntry, text: str, detector: str = "mcp-server-code") -> AssetDraft:
    name = next((m.group(1) for rx in _MCP_SERVER_NAME if (m := rx.search(text))), None)
    lang = entry.suffix.lstrip(".")
    resources = len(_PY_RESOURCE.findall(text)) + len(
        re.findall(r"\.(?:resource|registerResource|prompt|registerPrompt)\(", text)
    )
    return AssetDraft(
        kind="mcp-server",
        ecosystem="mcp",
        name=name or PurePosixPath(entry.path).parent.name or entry.path,
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
