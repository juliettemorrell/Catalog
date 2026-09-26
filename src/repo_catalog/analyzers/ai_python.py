"""Precise AI detection for Python source using the ``ast`` module.

Regexes cannot tell code from docstrings, comments or string literals, which produced
false positives such as ``server = MCPServer("demo")`` inside an SDK's own docstring.
Parsing the file gives exact call sites, keyword arguments, decorator-registered MCP
tools with their docstrings, and lets ``instructions=SYSTEM_PROMPT`` resolve to the
actual prompt text defined elsewhere in the module.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .ai_common import AssetDraft

PROMPT_NAME = re.compile(
    r"(prompt|instruction|system|persona|template|guideline|preamble|backstory)", re.I
)
PROMPT_KWARGS = {
    "system",
    "system_prompt",
    "instructions",
    "system_message",
    "system_instruction",
    "prompt",
    "backstory",
    "goal",
    "preamble",
    "instruction",
}
MIN_PROMPT = 180

MCP_SERVER_CLASSES = {"FastMCP", "MCPServer"}
AGENT_CTORS = {
    "Agent",
    "LlmAgent",
    "AssistantAgent",
    "CodeAgent",
    "ToolCallingAgent",
    "ChatCompletionAgent",
    "AgentDefinition",
    "ClaudeAgentOptions",
    "FunctionAgent",
    "ReActAgent",
    "create_react_agent",
    "create_agent",
    "SequentialAgent",
    "ParallelAgent",
    "LoopAgent",
}
# module prefixes whose presence makes an ``Agent(...)`` call meaningful, with ecosystem
AGENT_MODULES = (
    ("claude_agent_sdk", "claude-agent-sdk"),
    ("claude_code_sdk", "claude-agent-sdk"),
    ("google.adk", "google-adk"),
    ("agents", "openai-agents"),
    ("pydantic_ai", "pydantic-ai"),
    ("smolagents", "smolagents"),
    ("crewai", "crewai"),
    ("autogen", "autogen"),
    ("semantic_kernel", "semantic-kernel"),
    ("llama_index", "llamaindex"),
    ("langgraph", "langgraph"),
    ("langchain", "langchain"),
    ("strands", "strands"),
)


@dataclass
class PyFindings:
    prompts: list[AssetDraft] = field(default_factory=list)
    agents: list[AssetDraft] = field(default_factory=list)
    servers: list[AssetDraft] = field(default_factory=list)
    tools: list[tuple[str, str | None]] = field(default_factory=list)


def parse(text: str) -> ast.Module | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # invalid escape sequences in old code
            return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


class _Module:
    def __init__(self, tree: ast.Module, text: str, path: str):
        self.tree = tree
        self.text = text
        self.path = path
        self.modules: set[str] = set()
        self.imported: dict[str, str] = {}  # local name -> module it came from
        self.strings: dict[str, tuple[str, int]] = {}  # NAME -> (value, line)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.modules.add(alias.name)
                    self.imported[(alias.asname or alias.name).split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.modules.add(node.module)
                for alias in node.names:
                    self.imported[alias.asname or alias.name] = node.module
            elif isinstance(node, ast.Assign | ast.AnnAssign):
                value = node.value
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                s = self.literal(value) if value is not None else None
                if s is not None:
                    for t in targets:
                        if isinstance(t, ast.Name):
                            self.strings[t.id] = (s, node.lineno)

    def uses(self, *prefixes: str) -> bool:
        return any(m == p or m.startswith(p + ".") for m in self.modules for p in prefixes)

    def literal(self, node: ast.AST | None, resolve: bool = False) -> str | None:
        """String value of a constant, f-string (placeholders kept) or implicit concat."""
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    parts.append("{" + _unparse(v.value) + "}")
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.literal(node.left, resolve), self.literal(node.right, resolve)
            return left + right if left is not None and right is not None else None
        if resolve and isinstance(node, ast.Name) and node.id in self.strings:
            return self.strings[node.id][0]
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("strip", "format", "dedent")
        ):
            return self.literal(node.func.value, resolve) or (
                self.literal(node.args[0], resolve) if node.args else None
            )
        if isinstance(node, ast.Call) and _callee(node) == "dedent" and node.args:
            return self.literal(node.args[0], resolve)
        return None


def _base_name(node: ast.Attribute) -> str | None:
    return node.value.id if isinstance(node.value, ast.Name) else None


def _decorator_attr(dec: ast.expr) -> str | None:
    target = dec.func if isinstance(dec, ast.Call) else dec
    return target.attr if isinstance(target, ast.Attribute) else None


def _callee(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _unparse(node: ast.AST, limit: int = 120) -> str:
    try:
        s = ast.unparse(node)
    except Exception:
        return "?"
    s = re.sub(r"\s+", " ", s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _kw(call: ast.Call, *names: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg in names:
            return kw.value
    return None


def _tool_names(node: ast.AST | None) -> list[str]:
    if not isinstance(node, ast.List | ast.Tuple | ast.Set):
        return []
    out = []
    for el in node.elts:
        if isinstance(el, ast.Constant) and isinstance(el.value, str):
            out.append(el.value)
        elif isinstance(el, ast.Call):
            named = _kw(el, "tool_name", "name")
            if isinstance(named, ast.Constant) and isinstance(named.value, str):
                out.append(named.value)
            else:
                out.append(_unparse(el.func, 60))
        else:
            out.append(_unparse(el, 60))
    return out


def analyze(tree: ast.Module, text: str, path: str, *, want_prompts: bool) -> PyFindings:
    mod = _Module(tree, text, path)
    out = PyFindings()
    agent_calls: set[int] = set()
    fname = PurePosixPath(path).name

    agent_eco = next((eco for prefix, eco in AGENT_MODULES if mod.uses(prefix)), None)
    is_mcp = mod.uses("mcp", "fastmcp")
    # ``from app.server import mcp`` then ``@mcp.tool()``: tools registered in another module.
    # They are only kept if the repo defines an MCP server (they get attached to one later).
    local_imports = {
        local
        for local, module in mod.imported.items()
        if not module.startswith(("mcp", "fastmcp")) and local.islower()
    }

    # calls inside class bodies: a server built there with a computed name is a framework
    # wrapping the SDK (``self._server = Server(name=name)``), not a deployable server
    in_class = {id(n) for c in ast.walk(tree) if isinstance(c, ast.ClassDef) for n in ast.walk(c)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _callee(node)
            # ---- MCP servers -----------------------------------------------------------
            if is_mcp and (
                name in MCP_SERVER_CLASSES
                or (name == "Server" and mod.imported.get("Server", "").startswith("mcp.server"))
            ):
                label = mod.literal(node.args[0] if node.args else _kw(node, "name"), True)
                if label is None and id(node) in in_class:
                    continue
                instr = mod.literal(_kw(node, "instructions"), True)
                out.servers.append(
                    AssetDraft(
                        kind="mcp-server",
                        ecosystem="mcp",
                        name=label or _fallback_name(path),
                        path=path,
                        line=node.lineno,
                        detector="mcp-server-python",
                        text=text,
                        description=instr[:500] if instr else None,
                        frontmatter={"language": "py", "sdk": mod.imported.get(name, "")},
                        tags=["lang:py"],
                    )
                )
            elif is_mcp and name == "Tool":
                tool = mod.literal(_kw(node, "name"), True)
                if tool:
                    desc = mod.literal(_kw(node, "description"), True)
                    out.tools.append((tool, desc[:300] if desc else None))
            # ---- agents --------------------------------------------------------------------
            elif agent_eco and name in AGENT_CTORS:
                draft = _agent(mod, node, name, agent_eco)
                if draft:
                    agent_calls.add(id(node))
                    out.agents.append(draft)
            elif name == "StateGraph" and mod.uses("langgraph"):
                nodes = [
                    a.args[0].value
                    for a in ast.walk(tree)
                    if isinstance(a, ast.Call)
                    and _callee(a) == "add_node"
                    and a.args
                    and isinstance(a.args[0], ast.Constant)
                    and isinstance(a.args[0].value, str)
                ]
                out.agents.append(
                    AssetDraft(
                        kind="workflow",
                        ecosystem="langgraph",
                        name=f"{PurePosixPath(path).stem} graph",
                        path=path,
                        line=node.lineno,
                        detector="code-StateGraph",
                        text=_snippet(text, node.lineno, 40),
                        description=(
                            "LangGraph StateGraph with nodes: " + ", ".join(nodes[:15])
                            if nodes
                            else "LangGraph StateGraph"
                        ),
                        frontmatter={"nodes": nodes},
                        confidence="high",
                    )
                )
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and (
            is_mcp or (local_imports and agent_eco is None)
        ):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "tool"
                    and (is_mcp or _base_name(target) in local_imports)
                ):
                    call = dec if isinstance(dec, ast.Call) else None
                    explicit = mod.literal(_kw(call, "name"), True) if call else None
                    if call and call.args and not explicit:
                        explicit = mod.literal(call.args[0], True)
                    desc = mod.literal(_kw(call, "description"), True) if call else None
                    doc = ast.get_docstring(node) or ""
                    desc = desc or doc.strip().split("\n\n")[0].strip()
                    out.tools.append((explicit or node.name, desc[:300] or None))
    resources = sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        for d in n.decorator_list
        if _decorator_attr(d) in ("resource", "prompt")
    )
    for srv in out.servers:
        srv.frontmatter["resources_and_prompts"] = resources

    if want_prompts:
        out.prompts = _prompts(mod, fname, agent_calls)
    return out


def _agent(mod: _Module, call: ast.Call, ctor: str, eco: str) -> AssetDraft | None:
    name = mod.literal(_kw(call, "name", "role", "agent_name"), True)
    if not name and call.args:
        name = mod.literal(call.args[0], True)
    instr_node = _kw(
        call,
        "instructions",
        "system_prompt",
        "system_message",
        "instruction",
        "prompt",
        "backstory",
        "goal",
        "description",
    )
    instructions = mod.literal(instr_node, True)
    if instructions is None and instr_node is not None:
        instructions = f"<dynamic: {_unparse(instr_node, 80)}>"
    if not (name or instructions):
        return None
    model_node = _kw(call, "model", "llm")
    model = mod.literal(model_node, True)
    if model is None and isinstance(model_node, ast.Call):
        model = mod.literal(_kw(model_node, "model", "model_name", "id"), True)
    tools = _tool_names(_kw(call, "tools", "allowed_tools", "handoffs"))
    description = mod.literal(_kw(call, "description", "handoff_description", "goal"), True)
    kind = "workflow" if ctor in ("create_react_agent", "create_agent") and not name else "agent"
    return AssetDraft(
        kind=kind,
        ecosystem=eco,
        name=name or f"{ctor}@{mod.path}:{call.lineno}",
        path=mod.path,
        line=call.lineno,
        detector=f"code-{ctor}",
        text=_snippet(mod.text, call.lineno, 25, end=getattr(call, "end_lineno", None)),
        body=instructions or "",
        description=(description or instructions or "")[:500] or None,
        models=[model] if model else [],
        tools=tools[:40],
        frontmatter={"constructor": ctor, "line": call.lineno},
        confidence="high",
    )


def _prompts(mod: _Module, fname: str, skip_calls: set[int]) -> list[AssetDraft]:
    found: list[tuple[str, str, int]] = []
    seen_lines: set[int] = set()
    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Assign | ast.AnnAssign) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                var = (
                    t.id
                    if isinstance(t, ast.Name)
                    else (t.attr if isinstance(t, ast.Attribute) else None)
                )
                if var and PROMPT_NAME.search(var):
                    s = mod.literal(node.value)
                    if s:
                        found.append((var, s, node.lineno))
        elif isinstance(node, ast.Call) and id(node) not in skip_calls:
            for kw in node.keywords:
                if kw.arg in PROMPT_KWARGS:
                    s = mod.literal(kw.value)
                    if s:
                        found.append((kw.arg, s, kw.value.lineno))
        elif isinstance(node, ast.Dict):
            # {"role": "system", "content": "..."}
            keys = [k.value if isinstance(k, ast.Constant) else None for k in node.keys]
            if "role" in keys and "content" in keys:
                role = node.values[keys.index("role")]
                if isinstance(role, ast.Constant) and role.value in ("system", "developer"):
                    s = mod.literal(node.values[keys.index("content")])
                    if s:
                        found.append((f"{role.value}_message", s, node.lineno))
    drafts = []
    used: dict[str, int] = {}
    for var, body, line in sorted(found, key=lambda f: f[2]):
        if line in seen_lines or len(body.strip()) < MIN_PROMPT or body.count(" ") < 20:
            continue
        seen_lines.add(line)
        label = f"{fname}:{var}"
        used[label] = used.get(label, 0) + 1
        if used[label] > 1:
            label += f" #{used[label]}"
        variables = sorted(set(re.findall(r"\{\{\s*(\w+)\s*\}\}|\{(\w+)\}|\$\{(\w+)\}", body)))
        drafts.append(
            AssetDraft(
                kind="prompt",
                ecosystem="inline",
                name=label,
                path=mod.path,
                line=line,
                detector="inline-prompt",
                text=body.strip(),
                confidence="medium",
                arguments=[next(v for v in t if v) for t in variables][:20],
                tags=["embedded"],
                frontmatter={"variable": var, "line": line},
            )
        )
    return drafts


def _fallback_name(path: str) -> str:
    p = PurePosixPath(path)
    return (
        p.parent.name
        if p.stem in ("server", "main", "__main__", "app", "index") and p.parent.name
        else p.stem
    )


def _snippet(text: str, line: int, context: int, end: int | None = None) -> str:
    lines = text.splitlines()
    lo = max(0, line - 1)
    hi = min(len(lines), (end or line) + 1, lo + context * 3)
    return "\n".join(lines[lo:hi])
