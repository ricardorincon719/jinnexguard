"""Lo que un servidor MCP le dice al modelo: descripciones de herramientas y de parámetros.

Ese texto entra al contexto del modelo en cada llamada y la persona que instala el
servidor casi nunca lo lee. Un repo puede tener el README limpio y esconder la
instrucción ahí ("tool poisoning"). Se revisa aparte de la documentación porque las
reglas son otras: una descripción siempre le habla al modelo y el imperativo es
normal ("Use this tool to…", "Call this first"), así que eso solo no cuenta. Lo que
cuenta es lo que una descripción honesta no necesita: esconderle algo al usuario,
pedir archivos con credenciales, hablar de otras herramientas, texto invisible.

Solo se leen literales: nunca se importa ni se ejecuta el código. Si la descripción
se arma al correr (una llamada, algo bajado de la red), se avisa de que no se pudo
leer, porque puede cambiar después de que la aprobaste.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_right
from pathlib import Path

from jinnexguard.engine.checks.agents import (
    HIDE_FROM_USER, IGNORE_PREVIOUS, INJECTION_PATTERNS, NO_CONFIRMATION, SKIP_PERMISSIONS,
    _HIDDEN, _NEGATED, _hides_text)
from jinnexguard.engine.checks.dangerous_patterns import _TEST_HINT, _adjust, _snippet
from jinnexguard.engine.report import Finding, Severity

CATEGORY = "mcp-tool"
MAX_PER_PATTERN_PER_FILE = 3
PY_SUFFIXES = {".py"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
# Un archivo cuenta como servidor MCP si usa un SDK de MCP: `description=` aparece en
# argparse, pydantic, click… y ahí no la lee ningún modelo.
_PY_MCP = re.compile(r"(?m)^\s*(?:from|import)\s+(?:mcp|fastmcp|mcp_server|modelcontextprotocol)\b")
_JS_MCP = re.compile(r"@modelcontextprotocol/sdk|\bfastmcp\b|\bMcpServer\b|\binputSchema\b|"
                     r"\bregisterTool\b")
_TOOL_DECORATORS = {"tool", "prompt", "resource"}
_TOOL_CLASSES = {"Tool", "Prompt", "Resource", "ResourceTemplate"}
# Llamadas que solo dan forma a un literal: lo que devuelven se puede leer igual.
_SHAPING_CALLS = {"dedent", "strip", "lstrip", "rstrip", "format", "join", "cleandoc", "replace"}
_NETWORK_CALL = re.compile(
    r"\b(?:requests|httpx|aiohttp|urllib|urlopen|fetch|axios|got|http\.get|https\.get)\b")

# --- Reglas propias de una descripción ---
_SENSITIVE_PATH = re.compile(
    r"""(?:~|\$HOME|%USERPROFILE%)[/\\]\.(?:ssh|aws|gnupg|kube|docker|npmrc|netrc|cursor|claude|"""
    r"""codex|gemini|config[/\\]gcloud)\b|\bid_(?:rsa|ed25519|ecdsa)\b|"""
    r"""(?<![\w.])\.(?:aws|ssh)/[\w.]+|\bclaude_desktop_config\.json\b|\.claude\.json\b|"""
    r"""(?<![\w.-])\.cursor/mcp\.json\b""")
_PSEUDO_TAG = re.compile(r"(?i)<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|"
                         r"override)\s*>")
_OTHER_TOOLS = re.compile(
    r"(?i)\b(?:before|instead\s+of|rather\s+than|whenever|every\s+time|each\s+time|when)\s+"
    r"(?:you\s+|the\s+(?:assistant|agent|model)\s+)?(?:us(?:e|es|ing)|call(?:s|ing)?|"
    r"invok(?:e|es|ing)|run(?:s|ning)?)\s+(?:any\s+|the\s+|an?\s+)?(?:other|another|different)\s+"
    r"tools?\b|\b(?:do\s+not|don't|never)\s+(?:use|call|invoke)\s+(?:any\s+|the\s+)?"
    r"(?:other|another)\s+tools?\b")
_CONTEXT_GRAB = re.compile(
    r"(?i)\b(?:include|pass|send|put|attach|provide|copy|append|add)\b[^.]{0,80}\b(?:"
    r"(?:entire|full|whole|complete)\s+(?:conversation|chat)(?:\s+history)?|"
    r"(?:conversation|chat)\s+history|system\s+prompt|previous\s+messages|"
    r"(?:api|access|secret)\s+(?:keys?|tokens?)|environment\s+variables|credentials)\b")
DESCRIPTION_PATTERNS: tuple[tuple[re.Pattern, Severity, str, str], ...] = (
    (_SENSITIVE_PATH, Severity.HIGH, "Tool description points at credential or agent-config files",
     "The model reads this text on every call. A description that names where keys or agent "
     "settings live can make the agent read them and hand them over as an argument."),
    (_PSEUDO_TAG, Severity.MEDIUM, "Tool description uses system-style tags",
     "Tags such as <IMPORTANT> or <system> are there to make the model treat the text as an "
     "order rather than as documentation. Read what is inside."),
    (_CONTEXT_GRAB, Severity.MEDIUM, "Tool description asks for conversation or secrets as input",
     "It asks the agent to put the conversation, the system prompt or credentials into a tool "
     "argument: that is how data leaves through a tool that looks harmless."),
    (_OTHER_TOOLS, Severity.LOW, "Tool description talks about other tools",
     "It tells the agent how to use tools that are not this one. A server can use that to "
     "change what happens when you call a different, trusted server."),
)
# De las reglas para instrucciones de agentes se reutiliza lo que tampoco es normal acá.
_REUSED = {IGNORE_PREVIOUS: "Tool description asks to ignore previous instructions",
           HIDE_FROM_USER: "Tool description asks to hide something from the user",
           SKIP_PERMISSIONS: "Tool description asks to bypass the agent's permissions",
           NO_CONFIRMATION: "Tool description asks to act without confirmation"}
DYNAMIC_TITLE = "Tool description built at runtime"
DYNAMIC_DETAIL = ("The text the model will read is not written in the code: a call produces it "
                  "when the server starts. It could not be reviewed, and it can change without "
                  "a change in the repository.")
REMOTE_TITLE = "Tool description loaded from the network"
REMOTE_DETAIL = ("The text the model will read is downloaded when the server runs. Whoever "
                 "controls that address can change the instructions after you approved the "
                 "server, with no change in the repository.")


class _Collector:
    """Junta hallazgos de un archivo, con tope por regla y la rebaja por carpeta de tests."""

    def __init__(self, path: Path):
        self.path = path
        self.findings: list[Finding] = []
        self.counts: dict[str, int] = {}
        self.downgrade = 2 if _TEST_HINT.search(path.as_posix()) else 0
        self.described = 0

    def add(self, severity: Severity, title: str, detail: str, evidence: str, line: int) -> None:
        if self.counts.get(title, 0) >= MAX_PER_PATTERN_PER_FILE:
            return
        self.counts[title] = self.counts.get(title, 0) + 1
        self.findings.append(Finding(
            _adjust(severity, self.downgrade), CATEGORY, f"{title} ({self.path})", detail,
            evidence=_snippet(evidence), path=str(self.path), line=line))

    def scan(self, text: str, first_line: int) -> None:
        """Revisa una descripción. `first_line` es la línea del archivo donde empieza."""
        if not text.strip():
            return
        self.described += 1
        lines = text.splitlines() or [""]
        for index, line in enumerate(lines):
            if _HIDDEN.search(line):
                if _hides_text(line):
                    self.add(Severity.HIGH, "Invisible text in a tool description",
                             "Characters a person cannot see but the model reads: the typical "
                             "way to hide instructions.", line, first_line + index)
                else:
                    self.add(Severity.LOW, "Stray zero-width characters in a tool description",
                             "A few invisible zero-width characters, common in copy-pasted "
                             "text. Too few to hide a message, but the evidence shows where "
                             "they are.", line, first_line + index)
        # Las frases se buscan con la descripción en una sola línea: un salto de línea en
        # medio de "do not tell / the user" no tiene que esconderla.
        starts: list[int] = []
        parts: list[str] = []
        position = 0
        for line in lines:
            piece = " ".join(line.split())
            starts.append(position)
            parts.append(piece)
            position += len(piece) + 1
        flat = " ".join(parts)

        def report(match: re.Match, severity: Severity, title: str, detail: str) -> None:
            index = max(0, bisect_right(starts, match.start()) - 1)
            begin = max(0, match.start() - 60)
            self.add(severity, title, detail, flat[begin:match.end() + 120], first_line + index)

        for pattern, severity, title, detail in DESCRIPTION_PATTERNS:
            match = pattern.search(flat)
            if match:
                report(match, severity, title, detail)
        for pattern, severity, title, detail in INJECTION_PATTERNS:
            if title not in _REUSED:
                continue
            match = pattern.search(flat)
            if not match:
                continue
            if title in (NO_CONFIRMATION, SKIP_PERMISSIONS) and \
                    _NEGATED.search(flat[max(0, match.start() - 80):match.start()]):
                continue   # "never … without the user's consent" pide lo contrario
            report(match, severity, _REUSED[title], detail)


# --- Python: con el árbol sintáctico, sin importar nada ---
def _call_name(node: ast.AST) -> str:
    """`mcp.tool` → "tool"; `Tool` → "Tool"; `mcp.tool()` → "tool"."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _literal(node: ast.AST, constants: dict[str, tuple[str, int]]) -> tuple[str, int] | None:
    """El texto de la expresión si se puede leer sin ejecutar nada, con su línea."""
    if isinstance(node, ast.Constant):
        return (node.value, node.lineno) if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):   # f-string: se leen las partes fijas
        fixed = "".join(v.value for v in node.values
                        if isinstance(v, ast.Constant) and isinstance(v.value, str))
        return fixed, node.lineno
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _literal(node.left, constants)
        right = _literal(node.right, constants) if isinstance(node.op, ast.Add) else ("", 0)
        if left is None and right is None:
            return None
        return (left or ("", 0))[0] + (right or ("", 0))[0], node.lineno
    if isinstance(node, ast.Call) and _call_name(node) in _SHAPING_CALLS:
        inner = node.args[0] if _call_name(node) in ("dedent", "cleandoc") and node.args else \
            (node.func.value if isinstance(node.func, ast.Attribute) else None)
        return _literal(inner, constants) if inner is not None else None
    return None


def _python_source(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:   # noqa: BLE001  un nodo raro no tumba el chequeo
        return ""


def _check_python(path: Path, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    out = _Collector(path)
    constants = {target.id: (stmt.value.value, stmt.value.lineno)
                 for stmt in tree.body if isinstance(stmt, ast.Assign)
                 and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)
                 for target in stmt.targets if isinstance(target, ast.Name)}

    def description(value: ast.AST) -> None:
        found = _literal(value, constants)
        if found is not None:
            out.scan(*found)
            return
        source = _python_source(value)
        if not any(isinstance(n, (ast.Call, ast.Await)) for n in ast.walk(value)):
            return   # un nombre que viene de otro módulo o un parámetro: no hay qué afirmar
        if _NETWORK_CALL.search(source):
            out.add(Severity.MEDIUM, REMOTE_TITLE, REMOTE_DETAIL, source, value.lineno)
        else:
            out.add(Severity.LOW, DYNAMIC_TITLE, DYNAMIC_DETAIL, source, value.lineno)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorators = [d for d in node.decorator_list if _call_name(d) in _TOOL_DECORATORS
                          and isinstance(d.func if isinstance(d, ast.Call) else d, ast.Attribute)]
            if not decorators:
                continue
            explicit = [k.value for d in decorators if isinstance(d, ast.Call)
                        for k in d.keywords if k.arg == "description"]
            if explicit:
                description(explicit[0])
            # El docstring es la descripción cuando el decorador no trae una.
            first = node.body[0] if node.body else None
            if not explicit and isinstance(first, ast.Expr) \
                    and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                out.scan(first.value.value, first.value.lineno)
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            for keyword in node.keywords:
                # `Tool(description=…)` y las de parámetros (`Field(description=…)`): las dos
                # llegan al modelo dentro del esquema.
                if keyword.arg == "description" and name not in _TOOL_DECORATORS:
                    if name in _TOOL_CLASSES or name in ("Field", "Annotated", "Parameter"):
                        description(keyword.value)
    return _finish(out)


# --- JavaScript / TypeScript: literales junto a `description`, `.tool(` y `.describe(` ---
_JS_STRING = r"""(?P<q{n}>["'`])(?P<s{n}>(?:\\.|(?!(?P=q{n})).)*)(?P=q{n})"""
_JS_DESCRIPTION = re.compile(r"""\bdescription["']?\s*:\s*""" + _JS_STRING.format(n=1), re.DOTALL)
_JS_TOOL_CALL = re.compile(
    r"""\.(?:tool|registerTool|prompt|registerPrompt)\(\s*["'`][^"'`\n]{1,120}["'`]\s*,\s*"""
    + _JS_STRING.format(n=1), re.DOTALL)
_JS_DESCRIBE = re.compile(r"""\.describe\(\s*""" + _JS_STRING.format(n=1), re.DOTALL)
_JS_DYNAMIC = re.compile(
    r"""\bdescription["']?\s*:\s*(?P<expr>(?:await\s+)?[A-Za-z_$][\w$.]*\s*\([^\n]{0,160})""")
_JS_ESCAPE = re.compile(r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(.))",
                        re.DOTALL)
_JS_SIMPLE = {"n": "\n", "t": "\t", "r": "", "\n": ""}


def _js_unescape(value: str) -> str:
    """`\\u200b` escrito como escape también es texto invisible para quien lee el código."""
    def replace(match: re.Match) -> str:
        code = match.group(1) or match.group(2) or match.group(3)
        if code:
            try:
                return chr(int(code, 16))
            except (ValueError, OverflowError):
                return match.group(0)
        return _JS_SIMPLE.get(match.group(4), match.group(4))
    return _JS_ESCAPE.sub(replace, value)


def _check_javascript(path: Path, text: str) -> list[Finding]:
    out = _Collector(path)
    line_starts = [0]
    for match in re.finditer(r"\n", text):
        line_starts.append(match.end())
    seen: set[int] = set()
    for pattern in (_JS_TOOL_CALL, _JS_DESCRIPTION, _JS_DESCRIBE):
        for match in pattern.finditer(text):
            start = match.start("s1")
            if start in seen:
                continue
            seen.add(start)
            out.scan(_js_unescape(match.group("s1")), bisect_right(line_starts, start))
    for match in _JS_DYNAMIC.finditer(text):
        expression = match.group("expr")
        line = bisect_right(line_starts, match.start("expr"))
        if _NETWORK_CALL.search(expression):
            out.add(Severity.MEDIUM, REMOTE_TITLE, REMOTE_DETAIL, expression, line)
    return _finish(out)


def _finish(out: _Collector) -> list[Finding]:
    if not out.described and not out.findings:
        return []
    return [Finding(
        Severity.INFO, CATEGORY, f"MCP tool descriptions ({out.path})",
        "Text this server sends to the model on every call (tool and parameter descriptions). "
        "The agent treats it as trusted. Read it as you would read a prompt.",
        evidence=f"{out.described} description" + ("" if out.described == 1 else "s"), path=str(out.path)), *out.findings]


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        suffix = path.suffix.lower()
        if suffix in PY_SUFFIXES and _PY_MCP.search(text):
            findings += _check_python(path, text)
        elif suffix in JS_SUFFIXES and _JS_MCP.search(text):
            findings += _check_javascript(path, text)
    return findings
