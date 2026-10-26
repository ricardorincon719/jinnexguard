"""Lo que un repo le hace o le dice a tus agentes de IA (Claude Code, Codex, Cursor…).

Tres señales que los chequeos de malware clásicos no ven:
  - código que escribe en la configuración de agentes (`.claude.json`,
    `mcpServers`…) o en lo que arranca solo (`.bashrc`, crontab, systemd): cambia
    cómo se comporta tu agente o deja algo corriendo para siempre;
  - archivos de instrucciones (SKILL.md, AGENTS.md, CLAUDE.md…): el agente los
    obedece como si fueran tuyos, así que un texto invisible o un "no se lo digas
    al usuario" es prompt injection;
  - configuración de proyecto que el agente carga al abrir el repo
    (`.claude/settings.json` con hooks, `.mcp.json`): corre comandos.

La documentación (README, CONTRIBUTING, docs/…) pasa por la misma búsqueda de
prompt injection: un agente al que le pedís "instalá este repo" lee el README y
sigue sus pasos. Lo que va en un comentario HTML (`<!-- … -->`) pesa más: GitHub
no lo muestra, así que vos no lo ves, pero el agente lee el archivo crudo.
"""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from pathlib import Path

from jinnexguard.engine.checks.dangerous_patterns import (
    BIDI_CHARS, LINE_PATTERNS, _COMMENT, _RTL_LETTERS, _TEST_HINT, _adjust, _snippet)
from jinnexguard.engine.report import Finding, Severity
from jinnexguard.engine.textscan import lines_with

MAX_PER_PATTERN_PER_FILE = 3
CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".sh",
                 ".bash", ".zsh", ".fish", ".ps1", ".go", ".rs", ".rb", ".java", ".kt",
                 ".swift", ".cs", ".php", ".pl", ".lua"}

# --- Código que toca la configuración de agentes o deja algo arrancando solo ---
_AGENT_CONFIG = re.compile(
    r"""\.claude\.json\b|["'`/\\]\.claude["'`/\\]|claude_desktop_config\.json|"""
    r"""["'`/\\]\.(?:codex|gemini|cursor|windsurf|continue|qwen|kimi-code)["'`/\\]""")
# El nombre `mcpServers` solo no cuenta: una herramienta de IA lo usa en todo su código.
# Lo que importa es tocar la configuración del usuario, y eso pasa por una ruta.
_PERSISTENCE = re.compile(
    r"""(?:[~/"'`]|\$HOME/?)\.(?:bashrc|bash_profile|bash_login|zshrc|zshenv|zprofile|profile)\b|"""
    r"""\bcrontab\b|\.config/autostart\b|systemd/user\b|LaunchAgents\b""")
CODE_SIGNALS = (
    (_AGENT_CONFIG, (".claude", "claude_desktop", ".codex", ".gemini", ".cursor", ".windsurf",
                     ".continue", ".qwen", ".kimi-code"),
     Severity.MEDIUM, "agent-config",
     "Touches AI agent configuration",
     "Reads or writes where your agents keep their MCP servers, skills or permissions: "
     "it can change how they behave. Check what it writes and whether it asks first."),
    (_PERSISTENCE, ("bashrc", "bash_profile", "bash_login", "zshrc", "zshenv", "zprofile",
                    ".profile", "crontab", "autostart", "systemd/user", "LaunchAgents"),
     Severity.MEDIUM, "persistence",
     "Touches files that start on their own (shell, crontab, systemd)",
     "Whatever is written there runs on every session or at boot, even after the repo "
     "is deleted."),
)

# --- Archivos de instrucciones para agentes ---
INSTRUCTION_NAMES = {"SKILL.md", "AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md",
                     ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md"}
# Carpetas cuyo contenido .md/.mdc el agente carga como órdenes o comandos.
_INSTRUCTION_DIRS = ((".claude", "commands"), (".claude", "agents"), (".cursor", "rules"),
                     (".github", "prompts"))
# Invisible para una persona, legible para un modelo. Sin U+200D: une emojis (👨‍💻).
_HIDDEN = re.compile(f"[{BIDI_CHARS}\u200b\u200c\u2060\U000e0000-\U000e007f]")
# Lo que de verdad esconde texto: "tags" Unicode (texto que solo lee el modelo), controles
# bidi, o una tira larga de ancho cero (bits codificados). Unos pocos espacios de ancho
# cero sueltos son basura de traducciones o de copiar y pegar.
_SMUGGLING = re.compile("[\u202a-\u202e\U000e0000-\U000e007f]|[\u200b\u200c\u200d\u2060]{8,}")
_ISOLATES = re.compile("[\u2066-\u2069]")


def _hides_text(line: str) -> bool:
    # Los aislantes bidi junto a texto RTL son el uso correcto, no un escondite.
    return bool(_SMUGGLING.search(line)
                or (_ISOLATES.search(line) and not _RTL_LETTERS.search(line)))
_CURL_BASH = LINE_PATTERNS[0][0]
_NEGATED = re.compile(r"(?i)\b(?:never|don't|do\s+not|must\s+not|mustn't|should\s+not|"
                      r"shouldn't|cannot|can't|nunca|jam[aá]s|no\s+(?:debe|puede|hay\s+que))\b")
IGNORE_PREVIOUS = "Asks to ignore previous instructions"
HIDE_FROM_USER = "Asks to hide something from the user"
SKIP_PERMISSIONS = "Asks to bypass the agent's permissions"
NO_CONFIRMATION = "Asks to act without confirmation"
REMOTE_SCRIPT = "Asks the agent to run a remote script (curl|bash)"
INJECTION_PATTERNS: tuple[tuple[re.Pattern, Severity, str, str], ...] = (
    (re.compile(r"(?i)\bignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|"
                r"earlier)\s+(?:instructions|rules|prompts?)|\bignor[aáe]\w*\s+(?:todas\s+)?"
                r"(?:las\s+)?instrucciones\s+(?:anteriores|previas)"),
     Severity.HIGH, IGNORE_PREVIOUS,
     "Classic prompt injection phrase: it tries to override what you told the agent."),
    (re.compile(r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify)\s+"
                r"(?:this\s+|it\s+|anything\s+)?(?:to\s+)?the\s+user|\bno\s+(?:se\s+lo\s+|le\s+)?"
                r"(?:digas|avises|cuentes|menciones|muestres)\s+(?:nada\s+|esto\s+)?al\s+usuario"),
     Severity.HIGH, HIDE_FROM_USER,
     "A legitimate file has no reason to make the agent hide what it does from you."),
    (re.compile(r"--dangerously-skip-permissions|\bbypassPermissions\b|--yolo\b|"
                r"(?i:\bauto[- ]?approve\b)"),
     Severity.MEDIUM, SKIP_PERMISSIONS,
     "Turns off the confirmations that let you see each action before it happens."),
    (re.compile(r"(?i)\bwithout\s+(?:asking|confirm(?:ation|ing)?|(?:the\s+)?user'?s?\s+"
                r"(?:approval|consent|permission))|\bsin\s+(?:preguntar|confirmar|pedir\s+"
                r"(?:permiso|confirmaci[oó]n)|(?:tu\s+|su\s+)?(?:aprobaci[oó]n|permiso))"),
     Severity.MEDIUM, NO_CONFIRMATION,
     "Check which action it wants the agent to take without asking you."),
    (_CURL_BASH, Severity.MEDIUM, REMOTE_SCRIPT,
     "The agent would download and run code nobody has read."),
)


# Documentación que un agente lee y suele seguir. No son órdenes "oficiales" como
# un CLAUDE.md, así que lo que es normal en docs (un `curl | bash` de instalación,
# documentar `--dangerously-skip-permissions`) baja a low.
DOC_SUFFIXES = {".md", ".mdx", ".markdown", ".rst"}
DOC_SEVERITY = {SKIP_PERMISSIONS: Severity.LOW, NO_CONFIRMATION: Severity.LOW,
                REMOTE_SCRIPT: Severity.LOW}
# Un comentario HTML con texto dirigido a un modelo: tu navegador no lo muestra.
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
# Le habla a un modelo ("AI agent:", "Claude,", "Note to the AI", "If you are an AI"),
# no solo lo menciona: las plantillas de issues usan comentarios para guiar a personas.
_AI_NAMES = (r"(?:ai|llm|language\s+model|assistant|agent|claude|chatgpt|gpt|copilot|codex|gemini|"
             r"cursor|ia|asistente|agente|modelo)")
_ADDRESSES_AI = re.compile(
    r"(?i)^\s*(?:<!--\s*)?(?:dear\s+|hey\s+|note\s+(?:to|for)\s+(?:the\s+)?|nota\s+para\s+(?:el\s+|la\s+)?)?"
    + _AI_NAMES + r"(?:\s+(?:agent|assistant|model|agente|asistente))?\s*[:,]"
    r"|(?i:\bif\s+you\s+are\s+an?\s+(?:ai|llm|language\s+model|assistant|agent)\b"
    r"|\bsi\s+(?:eres|sos)\s+(?:una?\s+)?(?:ia|asistente|agente|modelo)\b)")
HIDDEN_COMMENT_SUFFIX = " (in a hidden HTML comment)"
HIDDEN_COMMENT_DETAIL = (" It is inside an HTML comment: GitHub does not show it when you read the "
                         "file, but the agent reads the raw text. It is rarely innocent.")


def _quoted_mention(line: str, index: int) -> bool:
    """¿La frase está citada ("…", “…”, «…» o `…`)? Ahí se la nombra, no se la ordena.

    No cuenta comillas simples: los apóstrofos del inglés ("don't") las confunden.
    """
    before = line[:index]
    # La cita puede haber empezado en otra línea: una comilla pegada a la frase también cuenta.
    if before.rstrip(" ").endswith(('"', "`", "\u201c", "\u00ab")):
        return True
    return (before.count('"') % 2 == 1 or before.count("`") % 2 == 1
            or before.count("\u201c") > before.count("\u201d")
            or before.count("\u00ab") > before.count("\u00bb"))


def _comment_spans(text: str) -> tuple[list[int], list[int]]:
    """Inicios y finales (posiciones en el texto) de los comentarios HTML, en orden."""
    spans = [(m.start(), m.end()) for m in _HTML_COMMENT.finditer(text)]
    return [a for a, _ in spans], [b for _, b in spans]


def _is_instruction_file(path: Path) -> bool:
    if path.name in INSTRUCTION_NAMES:
        return True
    if path.suffix.lower() not in (".md", ".mdc"):
        return False
    parts = path.parts
    return any(parts[i:i + 2] == pair for pair in _INSTRUCTION_DIRS
               for i in range(len(parts) - 1))


def _check_code(path: Path, text: str, native: set[str] = frozenset()) -> list[Finding]:
    findings: list[Finding] = []
    test_down = 1 if _TEST_HINT.search(str(path).replace("\\", "/")) else 0
    for pattern, literals, severity, category, title, detail in CODE_SIGNALS:
        hits = [(n, line) for n, line in lines_with(text, literals) if pattern.search(line)]
        if not hits:
            continue
        # Una bandera por archivo: la primera línea que ejecuta, o el comentario si es todo.
        lineno, line = next(((n, l) for n, l in hits if not _COMMENT.match(l)), hits[0])
        down = test_down + (2 if _COMMENT.match(line) else 0)
        extra = f"  (+{len(hits) - 1} more line(s))" if len(hits) > 1 else ""
        if category == "agent-config":
            touched = {m.group(1) or "claude" for _, l in hits for m in _AGENT_NAME.finditer(l)}
            if touched and touched <= native:
                down += 2
                detail = (f"This repo references the {', '.join(sorted(touched))} agent's "
                          "configuration across many files: it is most likely that agent's own "
                          "code managing its settings.")
        findings.append(Finding(
            _adjust(severity, down), category, f"{title} ({path})", detail,
            evidence=_snippet(line) + extra, path=str(path), line=lineno))
    return findings


def _scan_for_injection(path: Path, text: str, *, doc: bool) -> list[Finding]:
    """Prompt injection y texto invisible, en instrucciones (`doc=False`) o en documentación."""
    category = "agent-docs" if doc else "agent-instructions"
    starts, ends = _comment_spans(text) if "<!--" in text else ([], [])
    findings: list[Finding] = []
    counts: dict[str, int] = {}
    offset = 0   # posición en el texto donde empieza la línea actual

    def hidden(column: int) -> bool:
        """¿Esa columna de la línea actual cae dentro de un comentario HTML?

        Cuenta la posición, no la línea: un payload con una etiqueta `<!-- … -->` al
        lado no está escondido.
        """
        index = bisect_right(starts, offset + column) - 1
        return index >= 0 and offset + column < ends[index]

    def add(key: str, severity: Severity, title: str, detail: str, line: str, lineno: int,
            column: int):
        if counts.get(key, 0) >= MAX_PER_PATTERN_PER_FILE:
            return
        counts[key] = counts.get(key, 0) + 1
        if hidden(column):
            severity = Severity(min(int(severity) + 1, int(Severity.CRITICAL)))
            title, detail = title + HIDDEN_COMMENT_SUFFIX, detail + HIDDEN_COMMENT_DETAIL
        findings.append(Finding(severity, category, f"{title} ({path})", detail,
                                evidence=_snippet(line), path=str(path), line=lineno))

    for lineno, raw in enumerate(text.splitlines(keepends=True), start=1):
        line = (raw.splitlines() or [""])[0]
        invisible = [m.start() for m in _HIDDEN.finditer(line)]
        if invisible:
            where = "documentation" if doc else "agent instructions"
            # Basta un carácter invisible dentro de un comentario para que cuente como oculto.
            column = next((c for c in invisible if hidden(c)), invisible[0])
            if _hides_text(line):
                add("hidden", Severity.HIGH, f"Invisible text in {where}",
                    "Characters a person cannot see but the model reads: the typical way to "
                    "hide instructions.", line, lineno, column)
            else:
                add("stray", Severity.LOW if doc else Severity.MEDIUM,
                    f"Stray zero-width characters in {where}",
                    "A few invisible zero-width characters, common in translated or "
                    "copy-pasted text. Too few to hide a message, but the evidence shows "
                    "where they are.", line, lineno, column)
        matched = False
        for pattern, severity, title, detail in INJECTION_PATTERNS:
            match = pattern.search(line)
            if match:
                matched = True
                if title in (NO_CONFIRMATION, SKIP_PERMISSIONS) and \
                        _NEGATED.search(line[max(0, match.start() - 80):match.start()]):
                    # "never … without the user's consent" pide lo contrario.
                    severity = _adjust(severity, 2)
                if doc:
                    severity = DOC_SEVERITY.get(title, severity)
                    if _quoted_mention(line, match.start()):   # la documenta, no la ordena
                        severity = _adjust(severity, 2)
                add(title, severity, title, detail, line, lineno, match.start())
        addressed = None if matched else _ADDRESSES_AI.search(line)
        if addressed and hidden(addressed.start()):
            add("addressed", Severity.LOW, "Text addressed to an AI agent",
                "It speaks to a model, not to the reader. Read what it asks for.", line, lineno,
                addressed.start())
        offset += len(raw)
    return findings


def _check_instructions(path: Path, text: str) -> list[Finding]:
    return [Finding(
        Severity.INFO, "agent-instructions", f"Instructions for AI agents ({path})",
        "Your agent obeys this file if it works in the repo or if it is installed as a skill. "
        "Read it as you would read a script.", evidence=f"{len(text.splitlines())} lines",
        path=str(path)), *_scan_for_injection(path, text, doc=False)]


def _line_of(text: str, needle: str) -> int | None:
    index = text.find(needle)
    return None if index < 0 else text.count("\n", 0, index) + 1


def _commands(value) -> list[str]:
    """Todos los `command` dentro de una estructura de hooks, en orden."""
    if isinstance(value, dict):
        found = [value["command"]] if isinstance(value.get("command"), str) else []
        return found + [c for v in value.values() for c in _commands(v)]
    if isinstance(value, list):
        return [c for v in value for c in _commands(v)]
    return []


def _short(items: list[str], limit: int = 3) -> str:
    shown = " | ".join(item[:120] for item in items[:limit])
    return shown + (f"  (+{len(items) - limit} more)" if len(items) > limit else "")


def _check_claude_settings(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    findings: list[Finding] = []
    hooks = _commands(data.get("hooks"))
    if hooks:
        findings.append(Finding(
            Severity.HIGH, "agent-config", f"Claude Code hooks in the repo ({path})",
            "Claude Code runs these commands on its own, on every event, while working in this "
            "repo (once trusted). Read each one.",
            evidence=_short(hooks), path=str(path), line=_line_of(text, '"hooks"')))
    for key in ("apiKeyHelper", "statusLine"):
        value = data.get(key)
        command = value.get("command") if isinstance(value, dict) else value
        if isinstance(command, str) and command:
            findings.append(Finding(
                Severity.MEDIUM, "agent-config", f"Claude Code runs the repo's '{key}' ({path})",
                "It is a command Claude Code runs on its own while you work in the repo.",
                evidence=command[:180], path=str(path), line=_line_of(text, f'"{key}"')))
    allow = (data.get("permissions") or {}).get("allow") if isinstance(
        data.get("permissions"), dict) else None
    if isinstance(allow, list) and allow:
        findings.append(Finding(
            Severity.MEDIUM, "agent-config", f"The repo pre-approves agent permissions ({path})",
            "These actions stop asking you for confirmation inside the repo.",
            evidence=_short([str(a) for a in allow], 5), path=str(path),
            line=_line_of(text, '"allow"')))
    deny = (data.get("permissions") or {}).get("deny") if isinstance(
        data.get("permissions"), dict) else None
    if isinstance(deny, list) and deny:
        findings.append(Finding(
            Severity.INFO, "agent-config", f"The repo blocks agent actions ({path})",
            "Good sign: it forbids these actions even if you ask for them. It proves nothing "
            "about the rest of the repo; anyone can write a deny list.",
            evidence=f"{len(deny)} rules: " + _short([str(d) for d in deny], 5),
            path=str(path), line=_line_of(text, '"deny"')))
    if data.get("enableAllProjectMcpServers") is True:
        findings.append(Finding(
            Severity.MEDIUM, "agent-config", f"Enables every project MCP server ({path})",
            "Starts every MCP server the repo declares, without asking.",
            evidence="enableAllProjectMcpServers: true", path=str(path),
            line=_line_of(text, "enableAllProjectMcpServers")))
    return findings


def _check_mcp_json(path: Path, text: str) -> list[Finding]:
    try:
        servers = json.loads(text).get("mcpServers")
    except (ValueError, AttributeError):
        return []
    if not isinstance(servers, dict):
        return []
    findings: list[Finding] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        launch = " ".join([str(spec.get("command", ""))] + [str(a) for a in spec.get("args", [])
                                                             if isinstance(spec.get("args"), list)])
        remote = not spec.get("command") and bool(spec.get("url"))
        findings.append(Finding(
            Severity.LOW if remote else Severity.MEDIUM, "agent-config",
            f"MCP server declared by the repo ({path})",
            "A remote server: the agent sends it requests and reads its answers, but no code "
            "runs on your machine." if remote else
            "Opening the repo with the agent offers to start it: it is code that runs on your "
            "machine with your permissions.",
            evidence=f"{name}: {(launch.strip() or spec.get('url', ''))[:160]}",
            path=str(path), line=_line_of(text, f'"{name}"')))
    return findings


# Un repo que nombra la carpeta de UN agente en muchos archivos es el código de ese
# agente manejando su propia configuración (codex con ~/.codex), no un instalador que
# se cuela en la de otro: eso pasa en uno o dos archivos.
NATIVE_AGENT_FILES = 8
_AGENT_NAME = re.compile(r"\.(claude|codex|gemini|cursor|windsurf|continue|qwen|kimi-code)\b|"
                         r"claude_desktop")


def _native_agents(files: list[tuple[Path, str]]) -> set[str]:
    counts: dict[str, int] = {}
    for path, text in files:
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        names = {m.group(1) or "claude" for line in text.splitlines()
                 if _AGENT_CONFIG.search(line) for m in _AGENT_NAME.finditer(line)}
        for name in names:
            counts[name] = counts.get(name, 0) + 1
    return {name for name, count in counts.items() if count >= NATIVE_AGENT_FILES}


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    native = _native_agents(files)
    for path, text in files:
        posix = path.as_posix()
        if _is_instruction_file(path):
            findings += _check_instructions(path, text)
        elif posix.endswith((".claude/settings.json", ".claude/settings.local.json")):
            findings += _check_claude_settings(path, text)
        elif path.name == ".mcp.json" or posix.endswith((".cursor/mcp.json", ".vscode/mcp.json")):
            findings += _check_mcp_json(path, text)
        elif path.suffix.lower() in CODE_SUFFIXES:
            findings += _check_code(path, text, native)
        elif path.suffix.lower() in DOC_SUFFIXES:
            findings += _scan_for_injection(path, text, doc=True)
    return findings
