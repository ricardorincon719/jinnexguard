"""Patrones peligrosos en el código, con archivo:línea y el fragmento real.

Caza ataques evidentes (curl|bash, reverse shell, eval de contenido ofuscado,
lectura de claves). No pretende cazar al atacante cuidadoso: es un cedazo de
banderas, no una prueba de inocencia.
"""

from __future__ import annotations

import base64
import binascii
import io
import ipaddress
import re
import tokenize
from pathlib import Path

from jinnexguard.engine.report import Finding, Severity
from jinnexguard.engine.textscan import lines_with

MAX_PER_PATTERN_PER_FILE = 3
EVIDENCE_CHARS = 180
# No escanear como "código" lo que claramente es documentación.
SKIP_SUFFIXES = {".md", ".mdx", ".markdown", ".rst", ".adoc", ".txt", ".lock", ".svg", ".csv"}
# Datos/documentación: un comando ahí se MUESTRA, no se ejecuta. Baja 2 niveles.
DOC_DATA_SUFFIXES = {".html", ".htm", ".json", ".ndjson", ".yaml", ".yml", ".xml",
                     ".po", ".pot", ".xliff", ".xlf", ".strings", ".arb", ".resx"}
# Archivos de test: suelen traer el patrón como fixture. Baja 1 nivel.
_TEST_HINT = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata)(/|$)|"
                        r"\.(test|spec)\.|(^|/)test_[^/]+\.py$|_tests?\.\w+$")
# Contenedores y CI: lo que corre ahí no corre en la máquina de quien instala. Baja 2.
_INFRA_HINT = re.compile(r"(^|/)(Dockerfile[^/]*|[^/]+\.dockerfile|Containerfile)$|"
                         r"(^|/)(\.devcontainer|\.github|\.gitlab|\.circleci|ci)/|"
                         r"(^|/)\.gitlab-ci\.ya?ml$", re.IGNORECASE)
# Letras de escrituras de derecha a izquierda (hebreo, árabe, siríaco, thaana, n'ko…).
_RTL_LETTERS = re.compile("[\u0590-\u08ff\ufb1d-\ufdff\ufe70-\ufeff]")
_BIDI_OVERRIDES = re.compile("[\u202a-\u202e]")
# Traducciones: ahí los controles bidi acomodan texto RTL alrededor de un placeholder.
_I18N_HINT = re.compile(r"(^|/)(i18n|l10n|locales?|lang|langs|translations?)/|"
                        r"\.(po|pot|xliff|xlf|strings|arb|resx)$", re.IGNORECASE)
# Código (no shell): un curl|bash ahí se ejecuta solo si la línea lo pasa a un shell;
# si no, se muestra (un botón "copiar comando") o se arma para otra máquina.
_CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".go",
                  ".rs", ".rb", ".java", ".kt", ".swift", ".cs", ".php", ".pl", ".lua",
                  ".vue", ".svelte", ".astro"}
_EXEC_HINT = re.compile(r"\b(?:exec\w*|spawn\w*|system|popen|run|call|check_output|"
                        r"execSync|execa)\s*\(|\b(?:ba|z|da)?sh\s+-c\b|\$`|\bBun\.\$|"
                        r"child_process|shell\s*=\s*True|\bCommand::new\b")
_SHELL_EVAL = re.compile(r"\b(?:ba|z|da)?sh\s+-c\b|\beval\b")
# Un heredoc que no alimenta a un shell es texto (la ayuda de un instalador).
_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
# Una línea que es solo un nombre entre comillas (un elemento de lista): nombra, no ejecuta.
_LIST_ITEM = re.compile(r"""^\s*["'`][\w.-]+["'`]\s*[,;]?\s*$""")
# Tras el nombre entre comillas siguen palabras y no código: "'sudo' is not required".
_PROSE_AFTER = re.compile(r"\s+(?!(?:and|or|if|else|in|for|not|as)\b|is\s+(?:not\s+)?None\b)"
                          r"[a-z]+\s+[a-z]{2,}")
# Verbos de leer, copiar o mandar un archivo: sin ellos, nombrar ~/.ssh/id_rsa no lo toca.
_READS_FILE = re.compile(r"(?i)\b(?:open|read\w*|cat|get-content|load\w*|cp|copy\w*|scp|rsync|"
                         r"upload\w*|send\w*|post|fetch|exfil\w*|tar|zip|base64|curl|wget)\b|"
                         r"\bfs\.|<\s*[~$]")
_HEREDOC_TO_SHELL = re.compile(r"\b(?:ba|z|da)?sh\b|\beval\b|\bsource\b")
_COMMENT = re.compile(r"^\s*(#|//|\*|/\*|<!--|--)")
# Caracteres que cambian cómo se VE el texto sin verse ellos: bidi (Trojan Source),
# ancho cero y "tags" Unicode (texto escondido que un modelo sí lee).
BIDI_CHARS = "\u202a-\u202e\u2066-\u2069"
INVISIBLE_CHARS = re.compile(f"[{BIDI_CHARS}\u200b-\u200d\u2060\U000e0000-\U000e007f]")


# Metadatos de un paquete de Python: llevan el README adentro, son documentación.
PACKAGE_DOC_NAMES = {"METADATA", "PKG-INFO"}


def _role_downgrade(path: Path) -> int:
    levels = 0
    if path.suffix.lower() in DOC_DATA_SUFFIXES or path.name in PACKAGE_DOC_NAMES:
        levels += 2
    posix = str(path).replace("\\", "/")
    if _TEST_HINT.search(posix):
        levels += 1
    if _INFRA_HINT.search(posix):
        levels += 2
    return levels


# Lo que decodifica el comienzo de un base64 dice qué es: una imagen o un certificado
# son datos; un ejecutable o un archivo comprimido escondido en el código, no.
_BLOB_KINDS: tuple[tuple[bytes, str, bool], ...] = (
    (b"\x89PNG", "a PNG image", False), (b"\xff\xd8\xff", "a JPEG image", False),
    (b"GIF8", "a GIF image", False), (b"RIFF", "a RIFF media file (WebP/WAV)", False),
    (b"%PDF", "a PDF document", False), (b"wOF", "a web font", False),
    (b"\x00\x01\x00\x00", "a font", False), (b"OTTO", "a font", False),
    (b"{", "JSON", False), (b"-----BEGIN", "a PEM certificate or key", False),
    (b"\x30\x82", "a DER certificate or key", False), (b"<svg", "an SVG image", False),
    (b"<?xml", "XML", False), (b"\x00asm", "a WebAssembly module", False),
    (b"MZ", "a Windows executable", True), (b"\x7fELF", "a Linux executable", True),
    (b"\xcf\xfa\xed\xfe", "a macOS executable", True), (b"\x1f\x8b", "gzip-compressed data", True),
    (b"PK\x03\x04", "a ZIP archive", True), (b"BZh", "bzip2-compressed data", True),
    (b"\xfd7zXZ", "xz-compressed data", True),
)


def _classify_blob(blob: str, severity: Severity, detail: str) -> tuple[Severity, str]:
    if re.fullmatch(r"[0-9a-fA-F]+", blob) and re.search(r"\d", blob) and re.search(r"[a-fA-F]", blob):
        return Severity.LOW, ("A long hexadecimal number, usually a cryptographic constant "
                              "(a prime, a curve parameter), not code.")
    try:
        head = base64.b64decode(blob[:64] + "=" * (-len(blob[:64]) % 4))
    except (ValueError, binascii.Error):
        return severity, detail
    for magic, kind, suspicious in _BLOB_KINDS:
        if head.startswith(magic):
            if suspicious:
                return Severity.HIGH, (f"It decodes to {kind} hidden inside the code: the usual "
                                       "way to smuggle a payload past a reader.")
            return Severity.LOW, f"It decodes to {kind}: embedded data, not code."
    return severity, detail


def _heredoc_text_lines(text: str) -> set[int]:
    """Líneas (desde 1) dentro de heredocs que se imprimen o guardan, no se ejecutan."""
    inside: set[int] = set()
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        match = _HEREDOC_OPEN.search(lines[index])
        if not match:
            index += 1
            continue
        executed = bool(_HEREDOC_TO_SHELL.search(lines[index][:match.start()]))
        end = index + 1
        while end < len(lines) and lines[end].strip() != match.group(2):
            end += 1
        if not executed:
            inside.update(range(index + 2, end + 1))
        index = end + 1
    return inside


def _docstring_lines(text: str) -> set[int]:
    """Líneas (desde 1) de los docstrings de un archivo Python: texto, no se ejecutan.

    Cuenta como docstring una cadena que es una sentencia entera (nadie la asigna ni la
    pasa a nada). Si el archivo usa el atributo del docstring, no hay rebaja: pasárselo
    a exec es la forma de ejecutarlo.
    """
    lines: set[int] = set()
    previous = tokenize.NEWLINE   # tipo del último token significativo
    pending: tokenize.TokenInfo | None = None
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type in (tokenize.NL, tokenize.COMMENT):
                continue
            if token.type == tokenize.NAME and token.string == "__doc__":
                return set()
            if pending is not None and token.type == tokenize.NEWLINE:
                lines.update(range(pending.start[0], pending.end[0] + 1))
            pending = None
            if token.type == tokenize.STRING and previous in (
                    tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING):
                pending = token
            previous = token.type
    except (tokenize.TokenError, SyntaxError, IndentationError):
        # Python roto o viejo: lo visto hasta ahí vale, salvo que más abajo pueda
        # estar el uso del atributo que no se llegó a leer.
        return set() if "__doc__" in text else lines
    return lines


# Marcador de comentario a mitad de línea, según el lenguaje.
_HASH_COMMENT_SUFFIXES = {".py", ".pyi", ".rb", ".pl", ".sh", ".bash", ".zsh", ".fish", "",
                          ".yml", ".yaml", ".toml", ".ps1", ".r"}
_SLASH_COMMENT_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx", ".go",
                           ".rs", ".java", ".kt", ".swift", ".cs", ".php", ".vue", ".svelte",
                           ".c", ".h", ".cc", ".cpp", ".hpp"}


def _in_trailing_comment(line: str, index: int, suffix: str) -> bool:
    """¿La posición `index` cae en un comentario que empieza a mitad de línea?

    El marcador cuenta si está fuera de comillas y tras un espacio: así `$#`, `${#x}`
    o el `//` de una URL no pasan por comentario.
    """
    marker = ("#" if suffix in _HASH_COMMENT_SUFFIXES
              else "//" if suffix in _SLASH_COMMENT_SUFFIXES else "")
    if not marker:
        return False
    start = line.find(marker)
    while 0 < start < index:
        if line[start - 1] in " \t" and not _in_string(line, start):
            return True
        start = line.find(marker, start + 1)
    return False


def _in_string(line: str, index: int) -> bool:
    """¿La posición `index` cae dentro de una cadena entre comillas de esa línea?

    Heurística de una línea (no ve cadenas multilínea): basta para distinguir
    `"postinstall": "curl x | sh"` de un `curl x | sh` que se ejecuta.
    """
    quote, escaped = "", False
    for char in line[:index]:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            quote = "" if char == quote else quote
        elif char in "'\"`":
            quote = char
    return bool(quote)


def _adjust(severity: Severity, downgrade: int) -> Severity:
    return Severity(max(int(Severity.INFO), int(severity) - downgrade))

# (regex, severidad, título, detalle). Se evalúan por línea.
LINE_PATTERNS: tuple[tuple[re.Pattern, Severity, str, str], ...] = (
    # `| python3 -m json.tool` o `| node -e "…"` corren su propio código: lo bajado es dato.
    (re.compile(r"\b(?:curl|wget)\s+[^\s|][^\n|]{0,200}\|\s*(?:sudo\s+)?(?:[\w/]*/)?(?:bash|sh|zsh|python3?|node)\b"
                r"(?!\s+-[cmep]\b)"),
     Severity.CRITICAL, "Downloads and runs a remote script (curl|bash)",
     "Fetches code from the internet and runs it right away; nobody sees what it is."),
    (re.compile(r"/dev/tcp/\d|(?<!\w)nc\s+-e\s|bash\s+-i\b[^\n]*/dev/tcp"),
     Severity.CRITICAL, "Reverse shell pattern",
     "Opens a connection back to a server for remote control."),
    (re.compile(r"base64\s+(?:--decode|-d|-D)\b[^\n|]{0,120}\|\s*(?:bash|sh|zsh|python3?)"),
     Severity.HIGH, "base64 decoded and run in a shell",
     "Hides the real command in base64 to get past a quick read."),
    (re.compile(r"eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\("),
     Severity.HIGH, "eval of decoded/obfuscated content (JS)",
     "Runs code that is decoded first: typical payload obfuscation."),
    # exec(zlib.decompress(base64.b64decode(…))) y variantes: las capas no cambian la idea.
    (re.compile(r"(?:exec|eval)\s*\(\s*(?:(?:__import__\(['\"]\w+['\"]\)|zlib|gzip|bz2|lzma|marshal)"
                r"\.(?:decompress|loads)\s*\(\s*)*(?:base64\.b(?:64|32|85)decode|bytes\.fromhex|"
                r"codecs\.decode|__import__\(['\"]base64|marshal\.loads)"),
     Severity.HIGH, "exec/eval of decoded content (Python)",
     "Runs bytes decoded on the fly: typical payload obfuscation."),
    (re.compile(r"\bnew\s+Function\s*\("),
     Severity.MEDIUM, "Dynamic code construction (new Function)",
     "Builds code at runtime; sometimes legitimate, but worth a look."),
    (re.compile(r"""["'`](?:sudo|pkexec|doas)["'`]|^[ \t]*(?:sudo|pkexec|doas)\s+[\w/$"'-]""",
                re.MULTILINE),
     Severity.MEDIUM, PRIVILEGE_TITLE := "Asks for root privileges (sudo/pkexec/doas)",
     "Whatever runs there can touch the whole system; check which command it elevates and "
     "whether it asks first."),
    (re.compile(f"[{BIDI_CHARS}]"),
     Severity.HIGH, BIDI_TITLE := "Invisible bidi characters (Trojan Source)",
     "They reorder how the line looks versus how it runs: what you read is not what runs."),
    # Los tokens de npm, PyPI, git, Docker, Kubernetes y gh viven en archivos del home.
    (re.compile(r"\.ssh/id_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws/credentials\b|"
                r"(?:~|homedir\(\)|\$HOME|\bHOME\b|expanduser\(|Path\.home\(\)|USERPROFILE)"
                r"[^\n]{0,40}?[/\\]\.(?:npmrc|pypirc|git-credentials|netrc|docker[/\\]config\.json|"
                r"kube[/\\]config|config[/\\]gh[/\\]hosts\.yml)\b"),
     Severity.MEDIUM, CREDENTIALS_TITLE := "Accesses the user's keys or credentials",
     "Reads sensitive material from the machine; suspicious unless it is an SSH/AWS tool."),
    # Lo comprimido o cifrado que termina en un shell: nadie lee lo que corre (xz-utils).
    (re.compile(r"(?:\b(?:xz|unxz|xzcat|lzma|gunzip|zcat|bunzip2|bzcat)\b|\bgzip\s+-d|"
                r"\bopenssl\s+(?:enc|aes\S*)\b)[^\n|]*(?:\|[^\n|]*){0,6}\|\s*(?:sudo\s+)?"
                r"(?:[\w/]*/)?(?:bash|sh|zsh)\b"),
     Severity.HIGH, "Decompressed or decrypted data run in a shell",
     "The command that runs is hidden inside compressed or encrypted bytes."),
    (re.compile(r"\b(?:eval|Function)\s*\(\s*(?:await\s+)?(?!document\b|window\b)\w+(?:\.\w+)*?\."
                r"(?:data|body|responseText|text\(\))\b|\b(?:exec|eval)\s*\([^\n]{0,120}?"
                r"\b(?:urlopen|requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request)\b"),
     Severity.HIGH, "Runs code downloaded from the network",
     "Whatever the server sends is executed; it can change at any time, after any review."),
    (re.compile(r"JSON\.stringify\(\s*process\.env\s*[,)]|"
                r"\b(?:str|repr|json\.dumps)\(\s*(?:dict\(\s*)?os\.environ\b(?!\s*[.\[])|"
                r"b64encode\([^\n]{0,40}\benviron\b"),
     Severity.MEDIUM, ENV_TITLE := "Collects every environment variable",
     "Environment variables hold tokens and keys; serialising all of them is how many "
     "stealers grab them."),
    (re.compile(r"\b(?:webhook\.site|(?:discord(?:app)?\.com|ptb\.discord\.com)/api/webhooks|"
                r"pipedream\.net|requestbin\.(?:com|net)|[\w-]+\.oast\.(?:fun|pro|live|site|online|me)|"
                r"interact\.sh|burpcollaborator\.net)\b"),
     Severity.MEDIUM, "Sends data to a known collection endpoint",
     "Services built to receive arbitrary requests: a favourite drop for stolen data."),
    (re.compile(r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|"
                r"--yolo\b|--trust-all-tools\b"),
     Severity.HIGH, AGENT_CLI_TITLE := "Launches an AI agent with its safeguards off",
     "The agent runs any command without asking; malware has used local AI CLIs this way to "
     "hunt for secrets."),
    # Solo el módulo armado a mano: `module._compile` a secas es lo que hace cualquier loader.
    (re.compile(r"\bnew\s+module\.constructor\b"),
     Severity.MEDIUM, "Compiles code through the module loader (JS)",
     "Turns a string into a module at runtime; legitimate in loaders, also how event-stream "
     "ran its hidden payload."),
)

# Literales que toda línea marcada por LINE_PATTERNS[i] contiene: el prefiltro barato.
LINE_LITERALS: tuple[tuple[str, ...], ...] = (
    ("curl", "wget"),
    ("/dev/tcp", "-e"),
    ("base64",),
    ("eval",),
    ("exec", "eval"),
    ("Function",),
    ("sudo", "pkexec", "doas"),
    tuple(chr(c) for c in (*range(0x202a, 0x202f), *range(0x2066, 0x206a))),
    (".ssh/id_", ".aws/credentials", ".npmrc", ".pypirc", ".git-credentials", ".netrc",
     "config.json", "kube", "hosts.yml"),
    ("xz", "lzma", "zcat", "gunzip", "gzip", "bunzip2", "bzcat", "openssl"),
    ("eval", "exec", "Function"),
    ("environ", "process.env"),
    ("webhook.site", "discord", "pipedream", "requestbin", ".oast.", "interact.sh",
     "burpcollaborator"),
    ("--dangerously-", "--yolo", "--trust-all-tools"),
    ("module.constructor",),
)
# Lo que hace que volcar el entorno sea mandarlo o esconderlo, no un print de depuración.
_SENDS_OR_ENCODES = re.compile(r"requests\.|urlopen|fetch\(|axios|https?\b|b64encode|btoa|"
                               r"Buffer\.from|\.post\(|\.send\(")
# El nombre de un CLI de agentes en la línea: la bandera se usa, no se define ni se documenta.
_AGENT_CLI = re.compile(r"""(?:^|[\s"'`\[(])(?:claude|gemini|codex|qwen|q|cursor-agent|amp|"""
                        r"""opencode)(?:["'`]|\s)""")
_IP_LITERALS = ("http",)
# Un bidi dentro de una cadena puede ser un ataque (la "cadena estirada" de Trojan
# Source) o la lista de caracteres de un detector: la severidad no baja, pero el
# detalle dice cómo dejarlo inofensivo.
BIDI_IN_STRING_DETAIL = (
    "They are inside a string. If that is intended (e.g. the list a detector looks for), "
    "write them as escapes (`\\u202e`): they stay visible in the code and do not reorder the "
    "line in the editor. If not, the text you read is not the text that runs.")

BIDI_RTL_DETAIL = (
    "Isolate characters (U+2066–2069) on a line with right-to-left text: the standard way to "
    "mix Arabic or Hebrew with a file name or a variable. Low risk, shown for completeness.")

# Patrones a nivel de archivo (una bandera por archivo).
BLOB_PATTERNS: tuple[tuple[re.Pattern, Severity, str, str], ...] = (
    (re.compile(r"['\"][A-Za-z0-9+/]{300,}={0,2}['\"]"),
     Severity.MEDIUM, "Long encoded string (possible obfuscated payload)",
     "A huge base64 literal can be an executable or hidden data."),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){100,}"),
     Severity.MEDIUM, HEX_TITLE := "Long hexadecimal string (possible obfuscated payload)",
     "Chained \\xNN bytes often hide code or data."),
)


# Nombres de API escritos en hexadecimal: nadie esconde "child_process" sin motivo
# (event-stream guardaba así `_compile` y `createDecipher`).
_HEX_LITERAL = re.compile(r"""["'`]((?:[0-9a-fA-F]{2}){4,64})["'`]""")
_HIDDEN_NAME = re.compile(
    r"_compile|child_process|createDecipher\w*|\beval\b|\bexec\w*|\bspawn\w*|"
    r"\brequire\b|\bprocess\b|npm_package\w*|fromCharCode|\bFunction\b|\bos\.system\b|"
    r"\bsubprocess\b|\bsocket\b|urlopen|https?://|/bin/(?:ba)?sh\b")


def _hidden_hex_names(text: str) -> list[tuple[int, str, str]]:
    """(línea, literal, texto) de los literales hex que decodifican a un nombre sensible."""
    found = []
    for match in _HEX_LITERAL.finditer(text):
        try:
            decoded = bytes.fromhex(match.group(1)).decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and _HIDDEN_NAME.search(decoded):
            found.append((text.count("\n", 0, match.start()) + 1, match.group(1), decoded))
    return found


_IP_URL = re.compile(r"https?://((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")


def _ip_url_signal(line: str) -> tuple[Severity, str, str] | None:
    """La señal de la IP más preocupante de la línea: pública > LAN > loopback."""
    worst = None
    for match in _IP_URL.finditer(line):
        try:
            ip = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified:
            signal = (Severity.INFO, "URL to a local address (loopback)",
                      "Points at the machine itself: typical of tests and local services.")
        elif ip.is_private or ip.is_link_local or not ip.is_global:   # LAN, Tailscale, docs
            signal = (Severity.LOW, "URL to a private network IP",
                      "Points at the local network (LAN): normal for home automation or "
                      "self-hosted services.")
        else:
            signal = (Severity.MEDIUM, "URL pointing at a hardcoded public IP",
                      "Downloads/calls to a raw IP, with no domain, are often C2 or a "
                      "second-stage payload.")
        if worst is None or signal[0] > worst[0]:
            worst = signal
    return worst


def _snippet(line: str) -> str:
    # Lo invisible se muestra escapado: la evidencia tiene que dejar ver la trampa.
    line = INVISIBLE_CHARS.sub(lambda m: m.group(0).encode("unicode_escape").decode(), line.strip())
    return line if len(line) <= EVIDENCE_CHARS else line[:EVIDENCE_CHARS - 1] + "…"


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        role = _role_downgrade(path)   # dónde está el archivo pesa en la severidad
        posix = str(path).replace("\\", "/")
        is_test = bool(_TEST_HINT.search(posix))
        is_i18n = bool(_I18N_HINT.search(posix))
        suffix = path.suffix.lower()
        is_shell = suffix in {"", ".sh", ".bash", ".zsh", ".fish"}
        heredoc = _heredoc_text_lines(text) if is_shell and "<<" in text else set()
        docstrings: set[int] | None = None   # se calculan solo si hay candidatos
        counts: dict[int | str, int] = {}
        # Solo las líneas con el literal de algún patrón pasan por su regex.
        candidates: dict[int, tuple[str, list[int]]] = {}
        for index, literals in enumerate(LINE_LITERALS):
            for lineno, line in lines_with(text, literals):
                candidates.setdefault(lineno, (line, []))[1].append(index)
        ip_lines: set[int] = set()
        for lineno, line in lines_with(text, _IP_LITERALS):
            candidates.setdefault(lineno, (line, []))
            ip_lines.add(lineno)
        for lineno in sorted(candidates):
            line, indexes = candidates[lineno]
            if docstrings is None:
                docstrings = (_docstring_lines(text) if suffix in {".py", ".pyi"}
                              and ('"""' in text or "'''" in text) else set())
            # Un comentario, un docstring o el texto de un heredoc no se ejecutan.
            downgrade = role + (2 if _COMMENT.match(line) or lineno in heredoc
                                or lineno in docstrings else 0)
            for index in indexes:
                pattern, severity, title, detail = LINE_PATTERNS[index]
                if counts.get(index, 0) >= MAX_PER_PATTERN_PER_FILE:
                    continue
                match = pattern.search(line)
                if match:
                    counts[index] = counts.get(index, 0) + 1
                    quoted = _in_string(line, match.start())
                    # En un test, un comando entre comillas es lo que el test espera encontrar.
                    extra = 1 if quoted and is_test else 0
                    if not downgrade - role and _in_trailing_comment(line, match.start(), suffix):
                        extra += 2   # `codigo  # comentario`: lo comentado no corre
                    if index == 0 and not is_test:
                        if suffix in _CODE_SUFFIXES and not _EXEC_HINT.search(line):
                            extra += 1
                        elif is_shell and quoted and not _SHELL_EVAL.search(line):
                            extra += 1   # un echo "curl … | sh" de ayuda
                    if title == CREDENTIALS_TITLE and not _READS_FILE.search(line):
                        extra += 1   # un placeholder o un texto de ayuda que nombra la ruta
                    if title == ENV_TITLE and _SENDS_OR_ENCODES.search(line):
                        severity = Severity.HIGH
                    if title == AGENT_CLI_TITLE and not _AGENT_CLI.search(line):
                        extra += 2   # el propio CLI definiendo o probando su bandera
                    if title == PRIVILEGE_TITLE and (_LIST_ITEM.match(line) or (
                            match.group()[0] in "\"'`" and _PROSE_AFTER.match(line, match.end()))):
                        severity = Severity.LOW   # "sudo", en una lista de nombres o en una frase
                    if title == BIDI_TITLE and (is_i18n or (
                            _RTL_LETTERS.search(line) and not _BIDI_OVERRIDES.search(line))):
                        # Aislantes (U+2066–2069) junto a texto RTL: el uso correcto al
                        # mezclar árabe/hebreo con un nombre de archivo o una variable.
                        severity, detail = Severity.LOW, BIDI_RTL_DETAIL
                    elif quoted and title == BIDI_TITLE:
                        detail = BIDI_IN_STRING_DETAIL
                    findings.append(Finding(
                        _adjust(severity, downgrade + extra), "dangerous-pattern",
                        f"{title} ({path})", detail,
                        evidence=_snippet(line), path=str(path), line=lineno))
            signal = _ip_url_signal(line) if lineno in ip_lines else None
            if signal and counts.get(signal[1], 0) < MAX_PER_PATTERN_PER_FILE:
                severity, title, detail = signal
                counts[signal[1]] = counts.get(signal[1], 0) + 1
                findings.append(Finding(
                    _adjust(severity, downgrade), "dangerous-pattern",
                    f"{title} ({path})", detail,
                    evidence=_snippet(line), path=str(path), line=lineno))
        for pattern, severity, title, detail in BLOB_PATTERNS:
            if title == HEX_TITLE and "\\x" not in text:
                continue
            match = pattern.search(text)
            if match:
                if title != HEX_TITLE:
                    severity, detail = _classify_blob(match.group(0)[1:-1], severity, detail)
                findings.append(Finding(
                    _adjust(severity, role), "dangerous-pattern",
                    f"{title} ({path})", detail,
                    evidence=f"{match.group(0)[:40]}… ({len(match.group(0))} characters)",
                    path=str(path), line=text.count("\n", 0, match.start()) + 1))
        hidden = _hidden_hex_names(text) if '"' in text or "'" in text else []
        if hidden:
            # Sin rebaja por test: un fixture no necesita esconder nombres de API.
            lineno, literal, decoded = hidden[0]
            findings.append(Finding(
                _adjust(Severity.HIGH, role - (1 if is_test else 0)), "dangerous-pattern",
                f"API names hidden in hexadecimal strings ({path})",
                "Writing names like `_compile` or `child_process` in hex only serves to hide "
                "them from a reader or a scanner.",
                evidence="; ".join(f"{lit[:24]} → {dec[:40]}" for _, lit, dec in hidden[:4])
                         + (f"  (+{len(hidden) - 4} more)" if len(hidden) > 4 else ""),
                path=str(path), line=lineno))
    return findings
