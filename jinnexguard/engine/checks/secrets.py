"""Secretos escritos en el código: tokens con formato conocido y asignaciones.

Dos pasadas con los mismos detectores:
  - `run(files)`: el estado actual del repo (como los demás chequeos).
  - `run_history(root, files)`: las líneas agregadas en todo el historial de git,
    para cazar claves que se borraron del código pero siguen en los commits.

La evidencia NUNCA lleva el secreto completo: solo los primeros caracteres y el
largo, para que el reporte se pueda compartir sin filtrar nada.
"""

from __future__ import annotations

import math
import re
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator
from itertools import chain, pairwise
from pathlib import Path

from jinnexguard.engine.checks.dangerous_patterns import _TEST_HINT, _adjust
from jinnexguard.engine.fetch import SAFE_GIT_FLAGS, safe_git_env
from jinnexguard.engine.report import Finding, Severity
from jinnexguard.engine.textscan import lines_with

MAX_PER_FILE = 5
MAX_HISTORY_FINDINGS = 50
HISTORY_TIMEOUT = 120
EVIDENCE_CHARS = 180
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "Cargo.lock", "go.sum", "composer.lock", "uv.lock"}
SKIP_SUFFIXES = {".lock", ".svg", ".min.js", ".map"}

# Formatos de proveedor: si aparece, casi seguro es una credencial real.
KNOWN_TOKENS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub token (fine-grained)"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic key"),
    (re.compile(r"\bsk-or-v1-[a-f0-9]{40,}\b"), "OpenRouter key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"), "OpenAI-style key (sk-…)"),
    (re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "Stripe key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b"), "Telegram bot token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
     "private key"),
)

_SECRET_WORD = (r"(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|"
                r"access[_-]?key|private[_-]?key|local[_-]?key|client[_-]?secret|auth[_-]?pin)"
                r"(?![a-z])")   # "tokenizer", "secretary" no son credenciales
# NOMBRE = "valor" / "nombre": "valor" en código, JSON, YAML con comillas.
ASSIGNMENT = re.compile(
    r"(?i)\b([\w.-]*" + _SECRET_WORD + r"\w*)[\"']?\s*(?::|=|:=|=>)\s*[\"']([^\"'\s]{8,})[\"']")
# NOMBRE=valor sin comillas, solo en archivos .env*.
ENV_ASSIGNMENT = re.compile(
    r"^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PIN)[A-Z0-9_]*)"
    r"\s*=\s*[\"']?([^\"'\s#]{8,})")
_PLACEHOLDER_HINTS = ("example", "changeme", "change_me", "change-me", "your", "tu-", "tu_",
                      "placeholder", "dummy", "fake", "mock", "sample", "synthetic", "fixture",
                      "xxxx", "redacted", "replace", "todo", "<", ">", "${", "{{", "%(",
                      "***", "...", "…", "[%key:")
# Valores que se describen a sí mismos ("request-body-secret-value", "test-token-1"):
# una clave real no lleva la palabra "token" ni empieza con "test".
_SELF_DESCRIBING = re.compile(r"(?i)^test|token|secret|passw|^[a-z]+(?:[-_][a-z]+){2,}$|"
                              r"^[a-z]{3,}(?:[-_][a-z]+)*[-_]\d{1,4}$|"   # "invite-123"
                              r"^[a-z]+\d*(?:[A-Z][a-z]{2,}\d*)+$|^(?:[A-Z][a-z]{2,}\d*){2,}$|"  # camelCase
                              r"^[a-z]{3,}\d{1,2}$")   # "pcharge1": un nombre de campo
# Un nombre de archivo o de unidad ("…-9241ee6a.scope", "server.key") nombra algo, no es la clave.
_NAME_SUFFIX = re.compile(r"(?i)\.(?:scope|service|socket|slice|timer|target|mount|json|ya?ml|"
                          r"toml|ini|txt|log|db|sqlite|py|js|ts|sh|pem|crt|key|pub)$")


# "1234567890abcdef", "abcdefgh…": relleno de ejemplo. En un token aleatorio de 62
# símbolos, 8 caracteres seguidos en orden salen una vez en ~10^14: no pasa.
_SEQUENCES = ("01234567890123456789", "abcdefghijklmnopqrstuvwxyz")
FAKE_RUN = 8


def _has_sequence(value: str) -> bool:
    lower = value.lower()
    for sequence in (*_SEQUENCES, *(s[::-1] for s in _SEQUENCES)):
        if any(sequence[i:i + FAKE_RUN] in lower for i in range(len(sequence) - FAKE_RUN + 1)):
            return True
    return False


# Toda línea que algún detector podría marcar contiene una de estas piezas (en
# minúsculas): sirve de prefiltro barato antes de las expresiones caras.
_HINT_LITERALS = ("key", "secret", "token", "pass", "pin", "ghp_", "gho_", "ghu_", "ghs_",
                  "ghr_", "github_pat_", "sk-", "sk_live_", "rk_live_", "akia", "aiza",
                  "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", ":aa")


def _candidate_lines(text: str) -> list[tuple[int, str]]:
    return lines_with(text, _HINT_LITERALS, lower=True)


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _looks_like_secret(value: str) -> bool:
    lower = value.lower()
    if any(hint in lower for hint in _PLACEHOLDER_HINTS):
        return False
    if re.fullmatch(r"[A-Z0-9_]+", value) and "_" in value:   # nombre de otra variable
        return False
    if "://" in value or value.startswith(("/", "~", "$", "%")) or "(" in value:
        return False
    if len(set(value)) <= 3:                                  # "aaaaaaaa", "00000000"
        return False
    if _has_sequence(value):                                  # "1234567890abcdef"
        return False
    if re.fullmatch(r"0x[0-9a-fA-F]+", value):                # un número en hex, no una clave
        return False
    if _SELF_DESCRIBING.search(value):
        return False
    if _NAME_SUFFIX.search(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    # Un valor sin números ("refresh_token", "x-api-key") suele ser un nombre, no una clave.
    return (has_digit and has_alpha) or (len(value) >= 20 and _entropy(value) >= 3.5)


def _mask(value: str) -> str:
    return (value[:4] if len(value) > 8 else "") + "…"


def _evidence(line: str, value: str) -> str:
    masked = line.strip().replace(value, _mask(value))
    if len(masked) > EVIDENCE_CHARS:
        masked = masked[:EVIDENCE_CHARS - 1] + "…"
    return f"{masked}  ({len(value)} characters)"


def _skipped(path: Path) -> bool:
    name = path.name
    return name in SKIP_NAMES or any(name.endswith(s) for s in SKIP_SUFFIXES)


def _is_env_file(path: Path) -> bool:
    return path.name == ".env" or path.name.startswith(".env.")


# Cuerpo base64 de una clave PEM: sin él, "-----BEGIN … PRIVATE KEY" es documentación
# o código que busca ese encabezado, no una clave.
_KEY_BODY = re.compile(r"[A-Za-z0-9+/]{40,}")
# Un nombre que se declara falso (TEST_KEY, fake_token, DUMMY_SECRET…) baja 2 niveles.
_FAKE_NAME = re.compile(r"(?i)(?:^|[^a-z])(?:test|fake|dummy|mock|example|sample)(?:[^a-z]|$)")


def _scan(path: Path, lines: Iterable[tuple[int | None, str]],
          after: Callable[[int | None], str] | None = None
          ) -> Iterator[tuple[Severity, str, str, int | None, str]]:
    """Entrega (severidad, qué es, evidencia enmascarada, línea, valor) por secreto.

    `after(línea)` devuelve el texto que sigue a esa línea (para ver el cuerpo de una
    clave privada que empieza en la línea siguiente).
    """
    env_file = _is_env_file(path)
    real_env = path.name == ".env"
    for lineno, line in lines:
        seen: set[str] = set()
        for pattern, label in KNOWN_TOKENS:
            for match in pattern.finditer(line):
                value = match.group(0)
                if value in seen:
                    continue
                if "PRIVATE KEY" in value:
                    body = line[match.end():] + "\n" + (after(lineno) if after else "")
                    if not _KEY_BODY.search(body):
                        continue
                elif not _looks_like_secret(value):
                    continue
                seen.add(value)
                down = 2 if _FAKE_NAME.search(line[:match.start()]) else 0
                yield _adjust(Severity.HIGH, down), label, _evidence(line, value), lineno, value
        generic = ENV_ASSIGNMENT if env_file else ASSIGNMENT
        for match in generic.finditer(line):
            name, value = match.group(1), match.group(2)
            if value in seen or not _looks_like_secret(value):
                continue
            seen.add(value)
            # Un .env real subido es peor que un valor en .env.example o en el código.
            severity = Severity.HIGH if real_env else Severity.MEDIUM
            if _FAKE_NAME.search(name):
                severity = _adjust(severity, 2)
            yield severity, f"hardcoded value in {name}", _evidence(line, value), lineno, value


_DOCS_DIR = re.compile(r"(^|/)docs?/")


def _downgrade(path: Path) -> int:
    # Un test suele traer credenciales falsas como fixture, y docs/ trae salidas de
    # ejemplo; el .env de ejemplo no se baja.
    posix = str(path).replace("\\", "/")
    return 1 if _TEST_HINT.search(posix) or _DOCS_DIR.search(posix) else 0


def _following(text: str) -> Callable[[int | None], str]:
    lines = text.splitlines()
    return lambda lineno: "\n".join(lines[lineno:lineno + 2]) if lineno else ""


def _current_values(files: list[tuple[Path, str]]) -> set[str]:
    return {value for path, text in files if not _skipped(path)
            for *_, value in _scan(path, _candidate_lines(text), _following(text))}


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        if _skipped(path):
            continue
        down = _downgrade(path)
        for count, (severity, label, evidence, lineno, _value) in enumerate(
                _scan(path, _candidate_lines(text), _following(text))):
            if count >= MAX_PER_FILE:
                break
            # Claves de certificados de prueba (localhost.key): en tests, uno más abajo.
            extra = 1 if down and label == "private key" else 0
            findings.append(Finding(
                _adjust(severity, down + extra), "secret",
                f"Possible secret in the code: {label} ({path})",
                "A credential written in the repo can be used by anyone who reads it. "
                "Rotate it and move it to an environment variable.",
                evidence=evidence, path=str(path), line=lineno))
    return findings


def _git_log(root: Path) -> subprocess.Popen:
    cmd = [
        "git", "-C", str(root), *SAFE_GIT_FLAGS, "-c", "log.showSignature=false",
        "--no-pager", "log", "--all", "-p", "--unified=0", "--no-color",
        "--no-ext-diff", "--no-textconv", "--format=%x00commit %h %ad", "--date=short",
    ]
    return subprocess.Popen(cmd, env=safe_git_env(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                            errors="replace")


def run_history(root: Path, files: list[tuple[Path, str]]) -> tuple[list[Finding], dict]:
    """Secretos agregados en algún commit que YA NO están en el código actual.

    Los que siguen en el código ya los reporta `run`; acá solo va lo que un
    lector del estado actual no ve. Requiere que `root` tenga su `.git`.
    """
    if not (root / ".git").exists():
        raise RuntimeError("not a git repository (no .git): there is no history to check")
    current = _current_values(files)
    found: dict[str, dict] = {}       # valor -> datos del hallazgo y archivos donde aparece
    commits = 0
    truncated = False
    commit = ""
    path: Path | None = None
    deadline = time.monotonic() + HISTORY_TIMEOUT
    proc = _git_log(root)
    try:
        # De a pares: la línea siguiente puede traer el cuerpo de una clave privada.
        for raw, upcoming in pairwise(chain(proc.stdout, [""])):
            if raw.startswith("\x00commit "):
                commit = raw[len("\x00commit "):].strip()
                commits += 1
                if time.monotonic() > deadline:
                    truncated = True
                    break
                continue
            if raw.startswith("+++ "):
                target = raw[4:].strip()
                path = Path(target[2:]) if target.startswith("b/") else None
                continue
            if path is None or not raw.startswith("+") or _skipped(path):
                continue
            body = upcoming[1:] if upcoming.startswith("+") else ""
            for severity, label, evidence, _line, value in _scan(
                    path, [(None, raw[1:])], lambda _lineno: body):
                if value in current:
                    continue
                # git log va del más nuevo al más viejo: se pisa hasta quedar con el
                # commit que lo introdujo y el archivo donde apareció primero.
                entry = found.setdefault(value, {"places": set()})
                entry.update(severity=_adjust(severity, _downgrade(path)), label=label,
                             evidence=evidence, path=str(path), commit=commit)
                entry["places"].add(str(path))
            if len(found) >= MAX_HISTORY_FINDINGS:
                truncated = True
                break
    finally:
        proc.kill()
        proc.wait()
        proc.stdout.close()

    findings = []
    for entry in found.values():
        others = len(entry["places"]) - 1
        also = f" (and in {others} more file(s))" if others else ""
        findings.append(Finding(
            entry["severity"], "secret-history",
            f"Secret in the git history: {entry['label']} ({entry['path']})",
            "It is no longer in the current code, but it is still in the commits: anyone with "
            "access to the repo can recover it. If the credential is still valid, rotate it.",
            evidence=f"{entry['evidence']}  · added in {entry['commit']}{also}",
            path=entry["path"]))
    context = {"history_commits_scanned": commits}
    if truncated:
        context["history_truncated"] = True
    return findings, context
