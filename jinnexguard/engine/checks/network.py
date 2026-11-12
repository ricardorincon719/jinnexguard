"""A dónde habla el código: hosts nombrados y desvíos del tráfico del agente de IA.

Dos cosas distintas:

- Inventario: los hosts que aparecen en URLs fuera de la documentación y de los
  tests. No es una acusación (un hallazgo `info`): es la lista que una persona
  quiere ver antes de darle red a un servidor MCP o a una herramienta.
- `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` y parecidas apuntando a un servidor que
  no es el del proveedor: todo lo que el agente lee y escribe, y la clave o el
  token, pasan por ahí. Acá la documentación sí cuenta (con rebaja): el ataque
  típico es un README o un instalador que le pide al usuario exportar la variable.

Solo se leen literales; nunca se resuelve ni se contacta ningún host.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from jinnexguard.engine.checks.dangerous_patterns import (
    _COMMENT, _TEST_HINT, SKIP_SUFFIXES, _adjust, _snippet)
from jinnexguard.engine.report import Finding, Severity
from jinnexguard.engine.textscan import lines_with

CATEGORY = "network"
MAX_PER_TITLE_PER_FILE = 3
MAX_HOSTS_SHOWN = 40

# --- Inventario de hosts ---
_URL_HOST = re.compile(r"(?:https?|wss?)://([A-Za-z0-9.-]+)(.?)")
_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
              "bun.lock", "Cargo.lock", "uv.lock", "poetry.lock", "Pipfile.lock", "go.sum",
              "composer.lock", "Gemfile.lock", "flake.lock"}
_INVENTORY_SKIP_SUFFIXES = SKIP_SUFFIXES | {".map", ".snap", ".html", ".htm", ".po", ".pot"}
# Identificadores con forma de URL (espacios de nombres, esquemas, licencias): nadie los llama.
_REFERENCE_HOSTS = {"www.w3.org", "w3.org", "json-schema.org", "schemas.microsoft.com",
                    "schemas.android.com", "schemas.xmlsoap.org", "schemas.openxmlformats.org",
                    "purl.org", "xmlns.com", "ns.adobe.com", "www.apache.org", "apache.org",
                    "opensource.org", "creativecommons.org", "www.gnu.org", "spdx.org",
                    "maven.apache.org", "www.omg.org", "xml.org", "www.xml.org"}
_RESERVED_TLDS = ("example", "test", "invalid", "localhost", "local", "internal", "lan")
_EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net")
_TLD = re.compile(r"[a-z]{2,24}")


def _is_placeholder(host: str) -> bool:
    return (host.rsplit(".", 1)[-1] in _RESERVED_TLDS[:3]
            or any(host == d or host.endswith("." + d) for d in _EXAMPLE_DOMAINS))


def _is_local(host: str) -> bool:
    """La máquina misma o la red local: lo que no sale a internet."""
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    return ("." not in host or host == "host.docker.internal"
            or host.rsplit(".", 1)[-1] in _RESERVED_TLDS[3:])


def _public_host(raw: str) -> str | None:
    """El host en minúsculas si es un destino de internet con nombre o IP reales."""
    host = raw.lower().strip(".-")
    if not host or _is_placeholder(host) or _is_local(host) or host in _REFERENCE_HOSTS:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if not _TLD.fullmatch(labels[-1]) or any(not label for label in labels):
        return None
    return host


def _inventory(files: list[tuple[Path, str]]) -> list[Finding]:
    hosts: dict[str, set[str]] = {}
    for path, text in files:
        posix = path.as_posix()
        if path.suffix.lower() in _INVENTORY_SKIP_SUFFIXES or path.name in _LOCKFILES \
                or _TEST_HINT.search(posix):
            continue
        for _lineno, line in lines_with(text, ("://",)):
            if _COMMENT.match(line):
                continue   # licencias y enlaces en comentarios: no los llama nadie
            for match in _URL_HOST.finditer(line):
                if match.group(2) in ("{", "$", "%", "<", "@", "\\"):
                    continue   # host armado al correr, o usuario@host
                host = _public_host(match.group(1))
                if host:
                    hosts.setdefault(host, set()).add(posix)
    if not hosts:
        return []
    ranked = sorted(hosts, key=lambda h: (-len(hosts[h]), h))
    shown = [f"{h} ({len(hosts[h])} files)" if len(hosts[h]) > 1 else h
             for h in ranked[:MAX_HOSTS_SHOWN]]
    more = len(ranked) - len(shown)
    # En modo paquete todos los archivos cuelgan del nombre del artefacto: se dice cuál.
    tops = {path.parts[0] for path, _ in files if len(path.parts) > 1}
    top = tops.pop() if len(tops) == 1 and all(len(p.parts) > 1 for p, _ in files) else ""
    return [Finding(
        Severity.INFO, CATEGORY, "Hosts named in the code" + (f" ({top})" if top else ""),
        "Domains and public addresses that appear in URLs outside documentation, tests and "
        "comments. Naming a host is not contacting it, and a host built at runtime is not "
        "listed; but this is where to look for a destination you did not expect.",
        evidence=f"{len(ranked)} host" + ("" if len(ranked) == 1 else "s") + ": "
                 + ", ".join(shown) + (f" (+{more} more)" if more else ""),
        path=top)]


# --- Desvío del tráfico del agente ---
_AI_ENDPOINT = re.compile(
    r"""(?<![A-Za-z0-9_])(ANTHROPIC_(?:BASE_URL|API_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL)|"""
    r"""OPENAI_(?:BASE_URL|API_BASE)|GOOGLE_GEMINI_BASE_URL)["'`\]]*\s*[=:,]?\s*["'`]?\s*"""
    r"""(https?://[^\s"'`<>,;)]+)""")
_AI_LITERALS = ("ANTHROPIC_", "OPENAI_", "GEMINI_")
# El servidor del propio proveedor (o de la nube que lo revende): no hay desvío.
_OFFICIAL = ("anthropic.com", "openai.com", "openai.azure.com", "amazonaws.com",
             "googleapis.com", "azure.com")
# Otros proveedores de modelos y pasarelas conocidas: reciben lo mismo, pero se sabe quiénes son.
_KNOWN_PROVIDERS = (
    "openrouter.ai", "deepseek.com", "groq.com", "together.xyz", "together.ai", "mistral.ai",
    "x.ai", "z.ai", "bigmodel.cn", "moonshot.ai", "moonshot.cn", "aliyuncs.com", "fireworks.ai",
    "cerebras.ai", "perplexity.ai", "nvidia.com", "githubcopilot.com", "github.ai",
    "cloudflare.com", "huggingface.co", "cohere.com", "cohere.ai", "minimax.io", "minimaxi.com",
    "siliconflow.cn", "siliconflow.com", "novita.ai", "vercel.sh", "opencode.ai", "portkey.ai",
    "helicone.ai", "litellm.ai", "ollama.com")
_DOC_SUFFIXES = {".md", ".mdx", ".markdown", ".rst", ".adoc", ".txt", ".html", ".htm"}
_CLAUDE_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")

THIRD_PARTY_TITLE = "Sends the AI agent's traffic to a third-party server"
PROVIDER_TITLE = "Sends the AI agent's traffic to another AI provider"
LOCAL_TITLE = "Routes the AI agent's traffic through a local proxy"
_WHAT_TRAVELS = ("Every prompt, the code and files the agent reads, its answers and the API "
                 "key or token go to that address instead of the model provider's. ")
THIRD_PARTY_DETAIL = _WHAT_TRAVELS + ("Whoever runs that server can read them and change what "
                                      "the agent is told to do. Check who it belongs to.")
RAW_IP_DETAIL = _WHAT_TRAVELS + ("The address is a bare IP with no domain: there is no name "
                                 "to hold anyone to. Whoever runs it can read everything and "
                                 "change what the agent is told to do.")
PLAIN_HTTP_DETAIL = _WHAT_TRAVELS + ("The connection is plain HTTP, so anyone on the network "
                                     "path can read it too.")
PROVIDER_DETAIL = _WHAT_TRAVELS + ("It is a known model provider or gateway, which is a common "
                                   "setup; make sure it is the one you chose.")
LOCAL_DETAIL = ("The agent talks to a program on this machine or network instead of the model "
                "provider. That program sees every prompt, the code and the API key: check "
                "which one it is and where it forwards them.")
SETTINGS_NOTE = (" This file is project configuration for Claude Code: it takes effect when "
                 "the folder is opened, with no command to run.")


def _under(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _endpoint_signal(url: str) -> tuple[Severity, str, str] | None:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")   # "host.com." es el mismo host
    except ValueError:
        return None
    if not host or any(c in url for c in "{}$%") or _is_placeholder(host) \
            or re.search(r"your|xxx|placeholder|changeme", host) or _under(host, _OFFICIAL):
        return None
    if _is_local(host):
        return Severity.LOW, LOCAL_TITLE, LOCAL_DETAIL
    if _under(host, _KNOWN_PROVIDERS):
        return Severity.LOW, PROVIDER_TITLE, PROVIDER_DETAIL
    try:
        ipaddress.ip_address(host)
        return Severity.HIGH, THIRD_PARTY_TITLE, RAW_IP_DETAIL
    except ValueError:
        pass
    if parts.scheme == "http":
        return Severity.HIGH, THIRD_PARTY_TITLE, PLAIN_HTTP_DETAIL
    return Severity.MEDIUM, THIRD_PARTY_TITLE, THIRD_PARTY_DETAIL


def _endpoints(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        posix = path.as_posix()
        downgrade = (1 if path.suffix.lower() in _DOC_SUFFIXES else 0) \
            + (2 if _TEST_HINT.search(posix) else 0)
        settings = posix.endswith(_CLAUDE_SETTINGS)
        counts: dict[str, int] = {}
        seen: set[str] = set()
        for lineno, line in lines_with(text, _AI_LITERALS):
            for match in _AI_ENDPOINT.finditer(line):
                signal = _endpoint_signal(match.group(2))
                if signal is None or match.group(2) in seen:
                    continue
                severity, title, detail = signal
                if counts.get(title, 0) >= MAX_PER_TITLE_PER_FILE:
                    continue
                counts[title] = counts.get(title, 0) + 1
                seen.add(match.group(2))
                extra = 1 if _COMMENT.match(line) else 0
                if settings and title == THIRD_PARTY_TITLE:
                    severity = Severity(min(int(Severity.CRITICAL), int(severity) + 1))
                if settings:
                    detail += SETTINGS_NOTE
                findings.append(Finding(
                    _adjust(severity, downgrade + extra), CATEGORY, f"{title} ({path})", detail,
                    evidence=_snippet(line), path=str(path), line=lineno))
    return findings


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    return _inventory(files) + _endpoints(files)
