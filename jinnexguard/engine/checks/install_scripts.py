"""Hooks que corren solos al instalar el repo: donde vive casi todo el malware.

`npm install` ejecuta preinstall/install/postinstall/prepare; `pip install` de
una fuente corre setup.py; un devcontainer corre postCreateCommand; VS Code corre
las tareas `runOn: folderOpen`. Los lockfiles dicen qué DEPENDENCIAS traen sus
propios scripts de instalación. Reportamos su presencia con el comando exacto
como evidencia, sin ejecutarlo.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

from jinnexguard.engine.report import Finding, Severity

# Scripts de package.json que npm corre SOLO al instalar (sin pedir permiso).
NPM_AUTORUN = ("preinstall", "install", "postinstall")
# `prepare` corre con `npm install` dentro de un clon o al instalar desde git,
# pero NO al instalar el paquete publicado en el registro: riesgo menor.
NPM_PREPARE = "prepare"
# "npm run build", "tsc", "pnpm build"…: compilar el propio proyecto, nada más.
_BUILD_ONLY = re.compile(r"^(?:(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build|tsc(?:\s+-[-\w]+(?:\s+\S+)?)*)$")
# Comandos de `prepare` que solo instalan hooks de git para desarrollo.
_BENIGN_PREPARE = re.compile(
    r"^(?:npx\s+)?(?:is-ci\s*\|\|\s*)?(?:husky(?:\s+install)?|simple-git-hooks|"
    r"lefthook\s+install)(?:\s+\S+)?$")
# Lockfiles que marcan las dependencias con scripts de instalación propios.
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml")
# Corren al publicar/empaquetar: menos peligrosos para quien instala.
NPM_PACKAGING = ("prepublishOnly", "prepack", "postpack", "preprepare", "postprepare")
# devcontainer / Codespaces: corren al abrir el proyecto en un contenedor.
DEVCONTAINER_HOOKS = ("onCreateCommand", "postCreateCommand", "updateContentCommand",
                      "postStartCommand", "postAttachCommand")
# Construcciones en setup.py que significan "esto ejecuta código al instalar".
_SETUP_CODE = re.compile(
    r"\b(os\.system|subprocess\.|popen|pty\.spawn|exec\(|eval\(|compile\(|__import__|"
    r"urllib\.request|requests\.(get|post)|socket\.|base64\.b64decode)", re.IGNORECASE)


def _line_of(text: str, needle: str) -> int | None:
    index = text.find(needle)
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


def _check_package_json(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except ValueError:
        return [Finding(Severity.LOW, "install-script",
                        f"Unreadable package.json at {path}",
                        "It could not be parsed; check by hand whether it has install scripts.",
                        path=str(path))]
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []
    findings: list[Finding] = []
    for name, command in scripts.items():
        if not isinstance(command, str):
            continue
        if name in NPM_AUTORUN:
            findings.append(Finding(
                Severity.HIGH, "install-script",
                f"npm runs '{name}' on install ({path})",
                "This script runs on its own with `npm install`, without confirmation. "
                "It is the classic npm malware vector. Read the whole command.",
                evidence=f"{name}: {command}", path=str(path),
                line=_line_of(text, f'"{name}"')))
        elif name == NPM_PREPARE:
            hooks = bool(_BENIGN_PREPARE.match(command.strip()))
            build = bool(_BUILD_ONLY.match(command.strip()))
            findings.append(Finding(
                Severity.LOW if hooks or build else Severity.MEDIUM, "install-script",
                f"npm runs 'prepare' when installing from source ({path})",
                ("It only installs git hooks for development. " if hooks else
                 "It only runs the project's build. " if build else "")
                + "It runs with `npm install` inside a clone or when installing from git; "
                "not when installing the package published on npm. Read the whole command.",
                evidence=f"{name}: {command}", path=str(path),
                line=_line_of(text, f'"{name}"')))
        elif name in NPM_PACKAGING:
            findings.append(Finding(
                Severity.LOW, "install-script",
                f"Packaging script '{name}' ({path})",
                "It runs when publishing/packing, not on install; lower risk for whoever installs.",
                evidence=f"{name}: {command}", path=str(path),
                line=_line_of(text, f'"{name}"')))
    return findings


def _check_setup_py(path: Path, text: str) -> list[Finding]:
    match = _SETUP_CODE.search(text)
    if not match:
        return []
    return [Finding(
        Severity.HIGH, "install-script",
        f"setup.py runs code ({path})",
        "pip install from source runs setup.py. It uses constructs that run commands or "
        "reach the network on install; check what they do.",
        evidence=match.group(0), path=str(path),
        line=text.count("\n", 0, match.start()) + 1)]


_PTH_PAYLOAD = re.compile(r"\b(?:exec|eval|compile|urlopen|urllib|requests|socket|subprocess|"
                          r"system|popen|b64decode|decompress|marshal)\b")


def _check_pth(path: Path, text: str) -> list[Finding]:
    # Python ejecuta cada línea de un .pth instalado que empieza con `import`, en CADA arranque.
    for lineno, line in enumerate(text.splitlines(), start=1):
        if re.match(r"import[ \t]", line):
            # setuptools y coverage traen .pth que solo importan; ejecutar o bajar algo es otra cosa.
            return [Finding(
                Severity.HIGH if _PTH_PAYLOAD.search(line) else Severity.MEDIUM, "install-script",
                f"Python runs this .pth file on every start ({path})",
                "Once installed in site-packages, its `import` lines run each time any Python "
                "program starts, not just once at install.",
                evidence=line.strip()[:180], path=str(path), line=lineno)]
    return []


def _check_pyproject(path: Path, text: str) -> list[Finding]:
    # Un backend de build dentro del propio árbol (backend-path) ejecuta su código al construir.
    if "backend-path" not in text:
        return []
    return [Finding(
        Severity.MEDIUM, "install-script",
        f"pyproject uses a local build backend ({path})",
        "backend-path points at the repo's own code, which runs when the package is built. "
        "Review that backend.",
        evidence="backend-path", path=str(path), line=_line_of(text, "backend-path"))]


def _check_devcontainer(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(re.sub(r"//[^\n]*", "", text))   # devcontainer.json admite comentarios
    except ValueError:
        return []
    findings: list[Finding] = []
    for hook in DEVCONTAINER_HOOKS:
        if hook in data:
            command = data[hook]
            findings.append(Finding(
                Severity.MEDIUM, "install-script",
                f"devcontainer runs '{hook}' ({path})",
                "It runs when the project is opened in a container or Codespace.",
                evidence=f"{hook}: {json.dumps(command, ensure_ascii=False)}",
                path=str(path), line=_line_of(text, hook)))
    return findings


def _check_npm_lock(path: Path, text: str) -> list[Finding]:
    try:
        packages = json.loads(text).get("packages") or {}
    except (ValueError, AttributeError):
        return []
    findings: list[Finding] = []
    for key, meta in packages.items():
        if not key or not isinstance(meta, dict) or not meta.get("hasInstallScript"):
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        dev, optional = bool(meta.get("dev")), bool(meta.get("optional"))
        findings.append(Finding(
            Severity.LOW if dev else Severity.MEDIUM, "install-script",
            f"Dependency with an install script ({path})",
            "npm runs it on install, without confirmation: it usually downloads or builds "
            "native binaries. " + ("It is a dev dependency: it does not reach whoever installs "
                                   "the package." if dev
                                   else "It reaches whoever installs the package."),
            evidence=f"{name}@{meta.get('version', '?')}"
                     + (" (optional)" if optional else "") + (" (dev)" if dev else ""),
            path=str(path), line=_line_of(text, f'"{key}"')))
    return findings


def _check_pnpm_lock(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    current, current_line = "", None
    for lineno, line in enumerate(text.splitlines(), start=1):
        header = re.match(r"^  ['\"]?(/?[^\s'\"]+)['\"]?:\s*$", line)
        if header:
            current, current_line = header.group(1).lstrip("/"), lineno
        elif line.strip() == "requiresBuild: true" and current:
            findings.append(Finding(
                Severity.MEDIUM, "install-script",
                f"Dependency with an install script ({path})",
                "pnpm builds it on install (requiresBuild): it runs its own code.",
                evidence=current, path=str(path), line=current_line))
    return findings


def _check_vscode_tasks(path: Path, text: str) -> list[Finding]:
    # tasks.json admite comentarios; con runOn: folderOpen corre al abrir la carpeta.
    findings: list[Finding] = []
    for match in re.finditer(r'"runOn"\s*:\s*"folderOpen"', text):
        findings.append(Finding(
            Severity.HIGH, "install-script",
            f"VS Code runs a task when the folder opens ({path})",
            "With `runOn: folderOpen`, opening the repo in VS Code (once trusted) runs this "
            "task with no further warning. Read its `command`.",
            evidence=match.group(0), path=str(path),
            line=text.count("\n", 0, match.start()) + 1))
    return findings


# Un package.json de un fixture o un ejemplo no se instala con el repo: baja 2 niveles.
_FIXTURE_HINT = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|examples?)/")


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        name = path.name
        if name == "package.json":
            found = _check_package_json(path, text)
            if _FIXTURE_HINT.search(path.as_posix()):
                found = [replace(f, severity=Severity(max(int(Severity.INFO), int(f.severity) - 2)))
                         for f in found]
            findings += found
        elif name == "setup.py":
            findings += _check_setup_py(path, text)
        elif name == "pyproject.toml":
            findings += _check_pyproject(path, text)
        elif name == "devcontainer.json":
            findings += _check_devcontainer(path, text)
        elif name in ("package-lock.json", "npm-shrinkwrap.json"):
            findings += _check_npm_lock(path, text)
        elif name == "pnpm-lock.yaml":
            findings += _check_pnpm_lock(path, text)
        elif name == "tasks.json" and path.parent.name == ".vscode":
            findings += _check_vscode_tasks(path, text)
        elif path.suffix == ".pth":
            findings += _check_pth(path, text)
    return findings
