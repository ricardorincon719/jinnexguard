"""Typosquatting: nombre de paquete casi idéntico a uno popular.

El caso REA exacto: un repo que imita el nombre de uno conocido. Comparamos el
nombre declarado en los manifiestos contra una lista de paquetes populares. La
verificación de procedencia real (si npm/PyPI apunta a ESTE repo) necesita red y
queda para una fase siguiente.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from jinnexguard.engine.report import Finding, Severity

# Paquetes muy descargados y típicamente suplantados (npm + PyPI).
POPULAR = frozenset({
    # npm
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
    "debug", "request", "moment", "webpack", "babel", "eslint", "typescript",
    "vue", "angular", "jquery", "next", "nuxt", "cross-env", "dotenv", "uuid",
    "async", "colors", "node-fetch", "yargs", "socket.io", "mongoose", "redux",
    "rxjs", "mocha", "jest", "prettier", "nodemon", "body-parser", "cors",
    "passport", "bcrypt", "jsonwebtoken", "underscore", "styled-components",
    "tailwindcss", "vite", "rollup", "esbuild", "electron", "puppeteer",
    # PyPI
    "requests", "numpy", "pandas", "flask", "django", "scipy", "matplotlib",
    "tensorflow", "torch", "setuptools", "urllib3", "boto3", "beautifulsoup4",
    "selenium", "pytest", "pyyaml", "click", "jinja2", "sqlalchemy", "openai",
    "cryptography", "pillow", "scikit-learn", "anthropic", "transformers",
    "fastapi", "aiohttp", "certifi", "colorama", "python-dateutil",
})
MIN_LEN = 5   # "core" vs "cors", "test" vs "jest": en nombres cortos todo está a un carácter
# Manifiestos que nadie publica: ejemplos, tests, código vendorizado o compilado.
_NOT_PUBLISHED = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|examples?|"
                            r"vendor|third[_-]party|node_modules|compiled)/")


def _max_distance(popular: str) -> int:
    # Una letra de diferencia ya es sospechosa; dos, solo en nombres largos.
    return 2 if len(popular) >= 8 else 1


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) + len(b)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _norm(name: str) -> str:
    return re.sub(r"[-._]", "", name.lower())


def _candidate_names(files: list[tuple[Path, str]]) -> list[tuple[str, str]]:
    """(nombre, archivo) que el repo podría publicar con ese nombre."""
    names: list[tuple[str, str]] = []
    for path, text in files:
        if _NOT_PUBLISHED.search(path.as_posix()):
            continue
        try:
            if path.name == "package.json":
                data = json.loads(text)
                value = data.get("name") if isinstance(data, dict) else None
                # Un paquete privado no se publica, y uno con scope (@org/x) no se
                # confunde con otro sin él: el scope es del dueño.
                if isinstance(value, str) and not value.startswith("@") \
                        and data.get("private") is not True:
                    names.append((value, str(path)))
            elif path.name == "pyproject.toml":
                match = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
                if match:
                    names.append((match.group(1), str(path)))
            elif path.name == "setup.py":
                match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', text)
                if match:
                    names.append((match.group(1), str(path)))
        except ValueError:
            continue
    return names


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for name, path in _candidate_names(files):
        low = name.lower()
        if low in POPULAR or len(low) < MIN_LEN:
            continue
        norm = _norm(low)
        for popular in POPULAR:
            if (low, popular) in seen:
                continue
            distance = _levenshtein(low, popular)
            if 1 <= distance <= _max_distance(popular) and len(popular) >= MIN_LEN:
                seen.add((low, popular))
                findings.append(Finding(
                    Severity.HIGH, "impersonation",
                    f"Name '{name}' is nearly identical to '{popular}' (possible typosquatting)",
                    "A name one character away from a popular package is often impersonation "
                    "meant to be installed by mistake. Confirm it is the package you want.",
                    evidence=f"{name}  vs  {popular}", path=path))
            elif norm == _norm(popular) and low != popular:
                seen.add((low, popular))
                findings.append(Finding(
                    Severity.MEDIUM, "impersonation",
                    f"Name '{name}' matches '{popular}' except for separators",
                    "It differs from a popular package only in dashes or dots; an "
                    "impersonation trick.",
                    evidence=f"{name}  vs  {popular}", path=path))
    return findings
