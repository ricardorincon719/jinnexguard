"""Cadena de suministro del propio repo: CI de GitHub Actions y submódulos.

- Workflows con `pull_request_target`/`workflow_run` corren con secretos y
  permisos de escritura aunque el PR venga de un desconocido; si además hacen
  checkout del código del PR, ese código ajeno corre con esos secretos.
- `${{ github.event…title/body… }}` dentro de un `run:` es inyección de shell:
  quien abre el issue o PR elige el texto.
- Acciones de terceros sin fijar por SHA: el dueño puede mover la etiqueta.
- Submódulos: código de terceros que no se clonó ni se escaneó.
"""

from __future__ import annotations

import re
from pathlib import Path

from jinnexguard.engine.report import Finding, Severity

# Actividad fingida: un workflow programado que commitea solo, con contenido al azar.
_SCHEDULE = re.compile(r"(?m)^\s*(?:-\s*)?schedule\s*:|^\s*-?\s*cron\s*:")
_COMMITS = re.compile(r"createOrUpdateFileContents|createCommit\b|\bgit\s+(?:commit|push)\b|"
                      r"git-auto-commit-action|add-and-commit")
_RANDOM = re.compile(r"Math\.random\s*\(|\$\{?RANDOM\b|\bshuf\b|/dev/urandom|"
                     r"\brandom\.(?:choice|randint|random)\s*\(")
_PRIVILEGED_TRIGGER = re.compile(r"\b(pull_request_target|workflow_run)\b")
_CHECKOUT_LINE = re.compile(r"^\s*(?:-\s*)?ref:|\bcheckout\b|\bgit\s+fetch\b|\bgh\s+pr\s+checkout\b")
_PR_CHECKOUT = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref|refs/pull/|"
    r"github\.event\.workflow_run\.head_(?:sha|branch)")
_UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|"
    r"head_commit|commits|pages)[\w.\[\]*]*\.(?:title|body|message|name|label|ref|email|"
    r"head_ref|default_branch)|github\.head_ref)\s*\}\}")
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_FIRST_PARTY = ("actions/", "github/")
_RUN = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*)$")
_COMMENT = re.compile(r"^\s*#")
_ALL_SECRETS = re.compile(r"\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}")


def _check_workflow(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    trigger = next(((n, l) for n, l in enumerate(lines, start=1)
                    if _PRIVILEGED_TRIGGER.search(l) and not _COMMENT.match(l)), None)
    if trigger:
        lineno, line = trigger
        # Mencionar head_ref (para un comentario, un nombre) no es correr el código del PR:
        # cuenta solo en una línea que hace checkout o fetch.
        checkout = next((m for line in lines if _CHECKOUT_LINE.search(line)
                         for m in [_PR_CHECKOUT.search(line)] if m), None)
        findings.append(Finding(
            Severity.MEDIUM if checkout else Severity.LOW, "ci",
            f"Privileged workflow triggered by third parties ({path})",
            ("It also checks out the PR's code: someone else's code running with the repo's "
             "secrets (a 'pwn request'). " if checkout else
             "It runs with secrets and write permissions even when the PR comes from a "
             "stranger; check that it does not check out or run the PR's code. ")
            + "A risk for the repo owner, not for whoever installs it.",
            evidence=line.strip() + (f"  + {checkout.group(0)}" if checkout else ""),
            path=str(path), line=lineno))

    commits = _COMMITS.search(text)
    random = _RANDOM.search(text)
    if commits and random and _SCHEDULE.search(text):
        lineno = text.count("\n", 0, random.start()) + 1
        findings.append(Finding(
            Severity.MEDIUM, "ci", f"Scheduled workflow that commits randomised content ({path})",
            "It runs on a timer, makes commits on its own and uses random values to build "
            "them. That is how a repository is made to look actively maintained when nobody "
            "is working on it. Compare the commit history with the code that actually changed.",
            evidence=f"{lines[lineno - 1].strip()[:120]}  + {commits.group(0)}",
            path=str(path), line=lineno))

    run_indent: int | None = None
    injections = 0
    unpinned: list[tuple[int, str]] = []
    for lineno, line in enumerate(lines, start=1):
        indent = len(line) - len(line.lstrip())
        if run_indent is not None and line.strip() and indent <= run_indent:
            run_indent = None
        match = _RUN.match(line)
        script = None
        if match:
            rest = match.group(2).strip()
            if rest in ("|", ">", "|-", ">-", "|+", ">+") or not rest:
                run_indent = len(match.group(1))
            else:
                script = rest
        elif run_indent is not None:
            script = line
        if script and injections < 3 and _UNTRUSTED_EXPR.search(script):
            injections += 1
            findings.append(Finding(
                Severity.HIGH, "ci", f"Shell injection in a workflow ({path})",
                "Text chosen by whoever opens the issue/PR is pasted straight into the script: "
                "it can run commands with the repo's secrets. Pass it through `env:`.",
                evidence=script.strip()[:180], path=str(path), line=lineno))
        uses = _USES.match(line)
        if uses:
            ref = uses.group(1)
            if ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            action, version = ref.rsplit("@", 1)
            if not _SHA.match(version) and not ref.startswith(_FIRST_PARTY):
                unpinned.append((lineno, ref))
        if _ALL_SECRETS.search(line) and not _COMMENT.match(line):
            findings.append(Finding(
                Severity.HIGH, "ci", f"Workflow dumps every secret at once ({path})",
                "toJSON(secrets) hands all of the repo's secrets to one step; a stolen-token "
                "worm used exactly this to exfiltrate them. Pass only the secrets each step needs.",
                evidence=line.strip()[:180], path=str(path), line=lineno))
        if re.match(r"^\s*permissions:\s*write-all\b", line):
            findings.append(Finding(
                Severity.LOW, "ci", f"Workflow with every write permission ({path})",
                "If anything in the workflow is compromised, it can write to the whole repo.",
                evidence=line.strip(), path=str(path), line=lineno))
    if unpinned:
        findings.append(Finding(
            Severity.LOW, "ci", f"Third-party actions not pinned to a SHA ({path})",
            "A tag (@v1) can be moved to other code by its owner; a SHA cannot.",
            evidence=", ".join(ref for _, ref in unpinned[:4])
                     + (f"  (+{len(unpinned) - 4} more)" if len(unpinned) > 4 else ""),
            path=str(path), line=unpinned[0][0]))
    return findings


def _check_gitmodules(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    name = ""
    for lineno, line in enumerate(text.splitlines(), start=1):
        header = re.match(r'^\s*\[submodule\s+"([^"]+)"\]', line)
        if header:
            name = header.group(1)
            continue
        url = re.match(r"^\s*url\s*=\s*(\S+)", line)
        if not url:
            continue
        value = url.group(1)
        insecure = value.startswith(("http://", "git://"))
        findings.append(Finding(
            Severity.LOW if insecure else Severity.INFO, "submodule",
            f"Third-party submodule, not scanned ({path})",
            ("It is fetched unencrypted: someone in the middle can change the code. "
             if insecure else "")
            + "JinnexGuard does not clone submodules: this code was not reviewed.",
            evidence=f"{name}: {value}", path=str(path), line=lineno))
    return findings


def run(files: list[tuple[Path, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, text in files:
        posix = path.as_posix()
        if (posix.startswith(".github/workflows/") or "/.github/workflows/" in posix) and \
                path.suffix in (".yml", ".yaml"):
            findings += _check_workflow(path, text)
        elif path.name == ".gitmodules":
            findings += _check_gitmodules(path, text)
    return findings
