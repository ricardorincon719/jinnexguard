"""Reputación como CONTEXTO, nunca como veredicto (GitHub API sin token).

La reputación impecable es justo lo que exhiben los ataques más graves
(xz-utils, event-stream): sirve para contexto, no para absolver. Solo corre si
se pide `online=True`. Sin token hay 60 consultas/hora; si se agota, se reporta
como error y el resto del análisis sigue.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import UTC, datetime

from jinnexguard.engine.report import Finding, Severity

API = "https://api.github.com"
TIMEOUT = 8
# Pocos proyectos sostienen este ritmo durante meses sin ayuda artificial.
STARS_PER_DAY_SUSPICIOUS = 300
_REPO = re.compile(r"github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


def _owner_repo(target: str) -> tuple[str, str] | None:
    value = target.strip()
    if re.fullmatch(r"[\w.-]+/[\w.-]+", value):
        return tuple(value.split("/"))  # type: ignore[return-value]
    match = _REPO.search(value)
    return (match.group(1), match.group(2)) if match else None


def _get(url: str) -> dict:
    request = urllib.request.Request(url, headers={
        "User-Agent": "JinnexGuard", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _age_days(iso: str, now: datetime) -> int | None:
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return (now - when).days


def run(target: str, *, now: datetime | None = None) -> tuple[list[Finding], dict]:
    """Devuelve (hallazgos, contexto). Lanza en fallo de red: el runner lo aísla."""
    owner_repo = _owner_repo(target)
    if owner_repo is None:
        return [], {}
    owner, repo = owner_repo
    now = now or datetime.now(UTC)
    try:
        info = _get(f"{API}/repos/{owner}/{repo}")
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise RuntimeError("GitHub API rate limit reached (60/hour without a token).") from exc
        raise RuntimeError(f"GitHub API HTTP {exc.code}.") from exc

    stars = int(info.get("stargazers_count") or 0)
    repo_age = _age_days(info.get("created_at", ""), now)
    pushed_age = _age_days(info.get("pushed_at", ""), now)
    context = {
        "stars": stars,
        "forks": int(info.get("forks_count") or 0),
        "open_issues": int(info.get("open_issues_count") or 0),
        "repo_created_at": info.get("created_at"),
        "last_push_at": info.get("pushed_at"),
        "repo_age_days": repo_age,
        "owner_type": (info.get("owner") or {}).get("type"),
        "archived": bool(info.get("archived")),
    }
    findings: list[Finding] = []

    # El olor REA: muchísimas estrellas en un repo joven, o un ritmo que pocos sostienen.
    per_day = round(stars / max(repo_age, 1)) if repo_age is not None else None
    context["stars_per_day"] = per_day
    if repo_age is not None and ((repo_age < 90 and stars >= 1000) or
                                 (repo_age < 365 and per_day >= STARS_PER_DAY_SUSPICIOUS)):
        findings.append(Finding(
            Severity.MEDIUM, "reputation",
            f"{stars} stars on a {repo_age}-day-old repo",
            "A reputation that grows too fast may be inflated. "
            "It proves nothing on its own; take it as a signal, not a verdict.",
            evidence=f"stars={stars}, age={repo_age}d, ≈{per_day}/day"))

    try:
        user = _get(f"{API}/users/{owner}")
        account_age = _age_days(user.get("created_at", ""), now)
        context["owner_created_at"] = user.get("created_at")
        context["owner_age_days"] = account_age
        if account_age is not None and account_age < 60:
            findings.append(Finding(
                Severity.LOW, "reputation",
                f"The account '{owner}' is {account_age} days old",
                "A brand-new owner: context worth keeping in mind, not an accusation.",
                evidence=f"cuenta creada {user.get('created_at')}"))
    except urllib.error.HTTPError:
        pass   # el dato del dueño es secundario; no abortar por él

    if pushed_age is not None and pushed_age > 730:
        findings.append(Finding(
            Severity.INFO, "reputation",
            f"No changes in {pushed_age} days",
            "Possibly abandoned project; relevant for maintenance and patches.",
            evidence=f"last push {info.get('pushed_at')}"))
    return findings, context
