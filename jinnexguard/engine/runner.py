"""Orquesta el análisis: traer, leer, correr chequeos aislados, armar el reporte.

Un chequeo que falla no tumba a los demás ni al reporte: su error queda anotado.
Nunca se ejecuta código del objetivo.
"""

from __future__ import annotations

import tempfile
from pathlib import Path, PurePosixPath

from jinnexguard.engine import registry
from jinnexguard.engine.checks import FILE_CHECKS
from jinnexguard.engine.checks import binaries as binaries_check
from jinnexguard.engine.checks import published as published_check
from jinnexguard.engine.checks import reputation as reputation_check
from jinnexguard.engine.checks import secrets as secrets_check
from jinnexguard.engine.fetch import (
    FetchError, acquire, clone_at_ref, git_origin_url, git_tracked_files, iter_text_files)
from jinnexguard.engine.report import Finding, Report, Severity


def _run_file_checks(report: Report, files: list[tuple[Path, str]]) -> None:
    for check in FILE_CHECKS:
        try:
            for finding in check.run(files):
                report.add(finding)
        except Exception as exc:   # un chequeo roto no frena a los demás
            report.errors.append(f"{check.__name__}: {type(exc).__name__}: {exc}")


def _run_reputation(report: Report, target: str, reputation_target: str) -> None:
    try:
        findings, context = reputation_check.run(reputation_target)
        if context and reputation_target != target:
            context["reputation_target"] = reputation_target
        for finding in findings:
            report.add(finding)
        report.context.update(context)
    except Exception as exc:
        report.errors.append(f"reputation: {type(exc).__name__}: {exc}")


def _compare_release(report: Report, release: registry.Release, *, scan_all: bool) -> None:
    """Baja los artefactos de `release`, los compara con su repo y escanea lo que se instala.

    `scan_all=False` (modo repo) escanea solo lo que no es idéntico al repo, que
    ya se escaneó; `scan_all=True` (modo paquete) escanea el paquete entero.
    """
    summary: dict = {"package": release.spec.label, "repository": release.repo_url,
                     "repository_dir": release.repo_dir or None,
                     "provenance": release.provenance, "artifacts": []}
    if release.published_at:
        summary["published_at"] = release.published_at
    if release.other_wheels:
        summary["other_wheels_not_checked"] = release.other_wheels
    report.context.setdefault("published", []).append(summary)
    for finding in published_check.provenance_findings(
            release.spec.label, release.repo_url, release.provenance):
        report.add(finding)

    with tempfile.TemporaryDirectory(prefix="jinnexguard-pkg-", ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        repo_index, exact = None, False
        if release.repo_url is None:
            report.add(Finding(
                Severity.LOW, published_check.CATEGORY,
                f"{release.spec.label} does not declare a repository",
                "There is no code to compare what gets installed against: only the scan of "
                "the package itself remains."))
        else:
            commit = (release.provenance or {}).get("commit")
            exact_refs = [*([commit] if commit else []), *release.ref_hints,
                          *registry.tag_candidates(release.spec.name, release.spec.version or "")]
            try:
                used = clone_at_ref(release.repo_url, [*exact_refs, "HEAD"], work / "repo")
            except FetchError as exc:
                used = None
                report.errors.append(f"published: {exc}")
            if used is None:
                report.add(Finding(
                    Severity.LOW, published_check.CATEGORY,
                    f"Could not fetch the repo of {release.spec.label}",
                    "The declared repo could not be cloned (deleted, private or unreachable): "
                    "there is no comparison.", evidence=release.repo_url))
            else:
                exact = used != "HEAD"
                summary["compared_ref"] = used
                tracked = [PurePosixPath(p.as_posix()) for p in git_tracked_files(work / "repo") or []]
                if release.spec.ecosystem == "npm" and not release.repo_dir:
                    release.repo_dir = published_check.infer_npm_dir(
                        work / "repo", tracked, release.spec.name)
                    summary["repository_dir"] = release.repo_dir or None
                repo_index = published_check.RepoIndex(work / "repo", tracked, release.repo_dir)
                if not exact:
                    report.add(Finding(
                        Severity.LOW, published_check.CATEGORY,
                        f"The repo has neither the commit nor the tag of {release.spec.label}",
                        "It was compared against the default branch: differences may be "
                        "changes made after the version. A package that cannot be located in "
                        "its repo is a signal in itself.",
                        evidence="tried: " + ", ".join(exact_refs[:6])))

        for index, artifact in enumerate(release.artifacts):
            entry: dict = {"file": artifact.filename, "kind": artifact.kind}
            summary["artifacts"].append(entry)
            try:
                archive = registry.download(artifact, work)
                root = registry.extract(archive, work / f"pkg{index}")
            except (registry.RegistryError, OSError, EOFError) as exc:
                entry["error"] = str(exc)
                report.errors.append(f"published: {exc}")
                continue
            comparison = published_check.compare(artifact, root, repo_index, exact_ref=exact)
            entry.update(comparison.stats)
            for finding in comparison.findings:
                report.add(finding)
            files = [(Path(artifact.label) / path, text)
                     for path, text in iter_text_files(root, skip_dirs=frozenset())
                     if scan_all or path.as_posix() not in comparison.identical]
            entry["files_scanned"] = len(files)
            _run_file_checks(report, files)
            report.scanned = True


def _assess_package(target: str, spec: registry.PackageSpec, *, online: bool) -> Report:
    report = Report(target=target, source=spec.ecosystem)
    try:
        release = registry.resolve(spec)
    except registry.RegistryError as exc:
        report.errors.append(str(exc))
        return report
    report.context["version"] = release.spec.version
    _compare_release(report, release, scan_all=True)
    if online and release.repo_url:
        _run_reputation(report, target, release.repo_url)
    return report


def _published_from_repo(report: Report, files: list[tuple[Path, str]], repo_url: str | None) -> None:
    """Modo repo con `online`: compara el repo con lo que sus manifiestos publicaron."""
    for spec in registry.detect_packages(files):
        try:
            release = registry.resolve(spec)
        except registry.RegistryError as exc:
            report.context.setdefault("published_skipped", []).append(f"{spec.label}: {exc}")
            continue
        if not repo_url or not registry.same_repo(release.repo_url, repo_url):
            # Un nombre libre en el repo puede estar tomado en el registro por otro proyecto.
            report.context.setdefault("published_skipped", []).append(
                f"{release.spec.label} declares {release.repo_url or 'no repo'}, not this one; "
                "not compared")
            continue
        try:
            _compare_release(report, release, scan_all=False)
        except Exception as exc:
            report.errors.append(f"published: {type(exc).__name__}: {exc}")


def assess(target: str, *, online: bool = False, history: bool = False) -> Report:
    """Analiza un repo (URL o carpeta local) o un paquete (`npm:x`, `pypi:x`) y devuelve un Report.

    `online=True` agrega el contexto de reputación de la GitHub API (sin token) y,
    en un repo, compara lo que publicó en npm/PyPI con su código.
    `history=True` busca secretos en todo el historial de git (una URL se clona
    completa en vez de en superficie, así que tarda más en repos grandes).
    Un paquete siempre usa la red: se baja del registro y se compara con su repo.
    """
    try:
        spec = registry.parse_spec(target)
    except registry.RegistryError as exc:
        report = Report(target=target, source="")
        report.errors.append(str(exc))
        return report
    if spec is not None:
        report = _assess_package(target, spec, online=online)
        if history:
            report.context["history"] = "does not apply to a package; scan its repo with --history"
        return report

    report = Report(target=target, source="")
    reputation_target = target
    try:
        with acquire(target, full_history=history) as (root, source):
            report.source = source
            if source == "local" and online:
                # De un clon local, la reputación es la de su remoto `origin`.
                reputation_target = git_origin_url(root) or target
            tracked = git_tracked_files(root)
            binaries: list = []
            files = list(iter_text_files(root, tracked, binaries=binaries))
            report.context["files_scanned"] = len(files)
            report.scanned = True
            report.context["file_selection"] = (
                "whole folder" if tracked is None
                else "git: tracked + new files not ignored")
            _run_file_checks(report, files)
            try:
                for finding in binaries_check.run(binaries, files):
                    report.add(finding)
            except Exception as exc:   # aislado como los demás chequeos
                report.errors.append(f"binaries: {type(exc).__name__}: {exc}")
            if history:
                try:
                    findings, context = secrets_check.run_history(root, files)
                    for finding in findings:
                        report.add(finding)
                    report.context.update(context)
                except Exception as exc:
                    report.errors.append(f"history: {type(exc).__name__}: {exc}")
            if online:
                repo_url = registry.normalize_repo(reputation_target)
                _published_from_repo(report, files, repo_url[0] if repo_url else None)
    except FetchError as exc:
        report.errors.append(str(exc))
        return report

    if online:
        _run_reputation(report, target, reputation_target)
    return report
