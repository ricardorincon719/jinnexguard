"""Command-line interface: the engine without MCP (for scripts, hooks and CI).

  jinnexguard owner/repo
  jinnexguard /path/to/a/repo --online
  jinnexguard owner/repo --json
  jinnexguard /path/to/my/repo --history
  jinnexguard owner/repo --full     # do not group repeated findings
  jinnexguard npm:left-pad          # what gets installed vs. its repo
  jinnexguard pypi:requests==2.32.3

Exit code: the highest severity found (0 info … 4 critical), or 10 if the scan
failed or was incomplete — a scan that did not finish never passes as clean.
"""

from __future__ import annotations

import argparse
import json
import sys

from jinnexguard import __version__
from jinnexguard.engine import assess
from jinnexguard.engine.report import Severity

EXIT_SCAN_ERROR = 10   # fuera del rango 0–4 de severidades, para que un CI no lo confunda

EXAMPLES = """\
examples:
  jinnexguard owner/repo                    a repository on GitHub
  jinnexguard https://gitlab.com/group/repo any GitHub/GitLab/Codeberg/Bitbucket URL
  jinnexguard .                             the folder you are in
  jinnexguard owner/repo --online           add reputation from the GitHub API
  jinnexguard npm:left-pad                  what npm installs vs. its repository
  jinnexguard pypi:requests==2.32.3         a pinned PyPI release
  jinnexguard owner/repo --json             machine-readable output"""

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        # argparse sale con 2, que acá significa "medium": un uso incorrecto no es una severidad.
        self.print_usage(sys.stderr)
        self.exit(EXIT_SCAN_ERROR, f"{self.prog}: error: {message}\n")


def _human(report, *, full: bool = False) -> str:
    data = report.to_dict(compact=not full)
    lines = [f"Target: {data['target']}  ({data['source'] or 'unresolved'})",
             f"Status: {data['status']} — {data['verdict']}"]
    counts = data["counts"]
    summary = ", ".join(f"{ICON[s]} {counts[s]} {s}"
                        for s in ("critical", "high", "medium", "low", "info") if counts[s])
    lines.append("Signals: " + (summary or "none"))
    for finding in data["findings"]:
        loc = finding["path"] + (f":{finding['line']}" if finding["line"] else "")
        lines.append(f"\n{ICON[finding['severity']]} [{finding['severity'].upper()}] "
                     f"{finding['title']}")
        if loc:
            lines.append(f"   at {loc}")
        if finding.get("more_locations"):
            rest = finding["count"] - 1 - len(finding["more_locations"])
            lines.append("   and at " + ", ".join(finding["more_locations"])
                         + (f" … (+{rest} more)" if rest > 0 else ""))
        if finding["evidence"]:
            lines.append(f"   evidence: {finding['evidence']}")
        lines.append(f"   {finding['detail']}")
    if data["context"]:
        lines.append(f"\nContext: {json.dumps(data['context'], ensure_ascii=False)}")
    for error in data["errors"]:
        lines.append(f"\n⚠ {error}")
    return "\n".join(lines)


def exit_code(report) -> int:
    if report.status != "complete":
        return EXIT_SCAN_ERROR
    return int(max((f.severity for f in report.findings), default=Severity.INFO))


def _utf8_output() -> None:
    # En Windows un pipe o un archivo usan cp1252 y los emojis del reporte revientan
    # con UnicodeEncodeError. Se escribe UTF-8, que es lo que lee un agente o un script.
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass


def main(argv: list[str] | None = None) -> int:
    _utf8_output()
    parser = _Parser(
        prog="jinnexguard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Risk signals for a repository or an npm/PyPI package, with evidence. "
                    "Never runs the target's code.",
        epilog=EXAMPLES + "\n\nExit code: highest severity found (0 info … 4 critical); "
               f"{EXIT_SCAN_ERROR} if the scan failed or was incomplete.")
    parser.add_argument("target", help="owner/repo, a GitHub/GitLab/Codeberg/Bitbucket URL, "
                        "a local folder, npm:name[@version] or pypi:name[==version]")
    parser.add_argument("--online", action="store_true",
                        help="add reputation from the GitHub API (no token) and, for a repo, "
                             "compare what it published to npm/PyPI")
    parser.add_argument("--history", action="store_true",
                        help="also search the whole git history for secrets")
    parser.add_argument("--json", action="store_true", help="raw JSON output")
    parser.add_argument("--full", action="store_true",
                        help="do not group repeated findings (same title in many files)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    if not (sys.argv[1:] if argv is None else argv):
        # Quien lo ejecuta solo "a ver qué hace" recibe la ayuda entera, no un error seco.
        # No sale con 0: en un CI, un target vacío no puede pasar por repo limpio.
        parser.print_help(sys.stderr)
        return EXIT_SCAN_ERROR
    args = parser.parse_args(argv)

    report = assess(args.target, online=args.online, history=args.history)
    if args.json:
        print(json.dumps(report.to_dict(compact=not args.full), ensure_ascii=False, indent=2))
    else:
        print(_human(report, full=args.full))
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
