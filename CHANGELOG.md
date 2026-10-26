# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-26

First public release.

### Added

- `jinnexguard` command-line tool: scans a GitHub, GitLab, Codeberg or
  Bitbucket repository, a local folder, or an npm/PyPI package, and reports
  risk signals with evidence (file, line and snippet). It never runs the
  target's code.
- Checks for install-time scripts, dangerous patterns, credential theft and
  exfiltration, secrets in the code (masked in the report), AI agent
  configuration and instruction files, GitHub Actions supply-chain issues and
  package-name impersonation.
- Precompiled programs, libraries and kernel drivers committed to a
  repository, and whether the code or the agent instructions start them.
- `--history` to search the whole git history for secrets.
- `--online` for repository reputation from the GitHub API and, for a
  repository, a comparison with what it published to npm/PyPI.
- `npm:` and `pypi:` targets: compares the published artifact with its source
  repository at that version, using npm and PyPI provenance when it exists.
- `--json` output with an `untrusted_content` notice, and `--full` to list
  repeated findings one by one.
- Exit code with the highest severity found (`0`–`4`), or `10` when the scan
  failed or was incomplete.
- `jinnexguard-mcp`: MCP server (optional `mcp` extra) exposing the
  `assess_repo` tool to Claude Code, Codex, Cursor, Gemini CLI and other MCP
  clients.
- Support for Linux, macOS and Windows on Python 3.11 and later.

[1.0.0]: https://github.com/ricardorincon719/jinnexguard/releases/tag/v1.0.0
