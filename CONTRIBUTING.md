# Contributing to Clearfront

Thank you for your interest in contributing. This document covers the development
workflow and the checklist for adding new integrations.

Before contributing, read [DISCLAIMER.md](DISCLAIMER.md). Clearfront is for
authorized security research and educational use only.

## Getting started

```bash
# Install in editable mode with all extras and dev tools
pip install -e ".[all,web,dev]"

# Run tests
pytest -p no:freezegun

# Lint (the enforced gate: pyflakes + runtime-error rules)
ruff check --select F,E9 .
```

## Development workflow

1. Fork the repository and create a branch from `main`.
2. Write tests first; implementation follows. Target 80% coverage on new code.
3. Run `pytest -p no:freezegun` and `ruff check --select F,E9 .` before opening a pull request.
4. Use the pull request template, fill in the summary, type of change, and
   checklist before requesting review.

## Adding a new integration

A "tool" in Clearfront is a Python module in `clearfront/tools/` that exposes an
`async def run_*_osint(...)` coroutine. Adding a new tool requires registering
it in every interface layer:

| Layer | File | What to do |
|-------|------|------------|
| Tool module | `clearfront/tools/search_<name>.py` | Implement `run_<name>_osint` |
| Agentic loop | `clearfront/agent.py` | Import the function; add a tool definition to the tools list and a dispatch branch in the tool executor |
| MCP server | `clearfront/mcp_server.py` | Import the function; add an entry to the tool registry dict |
| CLI | `clearfront/cli.py` | Add a subcommand (argparse) that calls the tool directly |
| REPL | `clearfront/repl.py` | Add the tool to the displayed tool list and any command completion |
| Web UI | `clearfront/web_server.py` | Add the tool to the tool dispatch map used by the web endpoint |

### Environment variable convention

If the integration requires an API key, follow this naming pattern:

```
<SERVICE_NAME>_API_KEY
```

Examples: `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `CENSYS_API_ID`.

Add the new variable to `.env.example` with a comment explaining where to obtain
it, and document it in the environment variables table in `README.md`.

### Tests

Add at least one test for the new tool in `tests/`. The test should:

- Cover the happy path (valid input, expected output format).
- Cover the error path (missing binary, API error, timeout).
- Mock external HTTP calls or subprocesses, do not make live network requests
  in the test suite.

### Integrations table

Add a row for the new service to the Integrations table in `README.md` with the
service name, URL, and tool name.

## Reporting issues

Use the issue templates on GitHub:

- **Bug report**, unexpected behavior, crashes, or incorrect output.
- **Feature request**, new functionality or enhancements.
- **New integration**, request to add a new OSINT data source or API.
