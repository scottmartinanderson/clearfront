## Summary

<!-- What does this PR do? One to three sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] New integration (new OSINT tool or external API)
- [ ] Refactor / internal improvement
- [ ] Documentation update
- [ ] Other (describe below)

## Test plan

<!-- Steps to verify this change works correctly. -->

## Checklist

- [ ] All tests pass (`pytest`)
- [ ] Version bumped consistently across `pyproject.toml`, `clearfront/__init__.py`, and `README.md`
- [ ] README and docs updated where applicable
- [ ] If adding an integration: the new tool is registered in `agent.py`, `mcp_server.py`, `cli.py`, `repl.py`, and `web_server.py`
- [ ] `.env.example` updated for any new environment variable
- [ ] No secrets or API keys committed
