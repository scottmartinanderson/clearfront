# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in Clearfront, please report it privately so it
can be fixed before public disclosure. Please do not open a public issue for security
problems.

- Preferred: GitHub Private Vulnerability Reporting, from the repository's **Security**
  tab, then **Report a vulnerability**.
- Or email **security@clearfront.sh**.

Where you can, please include:

- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal proof of concept.
- The affected version or commit.

We aim to acknowledge a report within 72 hours and to share a remediation timeline once
it has been triaged. We appreciate coordinated disclosure; please allow a reasonable
window for a fix before publishing any details.

## Scope

Clearfront runs locally, uses your own API keys, and sends nothing to us. The reports we
are most interested in include:

- Anything that could leak a user's API keys, targets, or findings off the local machine.
- Injection or code-execution paths in the AI agent, the collection tools, or the web UI.

Generally out of scope:

- Vulnerabilities in third-party OSINT sources or upstream dependencies. Please report
  those to their maintainers; dependency advisories are tracked here via Dependabot.
- Issues that require an already-compromised host or physical access.

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

## Responsible use

Clearfront is for authorized security research and open-source intelligence only. See
[DISCLAIMER.md](DISCLAIMER.md).
Reports that depend on unauthorized targeting of third parties are not eligible.
