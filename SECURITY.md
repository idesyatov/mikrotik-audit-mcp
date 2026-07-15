# Security Policy

## Responsible disclosure

If you find a vulnerability in `mikrotik-audit-mcp`, please report it privately
via the repository's **GitHub Security Advisories** ("Security" tab →
"Report a vulnerability") and **do not open a public issue**.

Where possible, please include:

- the project version/commit and RouterOS version (if relevant);
- a description of the problem and its potential impact;
- reproduction steps or a PoC;
- a proposed fix, if any.

## Response timeline

- Acknowledgement of receipt — within 72 hours.
- Initial assessment and plan — within 7 days.
- Fix and disclosure coordination — by agreement, usually up to 90 days.

Please allow reasonable time to ship a fix before public disclosure. Thank you
for the responsible approach.

## Project security model

Key invariants; violating them is considered a vulnerability:

- 🔒 **Read-only.** The server must not be able to change the device
  configuration. All RouterOS commands go through a whitelist; sending a
  write/modify command is a security defect.
- **Transport isolation.** Secrets (passwords, keys, `export` contents) must
  not leak into the MCP transport's stdout or into build artifacts.
- **SSH via subprocess.** No C bindings; connection parameters must not allow
  injecting arbitrary commands into the `ssh` invocation.

## Supported versions

The project is in early development. Until the first stable release, only the
default branch (latest commit) is supported.
