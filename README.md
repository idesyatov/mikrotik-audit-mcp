# mikrotik-audit-mcp

An MCP server written in Rust for **read-only security auditing** of MikroTik
RouterOS devices. It connects to MCP clients (Claude Desktop, Claude Code,
Cursor) over stdio and exposes a set of configuration checks: firewall,
authentication, services, updates, logging, and network hygiene.

> **Status:** early development — the project scaffold is in place.
> Functionality lands stage by stage.

## Principles

- **Read-only.** The server never changes the device configuration. This is
  enforced in code: a whitelist of allowed RouterOS commands (`print`,
  `export`, `monitor`, `/system resource`, `/log`, `/user print`, etc.).
  Anything outside the whitelist is rejected before it is sent.
- **No C dependencies for SSH.** The device connection uses the system `ssh`
  (subprocess), not libssh or C bindings.
- **Reproducible development.** You do not need Rust on the host machine —
  all builds, tests, and linting run through Docker Compose.

## Quickstart (Docker Compose)

Only `docker` and `docker compose` are required.

```bash
# Interactive development: rebuild + test on every file change
docker compose up dev

# One-off test run
docker compose run --rm test

# Lint: formatting + clippy (warnings treated as errors)
docker compose run --rm lint

# Release build (binary ends up in ./target/release/)
docker compose run --rm build-release
```

The first run builds the dev image (Rust stable + cross toolchains +
`cargo-watch`) and warms the caches — this takes a few minutes. Subsequent
runs are fast thanks to caches stored in named Docker volumes.

## Installing the MCP server in a client

Coming soon (registering a stub tool and verifying it is visible in Claude
Desktop). A `stdio` server configuration example will go here.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test, and submit PRs.
- [SECURITY.md](SECURITY.md) — responsible disclosure of vulnerabilities.
- `docs/` — modular documentation (architecture, check domains, scoring),
  filled in as stages are implemented.

## License

[MIT](LICENSE).
