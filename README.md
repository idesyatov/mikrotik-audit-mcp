# mikrotik-audit-mcp

[![CI](https://github.com/idesyatov/mikrotik-audit-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/idesyatov/mikrotik-audit-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/idesyatov/mikrotik-audit-mcp?sort=semver)](https://github.com/idesyatov/mikrotik-audit-mcp/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An MCP server written in Rust for **read-only security auditing** of MikroTik
RouterOS. It connects to MCP clients (Claude Desktop, Claude Code, Cursor) over
stdio and reports configuration findings across firewall, authentication,
services, updates, logging, and network hygiene.

> ⚠️ **Early development.** The server already runs over MCP stdio with a single
> `ping` tool; SSH access and real audit checks land stage by stage — see
> [Status](#status).

## Why mikrotik-audit-mcp?

- **Read-only by design.** The server never changes the device configuration.
  It is enforced in code: a whitelist of allowed RouterOS commands (`print`,
  `export`, `monitor`, `/system resource`, `/log`, `/user print`, …). Anything
  outside the whitelist is rejected before it is sent.
- **No C dependencies for SSH.** The device connection uses the system `ssh`
  (subprocess), not libssh or C bindings.
- **Reproducible builds.** No Rust on the host — everything (build, test, lint,
  release) runs through Docker Compose, the same image locally and in CI.
- **Cross-platform.** Prebuilt binaries for Linux (x86_64 / aarch64), macOS
  (Intel / Apple Silicon), and Windows (x86_64).

## Audit scope (in progress)

Checks are grouped into domains and rolled out incrementally:

| Domain | Examples |
| --- | --- |
| **auth** | default `admin` user, users without address restriction, password policy |
| **services** | insecure services (telnet/ftp/www), unrestricted `/ip service` |
| **firewall** | default policy, drop invalid, input protection |
| **updates** | RouterOS version, available updates, release channel |
| **logging** | logging configured, remote syslog, audit events |
| **network hygiene** | neighbor discovery, bandwidth-server, MAC/Winbox, UPnP, DNS |

A scoring engine (weighted domains + penalties) and audit profiles
(home / corporate) come in later stages.

## Quick start

Grab the latest binary for your platform (Linux x86_64 shown):

```bash
VERSION=$(curl -s https://api.github.com/repos/idesyatov/mikrotik-audit-mcp/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
curl -LO "https://github.com/idesyatov/mikrotik-audit-mcp/releases/download/${VERSION}/mikrotik-audit-mcp-${VERSION}-linux-amd64.tar.gz"
tar xzf "mikrotik-audit-mcp-${VERSION}-linux-amd64.tar.gz"
./mikrotik-audit-mcp-${VERSION}-linux-amd64/mikrotik-audit-mcp
```

Other platforms, build-from-source, and MCP client setup are below.

<details>
<summary><b>Installation</b></summary>

Releases: <https://github.com/idesyatov/mikrotik-audit-mcp/releases>

Each archive contains the binary, `LICENSE`, and `README.md`.

### Binary download

| Platform | Asset |
| --- | --- |
| Linux x86_64 | `mikrotik-audit-mcp-<version>-linux-amd64.tar.gz` |
| Linux aarch64 | `mikrotik-audit-mcp-<version>-linux-arm64.tar.gz` |
| macOS Intel | `mikrotik-audit-mcp-<version>-macos-amd64.tar.gz` |
| macOS Apple Silicon | `mikrotik-audit-mcp-<version>-macos-arm64.tar.gz` |
| Windows x86_64 | `mikrotik-audit-mcp-<version>-windows-amd64.zip` |

### Linux

```bash
VERSION=v0.1.0            # or the latest release tag
ARCH=linux-amd64         # linux-arm64 on aarch64 (uname -m → aarch64)
curl -LO "https://github.com/idesyatov/mikrotik-audit-mcp/releases/download/${VERSION}/mikrotik-audit-mcp-${VERSION}-${ARCH}.tar.gz"
tar xzf "mikrotik-audit-mcp-${VERSION}-${ARCH}.tar.gz"
sudo install "mikrotik-audit-mcp-${VERSION}-${ARCH}/mikrotik-audit-mcp" /usr/local/bin/
mikrotik-audit-mcp
```

### macOS

```bash
VERSION=v0.1.0
ARCH=macos-arm64         # macos-amd64 on Intel Macs
curl -LO "https://github.com/idesyatov/mikrotik-audit-mcp/releases/download/${VERSION}/mikrotik-audit-mcp-${VERSION}-${ARCH}.tar.gz"
tar xzf "mikrotik-audit-mcp-${VERSION}-${ARCH}.tar.gz"
sudo install "mikrotik-audit-mcp-${VERSION}-${ARCH}/mikrotik-audit-mcp" /usr/local/bin/
# Binaries are unsigned; clear the quarantine flag if Gatekeeper blocks it:
xattr -dr com.apple.quarantine /usr/local/bin/mikrotik-audit-mcp
```

### Windows (x86_64)

PowerShell:

```powershell
$Version = "v0.1.0"
Invoke-WebRequest "https://github.com/idesyatov/mikrotik-audit-mcp/releases/download/$Version/mikrotik-audit-mcp-$Version-windows-amd64.zip" -OutFile mikrotik-audit-mcp.zip
Expand-Archive mikrotik-audit-mcp.zip -DestinationPath .
# Move mikrotik-audit-mcp-<version>-windows-amd64\mikrotik-audit-mcp.exe somewhere on your PATH
```

### From source

With Docker (no Rust on the host) — the binary lands in the build volume:

```bash
docker compose run --rm build-release
```

Or natively, if you have the Rust toolchain:

```bash
cargo build --release
# target/release/mikrotik-audit-mcp
```

</details>

<details>
<summary><b>Use with an MCP client</b></summary>

The server speaks MCP over stdio. Tools: `ping` (liveness) and `run_audit`,
which audits a **target alias** defined in an operator-owned config — host, user
and key never come from the client, so a prompt-injected model cannot pick an
arbitrary host or key. Define targets first (see
[`docs/targets.example.toml`](docs/targets.example.toml)):

```toml
# $MIKROTIK_AUDIT_CONFIG or ~/.config/mikrotik-audit-mcp/targets.toml
[targets.home-router]
host = "192.168.88.1"
user = "auditor"
identity_file = "~/.ssh/mikrotik_audit"
```

Then call `run_audit { "target": "home-router" }`. Point your client at the
binary as a `stdio` server. Claude Desktop config:

```json
{
  "mcpServers": {
    "mikrotik-audit": {
      "command": "/usr/local/bin/mikrotik-audit-mcp"
    }
  }
}
```

Config file location:

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

On Windows, use the full path to `mikrotik-audit-mcp.exe` (escape backslashes in
JSON, e.g. `C:\\Tools\\mikrotik-audit-mcp.exe`). Restart Claude Desktop, then
the `mikrotik-audit` server appears and its `ping` tool can be called.

</details>

<details>
<summary><b>Development</b></summary>

Requires only `docker` and `docker compose` (plus `make` for the shortcuts).

```bash
docker compose up dev              # interactive watch: check + test on change
docker compose run --rm test       # one-off test run
docker compose run --rm lint       # fmt --check + clippy (-D warnings)
docker compose run --rm build-release
```

Or via `make`:

```bash
make            # list targets
make check      # lint + test (same as CI)
make build-release
make release VERSION=vX.Y.Z   # tag + push → GitHub Actions builds the release
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and commit style.

</details>

<details>
<summary><b>Security model</b></summary>

The server is read-only by construction:

- 🔒 all RouterOS commands pass through a command whitelist; write/modify
  commands are rejected in code, before reaching the device;
- secrets (passwords, keys, `export` contents) must not leak into the MCP
  transport's stdout or into build artifacts;
- SSH runs via subprocess with no C bindings, and connection parameters must
  not allow command injection into the `ssh` invocation.

Vulnerability reporting and the full model: [SECURITY.md](SECURITY.md).

</details>

## Status

Early development. The scaffold, CI, and the 4-platform release pipeline work.
Stage 1 is done: the binary is a working MCP stdio server exposing a `ping`
tool. SSH access, the read-only command whitelist, and audit checks are added
in later stages against an internal roadmap.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
