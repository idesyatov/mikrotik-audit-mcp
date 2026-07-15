//! mikrotik-audit-mcp — read-only security audit of MikroTik RouterOS over MCP.
//!
//! For now this is only a compiling skeleton with no functionality.
//! TODO(Stage 1): bring up an MCP server on `rmcp` over stdio,
//! register a stub tool and verify that Claude Desktop sees the server.

fn main() -> anyhow::Result<()> {
    // IMPORTANT: stdout is owned by the MCP stdio transport, so logs go only to
    // stderr to avoid corrupting the protocol stream.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("mikrotik-audit-mcp: skeleton built, MCP server not yet implemented (Stage 1)");

    Ok(())
}
