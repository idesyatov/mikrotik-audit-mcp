//! mikrotik-audit-mcp — read-only security audit of MikroTik RouterOS over MCP.
//!
//! Stage 1: a minimal MCP server over stdio exposing a single stub `ping` tool.
//! SSH access, the command whitelist and real audit checks arrive in later stages.

use rmcp::{
    handler::server::router::tool::ToolRouter, model::*, tool, tool_handler, tool_router,
    transport::stdio, ErrorData as McpError, ServerHandler, ServiceExt,
};

#[derive(Clone)]
struct AuditServer {
    // Read by the `#[tool_handler]`-generated dispatch; the binary's dead-code
    // pass doesn't see that macro-generated read, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AuditServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Liveness stub: returns "pong". Real audit tools replace/extend it later.
    #[tool(description = "Health check — returns \"pong\"")]
    async fn ping(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("pong")]))
    }
}

#[tool_handler]
impl ServerHandler for AuditServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "Read-only security audit for MikroTik RouterOS. \
                 Currently a skeleton: the only tool is `ping`."
                    .to_string(),
            )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout carries the MCP stdio transport, so logs go to stderr only.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("starting mikrotik-audit-mcp MCP server (stdio)");

    let service = AuditServer::new().serve(stdio()).await.map_err(|e| {
        tracing::error!("failed to start MCP server: {e:?}");
        e
    })?;

    service.waiting().await?;
    Ok(())
}
