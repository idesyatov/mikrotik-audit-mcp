//! MCP server handler.
//!
//! Stage 1 exposes a single stub `ping` tool. The SSH transport and the
//! read-only whitelist (see [`crate::ssh`], [`crate::whitelist`]) are wired into
//! real audit tools starting from Stage 3.

use rmcp::{
    handler::server::router::tool::ToolRouter, model::*, tool, tool_handler, tool_router,
    ErrorData as McpError, ServerHandler,
};

#[derive(Clone)]
pub(crate) struct AuditServer {
    // Read by the `#[tool_handler]`-generated dispatch; the binary's dead-code
    // pass doesn't see that macro-generated read, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AuditServer {
    pub(crate) fn new() -> Self {
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
