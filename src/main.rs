//! mikrotik-audit-mcp — read-only security audit of MikroTik RouterOS over MCP.
//!
//! `main` only wires things together: it starts the MCP server on stdio.
//! The server handler lives in [`server`], the SSH transport in [`ssh`], and the
//! read-only command whitelist in [`whitelist`].

mod audit;
mod checks;
mod config;
mod scoring;
mod server;
mod ssh;
mod whitelist;

use rmcp::{transport::stdio, ServiceExt};

use crate::server::AuditServer;

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
