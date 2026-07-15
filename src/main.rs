//! mikrotik-audit-mcp — read-only security audit of MikroTik RouterOS over MCP.
//!
//! `main` wires the pieces and routes the CLI: the default (no subcommand) is
//! the MCP stdio server ([`server`]); the `audit` subcommand ([`cli`]) runs a
//! one-shot audit for cron/CI. Audit logic lives in [`audit`]/[`checks`], the
//! SSH transport in [`ssh`], the command whitelist in [`whitelist`].

mod audit;
mod checks;
mod cli;
mod config;
mod report;
mod scoring;
mod server;
mod ssh;
mod whitelist;

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout carries the MCP stdio transport (and CLI json output), so logs go
    // to stderr only.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = cli::Cli::parse();
    let code = match cli.command.unwrap_or(cli::Command::Serve) {
        cli::Command::Serve => {
            server::serve().await?;
            0
        }
        cli::Command::Audit(args) => cli::run_audit(args).await?,
    };

    std::process::exit(code);
}
