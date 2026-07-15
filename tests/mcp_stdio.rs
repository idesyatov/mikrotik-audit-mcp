//! Integration test for the Stage 1 MCP skeleton.
//!
//! Spawns the built server as a child process, performs the MCP handshake over
//! stdio, and checks that the `ping` tool is advertised and returns "pong".

use rmcp::{model::CallToolRequestParams, service::ServiceExt, transport::TokioChildProcess};
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_mikrotik-audit-mcp");

#[tokio::test]
async fn ping_tool_is_advertised_and_returns_pong() -> anyhow::Result<()> {
    let client = ().serve(TokioChildProcess::new(Command::new(BIN))?).await?;

    // tools/list must advertise `ping`.
    let tools = client.list_tools(Default::default()).await?;
    assert!(
        tools.tools.iter().any(|t| t.name.as_ref() == "ping"),
        "ping tool not found in tools/list: {tools:#?}"
    );

    // tools/call ping → "pong".
    let result = client.call_tool(CallToolRequestParams::new("ping")).await?;
    let json = serde_json::to_string(&result)?;
    assert!(json.contains("pong"), "unexpected ping result: {json}");

    client.cancel().await?;
    Ok(())
}

/// The security boundary of the target registry: a target not in the operator
/// config is refused. No device is contacted (lookup fails before any SSH).
#[tokio::test]
async fn run_audit_rejects_unknown_target() -> anyhow::Result<()> {
    // Minimal config with exactly one target.
    let dir = std::env::temp_dir().join(format!("mikrotik-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let cfg = dir.join("targets.toml");
    std::fs::write(&cfg, "[targets.home]\nhost = \"192.0.2.1\"\n")?;

    let mut cmd = Command::new(BIN);
    cmd.env("MIKROTIK_AUDIT_CONFIG", &cfg);
    let client = ().serve(TokioChildProcess::new(cmd)?).await?;

    let args = serde_json::json!({ "target": "does-not-exist" })
        .as_object()
        .unwrap()
        .clone();
    let result = client
        .call_tool(CallToolRequestParams::new("run_audit").with_arguments(args))
        .await;

    assert!(
        result.is_err(),
        "unknown target must be rejected, got: {result:?}"
    );

    client.cancel().await?;
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}
