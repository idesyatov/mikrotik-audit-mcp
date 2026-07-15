//! MCP server handler.
//!
//! Tools:
//!   - `ping` — liveness stub.
//!   - `run_audit` — runs the read-only audit against a target *alias* defined
//!     in the operator config. Connection details never come from tool
//!     arguments, so a prompt-injected model cannot choose an arbitrary host or
//!     key (see [`crate::config`]).

use rmcp::{
    handler::server::router::tool::ToolRouter, handler::server::wrapper::Parameters, model::*,
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};

use crate::checks::{Finding, Status};
use crate::scoring::{self, Score};
use crate::{audit, config};

#[derive(Clone)]
pub(crate) struct AuditServer {
    // Read by the `#[tool_handler]`-generated dispatch; the binary's dead-code
    // pass doesn't see that macro-generated read, hence the allow.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub(crate) struct RunAuditParams {
    #[schemars(description = "Alias of a target defined in the operator config")]
    target: String,
    #[serde(default)]
    #[schemars(description = "Audit profile: \"home\" (default) or \"corporate\"; \
                              overrides the target's configured profile")]
    profile: Option<String>,
}

#[tool_router]
impl AuditServer {
    pub(crate) fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Liveness stub: returns "pong".
    #[tool(description = "Health check — returns \"pong\"")]
    async fn ping(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("pong")]))
    }

    #[tool(description = "Run the read-only security audit against a configured target (by alias)")]
    async fn run_audit(
        &self,
        Parameters(params): Parameters<RunAuditParams>,
    ) -> Result<CallToolResult, McpError> {
        let cfg = config::load()
            .map_err(|e| McpError::internal_error(format!("config error: {e}"), None))?;
        let target = cfg
            .target(&params.target)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        // Profile precedence: tool argument → target config → Home.
        let profile = match params.profile.as_deref() {
            Some(name) => scoring::Profile::parse(name).ok_or_else(|| {
                McpError::invalid_params(format!("unknown profile {name:?}"), None)
            })?,
            None => target.profile.unwrap_or_default(),
        };

        let findings = audit::run_audit(&target.to_ssh_config())
            .await
            .map_err(|e| McpError::internal_error(format!("audit failed: {e}"), None))?;

        let score = scoring::score(&findings, profile);

        let summary = summarize(&params.target, &score, &findings);
        let findings_json = serde_json::to_string_pretty(&findings)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let score_json = serde_json::to_string_pretty(&score)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![
            ContentBlock::text(summary),
            ContentBlock::text(score_json),
            ContentBlock::text(findings_json),
        ]))
    }
}

fn summarize(target: &str, score: &Score, findings: &[Finding]) -> String {
    let count = |s: Status| findings.iter().filter(|f| f.status == s).count();
    let mut out = format!(
        "Audit of {:?} [{:?} profile]: score {}/100 — {} passed, {} failed, {} errored (of {} checks).\n",
        target,
        score.profile,
        score.total,
        count(Status::Pass),
        count(Status::Fail),
        count(Status::Error),
        findings.len()
    );
    for f in findings.iter().filter(|f| f.status == Status::Fail) {
        out.push_str(&format!(
            "- [{:?}] {} ({}): {}\n",
            f.severity, f.title, f.id, f.detail
        ));
    }
    out
}

#[tool_handler]
impl ServerHandler for AuditServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "Read-only security audit for MikroTik RouterOS. Use `run_audit` with a \
                 target alias (defined in the operator config) to audit a device; `ping` \
                 is a liveness check."
                    .to_string(),
            )
    }
}
