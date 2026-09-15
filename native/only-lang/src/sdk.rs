use crate::evidence_pack::{ProposalSubmitted, DecisionReturned, ExecutionResult};
use serde_json::Value;

#[derive(Debug)]
pub enum SdkError {
    Http(reqwest::Error),
    SafetyBlock(String),
    EscalationAwaiting(Vec<String>),
    Io(std::io::Error),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::Http(e) => write!(f, "HTTP error: {e}"),
            SdkError::SafetyBlock(reason) => write!(f, "Safety Block: {reason}"),
            SdkError::EscalationAwaiting(reasons) => write!(f, "Escalation Awaiting human approval: {:?}", reasons),
            SdkError::Io(e) => write!(f, "IO error: {e}"),
        }
    }
}

impl std::error::Error for SdkError {}

pub struct OnlyOSClient {
    api_base: String,
    client: reqwest::Client,
}

impl OnlyOSClient {
    pub fn new(api_base: &str) -> Self {
        Self {
            api_base: api_base.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn propose_action(&self, proposal: &ProposalSubmitted) -> Result<DecisionReturned, SdkError> {
        let url = format!("{}/api/agent/proposal", self.api_base);
        self.client.post(&url)
            .json(proposal)
            .send()
            .await
            .map_err(SdkError::Http)?
            .error_for_status()
            .map_err(SdkError::Http)?
            .json()
            .await
            .map_err(SdkError::Http)
    }

    pub async fn log_execution(&self, execution: &ExecutionResult) -> Result<serde_json::Value, SdkError> {
        let url = format!("{}/api/agent/execution", self.api_base);
        self.client.post(&url)
            .json(execution)
            .send()
            .await
            .map_err(SdkError::Http)?
            .error_for_status()
            .map_err(SdkError::Http)?
            .json()
            .await
            .map_err(SdkError::Http)
    }

    pub async fn execute_gated_tool<F, R>(
        &self,
        request_id: &str,
        agent_id: &str,
        workflow: &str,
        tool: &str,
        action: &str,
        params: Value,
        justification: &str,
        risk_level: &str,
        tool_fn: F,
    ) -> Result<R, SdkError>
    where
        F: FnOnce(Value) -> Result<R, Box<dyn std::error::Error + Send + Sync>>,
    {
        // 1. Propose action
        let proposal = ProposalSubmitted {
            request_id: request_id.to_string(),
            agent_id: agent_id.to_string(),
            workflow: workflow.to_string(),
            tool: tool.to_string(),
            action: action.to_string(),
            params: params.clone(),
            justification: justification.to_string(),
            llm_trace: None,
            risk_level: risk_level.to_string(),
            identity: serde_json::json!({
                "requester": {
                    "user_id": agent_id,
                    "roles": ["ClientAgent"]
                }
            }),
            ..Default::default()
        };

        let decision = self.propose_action(&proposal).await?;

        if decision.gate_state == "DENY" {
            let mut reason = decision.reason_codes.join(", ");
            if let Some(cf) = &decision.counterfactual {
                reason = format!("{} (Counterfactual: {})", reason, cf);
            }
            // Log denied execution
            let exec_result = ExecutionResult {
                request_id: request_id.to_string(),
                token_id: "".to_string(),
                executor_id: agent_id.to_string(),
                tool: tool.to_string(),
                action: action.to_string(),
                params,
                allowed: false,
                deny_reason: Some(reason.clone()),
                outcome: serde_json::json!({}),
                receipt: serde_json::json!({}),
                run_id: format!("{}_{}_execute", crate::evidence_pack::now_unix_ms(), request_id),
            };
            let _ = self.log_execution(&exec_result).await;
            return Err(SdkError::SafetyBlock(reason));
        }

        if decision.gate_state == "ESCALATE" {
            let mut reasons = decision.reason_codes.clone();
            if let Some(cf) = &decision.counterfactual {
                reasons.push(format!("Counterfactual: {}", cf));
            }
            return Err(SdkError::EscalationAwaiting(reasons));
        }

        // gate_state == "ALLOW"
        let token_id = decision.auth_token.as_ref()
            .map(|t| t.token_id.clone())
            .unwrap_or_default();

        match tool_fn(params.clone()) {
            Ok(result) => {
                // Log successful execution
                let exec_result = ExecutionResult {
                    request_id: request_id.to_string(),
                    token_id: token_id.clone(),
                    executor_id: agent_id.to_string(),
                    tool: tool.to_string(),
                    action: action.to_string(),
                    params,
                    allowed: true,
                    deny_reason: None,
                    outcome: serde_json::json!({ "success": true }),
                    receipt: serde_json::json!({}),
                    run_id: format!("{}_{}_execute", crate::evidence_pack::now_unix_ms(), request_id),
                };
                let _ = self.log_execution(&exec_result).await;
                Ok(result)
            }
            Err(e) => {
                // Log failed execution (error inside the tool function itself)
                let exec_result = ExecutionResult {
                    request_id: request_id.to_string(),
                    token_id: token_id.clone(),
                    executor_id: agent_id.to_string(),
                    tool: tool.to_string(),
                    action: action.to_string(),
                    params,
                    allowed: true,
                    deny_reason: None,
                    outcome: serde_json::json!({ "success": false, "error": e.to_string() }),
                    receipt: serde_json::json!({}),
                    run_id: format!("{}_{}_execute", crate::evidence_pack::now_unix_ms(), request_id),
                };
                let _ = self.log_execution(&exec_result).await;
                Err(SdkError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))
            }
        }
    }
}
