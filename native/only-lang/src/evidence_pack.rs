use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolProposal {
    pub tool: String,
    pub action: String,
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub tool: String,
    pub allowed: bool,
    pub deny_reason: Option<String>,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProposalSubmitted {
    pub request_id: String,
    pub agent_id: String,
    pub workflow: String,
    pub tool: String,
    pub action: String,
    pub params: Value,
    pub justification: String,
    pub llm_trace: Option<Value>,
    pub risk_level: String,
    pub identity: Value,
    
    // LifeStack Governed Fields
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposer_identity: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intended_consequence: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_authority: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_references: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_transition: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_conditions: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_replay_context: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenIssued {
    pub token_id: String,
    pub request_id: String,
    pub policy_version: String,
    pub tool: String,
    pub action: String,
    pub vendor: String,
    pub amount_cap: u64,
    pub expires_unix_ms: u64,
    pub approver_ids: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReturned {
    pub request_id: String,
    pub gate_state: String, // ALLOW, ESCALATE, DENY
    pub reason_codes: Vec<String>,
    pub approvals_required: u32,
    pub approvals_received: u32,
    pub auth_token: Option<AuthTokenIssued>,
    pub run_id: String,
    pub decision_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterfactual: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub request_id: String,
    pub token_id: String,
    pub executor_id: String,
    pub tool: String,
    pub action: String,
    pub params: Value,
    pub allowed: bool,
    pub deny_reason: Option<String>,
    pub outcome: Value,
    pub receipt: Value,
    pub run_id: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePack {
    pub run_id: String,
    pub created_unix_ms: u128,
    pub request: Value,
    pub policy_version: String,
    pub decision: Value,
    pub decision_hash: String,
    pub replay_inputs: Value,
    pub tool_proposals: Vec<ToolProposal>,
    pub tool_outcomes: Vec<ToolOutcome>,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub actor: Option<Value>,
}

fn default_event_type() -> String {
    "unknown".to_string()
}

#[derive(Debug, Clone)]
pub struct EvidenceArtifacts {
    pub svg_path: PathBuf,
    pub html_path: PathBuf,
    pub json_path: PathBuf,
}

pub fn run_id_unix_ms() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    ms.to_string()
}

pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn wrap_premium_html(html: &str, pack: &EvidencePack) -> String {
    // Extract inner body content
    let body_start_tag = "<body>";
    let body_end_tag = "</body>";
    let inner_body = if let Some(start_idx) = html.find(body_start_tag) {
        if let Some(end_idx) = html.rfind(body_end_tag) {
            &html[start_idx + body_start_tag.len()..end_idx]
        } else {
            html
        }
    } else {
        html
    };

    let title = if let Some(start_idx) = html.find("<title>") {
        if let Some(end_idx) = html.find("</title>") {
            &html[start_idx + "<title>".len()..end_idx]
        } else {
            "Audit Report"
        }
    } else {
        "Audit Report"
    };

    let gate_state = pack.decision.get("gate_state").and_then(|v| v.as_str()).unwrap_or("ALLOW");
    let next_step = pack.decision.get("next_step").and_then(|v| v.as_str()).unwrap_or("Continue");
    let request_id = pack.request.get("request_id").and_then(|v| v.as_str()).unwrap_or("—");
    let workflow = pack.request.get("workflow").and_then(|v| v.as_str()).unwrap_or("—");
    let risk_level = pack.request.get("risk_level").and_then(|v| v.as_str()).unwrap_or("—");

    let gate_badge_cls = match gate_state {
        "ALLOW" => "pill-allow",
        "ESCALATE" => "pill-escalate",
        "DENY" => "pill-deny",
        _ => "pill-allow",
    };

    let stage = if pack.run_id.contains("_submit") {
        "submit"
    } else if pack.run_id.contains("_triage") {
        "triage"
    } else if pack.run_id.contains("_gate") {
        "gate"
    } else if pack.run_id.contains("_tool") {
        "tool"
    } else {
        "unknown"
    };

    let reason_codes_html = if let Some(arr) = pack.decision.get("reason_codes").and_then(|v| v.as_array()) {
        if arr.is_empty() {
            "".to_string()
        } else {
            let pills = arr.iter()
                .map(|code| format!("<span class=\"pill pill-reason\">{}</span>", code.as_str().unwrap_or("").replace("\"", "")))
                .collect::<Vec<_>>()
                .join(" ");
            format!("<div class=\"panel\"><strong>Reason codes:</strong> {}</div>", pills)
        }
    } else {
        "".to_string()
    };

    let mut tools_html = String::new();
    if !pack.tool_proposals.is_empty() || !pack.tool_outcomes.is_empty() {
        tools_html.push_str("<div class=\"section-title\">Tool Gating Details</div>");
        tools_html.push_str("<div class=\"panel\">");
        tools_html.push_str("<table><thead><tr><th>Tool</th><th>Action</th><th>Parameters</th><th>Status</th><th>Deny Reason / Outcome</th></tr></thead><tbody>");
        for (i, proposal) in pack.tool_proposals.iter().enumerate() {
            let outcome = pack.tool_outcomes.get(i);
            let status_badge = match outcome {
                Some(o) => if o.allowed {
                    "<span class=\"pill pill-allow\">Allowed</span>"
                } else {
                    "<span class=\"pill pill-deny\">Denied</span>"
                },
                None => "<span class=\"pill\">Pending</span>"
            };
            let result_str = match outcome {
                Some(o) => if o.allowed {
                    serde_json::to_string(&o.result).unwrap_or_default()
                } else {
                    o.deny_reason.clone().unwrap_or_else(|| "Blocked".to_string())
                },
                None => "—".to_string()
            };
            tools_html.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td><pre class=\"mini-json\">{}</pre></td><td>{}</td><td><code>{}</code></td></tr>",
                proposal.tool,
                proposal.action,
                serde_json::to_string_pretty(&proposal.params).unwrap_or_default(),
                status_badge,
                result_str
            ));
        }
        tools_html.push_str("</tbody></table></div>");
    }

    let request_pretty = serde_json::to_string_pretty(&pack.request).unwrap_or_default();
    let decision_pretty = serde_json::to_string_pretty(&pack.decision).unwrap_or_default();

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{} | Audit Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      background-color: #030712;
      color: #f3f4f6;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      margin: 0;
      padding: 24px;
      line-height: 1.5;
    }}
    a {{
      color: #38bdf8;
      text-decoration: none;
      transition: color 0.2s;
    }}
    a:hover {{
      color: #0ea5e9;
      text-decoration: underline;
    }}
    .container {{
      max-width: 960px;
      margin: 0 auto;
    }}
    .header-card {{
      background: radial-gradient(100% 100% at 0% 0%, #1e1b4b 0%, #0f172a 100%);
      border: 1px solid #312e81;
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.7);
    }}
    .header-card::before {{
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 1px;
      background: linear-gradient(90deg, transparent, rgba(99, 102, 241, 0.4), transparent);
    }}
    .badge-container {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }}
    .pill {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 9999px;
      letter-spacing: 0.05em;
    }}
    .pill-allow {{
      background-color: rgba(16, 185, 129, 0.1);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }}
    .pill-escalate {{
      background-color: rgba(245, 158, 11, 0.1);
      color: #f59e0b;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }}
    .pill-deny {{
      background-color: rgba(239, 68, 68, 0.1);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }}
    .pill-stage {{
      background-color: rgba(99, 102, 241, 0.1);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.3);
    }}
    .pill-reason {{
      background-color: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.4);
      margin-left: 6px;
    }}
    .title-area {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .title-area h1 {{
      margin: 0;
      font-size: 28px;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: #ffffff;
    }}
    .run-id {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: #64748b;
      margin-top: 4px;
    }}
    .grid-meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 24px;
      border-top: 1px solid #1e293b;
      padding-top: 20px;
    }}
    .meta-item {{
      display: flex;
      flex-direction: column;
    }}
    .meta-label {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #64748b;
      margin-bottom: 4px;
    }}
    .meta-val {{
      font-size: 15px;
      font-weight: 500;
      color: #cbd5e1;
    }}
    .meta-val.mono {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      background: #090d16;
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid #1e293b;
      word-break: break-all;
    }}
    .section-title {{
      font-size: 18px;
      font-weight: 600;
      margin: 32px 0 16px 0;
      color: #e2e8f0;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .section-title::after {{
      content: '';
      flex: 1;
      height: 1px;
      background: #1e293b;
    }}
    .panel {{
      background-color: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    .box {{
      background-color: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 16px;
      margin: 16px 0;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }}
    .inner-content h1 {{
      font-size: 16px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      color: #e2e8f0;
      border-bottom: 1px solid #1e293b;
      padding-bottom: 6px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
    }}
    th {{
      font-family: 'Outfit', sans-serif;
      font-weight: 600;
      color: #94a3b8;
      border-bottom: 1px solid #1e293b;
      padding: 8px 12px;
      text-align: left;
      font-size: 13px;
    }}
    td {{
      border-bottom: 1px solid #0f172a;
      padding: 8px 12px;
      color: #cbd5e1;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    pre {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background-color: #030712;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 12px;
      margin: 0;
      white-space: pre-wrap;
      word-break: break-all;
      color: #a7f3d0;
    }}
    .mini-json {{
      background: #030712;
      border: 1px solid #1e293b;
      padding: 4px 8px;
      font-size: 11px;
      color: #cbd5e1;
      border-radius: 4px;
      max-height: 100px;
      overflow-y: auto;
    }}
    .grid-two {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 16px;
    }}
    .key {{ color: #f43f5e; font-weight: 500; }}
    .string {{ color: #10b981; }}
    .number {{ color: #f59e0b; }}
    .boolean {{ color: #3b82f6; }}
    .null {{ color: #64748b; }}
    @media (max-width: 768px) {{
      .grid-two {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-card">
      <div class="badge-container">
        <span class="pill {}">{}</span>
        <span class="pill pill-stage">{}</span>
      </div>
      <div class="title-area">
        <div>
          <h1>{}</h1>
          <div class="run-id">run_id: {}</div>
        </div>
      </div>
      
      <div class="grid-meta">
        <div class="meta-item">
          <div class="meta-label">Request ID</div>
          <div class="meta-val">{}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Workflow</div>
          <div class="meta-val">{}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Risk Level</div>
          <div class="meta-val">{}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Next Step</div>
          <div class="meta-val">{}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Timestamp</div>
          <div class="meta-val" id="local-timestamp">—</div>
        </div>
        <div class="meta-item" style="grid-column: span 2;">
          <div class="meta-label">Policy Version</div>
          <div class="meta-val mono">{}</div>
        </div>
        <div class="meta-item" style="grid-column: span 2;">
          <div class="meta-label">Decision Hash</div>
          <div class="meta-val mono">{}</div>
        </div>
      </div>
    </div>

    {}
    {}

    <div class="section-title">Decision Details</div>
    <div class="grid-two">
      <div class="panel">
        <div class="meta-label" style="margin-bottom:8px;">Request Payload</div>
        <pre><code class="json-code" id="req-json">{}</code></pre>
      </div>
      <div class="panel">
        <div class="meta-label" style="margin-bottom:8px;">Decision Response</div>
        <pre><code class="json-code" id="dec-json">{}</code></pre>
      </div>
    </div>

    <div class="section-title">Execution &amp; Verification Details</div>
    <div class="inner-content">
      {}
    </div>
  </div>

  <script>
    // Format timestamp in local time
    try {{
      const unixMs = {};
      if (unixMs) {{
        document.getElementById('local-timestamp').textContent = new Date(Number(unixMs)).toLocaleString();
      }}
    }} catch (e) {{}}

    // JSON syntax highlighting
    function syntaxHighlight(jsonStr) {{
      try {{
        const obj = JSON.parse(jsonStr);
        jsonStr = JSON.stringify(obj, null, 2);
      }} catch(e) {{}}
      jsonStr = jsonStr.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return jsonStr.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, function (match) {{
        let cls = 'number';
        if (/^"/.test(match)) {{
          if (/:$/.test(match)) {{
            cls = 'key';
          }} else {{
            cls = 'string';
          }}
        }} else if (/true|false/.test(match)) {{
          cls = 'boolean';
        }} else if (/null/.test(match)) {{
          cls = 'null';
        }}
        return '<span class="' + cls + '">' + match + '</span>';
      }});
    }}

    try {{
      const reqEl = document.getElementById('req-json');
      reqEl.innerHTML = syntaxHighlight(reqEl.textContent);
      const decEl = document.getElementById('dec-json');
      decEl.innerHTML = syntaxHighlight(decEl.textContent);
    }} catch(e) {{}}
  </script>
</body>
</html>"##,
        title,
        gate_badge_cls,
        gate_state,
        stage,
        title,
        pack.run_id,
        request_id,
        workflow,
        risk_level,
        next_step,
        pack.policy_version,
        pack.decision_hash,
        reason_codes_html,
        tools_html,
        request_pretty,
        decision_pretty,
        inner_body,
        pack.created_unix_ms
    )
}

pub fn write_evidence_pack(
    base: &Path,
    run_id: &str,
    svg: &str,
    html: &str,
    pack: &EvidencePack,
) -> io::Result<EvidenceArtifacts> {
    let out_dir = base.join("evidence");
    std::fs::create_dir_all(&out_dir)?;

    let svg_path = out_dir.join(format!("{run_id}.svg"));
    let html_path = out_dir.join(format!("{run_id}.html"));
    let json_path = out_dir.join(format!("{run_id}.json"));

    let wrapped_html = wrap_premium_html(html, pack);

    std::fs::write(&svg_path, svg)?;
    std::fs::write(&html_path, wrapped_html)?;

    let pack = ensure_only_script(pack.clone());
    let json =
        serde_json::to_string_pretty(&pack).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    std::fs::write(&json_path, json)?;

    Ok(EvidenceArtifacts {
        svg_path,
        html_path,
        json_path,
    })
}

fn ensure_only_script(mut pack: EvidencePack) -> EvidencePack {
    let default_script = "harmony(1e-12) residual() report()";
    match &mut pack.replay_inputs {
        Value::Object(map) => {
            if !map.contains_key("script")
                && !map.contains_key("only_script")
                && !map.contains_key("only_lang_script")
            {
                map.insert(
                    "script".to_string(),
                    Value::String(default_script.to_string()),
                );
            }
        }
        Value::Null => {
            pack.replay_inputs = json!({ "script": default_script });
        }
        other => {
            let prev = other.clone();
            pack.replay_inputs = json!({ "script": default_script, "raw": prev });
        }
    }
    pack
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifestItem {
    pub run_id: String,
    pub created_unix_ms: u128,
    pub request_id: String,
    pub workflow: String,
    pub stage: String,
    pub risk_level: String,
    pub needs_approval: bool,
    pub approved: bool,
    pub gate_state: String,
    pub next_step: String,
    pub sla_due_unix_ms: Option<u128>,
    pub policy_version: String,
    pub decision_hash: String,
    pub json: String,
    pub html: String,
    pub svg: String,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub actor: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub generated_unix_ms: u128,
    pub packs: Vec<EvidenceManifestItem>,
}

pub fn write_manifest(base: &Path, manifest: &EvidenceManifest) -> io::Result<PathBuf> {
    let out_dir = base.join("evidence");
    std::fs::create_dir_all(&out_dir)?;

    let path = out_dir.join("manifest.json");
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

pub fn sort_manifest_packs_desc(packs: &mut Vec<EvidenceManifestItem>) {
    packs.sort_by(|a, b| b.created_unix_ms.cmp(&a.created_unix_ms));
}

pub fn sort_manifest_desc(manifest: &mut EvidenceManifest) {
    sort_manifest_packs_desc(&mut manifest.packs);
}
