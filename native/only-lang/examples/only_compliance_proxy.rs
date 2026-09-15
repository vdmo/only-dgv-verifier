use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioListener, TcpStream};

const ONLY_CONTROL_URL: &str = "http://127.0.0.1:8091";
const UPSTREAM_LLM_URL: &str = "https://api.openai.com";

fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap())
}

fn phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\+?\d{1,3}[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b").unwrap())
}

fn cc_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap())
}

fn scrub_text(text: &str) -> (String, Vec<String>) {
    let mut redacted = Vec::new();
    let mut scrubbed = text.to_string();

    // Emails
    let mut email_idx = 1;
    let mut unique_emails = std::collections::HashSet::new();
    for mat in email_regex().find_iter(text) {
        unique_emails.insert(mat.as_str().to_string());
    }
    for email in unique_emails {
        let placeholder = format!("[EMAIL_REDACTED_{}]", email_idx);
        scrubbed = scrubbed.replace(&email, &placeholder);
        redacted.push(format!("Email: {} -> {}", placeholder, email));
        email_idx += 1;
    }

    // Credit Cards
    let mut cc_idx = 1;
    let mut unique_ccs = std::collections::HashSet::new();
    for mat in cc_regex().find_iter(text) {
        unique_ccs.insert(mat.as_str().to_string());
    }
    for cc in unique_ccs {
        let placeholder = format!("[CARD_REDACTED_{}]", cc_idx);
        scrubbed = scrubbed.replace(&cc, &placeholder);
        redacted.push(format!("CreditCard: {} -> {}", placeholder, cc));
        cc_idx += 1;
    }

    // Phone Numbers
    let mut phone_idx = 1;
    let mut unique_phones = std::collections::HashSet::new();
    for mat in phone_regex().find_iter(text) {
        let phone = mat.as_str().to_string();
        if phone.trim().len() >= 7 {
            unique_phones.insert(phone);
        }
    }
    for phone in unique_phones {
        let placeholder = format!("[PHONE_REDACTED_{}]", phone_idx);
        scrubbed = scrubbed.replace(&phone, &placeholder);
        redacted.push(format!("Phone: {} -> {}", placeholder, phone));
        phone_idx += 1;
    }

    (scrubbed, redacted)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("ONLY_COMPLIANCE_PROXY_ADDR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1:8093".to_string());

    let listener = TokioListener::bind(&addr).await?;
    println!("OnlyOS Rust Compliance Proxy listening on http://{}", addr);

    let client = reqwest::Client::new();

    loop {
        let (stream, _) = listener.accept().await?;
        let client_clone = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, client_clone).await {
                eprintln!("Error handling connection: {:?}", e);
            }
        });
    }
}

async fn read_http_request_async(
    stream: &mut TcpStream,
) -> Option<(String, String, HashMap<String, String>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 1024 * 128 {
            return None;
        }
    }

    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let (header_bytes, rest) = buf.split_at(header_end + 4);
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines.next()?.to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = Vec::with_capacity(content_len);
    body.extend_from_slice(rest);

    while body.len() < content_len {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 1024 * 1024 {
            break;
        }
    }

    Some((method, path, headers, body))
}

async fn handle_conn(mut stream: TcpStream, client: reqwest::Client) -> std::io::Result<()> {
    let req = match read_http_request_async(&mut stream).await {
        Some(r) => r,
        None => return Ok(()),
    };
    let (method, path_raw, headers, body) = req;
    
    // Handle CORS preflight
    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type, authorization\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nContent-Length: 0\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if method == "GET" && path_raw == "/health" {
        let body = json!({
            "status": "ok",
            "pii_protection": true,
            "gating_plane": ONLY_CONTROL_URL
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
            body_bytes.len()
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.write_all(&body_bytes).await?;
        return Ok(());
    }

    if method == "POST" && path_raw == "/v1/chat/completions" {
        let mut body_json: Value = match serde_json::from_slice(&body) {
            Ok(j) => j,
            Err(_) => {
                let resp = "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"error\":\"invalid_json\"}";
                stream.write_all(resp.as_bytes()).await?;
                return Ok(());
            }
        };

        // 1. Scrub PII
        let mut all_redacted = Vec::new();
        if let Some(messages) = body_json.get_mut("messages").and_then(|m| m.as_array_mut()) {
            for msg in messages {
                if let Some(content) = msg.get_mut("content").and_then(|c| c.as_str()) {
                    let (scrubbed, redacted) = scrub_text(content);
                    *msg.get_mut("content").unwrap() = Value::String(scrubbed);
                    all_redacted.extend(redacted);
                }
            }
        }

        // Extract prompt content
        let mut prompt_content = String::new();
        if let Some(messages) = body_json.get("messages").and_then(|m| m.as_array()) {
            for msg in messages {
                if msg.get("role").and_then(|r| r.as_str()) == Some("user") {
                    if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                        prompt_content.push_str(content);
                        prompt_content.push(' ');
                    }
                }
            }
        }

        // 2. Control plane gating proposal
        let lower_prompt = prompt_content.to_lowercase();
        if lower_prompt.contains("pay") || lower_prompt.contains("payment") || lower_prompt.contains("purchase") || lower_prompt.contains("transfer") {
            let mut vendor = "unknown";
            let mut amount = 0;

            for v in &["ACME", "EVILCORP", "OMNI-MED", "CITY-SUPPLY"] {
                if lower_prompt.contains(&v.to_lowercase()) {
                    vendor = v;
                    break;
                }
            }

            // Extract first number
            let num_re = Regex::new(r"\b\d+\b").unwrap();
            if let Some(m) = num_re.find(&prompt_content) {
                amount = m.as_str().parse::<u64>().unwrap_or(0);
            }

            // Call Only Control proposal
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let proposal = json!({
                "request_id": format!("rust_proxy_{now}"),
                "agent_id": "proxy:rust_gateway",
                "workflow": "compliance_proxy_rust",
                "tool": "finance.payment",
                "action": "execute_payment",
                "params": { "vendor": vendor, "amount": amount },
                "justification": format!("Intercepted prompt: '{}'", &prompt_content[..std::cmp::min(50, prompt_content.len())]),
                "risk_level": if amount > 10000 || vendor == "EVILCORP" { "high" } else { "medium" },
                "identity": { "requester": { "user_id": "user:anonymous", "roles": ["ProxyClient"] } }
            });

            match client.post(&format!("{}/api/agent/proposal", ONLY_CONTROL_URL))
                .json(&proposal)
                .send()
                .await 
            {
                Ok(g_res) if g_res.status() == reqwest::StatusCode::OK => {
                    if let Ok(decision) = g_res.json::<Value>().await {
                        let gate_state = decision.get("gate_state").and_then(|v| v.as_str()).unwrap_or("DENY");
                        if gate_state == "DENY" || gate_state == "ESCALATE" {
                            let mut msg = format!(
                                "Request blocked or escalated by OnlyOS Compliance: {:?}",
                                decision.get("reason_codes").and_then(|v| v.as_array())
                            );
                            if let Some(cf) = decision.get("counterfactual").and_then(|v| v.as_str()) {
                                msg = format!("{} (Counterfactual Hint: {})", msg, cf);
                            }
                            let err_body = json!({
                                "error": {
                                    "message": msg,
                                    "type": "compliance_blocked",
                                    "code": "compliance_blocked"
                                }
                            });
                            let body_bytes = serde_json::to_vec(&err_body).unwrap();
                            let resp = format!(
                                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
                                body_bytes.len()
                            );
                            stream.write_all(resp.as_bytes()).await?;
                            stream.write_all(&body_bytes).await?;
                            return Ok(());
                        }
                    }
                }
                _ => {
                    // Fail closed
                    let err_body = json!({
                        "error": {
                            "message": "Gating control plane unreachable or returned error",
                            "type": "gateway_error"
                        }
                    });
                    let body_bytes = serde_json::to_vec(&err_body).unwrap();
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
                        body_bytes.len()
                    );
                    stream.write_all(resp.as_bytes()).await?;
                    stream.write_all(&body_bytes).await?;
                    return Ok(());
                }
            }
        }

        // 3. Upstream Forwarding
        let auth_header = headers.get("authorization").cloned();
        let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();

        if api_key.is_empty() && auth_header.is_none() {
            // Mock LLM chat completion response
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut mock_text = format!("Hello! (Rust Compliance Proxy Active: scrubbed {} items). Here is the result of your query.", all_redacted.len());
            if !all_redacted.is_empty() {
                mock_text.push_str("\nRedacted details: ");
                mock_text.push_str(&all_redacted.join(", "));
            }
            let mock_body = json!({
                "id": "chatcmpl-mock-rust",
                "object": "chat.completion",
                "created": now,
                "model": body_json.get("model").unwrap_or(&json!("mock-model")),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": mock_text
                    },
                    "finish_reason": "stop"
                }]
            });
            let body_bytes = serde_json::to_vec(&mock_body).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
                body_bytes.len()
            );
            stream.write_all(resp.as_bytes()).await?;
            stream.write_all(&body_bytes).await?;
            return Ok(());
        }

        // Call Upstream LLM
        let mut req_builder = client.post(&format!("{}/v1/chat/completions", UPSTREAM_LLM_URL))
            .json(&body_json);
        if let Some(auth) = auth_header {
            req_builder = req_builder.header("Authorization", auth);
        } else {
            req_builder = req_builder.header("Authorization", format!("Bearer {api_key}"));
        }

        match req_builder.send().await {
            Ok(upstream_res) => {
                let status = upstream_res.status().as_u16();
                let status_line = match status {
                    200 => "200 OK",
                    400 => "400 Bad Request",
                    401 => "401 Unauthorized",
                    403 => "403 Forbidden",
                    404 => "404 Not Found",
                    _ => "502 Bad Gateway"
                };
                let body_bytes = upstream_res.bytes().await.unwrap_or_default();
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
                    status_line,
                    body_bytes.len()
                );
                stream.write_all(resp.as_bytes()).await?;
                stream.write_all(&body_bytes).await?;
            }
            Err(e) => {
                let err_body = json!({ "error": { "message": format!("Failed to connect to upstream LLM: {e}"), "type": "gateway_error" } });
                let body_bytes = serde_json::to_vec(&err_body).unwrap();
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
                    body_bytes.len()
                );
                stream.write_all(resp.as_bytes()).await?;
                stream.write_all(&body_bytes).await?;
            }
        }
    } else {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"error\":\"not_found\"}";
        stream.write_all(resp.as_bytes()).await?;
    }

    Ok(())
}
