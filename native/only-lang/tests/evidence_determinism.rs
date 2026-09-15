use only_lang::evidence_pack::{
    sort_manifest_desc, write_evidence_pack, EvidenceManifest, EvidenceManifestItem, EvidencePack,
};
use serde_json::json;

#[test]
fn evidencepack_json_is_stable() {
    let pack = EvidencePack {
        run_id: "RUN_MIN".to_string(),
        created_unix_ms: 1700000000000,
        request: json!({
            "request_id": "REQ-TEST-001",
            "identity": { "requester_id": "user:test" }
        }),
        policy_version: "pol_v0".to_string(),
        decision: json!({
            "gate_state": "ALLOW",
            "next_step": "Execute",
            "reason_codes": []
        }),
        decision_hash: "hash_RUN_MIN".to_string(),
        replay_inputs: json!({
            "llm": { "provider": "gemini", "prompt": "hi", "response": "ok" }
        }),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let expected = include_str!("golden/evidence_pack_minimal.json").trim_end();
    let got = serde_json::to_string_pretty(&pack).unwrap();
    assert_eq!(got, expected);
}

#[test]
fn write_evidence_pack_writes_artifacts() {
    let base = std::env::temp_dir().join("only_lang_test_evidence");
    let _ = std::fs::remove_dir_all(&base);

    let pack = EvidencePack {
        run_id: "RUN_X".to_string(),
        created_unix_ms: 1700000000001,
        request: json!({"request_id":"REQ-X"}),
        policy_version: "pol".to_string(),
        decision: json!({"gate_state":"ALLOW"}),
        decision_hash: "hash_RUN_X".to_string(),
        replay_inputs: json!({}),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };

    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect x="0" y="0" width="10" height="10"/></svg>"#;
    let html = "<!doctype html><html><body>ok</body></html>";

    let out = write_evidence_pack(&base, "RUN_X", svg, html, &pack).unwrap();

    assert!(out.svg_path.exists());
    assert!(out.html_path.exists());
    assert!(out.json_path.exists());
}

#[test]
fn manifest_sorting_is_descending() {
    let mut manifest = EvidenceManifest {
        generated_unix_ms: 0,
        packs: vec![
            EvidenceManifestItem {
                run_id: "r1".to_string(),
                created_unix_ms: 1,
                request_id: "req".to_string(),
                workflow: "w".to_string(),
                stage: "gate".to_string(),
                risk_level: "low".to_string(),
                needs_approval: false,
                approved: true,
                gate_state: "ALLOW".to_string(),
                next_step: "Execute".to_string(),
                sla_due_unix_ms: None,
                policy_version: "p".to_string(),
                decision_hash: "h1".to_string(),
                json: "r1.json".to_string(),
                html: "r1.html".to_string(),
                svg: "r1.svg".to_string(),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
            EvidenceManifestItem {
                run_id: "r2".to_string(),
                created_unix_ms: 2,
                request_id: "req".to_string(),
                workflow: "w".to_string(),
                stage: "gate".to_string(),
                risk_level: "low".to_string(),
                needs_approval: false,
                approved: true,
                gate_state: "ALLOW".to_string(),
                next_step: "Execute".to_string(),
                sla_due_unix_ms: None,
                policy_version: "p".to_string(),
                decision_hash: "h2".to_string(),
                json: "r2.json".to_string(),
                html: "r2.html".to_string(),
                svg: "r2.svg".to_string(),
                event_type: "unknown".to_string(),
                token_id: None,
                agent_id: None,
                actor: None,
            },
        ],
    };

    sort_manifest_desc(&mut manifest);
    assert_eq!(manifest.packs[0].created_unix_ms, 2);
    assert_eq!(manifest.packs[1].created_unix_ms, 1);
}
