//! Small claims qualification, letter generation, court filing stub.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcedureTrack {
    TypeA,
    TypeB,
    TypeC,
    Ineligible,
}

impl ProcedureTrack {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TypeA => "type_a",
            Self::TypeB => "type_b",
            Self::TypeC => "type_c",
            Self::Ineligible => "ineligible",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimFacts {
    pub claim_amount_gbp: f64,
    pub limitation_ok: bool,
    pub jurisdiction: String,
    pub dispute_type: String,
    pub has_contract: bool,
    pub has_payment_proof: bool,
    pub defendant_named: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualificationResult {
    pub track: ProcedureTrack,
    pub eligible: bool,
    pub missing_fields: Vec<String>,
    pub rule_trace: Vec<String>,
    pub auto_send_allowed: bool,
    pub escalate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LetterDraft {
    pub template_id: String,
    pub subject: String,
    pub body_text: String,
    pub facts_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourtFilingRequest {
    pub case_id: String,
    pub content_sha256: String,
    pub manifest_fingerprint: String,
    pub court_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourtFilingResult {
    pub accepted: bool,
    pub filing_reference: String,
    pub message: String,
}

const SMALL_CLAIMS_LIMIT_GBP: f64 = 10_000.0;
const AUTO_SEND_CAP_GBP: f64 = 500.0;

pub fn qualify(facts: &ClaimFacts) -> QualificationResult {
    let mut missing = Vec::new();
    let mut trace = Vec::new();

    if facts.jurisdiction.to_ascii_lowercase() != "eng_wales" {
        trace.push("jurisdiction_not_supported_in_pilot".into());
        return QualificationResult {
            track: ProcedureTrack::Ineligible,
            eligible: false,
            missing_fields: vec!["supported_jurisdiction".into()],
            rule_trace: trace,
            auto_send_allowed: false,
            escalate: false,
        };
    }

    if !facts.limitation_ok {
        trace.push("limitation_period_failed".into());
        return QualificationResult {
            track: ProcedureTrack::Ineligible,
            eligible: false,
            missing_fields: vec!["limitation_ok".into()],
            rule_trace: trace,
            auto_send_allowed: false,
            escalate: false,
        };
    }

    if facts.claim_amount_gbp <= 0.0 || facts.claim_amount_gbp > SMALL_CLAIMS_LIMIT_GBP {
        trace.push("amount_outside_small_claims_limit".into());
        return QualificationResult {
            track: ProcedureTrack::Ineligible,
            eligible: false,
            missing_fields: vec!["claim_amount_gbp".into()],
            rule_trace: trace,
            auto_send_allowed: false,
            escalate: false,
        };
    }

    if !facts.defendant_named {
        missing.push("defendant_name".into());
    }

    let simple = matches!(
        facts.dispute_type.to_ascii_lowercase().as_str(),
        "unpaid_invoice" | "deposit" | "goods_not_delivered"
    );

    if !facts.has_contract {
        missing.push("contract_or_agreement".into());
    }
    if !facts.has_payment_proof && facts.dispute_type.to_ascii_lowercase() == "deposit" {
        missing.push("payment_proof".into());
    }

    if !simple {
        trace.push("dispute_type_requires_type_b".into());
        return QualificationResult {
            track: ProcedureTrack::TypeB,
            eligible: true,
            missing_fields: missing,
            rule_trace: trace,
            auto_send_allowed: false,
            escalate: true,
        };
    }

    if !missing.is_empty() {
        trace.push("type_a_checklist_incomplete".into());
        return QualificationResult {
            track: ProcedureTrack::TypeA,
            eligible: true,
            missing_fields: missing,
            rule_trace: trace,
            auto_send_allowed: false,
            escalate: facts.claim_amount_gbp > AUTO_SEND_CAP_GBP,
        };
    }

    trace.push("type_a_qualified".into());
    QualificationResult {
        track: ProcedureTrack::TypeA,
        eligible: true,
        missing_fields: vec![],
        rule_trace: trace,
        auto_send_allowed: facts.claim_amount_gbp <= AUTO_SEND_CAP_GBP,
        escalate: facts.claim_amount_gbp > AUTO_SEND_CAP_GBP,
    }
}

pub fn generate_letter(case_id: &str, facts: &ClaimFacts, track: ProcedureTrack) -> LetterDraft {
    let template_id = match track {
        ProcedureTrack::TypeA => "LBA_type_a_v1",
        ProcedureTrack::TypeB => "LBA_type_b_v1",
        _ => "LBA_ineligible_v1",
    };
    let facts_json = serde_json::to_string(facts).unwrap_or_else(|_| "{}".into());
    let body = format!(
        "Case {case_id}\n\nLetter Before Action\n\nAmount: GBP {:.2}\nDispute: {}\n\n\
         [Template {template_id} — draft for review only, not legal advice.]",
        facts.claim_amount_gbp, facts.dispute_type
    );
    LetterDraft {
        template_id: template_id.to_string(),
        subject: format!("Letter Before Action — Case {case_id}"),
        body_text: body,
        facts_json,
    }
}

pub fn render_letter_pdf_bytes(draft: &LetterDraft) -> Vec<u8> {
    format!(
        "%PDF-1.4\n% OnlyOS Claims Letter\n1 0 obj<<>>endobj\n\
         trailer<<>>\n%% Letter: {}\n%% Template: {}\n%%EOF",
        draft.subject, draft.template_id
    )
    .into_bytes()
}

pub fn submit_court_filing(req: &CourtFilingRequest) -> CourtFilingResult {
    if req.content_sha256.len() != 64 || req.manifest_fingerprint.is_empty() {
        return CourtFilingResult {
            accepted: false,
            filing_reference: String::new(),
            message: "invalid content_sha256 or manifest_fingerprint".into(),
        };
    }
    CourtFilingResult {
        accepted: true,
        filing_reference: format!("MCOL-{}-{}", req.court_id, &req.case_id[..req.case_id.len().min(8)]),
        message: "Pilot stub — filing recorded pending court API integration".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_facts() -> ClaimFacts {
        ClaimFacts {
            claim_amount_gbp: 800.0,
            limitation_ok: true,
            jurisdiction: "eng_wales".into(),
            dispute_type: "deposit".into(),
            has_contract: true,
            has_payment_proof: true,
            defendant_named: true,
        }
    }

    #[test]
    fn type_a_when_complete() {
        let q = qualify(&base_facts());
        assert_eq!(q.track, ProcedureTrack::TypeA);
        assert!(q.missing_fields.is_empty());
    }

    #[test]
    fn ineligible_when_limitation_fails() {
        let mut f = base_facts();
        f.limitation_ok = false;
        assert_eq!(qualify(&f).track, ProcedureTrack::Ineligible);
    }
}
