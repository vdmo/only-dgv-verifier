//! C2PA / JUMBF read path (Phase 2 — structured parse, not full crypto validation).

use serde::{Deserialize, Serialize};

const JUMBF: &[u8; 4] = b"jumb";
const C2PA: &[u8; 4] = b"c2pa";
const CAIX: &[u8; 4] = b"CAIX";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct C2paSummary {
    pub present: bool,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default)]
    pub jumbf_boxes: usize,
    #[serde(default)]
    pub assertion_labels: Vec<String>,
    #[serde(default)]
    pub validation: String,
}

fn read_u32_be(bytes: &[u8], off: usize) -> Option<u32> {
    if off + 4 > bytes.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
    ]))
}

fn box_type_at(bytes: &[u8], off: usize) -> Option<[u8; 4]> {
    if off + 8 > bytes.len() {
        return None;
    }
    Some([bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]])
}

fn scan_urn_labels(bytes: &[u8]) -> Vec<String> {
    let mut labels = Vec::new();
    let needle = b"urn:c2pa:";
    let mut i = 0usize;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let end = bytes[i..]
                .iter()
                .position(|&b| b == 0 || b == b'"' || b == b'>' || b == b' ')
                .unwrap_or(bytes.len() - i);
            if let Ok(label) = std::str::from_utf8(&bytes[i..i + end]) {
                if !labels.contains(&label.to_string()) {
                    labels.push(label.to_string());
                }
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    labels.truncate(8);
    labels
}

fn scan_jumbf_boxes(bytes: &[u8]) -> (usize, Vec<String>) {
    let mut count = 0usize;
    let mut labels = scan_urn_labels(bytes);
    let mut i = 0usize;
    while i + 8 <= bytes.len() {
        if bytes[i..].starts_with(JUMBF) || (i >= 4 && &bytes[i..i + 4] == JUMBF) {
            count += 1;
        }
        if let Some(size) = read_u32_be(bytes, i) {
            let size = size as usize;
            if size >= 8 && i + size <= bytes.len() {
                if let Some(t) = box_type_at(bytes, i) {
                    if &t == JUMBF || &t == C2PA || &t == CAIX {
                        count += 1;
                    }
                }
                i += size;
                continue;
            }
        }
        i += 1;
    }
    labels.truncate(8);
    (count, labels)
}

fn detect_container_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"%PDF") {
        return Some("pdf");
    }
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        return Some("jpeg");
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        return Some("mp4");
    }
    None
}

/// Parse C2PA/JUMBF structure from file bytes.
pub fn parse_c2pa_summary(bytes: &[u8]) -> C2paSummary {
    let (jumbf_boxes, assertion_labels) = scan_jumbf_boxes(bytes);
    let hay = String::from_utf8_lossy(bytes);
    let marker_present = jumbf_boxes > 0
        || hay.contains("c2pa")
        || hay.contains("jumb")
        || bytes.windows(4).any(|w| w == b"jP  ");

    if !marker_present {
        return C2paSummary {
            present: false,
            status: "not_present".to_string(),
            validation: "none".to_string(),
            ..Default::default()
        };
    }

    let format = detect_container_format(bytes).map(|s| s.to_string());
    let validation = if jumbf_boxes > 0 && !assertion_labels.is_empty() {
        "structure_parsed_signature_not_verified"
    } else if jumbf_boxes > 0 {
        "jumbf_detected_assertions_not_extracted"
    } else {
        "marker_only"
    };

    C2paSummary {
        present: true,
        status: "parsed".to_string(),
        marker: Some("jumbf_or_c2pa".to_string()),
        format,
        jumbf_boxes,
        assertion_labels,
        validation: validation.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_when_no_marker() {
        let s = parse_c2pa_summary(b"plain text file");
        assert!(!s.present);
    }

    #[test]
    fn detects_embedded_urn() {
        let mut buf = b"prefix ".to_vec();
        buf.extend_from_slice(b"urn:c2pa:claim.test/v1");
        let s = parse_c2pa_summary(&buf);
        assert!(s.present);
        assert!(!s.assertion_labels.is_empty());
    }
}
