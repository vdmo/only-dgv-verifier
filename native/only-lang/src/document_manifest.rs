//! Document provenance manifests — content commitment + governance binding.
//!
//! Mirrors TPNN `run_manifest_json` pattern for files (PDF, images, letters).

use crate::c2pa_read::parse_c2pa_summary;
use crate::pir_watermark::{summary_for_untrusted_upload, verify_pir_watermark};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

pub const MANIFEST_VERSION: &str = "0.1";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How the bytes entered the system (honest labeling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentProvenanceClass {
    ClientUpload,
    PlatformGeneratedLetter,
    PlatformGeneratedPdf,
    TrustedCapture,
    ThirdPartyImport,
}

impl DocumentProvenanceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientUpload => "client_upload",
            Self::PlatformGeneratedLetter => "platform_generated_letter",
            Self::PlatformGeneratedPdf => "platform_generated_pdf",
            Self::TrustedCapture => "trusted_capture",
            Self::ThirdPartyImport => "third_party_import",
        }
    }
}

pub use crate::c2pa_read::C2paSummary;
pub use crate::pir_watermark::PirWatermarkSummary;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentManifest {
    pub manifest_version: String,
    pub content_sha256: String,
    pub mime: String,
    pub source: String,
    pub provenance_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_fingerprint: Option<String>,
    pub engine_version: String,
    pub manifest_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sidecar_path: Option<String>,
    pub ai_generated: bool,
    pub capture_trusted: bool,
    #[serde(default)]
    pub c2pa: C2paSummary,
    #[serde(default)]
    pub pir_watermark: PirWatermarkSummary,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRegistryEntry {
    pub registered_unix_ms: u128,
    pub manifest: DocumentManifest,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DocumentRegistry {
    pub generated_unix_ms: u128,
    pub documents: Vec<DocumentRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentVerifyResult {
    pub ok: bool,
    pub content_sha256: String,
    pub integrity: String,
    pub registered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<DocumentManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance: Option<serde_json::Value>,
    pub warnings: Vec<String>,
}

pub fn content_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn facts_fingerprint_hex(facts_json: &str) -> String {
    let mut h = DefaultHasher::new();
    facts_json.hash(&mut h);
    format!("{:016x}", h.finish())
}

pub fn manifest_fingerprint(m: &DocumentManifest) -> String {
    let mut h = DefaultHasher::new();
    m.content_sha256.hash(&mut h);
    m.mime.hash(&mut h);
    m.provenance_class.hash(&mut h);
    if let Some(ref t) = m.template_id {
        t.hash(&mut h);
    }
    if let Some(ref f) = m.facts_fingerprint {
        f.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

pub fn scan_c2pa_marker(bytes: &[u8]) -> C2paSummary {
    parse_c2pa_summary(bytes)
}

pub fn pir_watermark_for_class(
    provenance_class: DocumentProvenanceClass,
    capture_trusted: bool,
    bytes: Option<&[u8]>,
) -> PirWatermarkSummary {
    if provenance_class == DocumentProvenanceClass::TrustedCapture && capture_trusted {
        if let Some(b) = bytes {
            verify_pir_watermark(b, crate::pir_watermark::DEFAULT_WATERMARK_LEN, 1.0)
        } else {
            PirWatermarkSummary {
                applicable: true,
                verified: false,
                status: "awaiting_bytes_for_verification".to_string(),
                watermark_len: crate::pir_watermark::DEFAULT_WATERMARK_LEN,
                residual: None,
            }
        }
    } else {
        summary_for_untrusted_upload()
    }
}

pub fn default_warnings(provenance_class: DocumentProvenanceClass) -> Vec<String> {
    match provenance_class {
        DocumentProvenanceClass::ClientUpload | DocumentProvenanceClass::ThirdPartyImport => {
            vec![
                "Client upload — authenticity not cryptographically proven.".to_string(),
                "Use trusted capture or C2PA for stronger origin claims.".to_string(),
            ]
        }
        DocumentProvenanceClass::PlatformGeneratedLetter
        | DocumentProvenanceClass::PlatformGeneratedPdf => {
            vec!["Platform-generated output — bind to governance decision_hash before send.".to_string()]
        }
        DocumentProvenanceClass::TrustedCapture => {
            vec!["Trusted capture — PIR watermark verified when residual within tolerance.".to_string()]
        }
    }
}

pub struct DocumentManifestBuilder {
    bytes: Option<Vec<u8>>,
    content_sha256: Option<String>,
    mime: String,
    source: String,
    provenance_class: DocumentProvenanceClass,
    template_id: Option<String>,
    facts_fingerprint: Option<String>,
    decision_hash: Option<String>,
    gate_state: Option<String>,
    governance_run_id: Option<String>,
    ai_generated: bool,
    capture_trusted: bool,
}

impl DocumentManifestBuilder {
    pub fn new(
        mime: impl Into<String>,
        source: impl Into<String>,
        provenance_class: DocumentProvenanceClass,
    ) -> Self {
        Self {
            bytes: None,
            content_sha256: None,
            mime: mime.into(),
            source: source.into(),
            provenance_class,
            template_id: None,
            facts_fingerprint: None,
            decision_hash: None,
            gate_state: None,
            governance_run_id: None,
            ai_generated: matches!(
                provenance_class,
                DocumentProvenanceClass::PlatformGeneratedLetter
                    | DocumentProvenanceClass::PlatformGeneratedPdf
            ),
            capture_trusted: provenance_class == DocumentProvenanceClass::TrustedCapture,
        }
    }

    pub fn content_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.content_sha256 = Some(content_sha256_hex(&bytes));
        self.bytes = Some(bytes);
        self
    }

    pub fn content_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.content_sha256 = Some(sha256.into());
        self
    }

    pub fn template_id(mut self, id: impl Into<String>) -> Self {
        self.template_id = Some(id.into());
        self
    }

    pub fn facts_json(mut self, facts_json: &str) -> Self {
        self.facts_fingerprint = Some(facts_fingerprint_hex(facts_json));
        self
    }

    pub fn facts_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.facts_fingerprint = Some(fp.into());
        self
    }

    pub fn governance(
        mut self,
        decision_hash: impl Into<String>,
        gate_state: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        self.decision_hash = Some(decision_hash.into());
        self.gate_state = Some(gate_state.into());
        self.governance_run_id = Some(run_id.into());
        self
    }

    pub fn build(self) -> Result<(DocumentManifest, Option<Vec<u8>>), &'static str> {
        let content_sha256 = self
            .content_sha256
            .ok_or("content_sha256 or content bytes required")?;
        let bytes = self.bytes;
        let bytes_ref = bytes.as_deref();
        let c2pa = bytes_ref.map(parse_c2pa_summary).unwrap_or_default();
        let pir_watermark = pir_watermark_for_class(self.provenance_class, self.capture_trusted, bytes_ref);
        let mut warnings = default_warnings(self.provenance_class);
        if c2pa.present {
            if c2pa.validation.contains("not_verified") {
                warnings.push("C2PA structure parsed — cryptographic signature not verified in pilot.".to_string());
            }
        }

        let mut manifest = DocumentManifest {
            manifest_version: MANIFEST_VERSION.to_string(),
            content_sha256: content_sha256.clone(),
            mime: self.mime,
            source: self.source,
            provenance_class: self.provenance_class.as_str().to_string(),
            template_id: self.template_id,
            facts_fingerprint: self.facts_fingerprint,
            engine_version: ENGINE_VERSION.to_string(),
            manifest_fingerprint: String::new(),
            decision_hash: self.decision_hash,
            gate_state: self.gate_state,
            governance_run_id: self.governance_run_id,
            sidecar_path: None,
            ai_generated: self.ai_generated,
            capture_trusted: self.capture_trusted,
            c2pa,
            pir_watermark,
            warnings,
        };
        manifest.manifest_fingerprint = manifest_fingerprint(&manifest);
        Ok((manifest, bytes))
    }
}

/// Root for registry, sidecars, blobs. Override with `ONLY_DOCUMENTS_DIR`.
pub fn documents_root(base: &Path) -> PathBuf {
    std::env::var("ONLY_DOCUMENTS_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| base.join("documents"))
}

pub fn blob_path_for(base: &Path, content_sha256: &str) -> PathBuf {
    documents_root(base)
        .join("blobs")
        .join(content_sha256)
}

pub fn store_content_blob(base: &Path, content_sha256: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let path = blob_path_for(base, content_sha256);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, bytes)?;
    Ok(path)
}

pub fn read_content_blob(base: &Path, content_sha256: &str) -> io::Result<Vec<u8>> {
    std::fs::read(blob_path_for(base, content_sha256))
}

pub fn sidecar_path_for(base: &Path, content_sha256: &str) -> PathBuf {
    documents_root(base)
        .join("sidecars")
        .join(format!("{content_sha256}.manifest.json"))
}

pub fn write_sidecar(base: &Path, manifest: &DocumentManifest) -> io::Result<PathBuf> {
    let path = sidecar_path_for(base, &manifest.content_sha256);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut m = manifest.clone();
    m.sidecar_path = Some(path.to_string_lossy().to_string());
    let json = serde_json::to_string_pretty(&m)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

pub fn read_sidecar(base: &Path, content_sha256: &str) -> io::Result<DocumentManifest> {
    let path = sidecar_path_for(base, content_sha256);
    let txt = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&txt)?)
}

pub fn registry_path(base: &Path) -> PathBuf {
    documents_root(base).join("registry.json")
}

pub fn load_registry(base: &Path) -> io::Result<DocumentRegistry> {
    let path = registry_path(base);
    if !path.exists() {
        return Ok(DocumentRegistry {
            generated_unix_ms: 0,
            documents: Vec::new(),
        });
    }
    let txt = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&txt)?)
}

pub fn save_registry(base: &Path, registry: &DocumentRegistry) -> io::Result<()> {
    let path = registry_path(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(registry)?)
}

pub fn register_document(
    base: &Path,
    manifest: DocumentManifest,
    registered_unix_ms: u128,
    write_sidecar_file: bool,
) -> io::Result<DocumentManifest> {
    let mut manifest = manifest;
    if write_sidecar_file {
        let path = write_sidecar(base, &manifest)?;
        manifest.sidecar_path = Some(path.to_string_lossy().to_string());
    }
    let mut registry = load_registry(base)?;
    registry
        .documents
        .retain(|e| e.manifest.content_sha256 != manifest.content_sha256);
    registry.documents.push(DocumentRegistryEntry {
        registered_unix_ms,
        manifest: manifest.clone(),
    });
    registry.generated_unix_ms = registered_unix_ms;
    save_registry(base, &registry)?;
    Ok(manifest)
}

/// Sync governance fields on an existing manifest (e.g. before send execute).
pub fn bind_governance(
    base: &Path,
    content_sha256: &str,
    decision_hash: &str,
    gate_state: &str,
    governance_run_id: &str,
) -> io::Result<DocumentManifest> {
    let mut registry = load_registry(base)?;
    let entry = registry
        .documents
        .iter_mut()
        .find(|e| e.manifest.content_sha256.eq_ignore_ascii_case(content_sha256))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "document not registered"))?;
    entry.manifest.decision_hash = Some(decision_hash.to_string());
    entry.manifest.gate_state = Some(gate_state.to_string());
    entry.manifest.governance_run_id = Some(governance_run_id.to_string());
    let updated = entry.manifest.clone();
    save_registry(base, &registry)?;
    let _ = write_sidecar(base, &updated)?;
    Ok(updated)
}

pub fn register_document_with_blob(
    base: &Path,
    manifest: DocumentManifest,
    bytes: &[u8],
    registered_unix_ms: u128,
    write_sidecar_file: bool,
) -> io::Result<DocumentManifest> {
    store_content_blob(base, &manifest.content_sha256, bytes)?;
    register_document(base, manifest, registered_unix_ms, write_sidecar_file)
}

pub fn lookup_by_sha256(base: &Path, content_sha256: &str) -> io::Result<Option<DocumentManifest>> {
    let registry = load_registry(base)?;
    Ok(registry
        .documents
        .iter()
        .find(|e| e.manifest.content_sha256.eq_ignore_ascii_case(content_sha256))
        .map(|e| e.manifest.clone()))
}

pub fn verify_document(
    base: &Path,
    content_sha256: &str,
    content_bytes: Option<&[u8]>,
    governance_lookup: Option<serde_json::Value>,
) -> DocumentVerifyResult {
    let mut warnings = Vec::new();
    let integrity = match content_bytes {
        Some(bytes) => {
            let computed = content_sha256_hex(bytes);
            if computed.eq_ignore_ascii_case(content_sha256) {
                "MATCH".to_string()
            } else {
                warnings.push(format!(
                    "Content hash mismatch: expected {content_sha256}, got {computed}"
                ));
                "MISMATCH".to_string()
            }
        }
        None => "NOT_CHECKED".to_string(),
    };

    let sidecar = read_sidecar(base, content_sha256).ok();
    let registry = lookup_by_sha256(base, content_sha256).ok().flatten();
    let manifest = sidecar.or(registry);

    if manifest.is_none() {
        warnings.push("Document not registered in Only-Engine registry.".to_string());
    }

    if let Some(ref m) = manifest {
        warnings.extend(m.warnings.clone());
    }

    DocumentVerifyResult {
        ok: integrity != "MISMATCH",
        content_sha256: content_sha256.to_string(),
        integrity,
        registered: manifest.is_some(),
        manifest,
        governance: governance_lookup,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_stable() {
        let h1 = content_sha256_hex(b"hello letter");
        let h2 = content_sha256_hex(b"hello letter");
        assert_eq!(h1, h2);
        assert_ne!(h1, content_sha256_hex(b"other"));
    }

    #[test]
    fn sidecar_roundtrip() {
        let dir = std::env::temp_dir().join("only_doc_manifest_test");
        let _ = std::fs::remove_dir_all(&dir);
        let (manifest, _) = DocumentManifestBuilder::new(
            "application/pdf",
            "platform",
            DocumentProvenanceClass::PlatformGeneratedLetter,
        )
        .content_bytes(b"%PDF-1.4 demo".to_vec())
        .template_id("LBA_v1")
        .facts_json(r#"{"amount":800}"#)
        .build()
        .unwrap();
        write_sidecar(&dir, &manifest).unwrap();
        let read = read_sidecar(&dir, &manifest.content_sha256).unwrap();
        assert_eq!(read.template_id, Some("LBA_v1".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_integrity_mismatch() {
        let dir = std::env::temp_dir().join("only_doc_verify_test");
        let _ = std::fs::remove_dir_all(&dir);
        let (manifest, _) = DocumentManifestBuilder::new(
            "application/pdf",
            "client",
            DocumentProvenanceClass::ClientUpload,
        )
        .content_bytes(b"original".to_vec())
        .build()
        .unwrap();
        register_document(&dir, manifest.clone(), 1, true).unwrap();
        let result = verify_document(&dir, &manifest.content_sha256, Some(b"tampered"), None);
        assert_eq!(result.integrity, "MISMATCH");
        assert!(!result.ok);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
