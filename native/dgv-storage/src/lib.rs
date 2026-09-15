//! DGV Storage — trait-based persistence for the enforcement gate.
//!
//! Two backends:
//!   - SqliteStorage  (dev/test, single-file, zero-config)
//!   - PostgresStorage (production, multi-node, connection pooling)
//!
//! Both implement the same async Storage trait so the gate can swap backends
//! without changing business logic.

mod sqlite;
mod postgres;

pub use sqlite::SqliteStorage;
pub use postgres::PostgresStorage;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ── Records ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub run_id: String,
    pub request_id: String,
    pub decision_hash: String,
    pub gate_state: String,
    pub reason_codes: String, // JSON array
    pub replay_inputs: String, // JSON object
    pub signature: String,
    pub created_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token_id: String,
    pub request_id: String,
    pub tool: String,
    pub action: String,
    pub params_hash: String,
    pub expires_unix_ms: i64,
    pub consumed: bool,
    pub consumed_unix_ms: Option<i64>,
    pub decision_hash: String,
    pub signature: String,
    pub created_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub policy_id: String,
    pub tool: String,
    pub action: String,
    pub script: String,
    pub policy_version: String,
    pub created_unix_ms: i64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub actor_id: String,
    pub reason: String,
    pub revoked_unix_ms: i64,
    pub revoked_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRecord {
    pub key: String,       // e.g., "tenant:agent:tool"
    pub window_start_ms: i64,
    pub count: i64,
    pub max_count: i64,
    pub window_ms: i64,
}

// ── Storage trait ────────────────────────────────────────────────────────────

#[async_trait]
pub trait Storage: Send + Sync {
    // Decisions
    async fn store_decision(&self, d: DecisionRecord) -> Result<(), StorageError>;
    async fn get_decision(&self, run_id: &str) -> Result<Option<DecisionRecord>, StorageError>;

    // Tokens
    async fn store_token(&self, t: TokenRecord) -> Result<(), StorageError>;
    async fn get_token(&self, token_id: &str) -> Result<Option<TokenRecord>, StorageError>;
    async fn mark_token_consumed(&self, token_id: &str, consumed_unix_ms: i64) -> Result<(), StorageError>;

    // Policies
    async fn store_policy(&self, p: PolicyRecord) -> Result<(), StorageError>;
    async fn get_active_policy(&self, tool: &str, action: &str) -> Result<Option<PolicyRecord>, StorageError>;
    async fn deactivate_policy(&self, policy_id: &str) -> Result<(), StorageError>;

    // Revocations
    async fn store_revocation(&self, r: RevocationRecord) -> Result<(), StorageError>;
    async fn check_revocation(&self, actor_id: &str) -> Result<Option<RevocationRecord>, StorageError>;
    async fn list_revocations(&self) -> Result<Vec<RevocationRecord>, StorageError>;

    // Rate limiting
    async fn check_and_increment_rate(&self, key: &str, max_count: i64, window_ms: i64) -> Result<bool, StorageError>;

    // Multi-tenant
    async fn store_tenant_policy(&self, tenant_id: &str, p: PolicyRecord) -> Result<(), StorageError>;
    async fn get_tenant_active_policy(&self, tenant_id: &str, tool: &str, action: &str) -> Result<Option<PolicyRecord>, StorageError>;

    // Health
    async fn ping(&self) -> Result<(), StorageError>;
}

#[derive(Debug)]
pub enum StorageError {
    Sqlx(sqlx::Error),
    NotFound,
    Conflict,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Sqlx(e) => write!(f, "storage error: {}", e),
            StorageError::NotFound => write!(f, "not found"),
            StorageError::Conflict => write!(f, "conflict"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<sqlx::Error> for StorageError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => StorageError::NotFound,
            sqlx::Error::Database(ref d) if d.is_unique_violation() => StorageError::Conflict,
            other => StorageError::Sqlx(other),
        }
    }
}
