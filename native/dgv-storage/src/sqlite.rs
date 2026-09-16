//! SQLite storage backend.
//!
//! Uses sqlx with the `sqlite` feature. Single-file, zero-config.
//! Good for development, testing, and single-node deployments.

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::Row;
use std::str::FromStr;

use crate::{
    A2aEnvelopeRecord, AgentKeyRecord, ApprovalRecord, DecisionRecord, PolicyRecord,
    RevocationRecord, Storage, StorageError, TokenRecord,
};

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub async fn new(database_url: &str) -> Result<Self, StorageError> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = SqlitePool::connect_with(opts).await?;
        Self::migrate(&pool).await?;
        Ok(Self { pool })
    }

    /// In-memory database for tests.
    pub async fn in_memory() -> Result<Self, StorageError> {
        Self::new("sqlite::memory:").await
    }

    async fn migrate(pool: &SqlitePool) -> Result<(), StorageError> {
        // SQLite does support multiple statements, but split for consistency
        // with Postgres and clearer error reporting.
        let statements = [
            r#"CREATE TABLE IF NOT EXISTS decisions (
                run_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                gate_state TEXT NOT NULL,
                reason_codes TEXT NOT NULL,
                replay_inputs TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_unix_ms INTEGER NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS tokens (
                token_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                params_hash TEXT NOT NULL,
                expires_unix_ms INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                consumed_unix_ms INTEGER,
                decision_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_unix_ms INTEGER NOT NULL,
                min_approvals INTEGER NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                script TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                created_unix_ms INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                signature TEXT,
                min_approvals INTEGER NOT NULL DEFAULT 0,
                min_justification_length INTEGER NOT NULL DEFAULT 0
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_policy_lookup ON policies(tool, action, active)",
            r#"CREATE TABLE IF NOT EXISTS tenant_policies (
                tenant_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                script TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                created_unix_ms INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                signature TEXT,
                min_approvals INTEGER NOT NULL DEFAULT 0,
                min_justification_length INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, policy_id)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_tenant_policy ON tenant_policies(tenant_id, tool, action, active)",
            r#"CREATE TABLE IF NOT EXISTS revocations (
                actor_id TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                revoked_unix_ms INTEGER NOT NULL,
                revoked_by TEXT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT NOT NULL,
                window_start_ms INTEGER NOT NULL,
                count INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                window_ms INTEGER NOT NULL,
                PRIMARY KEY (key, window_start_ms)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS approvals (
                token_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                approved_unix_ms INTEGER NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (token_id, approver_id)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS agent_keys (
                agent_id TEXT PRIMARY KEY,
                public_key_hex TEXT NOT NULL,
                enc_public_key_hex TEXT,
                registered_unix_ms INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )"#,
            r#"CREATE TABLE IF NOT EXISTS a2a_envelopes (
                envelope_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                nonce TEXT NOT NULL,
                sent_unix_ms INTEGER NOT NULL,
                expires_unix_ms INTEGER NOT NULL,
                sender_signature TEXT NOT NULL,
                gate_receipt_signature TEXT NOT NULL,
                transport_ref TEXT,
                delivered INTEGER NOT NULL DEFAULT 0,
                delivered_unix_ms INTEGER
            )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_nonce ON a2a_envelopes(sender_id, nonce)",
            "CREATE INDEX IF NOT EXISTS idx_a2a_inbox ON a2a_envelopes(recipient_id, delivered)",
        ];
        for stmt in statements {
            sqlx::query(stmt).execute(pool).await?;
        }
        // Backfill columns added after initial release — SQLite has no
        // ADD COLUMN IF NOT EXISTS, so ignore "duplicate column" failures.
        for alter in [
            "ALTER TABLE agent_keys ADD COLUMN enc_public_key_hex TEXT",
            "ALTER TABLE a2a_envelopes ADD COLUMN transport_ref TEXT",
        ] {
            let _ = sqlx::query(alter).execute(pool).await;
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn store_decision(&self, d: DecisionRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO decisions
               (run_id, request_id, decision_hash, gate_state, reason_codes, replay_inputs, signature, created_unix_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&d.run_id)
        .bind(&d.request_id)
        .bind(&d.decision_hash)
        .bind(&d.gate_state)
        .bind(&d.reason_codes)
        .bind(&d.replay_inputs)
        .bind(&d.signature)
        .bind(d.created_unix_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_decision(&self, run_id: &str) -> Result<Option<DecisionRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM decisions WHERE run_id = ?")
            .bind(run_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(DecisionRecord {
                run_id: r.get("run_id"),
                request_id: r.get("request_id"),
                decision_hash: r.get("decision_hash"),
                gate_state: r.get("gate_state"),
                reason_codes: r.get("reason_codes"),
                replay_inputs: r.get("replay_inputs"),
                signature: r.get("signature"),
                created_unix_ms: r.get("created_unix_ms"),
            })),
            None => Ok(None),
        }
    }

    async fn store_token(&self, t: TokenRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO tokens
               (token_id, request_id, tool, action, params_hash, expires_unix_ms, consumed, consumed_unix_ms, decision_hash, signature, created_unix_ms, min_approvals)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&t.token_id)
        .bind(&t.request_id)
        .bind(&t.tool)
        .bind(&t.action)
        .bind(&t.params_hash)
        .bind(t.expires_unix_ms)
        .bind(t.consumed)
        .bind(t.consumed_unix_ms)
        .bind(&t.decision_hash)
        .bind(&t.signature)
        .bind(t.created_unix_ms)
        .bind(t.min_approvals)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<TokenRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM tokens WHERE token_id = ?")
            .bind(token_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(TokenRecord {
                token_id: r.get("token_id"),
                request_id: r.get("request_id"),
                tool: r.get("tool"),
                action: r.get("action"),
                params_hash: r.get("params_hash"),
                expires_unix_ms: r.get("expires_unix_ms"),
                consumed: r.get::<i64, _>("consumed") != 0,
                consumed_unix_ms: r.get("consumed_unix_ms"),
                decision_hash: r.get("decision_hash"),
                signature: r.get("signature"),
                created_unix_ms: r.get("created_unix_ms"),
                min_approvals: r.get("min_approvals"),
            })),
            None => Ok(None),
        }
    }

    async fn mark_token_consumed(&self, token_id: &str, consumed_unix_ms: i64) -> Result<(), StorageError> {
        let result = sqlx::query(
            r#"UPDATE tokens SET consumed = 1, consumed_unix_ms = ? WHERE token_id = ? AND consumed = 0"#,
        )
        .bind(consumed_unix_ms)
        .bind(token_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict); // already consumed
        }
        Ok(())
    }

    async fn store_policy(&self, p: PolicyRecord) -> Result<(), StorageError> {
        // Deactivate existing active policies for this tool+action
        sqlx::query("UPDATE policies SET active = 0 WHERE tool = ? AND action = ? AND active = 1")
            .bind(&p.tool)
            .bind(&p.action)
            .execute(&self.pool)
            .await?;
        // Insert new active policy
        sqlx::query(
            r#"INSERT INTO policies
               (policy_id, tool, action, script, policy_version, created_unix_ms, active, signature, min_approvals, min_justification_length)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)"#,
        )
        .bind(&p.policy_id)
        .bind(&p.tool)
        .bind(&p.action)
        .bind(&p.script)
        .bind(&p.policy_version)
        .bind(p.created_unix_ms)
        .bind(&p.signature)
        .bind(p.min_approvals)
        .bind(p.min_justification_length)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_active_policy(&self, tool: &str, action: &str) -> Result<Option<PolicyRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM policies WHERE tool = ? AND action = ? AND active = 1 ORDER BY created_unix_ms DESC LIMIT 1")
            .bind(tool)
            .bind(action)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(PolicyRecord {
                policy_id: r.get("policy_id"),
                tool: r.get("tool"),
                action: r.get("action"),
                script: r.get("script"),
                policy_version: r.get("policy_version"),
                created_unix_ms: r.get("created_unix_ms"),
                active: r.get::<i64, _>("active") != 0,
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })),
            None => Ok(None),
        }
    }

    async fn deactivate_policy(&self, policy_id: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE policies SET active = 0 WHERE policy_id = ?")
            .bind(policy_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_policy_versions(&self, tool: &str, action: &str) -> Result<Vec<PolicyRecord>, StorageError> {
        let rows = sqlx::query("SELECT * FROM policies WHERE tool = ? AND action = ? ORDER BY created_unix_ms DESC")
            .bind(tool)
            .bind(action)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| PolicyRecord {
                policy_id: r.get("policy_id"),
                tool: r.get("tool"),
                action: r.get("action"),
                script: r.get("script"),
                policy_version: r.get("policy_version"),
                created_unix_ms: r.get("created_unix_ms"),
                active: r.get::<i64, _>("active") != 0,
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })
            .collect())
    }

    async fn reactivate_policy(&self, policy_id: &str) -> Result<(), StorageError> {
        // Look up the policy to find its tool+action scope
        let row = sqlx::query("SELECT tool, action FROM policies WHERE policy_id = ?")
            .bind(policy_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::NotFound)?;
        let tool: String = row.get("tool");
        let action: String = row.get("action");

        // Deactivate all versions for this tool+action, then activate the target
        sqlx::query("UPDATE policies SET active = 0 WHERE tool = ? AND action = ?")
            .bind(&tool)
            .bind(&action)
            .execute(&self.pool)
            .await?;
        sqlx::query("UPDATE policies SET active = 1 WHERE policy_id = ?")
            .bind(policy_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn store_revocation(&self, r: RevocationRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO revocations (actor_id, reason, revoked_unix_ms, revoked_by)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(&r.actor_id)
        .bind(&r.reason)
        .bind(r.revoked_unix_ms)
        .bind(&r.revoked_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn check_revocation(&self, actor_id: &str) -> Result<Option<RevocationRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM revocations WHERE actor_id = ?")
            .bind(actor_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(RevocationRecord {
                actor_id: r.get("actor_id"),
                reason: r.get("reason"),
                revoked_unix_ms: r.get("revoked_unix_ms"),
                revoked_by: r.get("revoked_by"),
            })),
            None => Ok(None),
        }
    }

    async fn list_revocations(&self) -> Result<Vec<RevocationRecord>, StorageError> {
        let rows = sqlx::query("SELECT * FROM revocations ORDER BY revoked_unix_ms DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| RevocationRecord {
                actor_id: r.get("actor_id"),
                reason: r.get("reason"),
                revoked_unix_ms: r.get("revoked_unix_ms"),
                revoked_by: r.get("revoked_by"),
            })
            .collect())
    }

    async fn check_and_increment_rate(&self, key: &str, max_count: i64, window_ms: i64) -> Result<bool, StorageError> {
        let now = chrono::Utc::now().timestamp_millis();
        let window_start = now - (now % window_ms);

        // Try to update existing record
        let result = sqlx::query(
            r#"UPDATE rate_limits SET count = count + 1
               WHERE key = ? AND window_start_ms = ? AND count < max_count"#,
        )
        .bind(key)
        .bind(window_start)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            return Ok(true);
        }

        // Check if we're blocked (record exists but count >= max)
        let existing = sqlx::query("SELECT count, max_count FROM rate_limits WHERE key = ? AND window_start_ms = ?")
            .bind(key)
            .bind(window_start)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = existing {
            let count: i64 = row.get("count");
            let max: i64 = row.get("max_count");
            if count >= max {
                return Ok(false); // rate limited
            }
            // Try again to increment (race condition handling)
            let result = sqlx::query(
                r#"UPDATE rate_limits SET count = count + 1
                   WHERE key = ? AND window_start_ms = ? AND count < max_count"#,
            )
            .bind(key)
            .bind(window_start)
            .execute(&self.pool)
            .await?;
            return Ok(result.rows_affected() > 0);
        }

        // Insert new record for this window
        sqlx::query(
            r#"INSERT OR REPLACE INTO rate_limits (key, window_start_ms, count, max_count, window_ms)
               VALUES (?, ?, 1, ?, ?)"#,
        )
        .bind(key)
        .bind(window_start)
        .bind(max_count)
        .bind(window_ms)
        .execute(&self.pool)
        .await?;

        Ok(true)
    }

    async fn store_tenant_policy(&self, tenant_id: &str, p: PolicyRecord) -> Result<(), StorageError> {
        // Deactivate existing active tenant policies
        sqlx::query("UPDATE tenant_policies SET active = 0 WHERE tenant_id = ? AND tool = ? AND action = ? AND active = 1")
            .bind(tenant_id)
            .bind(&p.tool)
            .bind(&p.action)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO tenant_policies
               (tenant_id, policy_id, tool, action, script, policy_version, created_unix_ms, active, signature, min_approvals, min_justification_length)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)"#,
        )
        .bind(tenant_id)
        .bind(&p.policy_id)
        .bind(&p.tool)
        .bind(&p.action)
        .bind(&p.script)
        .bind(&p.policy_version)
        .bind(p.created_unix_ms)
        .bind(&p.signature)
        .bind(p.min_approvals)
        .bind(p.min_justification_length)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_tenant_active_policy(&self, tenant_id: &str, tool: &str, action: &str) -> Result<Option<PolicyRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM tenant_policies WHERE tenant_id = ? AND tool = ? AND action = ? AND active = 1 ORDER BY created_unix_ms DESC LIMIT 1")
            .bind(tenant_id)
            .bind(tool)
            .bind(action)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(PolicyRecord {
                policy_id: r.get("policy_id"),
                tool: r.get("tool"),
                action: r.get("action"),
                script: r.get("script"),
                policy_version: r.get("policy_version"),
                created_unix_ms: r.get("created_unix_ms"),
                active: r.get::<i64, _>("active") != 0,
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })),
            None => Ok(None),
        }
    }

    async fn store_approval(&self, a: ApprovalRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO approvals
               (token_id, approver_id, approved_unix_ms, signature)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(&a.token_id)
        .bind(&a.approver_id)
        .bind(a.approved_unix_ms)
        .bind(&a.signature)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn count_approvals(&self, token_id: &str) -> Result<i64, StorageError> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM approvals WHERE token_id = ?")
            .bind(token_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    async fn register_agent_key(&self, k: AgentKeyRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT OR REPLACE INTO agent_keys
               (agent_id, public_key_hex, enc_public_key_hex, registered_unix_ms, active)
               VALUES (?, ?, ?, ?, ?)"#,
        )
        .bind(&k.agent_id)
        .bind(&k.public_key_hex)
        .bind(&k.enc_public_key_hex)
        .bind(k.registered_unix_ms)
        .bind(k.active)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_agent_key(&self, agent_id: &str) -> Result<Option<AgentKeyRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM agent_keys WHERE agent_id = ?")
            .bind(agent_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(AgentKeyRecord {
                agent_id: r.get("agent_id"),
                public_key_hex: r.get("public_key_hex"),
                enc_public_key_hex: r.get("enc_public_key_hex"),
                registered_unix_ms: r.get("registered_unix_ms"),
                active: r.get::<i64, _>("active") != 0,
            })),
            None => Ok(None),
        }
    }

    async fn deactivate_agent_key(&self, agent_id: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE agent_keys SET active = 0 WHERE agent_id = ?")
            .bind(agent_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn store_a2a_envelope(&self, e: A2aEnvelopeRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO a2a_envelopes
               (envelope_id, sender_id, recipient_id, payload_hash, nonce, sent_unix_ms,
                expires_unix_ms, sender_signature, gate_receipt_signature, transport_ref,
                delivered, delivered_unix_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
        )
        .bind(&e.envelope_id)
        .bind(&e.sender_id)
        .bind(&e.recipient_id)
        .bind(&e.payload_hash)
        .bind(&e.nonce)
        .bind(e.sent_unix_ms)
        .bind(e.expires_unix_ms)
        .bind(&e.sender_signature)
        .bind(&e.gate_receipt_signature)
        .bind(&e.transport_ref)
        .bind(e.delivered)
        .bind(e.delivered_unix_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_a2a_inbox(&self, recipient_id: &str) -> Result<Vec<A2aEnvelopeRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT * FROM a2a_envelopes WHERE recipient_id = ? AND delivered = 0 ORDER BY sent_unix_ms ASC",
        )
        .bind(recipient_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| A2aEnvelopeRecord {
                envelope_id: r.get("envelope_id"),
                sender_id: r.get("sender_id"),
                recipient_id: r.get("recipient_id"),
                payload_hash: r.get("payload_hash"),
                nonce: r.get("nonce"),
                sent_unix_ms: r.get("sent_unix_ms"),
                expires_unix_ms: r.get("expires_unix_ms"),
                sender_signature: r.get("sender_signature"),
                gate_receipt_signature: r.get("gate_receipt_signature"),
                transport_ref: r.get("transport_ref"),
                delivered: r.get::<i64, _>("delivered") != 0,
                delivered_unix_ms: r.get("delivered_unix_ms"),
            })
            .collect())
    }

    async fn mark_a2a_delivered(&self, envelope_id: &str, delivered_unix_ms: i64) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE a2a_envelopes SET delivered = 1, delivered_unix_ms = ? WHERE envelope_id = ? AND delivered = 0",
        )
        .bind(delivered_unix_ms)
        .bind(envelope_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict); // already delivered or not found
        }
        Ok(())
    }

    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}
