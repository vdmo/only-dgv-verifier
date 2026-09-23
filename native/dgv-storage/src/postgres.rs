//! PostgreSQL storage backend.
//!
//! Uses sqlx with the `postgres` feature. Production-grade, multi-node,
//! connection pooling. Good for distributed deployments where multiple
//! gate instances share the same database.

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;

use crate::{
    A2aEnvelopeRecord, AgentKeyRecord, ApprovalRecord, DecisionRecord, DelegationRecord,
    EvidenceArtifactRecord, PendingDecisionRecord, PolicyRecord, RevocationRecord,
    SessionActionRecord, Storage, StorageError, TokenRecord, VerificationEventRecord,
    VerificationUsageSummary,
};

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self, StorageError> {
        // Short acquire timeout: a gate should surface an unreachable Postgres
        // in seconds and fall back to degraded boot, not hang for 30s.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(database_url)
            .await?;
        Self::run_migrations(&pool).await?;
        Ok(Self { pool })
    }

    /// Build a storage whose pool connects lazily. The gate boots "degraded":
    /// every query fails until Postgres is reachable, which the partition
    /// policy turns into fail-closed denials. Call `migrate` in a retry loop
    /// until it succeeds — the node self-heals when the database returns.
    pub fn new_lazy(database_url: &str) -> Result<Self, StorageError> {
        // Short acquire timeout: under partition every query must fail fast,
        // not park a request for the 30s default.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect_lazy(database_url)?;
        Ok(Self { pool })
    }

    /// Run schema migrations against the pool. Idempotent (IF NOT EXISTS).
    pub async fn migrate(&self) -> Result<(), StorageError> {
        Self::run_migrations(&self.pool).await
    }

    async fn run_migrations(pool: &PgPool) -> Result<(), StorageError> {
        // Postgres doesn't support multiple commands in a single prepared statement.
        // Execute each migration separately.
        let statements = [
            r#"CREATE TABLE IF NOT EXISTS decisions (
                run_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                decision_hash TEXT NOT NULL,
                gate_state TEXT NOT NULL,
                reason_codes TEXT NOT NULL,
                replay_inputs TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS tokens (
                token_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                params_hash TEXT NOT NULL,
                expires_unix_ms BIGINT NOT NULL,
                consumed BOOLEAN NOT NULL DEFAULT FALSE,
                consumed_unix_ms BIGINT,
                decision_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL,
                min_approvals BIGINT NOT NULL DEFAULT 0,
                granted_to TEXT NOT NULL DEFAULT '',
                parent_token_id TEXT,
                delegation_depth BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS delegations (
                delegation_id TEXT PRIMARY KEY,
                parent_token_id TEXT NOT NULL,
                child_token_id TEXT NOT NULL UNIQUE,
                delegator_id TEXT NOT NULL,
                delegatee_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                script TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                signature TEXT,
                min_approvals BIGINT NOT NULL DEFAULT 0,
                min_justification_length BIGINT NOT NULL DEFAULT 0
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_policy_lookup ON policies(tool, action, active)",
            r#"CREATE TABLE IF NOT EXISTS tenant_policies (
                tenant_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                script TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                signature TEXT,
                min_approvals BIGINT NOT NULL DEFAULT 0,
                min_justification_length BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, policy_id)
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_tenant_policy ON tenant_policies(tenant_id, tool, action, active)",
            r#"CREATE TABLE IF NOT EXISTS revocations (
                actor_id TEXT PRIMARY KEY,
                reason TEXT NOT NULL,
                revoked_unix_ms BIGINT NOT NULL,
                revoked_by TEXT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT NOT NULL,
                window_start_ms BIGINT NOT NULL,
                count BIGINT NOT NULL,
                max_count BIGINT NOT NULL,
                window_ms BIGINT NOT NULL,
                PRIMARY KEY (key, window_start_ms)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS approvals (
                token_id TEXT NOT NULL,
                approver_id TEXT NOT NULL,
                approved_unix_ms BIGINT NOT NULL,
                signature TEXT NOT NULL,
                PRIMARY KEY (token_id, approver_id)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS agent_keys (
                agent_id TEXT PRIMARY KEY,
                public_key_hex TEXT NOT NULL,
                enc_public_key_hex TEXT,
                pq_public_key_hex TEXT,
                registered_unix_ms BIGINT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE
            )"#,
            r#"CREATE TABLE IF NOT EXISTS a2a_envelopes (
                envelope_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                nonce TEXT NOT NULL,
                sent_unix_ms BIGINT NOT NULL,
                expires_unix_ms BIGINT NOT NULL,
                sender_signature TEXT NOT NULL,
                gate_receipt_signature TEXT NOT NULL,
                transport_ref TEXT,
                delivered BOOLEAN NOT NULL DEFAULT FALSE,
                delivered_unix_ms BIGINT
            )"#,
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_nonce ON a2a_envelopes(sender_id, nonce)",
            "CREATE INDEX IF NOT EXISTS idx_a2a_inbox ON a2a_envelopes(recipient_id, delivered)",
            "ALTER TABLE agent_keys ADD COLUMN IF NOT EXISTS enc_public_key_hex TEXT",
            "ALTER TABLE agent_keys ADD COLUMN IF NOT EXISTS pq_public_key_hex TEXT",
            "ALTER TABLE a2a_envelopes ADD COLUMN IF NOT EXISTS transport_ref TEXT",
            "ALTER TABLE tokens ADD COLUMN IF NOT EXISTS granted_to TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE tokens ADD COLUMN IF NOT EXISTS parent_token_id TEXT",
            "ALTER TABLE tokens ADD COLUMN IF NOT EXISTS delegation_depth BIGINT NOT NULL DEFAULT 0",
            "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS parent_decision_hash TEXT",
            r#"CREATE TABLE IF NOT EXISTS decision_chain_tail (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                latest_decision_hash TEXT
            )"#,
            "INSERT INTO decision_chain_tail (id, latest_decision_hash) VALUES (1, NULL) ON CONFLICT (id) DO NOTHING",
            r#"CREATE TABLE IF NOT EXISTS evidence_artifacts (
                artifact_id TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                size_bytes BIGINT NOT NULL,
                content_ref TEXT,
                content_b64 TEXT,
                verified BOOLEAN NOT NULL DEFAULT FALSE,
                metadata TEXT,
                registered_by TEXT NOT NULL,
                registered_unix_ms BIGINT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS session_actions (
                agent_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                risk_level TEXT,
                gate_state TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_session_actions_agent ON session_actions(agent_id, created_unix_ms DESC)",
            r#"CREATE TABLE IF NOT EXISTS pending_decisions (
                pending_token TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                workflow TEXT NOT NULL,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                params_json TEXT NOT NULL,
                justification TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                identity_json TEXT NOT NULL,
                tenant_id TEXT,
                context_hash TEXT,
                reason TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL,
                expires_unix_ms BIGINT NOT NULL,
                resolved BOOLEAN NOT NULL DEFAULT FALSE
            )"#,
            r#"CREATE TABLE IF NOT EXISTS verification_events (
                id TEXT PRIMARY KEY,
                run_id TEXT,
                verified BOOLEAN NOT NULL,
                source TEXT NOT NULL,
                api_key_id TEXT NOT NULL DEFAULT '',
                created_unix_ms BIGINT NOT NULL
            )"#,
            "CREATE INDEX IF NOT EXISTS idx_verification_events_created ON verification_events(created_unix_ms)",
            "CREATE INDEX IF NOT EXISTS idx_verification_events_key ON verification_events(api_key_id, created_unix_ms)",
        ];
        for stmt in statements {
            sqlx::query(stmt).execute(pool).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Storage for PostgresStorage {
    async fn store_decision(&self, d: DecisionRecord) -> Result<(), StorageError> {
        // Chained under one transaction: lock the tail row, insert this
        // decision pointing at its current value, advance it, commit. The
        // row lock (SELECT ... FOR UPDATE) is what prevents two concurrent
        // decisions from both linking to the same parent and forking the
        // chain under real Postgres concurrency.
        let mut tx = self.pool.begin().await?;
        let parent_decision_hash: Option<String> =
            sqlx::query("SELECT latest_decision_hash FROM decision_chain_tail WHERE id = 1 FOR UPDATE")
                .fetch_one(&mut *tx)
                .await?
                .get("latest_decision_hash");
        sqlx::query(
            r#"INSERT INTO decisions
               (run_id, request_id, decision_hash, gate_state, reason_codes, replay_inputs, signature, created_unix_ms, parent_decision_hash)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(&d.run_id)
        .bind(&d.request_id)
        .bind(&d.decision_hash)
        .bind(&d.gate_state)
        .bind(&d.reason_codes)
        .bind(&d.replay_inputs)
        .bind(&d.signature)
        .bind(d.created_unix_ms)
        .bind(&parent_decision_hash)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE decision_chain_tail SET latest_decision_hash = $1 WHERE id = 1")
            .bind(&d.decision_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_decision(&self, run_id: &str) -> Result<Option<DecisionRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM decisions WHERE run_id = $1")
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
                parent_decision_hash: r.get("parent_decision_hash"),
            })),
            None => Ok(None),
        }
    }

    async fn get_decision_by_request_id(&self, request_id: &str) -> Result<Option<DecisionRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM decisions WHERE request_id = $1 ORDER BY created_unix_ms DESC LIMIT 1")
            .bind(request_id)
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
                parent_decision_hash: r.get("parent_decision_hash"),
            })),
            None => Ok(None),
        }
    }

    async fn list_decisions_chained(&self, after_unix_ms: i64, limit: i64) -> Result<Vec<DecisionRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT * FROM decisions WHERE created_unix_ms > $1 ORDER BY created_unix_ms ASC LIMIT $2",
        )
        .bind(after_unix_ms)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DecisionRecord {
                run_id: r.get("run_id"),
                request_id: r.get("request_id"),
                decision_hash: r.get("decision_hash"),
                gate_state: r.get("gate_state"),
                reason_codes: r.get("reason_codes"),
                replay_inputs: r.get("replay_inputs"),
                signature: r.get("signature"),
                created_unix_ms: r.get("created_unix_ms"),
                parent_decision_hash: r.get("parent_decision_hash"),
            })
            .collect())
    }

    async fn store_token(&self, t: TokenRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO tokens
               (token_id, request_id, tool, action, params_hash, expires_unix_ms, consumed, consumed_unix_ms, decision_hash, signature, created_unix_ms, min_approvals, granted_to, parent_token_id, delegation_depth)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"#,
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
        .bind(&t.granted_to)
        .bind(&t.parent_token_id)
        .bind(t.delegation_depth)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_token(&self, token_id: &str) -> Result<Option<TokenRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM tokens WHERE token_id = $1")
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
                consumed: r.get("consumed"),
                consumed_unix_ms: r.get("consumed_unix_ms"),
                decision_hash: r.get("decision_hash"),
                signature: r.get("signature"),
                created_unix_ms: r.get("created_unix_ms"),
                min_approvals: r.get("min_approvals"),
                granted_to: r.get("granted_to"),
                parent_token_id: r.get("parent_token_id"),
                delegation_depth: r.get("delegation_depth"),
            })),
            None => Ok(None),
        }
    }

    async fn store_delegation(&self, d: DelegationRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO delegations
               (delegation_id, parent_token_id, child_token_id, delegator_id, delegatee_id, signature, created_unix_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(&d.delegation_id)
        .bind(&d.parent_token_id)
        .bind(&d.child_token_id)
        .bind(&d.delegator_id)
        .bind(&d.delegatee_id)
        .bind(&d.signature)
        .bind(d.created_unix_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_delegation(&self, child_token_id: &str) -> Result<Option<DelegationRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM delegations WHERE child_token_id = $1")
            .bind(child_token_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(DelegationRecord {
                delegation_id: r.get("delegation_id"),
                parent_token_id: r.get("parent_token_id"),
                child_token_id: r.get("child_token_id"),
                delegator_id: r.get("delegator_id"),
                delegatee_id: r.get("delegatee_id"),
                signature: r.get("signature"),
                created_unix_ms: r.get("created_unix_ms"),
            })),
            None => Ok(None),
        }
    }

    async fn mark_token_consumed(&self, token_id: &str, consumed_unix_ms: i64) -> Result<(), StorageError> {
        let result = sqlx::query(
            r#"UPDATE tokens SET consumed = TRUE, consumed_unix_ms = $1
               WHERE token_id = $2 AND consumed = FALSE"#,
        )
        .bind(consumed_unix_ms)
        .bind(token_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn store_policy(&self, p: PolicyRecord) -> Result<(), StorageError> {
        sqlx::query("UPDATE policies SET active = FALSE WHERE tool = $1 AND action = $2 AND active = TRUE")
            .bind(&p.tool)
            .bind(&p.action)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO policies
               (policy_id, tool, action, script, policy_version, created_unix_ms, active, signature, min_approvals, min_justification_length)
               VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8, $9)"#,
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
        let row = sqlx::query("SELECT * FROM policies WHERE tool = $1 AND action = $2 AND active = TRUE ORDER BY created_unix_ms DESC LIMIT 1")
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
                active: r.get("active"),
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })),
            None => Ok(None),
        }
    }

    async fn deactivate_policy(&self, policy_id: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE policies SET active = FALSE WHERE policy_id = $1")
            .bind(policy_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_policy_versions(&self, tool: &str, action: &str) -> Result<Vec<PolicyRecord>, StorageError> {
        let rows = sqlx::query("SELECT * FROM policies WHERE tool = $1 AND action = $2 ORDER BY created_unix_ms DESC")
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
                active: r.get("active"),
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })
            .collect())
    }

    async fn reactivate_policy(&self, policy_id: &str) -> Result<(), StorageError> {
        let row = sqlx::query("SELECT tool, action FROM policies WHERE policy_id = $1")
            .bind(policy_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StorageError::NotFound)?;
        let tool: String = row.get("tool");
        let action: String = row.get("action");

        sqlx::query("UPDATE policies SET active = FALSE WHERE tool = $1 AND action = $2")
            .bind(&tool)
            .bind(&action)
            .execute(&self.pool)
            .await?;
        sqlx::query("UPDATE policies SET active = TRUE WHERE policy_id = $1")
            .bind(policy_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn list_active_policies(&self) -> Result<Vec<PolicyRecord>, StorageError> {
        let rows = sqlx::query("SELECT * FROM policies WHERE active = TRUE ORDER BY tool, action")
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
                active: r.get("active"),
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })
            .collect())
    }

    async fn store_revocation(&self, r: RevocationRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO revocations (actor_id, reason, revoked_unix_ms, revoked_by)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (actor_id) DO UPDATE SET reason = $2, revoked_unix_ms = $3, revoked_by = $4"#,
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
        let row = sqlx::query("SELECT * FROM revocations WHERE actor_id = $1")
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
               WHERE key = $1 AND window_start_ms = $2 AND count < max_count"#,
        )
        .bind(key)
        .bind(window_start)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() > 0 {
            return Ok(true);
        }

        // Check if blocked
        let existing = sqlx::query("SELECT count, max_count FROM rate_limits WHERE key = $1 AND window_start_ms = $2")
            .bind(key)
            .bind(window_start)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = existing {
            let count: i64 = row.get("count");
            if count >= max_count {
                return Ok(false);
            }
            let result = sqlx::query(
                r#"UPDATE rate_limits SET count = count + 1
                   WHERE key = $1 AND window_start_ms = $2 AND count < max_count"#,
            )
            .bind(key)
            .bind(window_start)
            .execute(&self.pool)
            .await?;
            return Ok(result.rows_affected() > 0);
        }

        // Insert new record for this window (or increment if it already exists)
        let result = sqlx::query(
            r#"INSERT INTO rate_limits (key, window_start_ms, count, max_count, window_ms)
               VALUES ($1, $2, 1, $3, $4)
               ON CONFLICT (key, window_start_ms) DO UPDATE
               SET count = rate_limits.count + 1
               WHERE rate_limits.count < rate_limits.max_count"#,
        )
        .bind(key)
        .bind(window_start)
        .bind(max_count)
        .bind(window_ms)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn store_tenant_policy(&self, tenant_id: &str, p: PolicyRecord) -> Result<(), StorageError> {
        sqlx::query("UPDATE tenant_policies SET active = FALSE WHERE tenant_id = $1 AND tool = $2 AND action = $3 AND active = TRUE")
            .bind(tenant_id)
            .bind(&p.tool)
            .bind(&p.action)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"INSERT INTO tenant_policies
               (tenant_id, policy_id, tool, action, script, policy_version, created_unix_ms, active, signature, min_approvals, min_justification_length)
               VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $9, $10)"#,
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
        let row = sqlx::query("SELECT * FROM tenant_policies WHERE tenant_id = $1 AND tool = $2 AND action = $3 AND active = TRUE ORDER BY created_unix_ms DESC LIMIT 1")
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
                active: r.get("active"),
                signature: r.get("signature"),
                min_approvals: r.get("min_approvals"),
                min_justification_length: r.get("min_justification_length"),
            })),
            None => Ok(None),
        }
    }

    async fn store_approval(&self, a: ApprovalRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO approvals (token_id, approver_id, approved_unix_ms, signature)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (token_id, approver_id) DO UPDATE SET
                 approved_unix_ms = EXCLUDED.approved_unix_ms,
                 signature = EXCLUDED.signature"#,
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
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM approvals WHERE token_id = $1")
            .bind(token_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("cnt"))
    }

    async fn register_agent_key(&self, k: AgentKeyRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO agent_keys (agent_id, public_key_hex, enc_public_key_hex, pq_public_key_hex, registered_unix_ms, active)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (agent_id) DO UPDATE SET
                 public_key_hex = EXCLUDED.public_key_hex,
                 enc_public_key_hex = EXCLUDED.enc_public_key_hex,
                 pq_public_key_hex = EXCLUDED.pq_public_key_hex,
                 registered_unix_ms = EXCLUDED.registered_unix_ms,
                 active = EXCLUDED.active"#,
        )
        .bind(&k.agent_id)
        .bind(&k.public_key_hex)
        .bind(&k.enc_public_key_hex)
        .bind(&k.pq_public_key_hex)
        .bind(k.registered_unix_ms)
        .bind(k.active)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_agent_key(&self, agent_id: &str) -> Result<Option<AgentKeyRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM agent_keys WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(AgentKeyRecord {
                agent_id: r.get("agent_id"),
                public_key_hex: r.get("public_key_hex"),
                enc_public_key_hex: r.get("enc_public_key_hex"),
                pq_public_key_hex: r.get("pq_public_key_hex"),
                registered_unix_ms: r.get("registered_unix_ms"),
                active: r.get("active"),
            })),
            None => Ok(None),
        }
    }

    async fn deactivate_agent_key(&self, agent_id: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE agent_keys SET active = FALSE WHERE agent_id = $1")
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
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
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
            "SELECT * FROM a2a_envelopes WHERE recipient_id = $1 AND delivered = FALSE ORDER BY sent_unix_ms ASC",
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
                delivered: r.get("delivered"),
                delivered_unix_ms: r.get("delivered_unix_ms"),
            })
            .collect())
    }

    async fn mark_a2a_delivered(&self, envelope_id: &str, delivered_unix_ms: i64) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE a2a_envelopes SET delivered = TRUE, delivered_unix_ms = $1 WHERE envelope_id = $2 AND delivered = FALSE",
        )
        .bind(delivered_unix_ms)
        .bind(envelope_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict);
        }
        Ok(())
    }

    async fn store_evidence_artifact(&self, a: EvidenceArtifactRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO evidence_artifacts
               (artifact_id, sha256, size_bytes, content_ref, content_b64, verified, metadata, registered_by, registered_unix_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               ON CONFLICT (artifact_id) DO UPDATE SET
                 sha256 = $2, size_bytes = $3, content_ref = $4, content_b64 = $5,
                 verified = $6, metadata = $7, registered_by = $8, registered_unix_ms = $9"#,
        )
        .bind(&a.artifact_id)
        .bind(&a.sha256)
        .bind(a.size_bytes)
        .bind(&a.content_ref)
        .bind(&a.content_b64)
        .bind(a.verified)
        .bind(&a.metadata)
        .bind(&a.registered_by)
        .bind(a.registered_unix_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_evidence_artifact(&self, artifact_id: &str) -> Result<Option<EvidenceArtifactRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM evidence_artifacts WHERE artifact_id = $1")
            .bind(artifact_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| EvidenceArtifactRecord {
            artifact_id: r.get("artifact_id"),
            sha256: r.get("sha256"),
            size_bytes: r.get("size_bytes"),
            content_ref: r.get("content_ref"),
            content_b64: r.get("content_b64"),
            verified: r.get("verified"),
            metadata: r.get("metadata"),
            registered_by: r.get("registered_by"),
            registered_unix_ms: r.get("registered_unix_ms"),
        }))
    }

    async fn list_evidence_artifacts(&self, limit: i64) -> Result<Vec<EvidenceArtifactRecord>, StorageError> {
        let rows = sqlx::query("SELECT * FROM evidence_artifacts ORDER BY registered_unix_ms DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| EvidenceArtifactRecord {
                artifact_id: r.get("artifact_id"),
                sha256: r.get("sha256"),
                size_bytes: r.get("size_bytes"),
                content_ref: r.get("content_ref"),
                content_b64: r.get("content_b64"),
                verified: r.get("verified"),
                metadata: r.get("metadata"),
                registered_by: r.get("registered_by"),
                registered_unix_ms: r.get("registered_unix_ms"),
            })
            .collect())
    }

    async fn record_session_action(&self, s: SessionActionRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO session_actions
               (agent_id, request_id, tool, action, risk_level, gate_state, created_unix_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(&s.agent_id)
        .bind(&s.request_id)
        .bind(&s.tool)
        .bind(&s.action)
        .bind(&s.risk_level)
        .bind(&s.gate_state)
        .bind(s.created_unix_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_session_context(&self, agent_id: &str, limit: i64) -> Result<Vec<SessionActionRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT * FROM session_actions WHERE agent_id = $1 ORDER BY created_unix_ms DESC LIMIT $2",
        )
        .bind(agent_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SessionActionRecord {
                agent_id: r.get("agent_id"),
                request_id: r.get("request_id"),
                tool: r.get("tool"),
                action: r.get("action"),
                risk_level: r.get("risk_level"),
                gate_state: r.get("gate_state"),
                created_unix_ms: r.get("created_unix_ms"),
            })
            .collect())
    }

    async fn store_pending_decision(&self, p: PendingDecisionRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO pending_decisions
               (pending_token, request_id, agent_id, workflow, tool, action, params_json,
                justification, risk_level, identity_json, tenant_id, context_hash, reason,
                created_unix_ms, expires_unix_ms, resolved)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"#,
        )
        .bind(&p.pending_token)
        .bind(&p.request_id)
        .bind(&p.agent_id)
        .bind(&p.workflow)
        .bind(&p.tool)
        .bind(&p.action)
        .bind(&p.params_json)
        .bind(&p.justification)
        .bind(&p.risk_level)
        .bind(&p.identity_json)
        .bind(&p.tenant_id)
        .bind(&p.context_hash)
        .bind(&p.reason)
        .bind(p.created_unix_ms)
        .bind(p.expires_unix_ms)
        .bind(p.resolved)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_pending_decision(&self, pending_token: &str) -> Result<Option<PendingDecisionRecord>, StorageError> {
        let row = sqlx::query("SELECT * FROM pending_decisions WHERE pending_token = $1")
            .bind(pending_token)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| PendingDecisionRecord {
            pending_token: r.get("pending_token"),
            request_id: r.get("request_id"),
            agent_id: r.get("agent_id"),
            workflow: r.get("workflow"),
            tool: r.get("tool"),
            action: r.get("action"),
            params_json: r.get("params_json"),
            justification: r.get("justification"),
            risk_level: r.get("risk_level"),
            identity_json: r.get("identity_json"),
            tenant_id: r.get("tenant_id"),
            context_hash: r.get("context_hash"),
            reason: r.get("reason"),
            created_unix_ms: r.get("created_unix_ms"),
            expires_unix_ms: r.get("expires_unix_ms"),
            resolved: r.get("resolved"),
        }))
    }

    async fn mark_pending_resolved(&self, pending_token: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE pending_decisions SET resolved = TRUE WHERE pending_token = $1")
            .bind(pending_token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn record_verification_event(&self, e: VerificationEventRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO verification_events (id, run_id, verified, source, api_key_id, created_unix_ms)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&e.id)
        .bind(&e.run_id)
        .bind(e.verified)
        .bind(&e.source)
        .bind(&e.api_key_id)
        .bind(e.created_unix_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn verification_usage_summary(
        &self,
        since_unix_ms: i64,
        api_key_id: Option<&str>,
    ) -> Result<VerificationUsageSummary, StorageError> {
        let row = if let Some(key) = api_key_id {
            sqlx::query(
                "SELECT COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE verified) AS verified_true,
                        COUNT(*) FILTER (WHERE NOT verified) AS verified_false
                 FROM verification_events WHERE created_unix_ms >= $1 AND api_key_id = $2",
            )
            .bind(since_unix_ms)
            .bind(key)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE verified) AS verified_true,
                        COUNT(*) FILTER (WHERE NOT verified) AS verified_false
                 FROM verification_events WHERE created_unix_ms >= $1",
            )
            .bind(since_unix_ms)
            .fetch_one(&self.pool)
            .await?
        };
        Ok(VerificationUsageSummary {
            since_unix_ms,
            total: row.try_get::<i64, _>("total").unwrap_or(0),
            verified_true: row.try_get::<i64, _>("verified_true").unwrap_or(0),
            verified_false: row.try_get::<i64, _>("verified_false").unwrap_or(0),
        })
    }

    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}
