//! PostgreSQL storage backend.
//!
//! Uses sqlx with the `postgres` feature. Production-grade, multi-node,
//! connection pooling. Good for distributed deployments where multiple
//! gate instances share the same database.

use async_trait::async_trait;
use sqlx::postgres::PgPool;
use sqlx::Row;

use crate::{
    DecisionRecord, PolicyRecord, RevocationRecord, Storage, StorageError, TokenRecord,
};

pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub async fn new(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPool::connect(database_url).await?;
        Self::migrate(&pool).await?;
        Ok(Self { pool })
    }

    async fn migrate(pool: &PgPool) -> Result<(), StorageError> {
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
                created_unix_ms BIGINT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                tool TEXT NOT NULL,
                action TEXT NOT NULL,
                script TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                created_unix_ms BIGINT NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE
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
        sqlx::query(
            r#"INSERT INTO decisions
               (run_id, request_id, decision_hash, gate_state, reason_codes, replay_inputs, signature, created_unix_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
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
            })),
            None => Ok(None),
        }
    }

    async fn store_token(&self, t: TokenRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO tokens
               (token_id, request_id, tool, action, params_hash, expires_unix_ms, consumed, consumed_unix_ms, decision_hash, signature, created_unix_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
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
               (policy_id, tool, action, script, policy_version, created_unix_ms, active)
               VALUES ($1, $2, $3, $4, $5, $6, TRUE)"#,
        )
        .bind(&p.policy_id)
        .bind(&p.tool)
        .bind(&p.action)
        .bind(&p.script)
        .bind(&p.policy_version)
        .bind(p.created_unix_ms)
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
               (tenant_id, policy_id, tool, action, script, policy_version, created_unix_ms, active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)"#,
        )
        .bind(tenant_id)
        .bind(&p.policy_id)
        .bind(&p.tool)
        .bind(&p.action)
        .bind(&p.script)
        .bind(&p.policy_version)
        .bind(p.created_unix_ms)
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
            })),
            None => Ok(None),
        }
    }

    async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}
