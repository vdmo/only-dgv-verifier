# Deploying the DGV Gate

This is the reference deployment: one gate, one Postgres, TLS in front,
OIDC-issued identity on `/govern` and `/execute`. It is the topology the
Minuta CRM integration (`DGV_GATE_URL`) expects.

Verified here means *the artifacts are tested* — compose syntax, gate boot,
health, migrations, JWT rejection paths. It does not mean this document has
been exercised against your cloud. Treat the first real deploy as a
deployment test and record what you find.

## Topology

```
client ──TLS──► nginx :443 ──► dgv-gate :7878 ──► postgres :5432
              (profile tls)    (127.0.0.1 only)   (internal network only)
```

The gate port binds to loopback. Postgres publishes nothing. The only public
surface is nginx on 443. The gate's Ed25519 receipt-signing key lives in the
`gate_data` volume (`/data/dgv_signing_key.hex`), created on first boot —
**back this file up; it is the receipt trust root.**

## Prerequisites

- Docker Engine 24+ with the compose plugin.
- A DNS name pointing at the host (TLS certificates need it).
- TLS keypair in `./certs/` as `fullchain.pem` + `privkey.pem`
  (certbot, your CA, or a cloud load balancer doing TLS instead — in that
  case drop the nginx profile and point the LB at `127.0.0.1:7878`).
- An OIDC issuer or JWKS endpoint that mints tokens for your agents.

## 1. Configure

```bash
cp .env.example .env
$EDITOR .env
```

Fill the REQUIRED block: `POSTGRES_PASSWORD`, `DGV_ADMIN_KEY`, and one
identity mode. Generate secrets with `openssl rand -hex 32`.

Identity modes (pick one):

| Mode | Variable | Use when |
|---|---|---|
| OIDC discovery | `DGV_OIDC_ISSUER` | Auth0, Entra ID, Keycloak, Google — anything with `/.well-known/openid-configuration` |
| Direct JWKS | `DGV_JWT_JWKS_URL` | Issuer has JWKS but nonstandard discovery |
| Pinned RS256 key | `DGV_JWT_PUBLIC_KEY` | Single issuer, manual rotation |
| HS256 secret | `DGV_JWT_SECRET` | **Dev only.** A shared secret is not agent identity. |

Set `DGV_JWT_ISSUER` and `DGV_JWT_AUDIENCE` alongside any mode. When any JWT
variable is set, `/govern` and `/execute` require `Authorization: Bearer`
whose `sub` is the acting `agent_id`.

## 2. Bring it up

```bash
docker compose -f docker-compose.gate.yml up -d --build
# or, with TLS in front:
docker compose -f docker-compose.gate.yml --profile tls up -d --build
```

Startup checks:

```bash
docker compose -f docker-compose.gate.yml logs gate | head -20
curl -s http://127.0.0.1:7878/health          # expect {"status":"ok"}
curl -s https://gate.example.com/health       # through nginx, with TLS
```

In the logs you want to see: `jwt_auth_enabled` (with your mode) or
`jwt_auth_disabled`, `oidc_discovery` with the resolved `jwks_uri`, and no
`postgres` errors — migrations run at boot.

Then run the posture check — it exits non-zero unless the deployment is
actually production-shaped (JWT on, admin key enforced, fail-closed,
reachable evidence endpoints):

```bash
./deploy-check.sh https://gate.example.com "$DGV_ADMIN_KEY"
```

## 3. Provision agents

Agent registration is admin-gated (`X-Admin-Key`):

```bash
curl -X POST https://gate.example.com/agents/keys \
  -H "X-Admin-Key: $DGV_ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"agent_id":"crm:service:agent","public_key":"<ed25519 hex>","enc_public_key":"<x25519 hex>"}'
```

Retire a key with `DELETE /agents/keys/:agent_id` under the same header.

## 4. Point the CRM at it

In the CRM repo root `.env`:

```bash
DGV_GATE_URL="https://gate.example.com"
DGV_GATE_TOKEN="<JWT minted for sub=crm:service:agent>"   # when JWT is on
```

Every governed CRM write then produces a gate receipt the Settings →
Governance page can re-verify.

## 5. Multi-node

`--profile replica` starts a second gate on the same Postgres. For real
multi-node:

- Point every node at the same Postgres (`DGV_DATABASE_URL`) — that is the
  consistency boundary.
- Set `DGV_PEERS` on each node to the others' base URLs, and
  `DGV_GOSSIP_KEYS` to each other's verifying keys (printed at startup as
  `Verifying key: <hex>`).
- `DGV_PARTITION_POLICY=fail_closed` is the default and the production
  answer — a node that cannot reach Postgres denies rather than guesses.

Gossip is authenticated eventual propagation, **not consensus**. If your
deployment genuinely needs quorum, that is a separate design discussion —
do not read gossip as providing it.

## Operations

| Task | How |
|---|---|
| Rotate admin key | Change `.env`, `up -d` — no data impact |
| Rotate signing key | Replace `/data/dgv_signing_key.hex`; old receipts no longer verify against the new key — archive the old public half in your audit records first |
| Rotate agent keys | `DELETE /admin/agents/keys/:id` then re-register; revocation propagates via shared store + gossip |
| Backup | `pg_dump` the `dgv_gate` DB **plus** the signing key file — receipts are worthless without both |
| Observe | `GET /metrics` (Prometheus), `GET /revocations/digest` (divergence check across nodes), `DGV_LOG_FORMAT=json` logs |
| Upgrade | `git pull && docker compose -f docker-compose.gate.yml up -d --build` — migrations run at boot |

## Failure modes worth knowing

- **Postgres down, `fail_closed`**: gate boots degraded, denies `/govern`
  and `/execute`, retries migrations in the background, self-heals on
  reconnect. `/health` still answers.
- **OIDC discovery fails at boot**: the gate **refuses to start** — an
  explicitly configured issuer that cannot be discovered exits rather than
  run with identity verification silently off. Set `DGV_JWT_JWKS_URL` as a
  fallback if your IdP's discovery doc is flaky.
- **No `DGV_ADMIN_KEY`**: admin surface runs unauthenticated. The compose
  file refuses to start without it; do not bypass that guard.
- **Receipt signature fails after redeploy**: the signing key did not
  persist — the `gate_data` volume was recreated. Restore from backup.
