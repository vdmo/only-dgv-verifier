# Deploy runbook — export auth, chained early denials, unique run IDs

Target: the live gate at `https://gate.only.institute` (compose deployment, see
`DEPLOYMENT.md`). Change set: three commits on
`feat/gate-export-auth-and-early-denials`.

**Status of this document.** Written from the repo and from read-only probes of
the live gate. It has not been executed. Items in *Unknowns* below are things
the author could not see from a development machine — confirm them on the host
before starting. Treat the first run as a deployment test and record what you
find, as `DEPLOYMENT.md` says.

## What ships

| Commit | Change | Operator-visible effect |
|---|---|---|
| `70b8d38` | Verification metering (`verification_events` table, `GET /usage/verifications`) | **Not yet on the live gate** (route 404s today), so this deploy carries it. Additive `CREATE TABLE IF NOT EXISTS` at boot. `GET /verify/:run_id` now writes one row per call. |
| `e9cd6bc` | `/decisions/export` requires `X-Export-Key` or `X-Admin-Key`; `?redact=true`; early denials (bad identity, rate limit, open circuit) are signed and chained | Export stops being world-readable. Chain now contains every refusal, up to a cap of 600/min. |
| `3c65c94` | Unique run IDs; chain-ordered export; no silent persist failures | Concurrent requests no longer collide and lose chain records. New metrics `dgv_decisions_unpersisted_total`, `dgv_early_denials_unpersisted_total`. |

## Unknowns to confirm on the host first

- SSH target, the checkout path of `only-dgv-verifier`, and which compose
  profile is running (`tls`? `replica`?).
- That the live gate is the compose stack (Postgres) and not a bare binary. The
  code paths were tested on both SQLite and Postgres 16, but the migration and
  volume steps below assume compose.
- That the deployed `nginx.conf` matches the repo's. It contains no `limit_req`
  on `/govern` or `/verify`.
- That nothing else reads `/decisions/export` unauthenticated. Searching this
  monorepo found only the offline verifier script.

## Step 0 — optional stopgap, no code deploy (recommended today)

The export is public right now. If the deploy will be delayed, block it at
nginx and reload (`docker compose -f docker-compose.gate.yml exec nginx nginx -s reload`):

```nginx
location = /decisions/export {
    allow <your-ip>;
    deny  all;
    proxy_pass http://dgv_gate;
}
```

Remove it after step 5 (the gate enforces the key itself). Any caller that is
not you will get 403 either way.

## Step 1 — capture a baseline (before touching anything)

The export is still open, so capture it now, then it will need the key.

```bash
B=https://gate.only.institute; D=~/dgv-deploy-$(date +%F); mkdir -p $D
curl -s $B/health                          > $D/health.pre.json
curl -s $B/stats                           > $D/stats.pre.json
curl -s "$B/decisions/export?limit=2000"   > $D/export.pre.json   # contains agent_id/params — keep private
python3 scripts/verify_decision_chain.py $D/export.pre.json | tail -2
```

Write down two values: the **`verifying_key`** from `health.pre.json`
(currently `b287cda6da0c1934…`) and the **last `decision_hash`** in
`export.pre.json`. Both are checked after the deploy.

## Step 2 — back up

Receipts are worthless without both the database and the signing key
(`DEPLOYMENT.md`).

```bash
docker compose -f docker-compose.gate.yml exec -T postgres pg_dump -U postgres dgv_gate > $D/dgv_gate.sql
docker cp dgv-gate:/data/dgv_signing_key.hex $D/dgv_signing_key.hex   # secret — store offline
docker tag $(docker inspect -f '{{.Image}}' dgv-gate) dgv-gate:pre-2026-09-24   # rollback image
```

## Step 3 — configure

Add to the server's `.env` (compose passes it through `env_file`):

```bash
DGV_EXPORT_KEY=$(openssl rand -hex 32)   # store in your password manager
# DGV_EARLY_DENIAL_LOG_MAX_PER_MIN=600   # default; lower it if /govern is publicly reachable
```

Leaving `DGV_EXPORT_KEY` empty is safe: an empty value is ignored, and with
`DGV_ADMIN_KEY` set the export stays available to `X-Admin-Key` only. It never
falls back to public unless `DGV_EXPORT_PUBLIC=1` is set — do not set that.

## Step 4 — deploy

```bash
git fetch origin && git checkout <branch-or-merged-main> && git log --oneline -4
docker compose -f docker-compose.gate.yml [--profile tls] up -d --build gate
docker compose -f docker-compose.gate.yml logs -f gate | head -30
```

Build only `gate`; do not recreate `postgres` or `nginx`. The Rust build takes
minutes; the outage is only the container restart (seconds). During it `/govern`
and `/execute` are unavailable and callers fail closed. Do not change
`DGV_SIGNING_KEY` or remove the `gate_data` volume. Migrations run at boot.

## Step 5 — verify (every line must pass)

```bash
K=<the new DGV_EXPORT_KEY>
curl -s $B/health | grep -o '"verifying_key":"[^"]*"'   # IDENTICAL to step 1 — if not, the signing key did not persist: STOP, roll back
curl -s $B/health | grep -o '"jwt_mode":"[^"]*"'        # still jwks
./deploy-check.sh $B "$DGV_ADMIN_KEY"                   # exits 0

# export is closed, and open to the right keys only
curl -s -o /dev/null -w "%{http_code}\n" "$B/decisions/export"                        # 401
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Export-Key: wrong" "$B/decisions/export"  # 401
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Export-Key: $K" "$B/decisions/export"     # 200

# chain continuity across the deploy, and offline verification
curl -s -H "X-Export-Key: $K" "$B/decisions/export?limit=2000" > $D/export.post.json
python3 scripts/verify_decision_chain.py $D/export.post.json | tail -2   # all verified
# the first post-deploy record's parent must equal step 1's last decision_hash

# metering route now exists (401 = present behind admin auth; 404 = old binary)
curl -s -o /dev/null -w "%{http_code}\n" $B/usage/verifications
```

Then prove early denials chain end to end with one harmless probe:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST $B/govern -H 'content-type: application/json' \
  -H 'Authorization: Bearer not.a.jwt' \
  -d '{"request_id":"deploy-probe","agent_id":"deploy-probe","workflow":"w","tool":"t","action":"a","params":{},"justification":"j","risk_level":"1","identity":{}}'   # 401
curl -s -H "X-Export-Key: $K" "$B/decisions/export?limit=2000" \
  | python3 -c "import json,sys;d=json.load(sys.stdin)['decisions'];r=[x for x in d if x['request_id']=='deploy-probe'];print(r[-1]['gate_state'],r[-1]['replay_inputs'].get('early_denial'),r[-1]['replay_inputs'].get('agent_id_verified'))"   # DENY True False
curl -s $B/metrics | grep unpersisted_total     # both 0
```

## Step 6 — after

- Remove the step 0 nginx rule if you added it.
- Alert on `dgv_decisions_unpersisted_total > 0` (a verdict was issued with no
  chain record) and on any sustained rise in
  `dgv_early_denials_unpersisted_total` (the 600/min cap is being hit, i.e. the
  chain is intentionally incomplete for that period).
- `docs/LIMITATIONS.md` already describes the new behaviour. The publication
  `only-institute/web/content/publications/dgv-public-and-chained.md` says the
  export is available without mentioning a key; add one line.
- Give auditors `DGV_EXPORT_KEY` (read-only), never the admin key.

## Rollback

```bash
docker tag dgv-gate:pre-2026-09-24 <the tag compose expects>   # or: git checkout <previous-commit>
docker compose -f docker-compose.gate.yml up -d --no-build gate  # or --build if you checked out the old commit
```

Schema is additive (`verification_events` is ignored by the old binary), and
the rows the new binary wrote — including early denials, which only add
`early_denial` / `agent_id_verified` keys to `replay_inputs` — remain valid
chain records for the old one. **Rolling back re-opens the export**, so re-apply
the step 0 nginx rule immediately after.

## Known follow-ups (not fixed here)

- `GET /verify/:run_id` is public and now writes a metering row per call. An
  unauthenticated caller can grow that table without bound. Rate-limit it at
  nginx or in the gate before relying on it for billing.
- Export pagination is still by timestamp and can skip decisions that share a
  millisecond at a page boundary; export in one request when verifying.
- Two gate instances on one database can still, rarely, draw the same run id in
  the same millisecond.
- `test_revocation_quorum.py` has one stale assertion (expects DENY, gets the
  newer DEFER); it fails identically before this change.
