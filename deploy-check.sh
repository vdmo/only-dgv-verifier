#!/usr/bin/env bash
# deploy-check.sh — validate a running DGV gate deployment.
#
#   ./deploy-check.sh https://gate.example.com [admin_key]
#
# Exits non-zero if any production-posture check fails. This is the "prove it"
# counterpart to DEPLOYMENT.md — run it after every deploy and record output.

set -u
BASE="${1:?usage: deploy-check.sh <gate-url> [admin_key]}"
ADMIN="${2:-}"
BASE="${BASE%/}"
FAIL=0

check() { # name, condition-result(0/1), detail
  if [ "$2" -eq 0 ]; then
    printf "  PASS  %s  %s\n" "$1" "$3"
  else
    printf "  FAIL  %s  %s\n" "$1" "$3"
    FAIL=1
  fi
}

echo "== reachability =="
HEALTH=$(curl -sf --max-time 5 "$BASE/health" 2>/dev/null)
check "health endpoint answers" "$([ -n "$HEALTH" ] && echo 0 || echo 1)" "$BASE/health"

[ -z "$HEALTH" ] && { echo "gate unreachable — stopping"; exit 1; }

echo "== production posture (from /health) =="
echo "$HEALTH" | grep -q '"jwt_mode":"disabled"' \
  && check "JWT verification enabled" 1 "jwt_mode=disabled — /govern accepts unauthenticated callers" \
  || check "JWT verification enabled" 0 "$(echo "$HEALTH" | grep -o '"jwt_mode":"[^"]*"')"

echo "$HEALTH" | grep -q '"admin_auth":true' \
  && check "admin auth on" 0 "X-Admin-Key required" \
  || check "admin auth on" 1 "admin_auth=false — admin surface is OPEN"

echo "$HEALTH" | grep -q '"partition_policy":"fail_closed"' \
  && check "partition policy fail_closed" 0 "" \
  || check "partition policy fail_closed" 1 "$(echo "$HEALTH" | grep -o '"partition_policy":"[^"]*"')"

echo "$HEALTH" | grep -q '"storage":"connected"' \
  && check "storage connected" 0 "" \
  || check "storage connected" 1 "$(echo "$HEALTH" | grep -o '"storage":"[^"]*"')"

echo "== unauthenticated probes (all must be denied) =="
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$BASE/govern" -H 'content-type: application/json' -d '{}')
case "$CODE" in
  4*) check "/govern rejects empty caller" 0 "http $CODE" ;;
  *)  check "/govern rejects empty caller" 1 "http $CODE — expected 4xx" ;;
esac

CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$BASE/revocations" -H 'content-type: application/json' -d '{"actor_id":"x","reason":"y"}')
[ "$CODE" = "401" ] \
  && check "/revocations requires admin key" 0 "http $CODE" \
  || check "/revocations requires admin key" 1 "http $CODE — expected 401"

echo "== evidence surface =="
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/revocations/digest")
[ "$CODE" = "200" ] \
  && check "revocation digest readable" 0 "http $CODE" \
  || check "revocation digest readable" 1 "http $CODE"

CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE/verify/definitely-not-a-run")
[ "$CODE" = "404" ] \
  && check "verify 404s unknown run" 0 "http $CODE" \
  || check "verify 404s unknown run" 1 "http $CODE — expected 404"

if [ -n "$ADMIN" ]; then
  echo "== admin key check =="
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$BASE/agents/keys" \
    -H "X-Admin-Key: wrong-key-probe" -H 'content-type: application/json' -d '{}')
  [ "$CODE" = "401" ] || [ "$CODE" = "403" ] \
    && check "wrong admin key rejected" 0 "http $CODE" \
    || check "wrong admin key rejected" 1 "http $CODE — expected 4xx"
fi

echo
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || echo "FAILURES PRESENT — do not call this deployment production-ready"
exit "$FAIL"
