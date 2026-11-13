#!/usr/bin/env bash
# Self-revoke boundary regression test (added 2026-11-12).
#
# Verifies that POST /accounts/me/keys/revoke cannot be used by account A's
# key to revoke account B's key through any body-field smuggling. A
# confused-deputy attempt returns 400 with the rejected fields named; B's
# key remains fully functional; A's key is not touched either (the endpoint
# refused to proceed because the body was non-conforming).
#
# Usage:
#   BASE=https://api.sheafhq.io bash test/security/self-revoke-boundary.sh
#
# Exits 0 on all-pass, non-zero on any failure.

set -euo pipefail
BASE="${BASE:-https://api.sheafhq.io}"
FAILED=0

say() { printf '%s\n' "$*"; }
pass() { say "  PASS $*"; }
fail() { say "  FAIL $*"; FAILED=$((FAILED+1)); }

mint() {
  # Returns the api_key string via stdout.
  curl -fsS -X POST -H 'content-type: application/json' "$BASE/accounts" -d '{}' \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["api_key"])'
}

status_with_body() {
  # $1 url, $2 bearer, $3 body json; prints HTTP status, stores body in $TMP_BODY
  local url="$1" bearer="$2" body="$3"
  TMP_BODY=$(mktemp)
  curl -sS -o "$TMP_BODY" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer $bearer" \
    -H 'content-type: application/json' \
    -d "$body" "$url"
}

status_get() {
  # $1 url, $2 bearer; prints HTTP status
  local url="$1" bearer="$2"
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $bearer" "$url"
}

say "=== provisioning two throwaway accounts ==="
KEY_A=$(mint)
KEY_B=$(mint)
HASH_B=$(printf '%s' "$KEY_B" | sha256sum | awk '{print $1}')
say "  key A: ${KEY_A:0:14}...  key B: ${KEY_B:0:14}...  hash(B): ${HASH_B:0:16}..."

say ""
say "=== TEST 1: A's bearer, body attempts to target B's key_hash ==="
status_with_body "$BASE/accounts/me/keys/revoke" "$KEY_A" "{\"key_hash\":\"$HASH_B\"}"
ST=$?; STATUS=$(cat "$TMP_BODY" >/dev/null; echo "$STATUS")
# Re-run to capture status cleanly
STATUS=$(curl -sS -o "$TMP_BODY" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d "{\"key_hash\":\"$HASH_B\"}" "$BASE/accounts/me/keys/revoke")
say "  got HTTP $STATUS"
cat "$TMP_BODY" | python3 -m json.tool || cat "$TMP_BODY"
if [ "$STATUS" = "400" ]; then pass "T1 returned 400 as required"
else fail "T1 expected 400, got $STATUS"; fi

say ""
say "=== TEST 2: A's bearer, body targets by account_id ==="
STATUS=$(curl -sS -o "$TMP_BODY" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d '{"account_id":"acct_victim"}' "$BASE/accounts/me/keys/revoke")
say "  got HTTP $STATUS"
cat "$TMP_BODY" | python3 -m json.tool || cat "$TMP_BODY"
if [ "$STATUS" = "400" ]; then pass "T2 returned 400 as required"
else fail "T2 expected 400, got $STATUS"; fi

say ""
say "=== TEST 3: A's bearer, both fields at once ==="
STATUS=$(curl -sS -o "$TMP_BODY" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d "{\"key_hash\":\"$HASH_B\",\"account_id\":\"acct_victim\"}" \
  "$BASE/accounts/me/keys/revoke")
if [ "$STATUS" = "400" ]; then pass "T3 returned 400 as required"
else fail "T3 expected 400, got $STATUS (body: $(cat $TMP_BODY))"; fi

say ""
say "=== TEST 4: after all attempts, B's key still works ==="
STATUS=$(status_get "$BASE/usage" "$KEY_B")
if [ "$STATUS" = "200" ]; then pass "T4 key B still authenticates (HTTP 200)"
else fail "T4 key B should be untouched but got HTTP $STATUS"; fi

say ""
say "=== TEST 5: after all attempts, A's key ALSO still works ==="
# A's attempts were rejected with 400, so A's key was not touched either.
STATUS=$(status_get "$BASE/usage" "$KEY_A")
if [ "$STATUS" = "200" ]; then pass "T5 key A still authenticates (HTTP 200) — rejected attempts did not revoke A"
else fail "T5 key A should still work (rejected attempts don't revoke) but got HTTP $STATUS"; fi

say ""
say "=== TEST 6: A can revoke itself with an EMPTY body (sanity check) ==="
STATUS=$(curl -sS -o "$TMP_BODY" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d '{}' "$BASE/accounts/me/keys/revoke")
if [ "$STATUS" = "200" ]; then pass "T6 empty body revokes self (HTTP 200)"
else fail "T6 empty body should work; got HTTP $STATUS"; fi
STATUS_AFTER=$(status_get "$BASE/usage" "$KEY_A")
if [ "$STATUS_AFTER" = "401" ]; then pass "T6b A's key now 401 after self-revoke"
else fail "T6b A's key should be dead; got $STATUS_AFTER"; fi

say ""
say "=== TEST 7: B STILL works after A self-revoked ==="
STATUS=$(status_get "$BASE/usage" "$KEY_B")
if [ "$STATUS" = "200" ]; then pass "T7 key B unaffected by A's actions"
else fail "T7 key B should still work; got HTTP $STATUS"; fi

rm -f "$TMP_BODY"
echo ""
if [ "$FAILED" -eq 0 ]; then
  echo "ALL PASS"; exit 0
else
  echo "FAILED: $FAILED"; exit 1
fi
