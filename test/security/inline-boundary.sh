#!/usr/bin/env bash
# Inline runner for the self-revoke boundary tests. Separates each curl
# step cleanly so every status + body is visible in the transcript.
set -u
BASE="${BASE:-https://api.sheafhq.io}"

say() { printf '%s\n' "$*"; }

say "=== provision two throwaway accounts ==="
KEY_A=$(curl -fsS -X POST -H 'content-type: application/json' "$BASE/accounts" -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["api_key"])')
KEY_B=$(curl -fsS -X POST -H 'content-type: application/json' "$BASE/accounts" -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["api_key"])')
HASH_B=$(printf '%s' "$KEY_B" | sha256sum | awk '{print $1}')
say "key A prefix: ${KEY_A:0:14}..."
say "key B prefix: ${KEY_B:0:14}..."
say "hash(B):      ${HASH_B:0:16}..."
say ""

say "=== T1: A auth, body targets B via key_hash -> expect 400 ==="
STATUS=$(curl -sS -o /tmp/t1.json -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d "{\"key_hash\":\"$HASH_B\"}" "$BASE/accounts/me/keys/revoke")
say "HTTP $STATUS"
cat /tmp/t1.json; say ""

say ""
say "=== T2: A auth, body targets by account_id -> expect 400 ==="
STATUS=$(curl -sS -o /tmp/t2.json -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d '{"account_id":"acct_victim"}' "$BASE/accounts/me/keys/revoke")
say "HTTP $STATUS"
cat /tmp/t2.json; say ""

say ""
say "=== T3: both fields together -> expect 400 ==="
STATUS=$(curl -sS -o /tmp/t3.json -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d "{\"key_hash\":\"$HASH_B\",\"account_id\":\"acct_victim\"}" \
  "$BASE/accounts/me/keys/revoke")
say "HTTP $STATUS"
cat /tmp/t3.json; say ""

say ""
say "=== T4: B unaffected -> expect 200 ==="
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $KEY_B" "$BASE/usage")
say "HTTP $STATUS  (B still works)"

say ""
say "=== T5: A also unaffected by rejected attempts -> expect 200 ==="
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $KEY_A" "$BASE/usage")
say "HTTP $STATUS  (A still works)"

say ""
say "=== T6: empty body revokes self -> expect 200 then 401 on /usage ==="
STATUS=$(curl -sS -o /tmp/t6.json -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $KEY_A" -H 'content-type: application/json' \
  -d '{}' "$BASE/accounts/me/keys/revoke")
say "revoke HTTP $STATUS"
cat /tmp/t6.json; say ""
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $KEY_A" "$BASE/usage")
say "post-revoke /usage: HTTP $STATUS  (should be 401)"

say ""
say "=== T7: B STILL unaffected after A self-revoked -> expect 200 ==="
STATUS=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $KEY_B" "$BASE/usage")
say "HTTP $STATUS  (B still works)"
