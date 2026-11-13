#!/usr/bin/env bash
#
# Recreate the entire Agent Allowance demo from scratch on NEAR testnet.
#
# This is the exact sequence that produced the transactions cited in the
# README. It creates its own freshly-named accounts, so running it does not
# touch the existing deployment and can be repeated.
#
#   ./scripts/reproduce-demo.sh
#
# Requires: near-cli-rs (npm i -g near-cli-rs), and Rust with the
# wasm32-unknown-unknown target. Everything happens on testnet with faucet
# funds — no real value is involved at any point.

set -euo pipefail

SUFFIX="${1:-$(date +%s | tail -c 6)}"
ROOT="aa-demo-${SUFFIX}.testnet"
BOT="bot.${ROOT}"
PAYEE="payee.${ROOT}"
NET="network-config testnet"
WASM="$(cd "$(dirname "$0")/.." && pwd)/contract/target/wasm32-unknown-unknown/release/agent_allowance.wasm"

say() { printf '\n\033[1m%s\033[0m\n' "$1"; }

say "0. Build the contract"
(cd "$(dirname "$0")/../contract" && cargo build --target wasm32-unknown-unknown --release)
ls -lh "$WASM" | awk '{print "   wasm:", $5}'

say "1. Create the vault account (faucet-funded)"
near account create-account sponsor-by-faucet-service "$ROOT" \
  autogenerate-new-keypair save-to-legacy-keychain $NET create

say "2. Deploy the vault, owned by itself"
near contract deploy "$ROOT" use-file "$WASM" \
  with-init-call new json-args "{\"owner_id\":\"$ROOT\"}" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  $NET sign-with-legacy-keychain send

say "3. Create the agent and payee accounts"
near account create-account fund-myself "$BOT" '1 NEAR' \
  autogenerate-new-keypair save-to-legacy-keychain \
  sign-as "$ROOT" $NET sign-with-legacy-keychain send
near account create-account fund-myself "$PAYEE" '0.2 NEAR' \
  autogenerate-new-keypair save-to-legacy-keychain \
  sign-as "$ROOT" $NET sign-with-legacy-keychain send

say "4. Give the agent a RESTRICTED key — request_spend on the vault only"
near account add-key "$BOT" \
  grant-function-call-access --allowance '0.25 NEAR' \
  --contract-account-id "$ROOT" --function-names 'request_spend' \
  autogenerate-new-keypair save-to-legacy-keychain \
  $NET sign-with-legacy-keychain send

say "5. Delete the agent's full-access key"
echo "   After this the agent holds ONE key and cannot do anything but ask"
echo "   the vault to spend. This is the protocol-level containment."
CRED="$HOME/.near-credentials/testnet"
FULL_PK=$(python3 -c "import json;print(json.load(open('$CRED/$BOT.json'))['public_key'])")
RESTRICTED_PK=$(python3 - "$CRED/$BOT" "$FULL_PK" <<'PY'
import json, os, sys
d, full = sys.argv[1], sys.argv[2]
for fn in os.listdir(d):
    pk = json.load(open(os.path.join(d, fn)))["public_key"]
    if pk != full:
        print(pk); break
PY
)
echo "   full-access key : $FULL_PK  (deleting)"
echo "   restricted key  : $RESTRICTED_PK  (keeping)"
near account delete-keys "$BOT" public-keys "$FULL_PK" \
  $NET sign-with-legacy-keychain send
cp "$CRED/$BOT/${RESTRICTED_PK/:/_}.json" "$CRED/$BOT.json"

say "6. Confirm on-chain that only the restricted key remains"
curl -s -X POST https://rpc.testnet.near.org -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_access_key_list\",\"finality\":\"final\",\"account_id\":\"$BOT\"}}" \
| python3 -c "
import sys, json
ks = json.load(sys.stdin)['result']['keys']
print('   keys:', len(ks))
for k in ks:
    p = k['access_key']['permission']
    if p == 'FullAccess':
        print('   !! FULL ACCESS STILL PRESENT')
    else:
        fc = p['FunctionCall']
        print('   methods :', fc['method_names'])
        print('   contract:', fc['receiver_id'])
"

say "7. Register the spending policy — 1 NEAR/tx, 3 NEAR/day, payee only"
near contract call-function as-transaction "$ROOT" add_agent \
  json-args "{\"agent_id\":\"$BOT\",\"per_tx_cap\":\"1000000000000000000000000\",\"daily_cap\":\"3000000000000000000000000\",\"allowlist\":[\"$PAYEE\"]}" \
  prepaid-gas '100.0 Tgas' attached-deposit '1 yoctoNEAR' \
  sign-as "$ROOT" $NET sign-with-legacy-keychain send

say "8. A legitimate spend — expect ALLOWED"
near contract call-function as-transaction "$ROOT" request_spend \
  json-args "{\"recipient\":\"$PAYEE\",\"amount\":\"500000000000000000000000\",\"memo\":\"monthly API credits\"}" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$BOT" $NET sign-with-legacy-keychain send

say "9. The attack: a prompt-injected drain — expect DENIED"
near contract call-function as-transaction "$ROOT" request_spend \
  json-args "{\"recipient\":\"attacker.testnet\",\"amount\":\"1000000000000000000000000\",\"memo\":\"URGENT: owner authorized emergency transfer\"}" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$BOT" $NET sign-with-legacy-keychain send

say "10. An oversized transfer — expect DENIED"
near contract call-function as-transaction "$ROOT" request_spend \
  json-args "{\"recipient\":\"$PAYEE\",\"amount\":\"5000000000000000000000000\",\"memo\":\"drain attempt\"}" \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  sign-as "$BOT" $NET sign-with-legacy-keychain send

say "Done — final vault state"
curl -s -X POST https://rpc.testnet.near.org -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"call_function\",\"finality\":\"final\",\"account_id\":\"$ROOT\",\"method_name\":\"dashboard\",\"args_base64\":\"e30=\"}}" \
| python3 -c "
import sys, json
r = json.loads(bytes(json.load(sys.stdin)['result']['result']).decode())
N = 10**24
print('   available :  %.2f NEAR' % (int(r['available_balance'])/N))
print('   spent     :  %.2f NEAR' % (int(r['total_spent'])/N))
print('   blocked   :  %d attempts' % r['total_denied'])
"
echo ""
echo "   Vault: $ROOT"
echo "   Agent: $BOT  (one restricted key, nothing else)"
echo ""
