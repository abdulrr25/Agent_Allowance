#!/usr/bin/env python3
"""
Verify every claim Agent Allowance makes, directly against NEAR testnet.

Requires only Python 3 — no keys, no Rust, no npm, no packages, no setup.

    python3 scripts/verify.py
"""
import base64
import json
import sys
import time
import urllib.error
import urllib.request

RPCS = ["https://rpc.testnet.near.org", "https://test.rpc.fastnear.com"]
VAULT = "agent-allowance.testnet"
AGENT = "bot.agent-allowance.testnet"
# The agent whose private key is published on the attack page. Everything the
# site claims about that key is checked here, against the chain.
PLAYGROUND = "aa-agent.testnet"
TOKEN = "usdc.fakes.testnet"
YOCTO = 10**24

# (transaction hash, signer, expected event or deny reason, description)
PROOFS = [
    ("2UEaarEHrGvi3MbCohmTGF7fEnr4pTXs6JcnK9edXzPr", AGENT, "spend_allowed",
     "legitimate payment to an allowlisted payee"),
    ("HAd35gbQuPMe8d8JVzJhmFobgsT7s8igoyqVv7iUWz8y", AGENT, "recipient_not_allowlisted",
     "prompt-injected drain to attacker.testnet"),
    ("2AGh8GW2DoZaPbQkrgew7C5b6DouvD6aVHZkBFF5FknA", AGENT, "exceeds_per_tx_cap",
     "oversized transfer, above the per-transaction cap"),
    ("GuJRKr2v51koWPfMYKBJCN8upGnP26eowsMPNXjNE9SM", PLAYGROUND, "ft_spend_allowed",
     "legitimate USDC.e payment to an allowlisted payee"),
    ("5td8rsqQgbsTgjqQ4N8cGTSD4APJwXZo6cWv2aY6iZTT", PLAYGROUND, "recipient_not_allowlisted",
     "prompt-injected stablecoin drain to attacker.testnet"),
]

_tty = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if _tty else s
bold = lambda s: c("1", s)

results = []
def check(passed, msg):
    results.append(passed)
    print(f"  {c('32','PASS') if passed else c('31','FAIL')}  {msg}")


def rpc(payload, attempts=4):
    """POST to NEAR RPC with retry and endpoint fallback.

    Public endpoints throttle bursts, so back off rather than treating the
    first refusal as a failed claim.
    """
    last = None
    for endpoint in RPCS:
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(
                    endpoint,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=30) as r:
                    body = json.loads(r.read().decode())
                if "error" in body:
                    last = body["error"]
                    time.sleep(0.6 * (attempt + 1))
                    continue
                return body["result"]
            except Exception as e:                      # noqa: BLE001
                last = e
                time.sleep(0.6 * (attempt + 1))
    raise RuntimeError(f"all RPC endpoints failed: {last}")


def view(method, args=None):
    res = rpc({
        "jsonrpc": "2.0", "id": 1, "method": "query",
        "params": {
            "request_type": "call_function", "finality": "final",
            "account_id": VAULT, "method_name": method,
            "args_base64": base64.b64encode(
                json.dumps(args or {}).encode()).decode(),
        },
    })
    return json.loads(bytes(res["result"]).decode())


def near(y): return int(y) / YOCTO


def check_key(account, expected_methods):
    """Assert an agent account holds exactly one protocol-restricted key."""
    print(f"\n   {account}")
    keys = rpc({
        "jsonrpc": "2.0", "id": 1, "method": "query",
        "params": {"request_type": "view_access_key_list",
                   "finality": "final", "account_id": account},
    })["keys"]
    full = [k for k in keys if k["access_key"]["permission"] == "FullAccess"]
    fc = [k for k in keys if k["access_key"]["permission"] != "FullAccess"]
    for k in fc:
        p = k["access_key"]["permission"]["FunctionCall"]
        allowance = p.get("allowance")
        print(f"        methods  : {p['method_names']}")
        print(f"        contract : {p['receiver_id']}")
        # An allowance may legitimately be null, meaning unlimited gas. It is
        # still gas only: no function-call key can attach a token deposit.
        print("        allowance: " + (
            f"{near(allowance):.2f} NEAR (gas only — a function-call key "
            "cannot move tokens)" if allowance else
            "unlimited gas — still cannot move tokens"))
    perm = fc[0]["access_key"]["permission"]["FunctionCall"] if len(fc) == 1 else {}
    check(len(keys) == 1, f"{account} holds exactly one access key")
    check(not full, f"no full-access key exists on {account}")
    check(perm.get("method_names") == expected_methods,
          f"key is limited to {', '.join(expected_methods)}")
    check(perm.get("receiver_id") == VAULT,
          "key is limited to the vault contract")


def main():
    print(bold("Agent Allowance — on-chain verification"))
    print(f"contract : {VAULT}")
    print(f"agent    : {AGENT}")

    # 1 ------------------------------------------------- contract is live
    print(bold("\n1. Contract is deployed and holds state"))
    try:
        d = view("dashboard")
    except Exception as e:                              # noqa: BLE001
        check(False, f"contract did not respond: {e}")
        return summary()
    check(bool(d.get("owner_id")), f"owner is {d['owner_id']}")
    print(f"        vault available : {near(d['available_balance']):.2f} NEAR")
    print(f"        total spent     : {near(d['total_spent']):.2f} NEAR")
    print(f"        attempts blocked: {d['total_denied']}")
    print(f"        kill switch     : {'PAUSED' if d['paused'] else 'active'}")

    # 2 --------------------------------------- the protocol-level guarantee
    print(bold("\n2. Agent keys are restricted by the NEAR protocol"))
    print("   Claim: each agent holds exactly one key, and that key can call")
    print("   only its named methods on the vault — nothing else on NEAR.")
    check_key(AGENT, ["request_spend"])
    check_key(PLAYGROUND, ["request_spend", "request_spend_ft"])

    # 3 ------------------------------------------------- policy is enforced
    print(bold("\n3. Spending policy is live on-chain"))
    agent = next((a for a in d["agents"] if a["agent_id"] == AGENT), None)
    if not agent:
        check(False, f"{AGENT} is registered")
    else:
        p = agent["policy"]
        print(f"        per-tx cap : {near(p['per_tx_cap']):.2f} NEAR")
        print(f"        daily cap  : {near(p['daily_cap']):.2f} NEAR")
        print(f"        allowlist  : {', '.join(p['allowlist'])}")
        print(f"        allowed    : {p['allowed_count']}")
        print(f"        blocked    : {p['denied_count']}")
        check(p["enabled"], "agent is registered and enabled")
        check(int(p["per_tx_cap"]) <= int(p["daily_cap"]),
              "per-transaction cap does not exceed the daily cap")
        check(len(p["allowlist"]) > 0, "an allowlist is configured")
        check(p["denied_count"] > 0,
              f"{p['denied_count']} attempts were blocked and recorded")

    play = next((a for a in d["agents"] if a["agent_id"] == PLAYGROUND), None)
    print(f"\n   {PLAYGROUND} — the agent whose key the site publishes")
    if not play:
        check(False, f"{PLAYGROUND} is registered against the vault")
    else:
        check(play["policy"]["enabled"], "the published agent is registered and enabled")
        tok = next((t for t in play["tokens"] if t["token_id"] == TOKEN), None)
        if tok:
            print(f"        {TOKEN} per-tx: {int(tok['policy']['per_tx_cap'])/10**6:.2f}"
                  f"  daily: {int(tok['policy']['daily_cap'])/10**6:.2f}")
        check(tok is not None, f"a {TOKEN} policy governs the published agent")
        held = next((t for t in d["tokens"] if t["token_id"] == TOKEN), None)
        if held:
            print(f"        vault holds: {int(held['balance'])/10**6:.2f} USDC.e")
        check(held is not None and int(held["balance"]) > 0,
              "the vault really holds the stablecoin it governs")

    # 4 ------------------------------------------------------ proof on chain
    print(bold("\n4. Recorded outcomes of five real transactions"))
    for tx_hash, signer, expect, label in PROOFS:
        try:
            out = rpc({"jsonrpc": "2.0", "id": 1, "method": "tx",
                       "params": [tx_hash, signer]})
            logs = [l for o in out.get("receipts_outcome", [])
                    for l in o["outcome"]["logs"] if "EVENT_JSON" in l]
            events = []
            for line in logs:
                e = json.loads(line.split("EVENT_JSON:", 1)[1])
                data = e["data"][0]
                events.append(e["event"])
                if data.get("reason"):
                    events.append(data["reason"])
                if data.get("memo"):
                    print(f"        memo: \"{data['memo']}\"")
            print(f"        {label}")
            print(f"          events: {', '.join(events) or '<none>'}")
            check(expect in events, f"{label} → {expect}")
        except Exception as e:                          # noqa: BLE001
            check(False, f"{label}: {e}")

    summary()


def summary():
    passed, failed = sum(results), len(results) - sum(results)
    print(bold("\nSummary"))
    print(f"  {passed} passed, {failed} failed\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
