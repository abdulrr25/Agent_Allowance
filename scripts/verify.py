#!/usr/bin/env python3
"""
Verify every claim Agent Allowance makes, directly against NEAR testnet.

Read-only: it signs nothing and spends nothing. Requires only Python 3 — no
keys, no Rust, no npm, no packages, no setup.

    python3 scripts/verify.py
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nearlite as near  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VAULT = "agent-allowance.testnet"
AGENT = "bot.agent-allowance.testnet"
# The agent whose private key is published on the attack page. Everything the
# site claims about that key is checked here, against the chain.
PLAYGROUND = "aa-agent.testnet"
# An earlier playground agent. Its key was published too and is still in this
# repository's git history, so it is held to the same standard.
RETIRED = "aa-playground.testnet"
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


def view(method, args=None):
    return near.view(VAULT, method, args)


def to_near(y): return int(y) / YOCTO


def check_key(account, expected_methods):
    """Assert an agent account holds exactly one protocol-restricted key."""
    print(f"\n   {account}")
    keys = near.access_keys(account)
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
            f"{to_near(allowance):.2f} NEAR (gas only — a function-call key "
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
    print(f"        vault available : {to_near(d['available_balance']):.2f} NEAR")
    print(f"        total spent     : {to_near(d['total_spent']):.2f} NEAR")
    print(f"        attempts blocked: {d['total_denied']}")
    print(f"        kill switch     : {'PAUSED' if d['paused'] else 'active'}")

    # 2 --------------------------------------- the protocol-level guarantee
    print(bold("\n2. Agent keys are restricted by the NEAR protocol"))
    print("   Claim: each agent holds exactly one key, and that key can call")
    print("   only its named methods on the vault — nothing else on NEAR.")
    check_key(AGENT, ["request_spend"])
    check_key(PLAYGROUND, ["request_spend", "request_spend_ft"])
    check_key(RETIRED, ["request_spend"])

    # 3 ------------------------------------------------- policy is enforced
    print(bold("\n3. Spending policy is live on-chain"))
    agent = next((a for a in d["agents"] if a["agent_id"] == AGENT), None)
    if not agent:
        check(False, f"{AGENT} is registered")
    else:
        p = agent["policy"]
        print(f"        per-tx cap : {to_near(p['per_tx_cap']):.2f} NEAR")
        print(f"        daily cap  : {to_near(p['daily_cap']):.2f} NEAR")
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
            out = near.transaction(tx_hash, signer)
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

    # 5 ------------------------------------------- the key in this repository
    print(bold("\n5. The private key published in this repository"))
    print("   Claim: the repository contains exactly one private key, and it is")
    print(f"   the restricted key of {PLAYGROUND} checked above — nothing more.")
    found = scan_for_secrets()
    for secret, files in found.items():
        print(f"        {secret[:16]}…  in {', '.join(sorted(files))}")
    check(len(found) == 1, "exactly one private key is present in the working tree")
    onchain = [k["public_key"] for k in near.access_keys(PLAYGROUND)]
    derived = [near.Key(s).public for s in found]
    check(len(derived) == 1 and derived == onchain,
          f"it is the sole key of {PLAYGROUND}, the one restricted to the vault")

    summary()


def scan_for_secrets():
    """Every ed25519 secret key in the repository's text files, by file."""
    pattern = re.compile(r"ed25519:[1-9A-HJ-NP-Za-km-z]{80,90}")
    skip = {"target", "node_modules", "__pycache__"}
    found = {}
    for folder, dirs, files in os.walk(ROOT):
        # Hidden directories are tool state, not project source — except the
        # CI configuration, which is part of what gets published.
        dirs[:] = [d for d in dirs if d not in skip
                   and (not d.startswith(".") or d == ".github")]
        for name in files:
            path = os.path.join(folder, name)
            try:
                text = open(path, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            # A key may be wrapped across adjacent string literals in source.
            joined = re.sub(r'"\s*\n\s*"', "", text)
            for secret in set(pattern.findall(text)) | set(pattern.findall(joined)):
                found.setdefault(secret, set()).add(os.path.relpath(path, ROOT))
    return found


def summary():
    passed, failed = sum(results), len(results) - sum(results)
    print(bold("\nSummary"))
    print(f"  {passed} passed, {failed} failed\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
