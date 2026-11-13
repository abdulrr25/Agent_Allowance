#!/usr/bin/env python3
"""
An MCP server that gives any AI agent a spending tool it cannot abuse.

The agent gets two tools: `request_payment` and `get_policy`. Every payment is
a signed `request_spend` call to the vault, so the limits are enforced by the
NEAR protocol and the contract — not by this process, the model, or the
prompt. Requires only Python 3.

Configure an MCP client to run it over stdio:

    {
      "mcpServers": {
        "agent-allowance": {
          "command": "python3",
          "args": ["/path/to/scripts/mcp_server.py"],
          "env": {
            "AGENT_ACCOUNT": "my-agent.testnet",
            "AGENT_KEY": "ed25519:...",
            "VAULT_ACCOUNT": "agent-allowance.testnet"
          }
        }
      }
    }

AGENT_KEY must be the agent's function-call key, never a full-access key.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nearlite as near  # noqa: E402

VAULT = os.environ.get("VAULT_ACCOUNT", "agent-allowance.testnet")
AGENT = os.environ.get("AGENT_ACCOUNT", "")
PROTOCOL = "2024-11-05"
DECIMALS = {"near": 24}

TOOLS = [
    {
        "name": "request_payment",
        "description": (
            "Ask the vault to pay a recipient. The vault allows or denies the request "
            "under the owner's policy; a denial is final and is recorded on-chain. "
            "Returns whether it was allowed and, if not, the reason."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "recipient": {"type": "string", "description": "NEAR account to pay"},
                "amount": {"type": "string",
                           "description": "Decimal amount, e.g. \"0.005\""},
                "token": {"type": "string",
                          "description": "NEP-141 token account; omit for native NEAR"},
                "memo": {"type": "string", "description": "Why the payment is being made"},
            },
            "required": ["recipient", "amount"],
        },
    },
    {
        "name": "get_policy",
        "description": ("Read this agent's spending policy from the vault: caps, "
                        "allowed recipients and what is left in the current window."),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def to_units(text, decimals):
    """Exact decimal-to-integer conversion; no floats on the way to the chain."""
    whole, _, frac = str(text).strip().partition(".")
    if not (whole + frac).isdigit() or len(frac) > decimals:
        raise ValueError(f"{text!r} is not a valid amount for an asset with "
                         f"{decimals} decimals")
    units = int(whole + frac.ljust(decimals, "0"))
    if units == 0:
        raise ValueError("amount must be greater than zero")
    return units


def token_decimals(token):
    if token not in DECIMALS:
        meta = near.view(token, "ft_metadata")
        DECIMALS[token] = int(meta["decimals"])
    return DECIMALS[token]


def request_payment(args):
    token = args.get("token")
    decimals = token_decimals(token) if token else 24
    # Validate before touching the key, so a malformed request never signs.
    call = {"recipient": args["recipient"],
            "amount": str(to_units(args["amount"], decimals)),
            "memo": args.get("memo")}
    if not AGENT or "AGENT_KEY" not in os.environ:
        raise RuntimeError("set AGENT_ACCOUNT and AGENT_KEY for this server")
    key = near.Key(os.environ["AGENT_KEY"])
    method = "request_spend"
    if token:
        call["token_id"] = token
        method = "request_spend_ft"
    try:
        tx_hash, result = near.send(key, AGENT, VAULT, [near.function_call(method, call)])
    except near.RpcError as e:
        return {"allowed": False, "stopped_by": "network",
                "reason": json.dumps(e.data) if e.data else str(e)}
    for ev in near.events(result):
        d = ev["data"][0]
        if ev["event"].endswith("denied"):
            return {"allowed": False, "stopped_by": "vault", "reason": d.get("reason"),
                    "transaction": tx_hash}
        if ev["event"].endswith("spend_allowed"):
            return {"allowed": True, "transaction": tx_hash}
    return {"allowed": False, "stopped_by": "vault",
            "reason": "the call failed without a policy decision",
            "transaction": tx_hash}


def get_policy(_args):
    dash = near.view(VAULT, "dashboard")
    me = next((a for a in dash["agents"] if a["agent_id"] == AGENT), None)
    if not me:
        return {"registered": False, "agent": AGENT, "vault": VAULT}

    def describe(policy, remaining, decimals, unit):
        scale = 10 ** decimals
        return {"asset": unit, "enabled": policy["enabled"],
                "per_payment_cap": f"{int(policy['per_tx_cap']) / scale:g}",
                "daily_cap": f"{int(policy['daily_cap']) / scale:g}",
                "remaining_in_window": f"{int(remaining) / scale:g}",
                "allowed_recipients": policy["allowlist"]}

    assets = [describe(me["policy"], me["remaining_today"], 24, "NEAR")]
    for t in me.get("tokens", []):
        assets.append(describe(t["policy"], t["remaining_today"],
                               token_decimals(t["token_id"]), t["token_id"]))
    return {"registered": True, "agent": AGENT, "vault": VAULT,
            "vault_paused": dash["paused"], "assets": assets}


HANDLERS = {"request_payment": request_payment, "get_policy": get_policy}


def handle(msg):
    """One JSON-RPC message in, one response out — or None for a notification."""
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None
    if method == "initialize":
        result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                  "serverInfo": {"name": "agent-allowance", "version": "1.0.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        fn = HANDLERS.get(params.get("name"))
        if not fn:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": "unknown tool"}}
        try:
            out, failed = fn(params.get("arguments") or {}), False
        except Exception as e:                          # noqa: BLE001
            out, failed = {"error": str(e)}, True
        result = {"content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                  "isError": failed}
    else:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            reply = handle(json.loads(line))
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
