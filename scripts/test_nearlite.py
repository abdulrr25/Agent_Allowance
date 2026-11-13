#!/usr/bin/env python3
"""
Offline tests for the Python tooling — no network, no dependencies.

    python3 scripts/test_nearlite.py

A hand-written signature scheme is only worth trusting against published
vectors, so the Ed25519 code is checked against RFC 8032 section 7.1, and the
transaction encoding against a key the chain already recognises.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nearlite as near  # noqa: E402
import mcp_server  # noqa: E402

# RFC 8032, section 7.1: (seed, public key, message, signature)
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]

# The key published in this repository, and the public key NEAR testnet holds
# for aa-agent.testnet. verify.py checks the second half against the chain.
PUBLISHED = ("ed25519:dmA2aFjMVuTGSfkcAHLavZs7zXRhFjraP3xF6pZgLH7gdPVJvn9aMaz"
             "SovmpmB1CPvLa3EAhJupSHoE1zuaAbQb")
PUBLISHED_PUBLIC = "ed25519:Cx2FXgPDB5Ty5r3cRVQQsdKXmVRUxnosPwBu8YhwxjKd"

TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


@test
def rfc8032_public_keys():
    for seed, public, _, _ in RFC8032:
        assert near.ed25519_public(bytes.fromhex(seed)).hex() == public


@test
def rfc8032_signatures():
    for seed, _, msg, sig in RFC8032:
        got = near.ed25519_sign(bytes.fromhex(seed), bytes.fromhex(msg))
        assert got.hex() == sig


@test
def rfc8032_signatures_verify():
    for _, public, msg, sig in RFC8032:
        assert near.ed25519_verify(bytes.fromhex(public), bytes.fromhex(msg),
                                   bytes.fromhex(sig))


@test
def a_changed_message_does_not_verify():
    _, public, _, sig = RFC8032[1]
    assert not near.ed25519_verify(bytes.fromhex(public), b"s", bytes.fromhex(sig))


@test
def a_changed_signature_does_not_verify():
    _, public, msg, sig = RFC8032[2]
    bad = bytearray(bytes.fromhex(sig))
    bad[5] ^= 1
    assert not near.ed25519_verify(bytes.fromhex(public), bytes.fromhex(msg), bytes(bad))


@test
def a_signature_with_an_out_of_range_scalar_is_rejected():
    _, public, msg, sig = RFC8032[0]
    forged = bytes.fromhex(sig)[:32] + b"\xff" * 32
    assert not near.ed25519_verify(bytes.fromhex(public), bytes.fromhex(msg), forged)


@test
def base58_round_trips_including_leading_zeros():
    for raw in (b"", b"\0", b"\0\0abc", bytes(range(1, 33)), b"\xff" * 64):
        assert near.b58decode(near.b58encode(raw)) == raw
    assert near.b58encode(b"hello world") == "StV1DL6CwTryKyV"


@test
def the_published_key_derives_its_known_public_key():
    assert near.Key(PUBLISHED).public == PUBLISHED_PUBLIC


@test
def a_secret_that_disagrees_with_its_public_half_is_refused():
    raw = bytearray(near.b58decode(PUBLISHED.split(":")[1]))
    raw[40] ^= 1
    try:
        near.Key("ed25519:" + near.b58encode(bytes(raw)))
    except ValueError:
        return
    raise AssertionError("a corrupted key was accepted")


@test
def function_call_is_borsh_encoded_as_near_expects():
    got = near.function_call("ping", {"a": 1}, gas=5, deposit=7)
    want = (b"\x02"                               # Action::FunctionCall
            + (4).to_bytes(4, "little") + b"ping"
            + (8).to_bytes(4, "little") + b'{"a": 1}'
            + (5).to_bytes(8, "little")
            + (7).to_bytes(16, "little"))
    assert got == want
    assert near.transfer(9) == b"\x03" + (9).to_bytes(16, "little")


@test
def a_signed_transaction_carries_a_valid_signature_over_its_hash():
    key = near.Key(PUBLISHED)
    block_hash = near.b58encode(bytes(range(32)))
    tx_hash, signed = near.signed_transaction(
        key, "aa-agent.testnet", "agent-allowance.testnet", 42, block_hash,
        [near.function_call("request_spend", {"recipient": "x.testnet"})])
    body, sig = signed[:-65], signed[-64:]
    assert signed[-65] == 0                       # ed25519 signature tag
    digest = hashlib.sha256(body).digest()
    assert near.b58encode(digest) == tx_hash
    assert near.ed25519_verify(key.public_raw, digest, sig)
    assert bytes(range(32)) in body and key.public_raw in body


@test
def an_invalid_nonce_error_is_recognised_and_nothing_else_is():
    stale = {"TxExecutionError": {"InvalidTxError": {
        "InvalidNonce": {"ak_nonce": 12, "tx_nonce": 11}}}}
    refused = {"TxExecutionError": {"InvalidTxError": {
        "InvalidAccessKeyError": "RequiresFullAccess"}}}
    assert near._invalid_nonce(stale) == 12
    assert near._invalid_nonce(refused) is None
    assert near._invalid_nonce("Timeout") is None
    assert near._invalid_nonce(None) is None


@test
def mcp_server_answers_the_handshake_and_lists_its_tools():
    init = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init["result"]["capabilities"] == {"tools": {}}
    listed = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in listed["result"]["tools"]]
    assert names == ["request_payment", "get_policy"]
    for tool in listed["result"]["tools"]:
        assert tool["inputSchema"]["type"] == "object"


@test
def mcp_server_ignores_notifications_and_rejects_unknown_calls():
    assert mcp_server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"] == -32601
    bad = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": "no_such_tool"}})
    assert bad["error"]["code"] == -32602


@test
def mcp_server_reports_a_bad_amount_as_a_tool_error_without_signing():
    out = mcp_server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "request_payment", "arguments": {"recipient": "x.testnet", "amount": "abc"}}})
    assert out["result"]["isError"] is True


@test
def amounts_convert_to_base_units_exactly():
    assert mcp_server.to_units("0.005", 24) == 5 * 10**21
    assert mcp_server.to_units("2", 6) == 2_000_000
    assert mcp_server.to_units("123456789.123456", 6) == 123456789123456
    for bad in ("0", "-1", "1e5", "0.0000001", "abc", ""):
        try:
            mcp_server.to_units(bad, 6)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} was accepted")


def main():
    failed = 0
    for fn in TESTS:
        try:
            fn()
            print(f"  PASS  {fn.__name__.replace('_', ' ')}")
        except Exception as e:                          # noqa: BLE001
            failed += 1
            print(f"  FAIL  {fn.__name__.replace('_', ' ')}: {e!r}")
    print(f"\n  {len(TESTS) - failed} passed, {failed} failed\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
