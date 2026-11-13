"""
A minimal NEAR client in the Python standard library: Ed25519 signing, base58,
Borsh transaction encoding and JSON-RPC.

It exists so that `redteam.py` and `verify.py` can sign and inspect real
transactions with nothing installed — no pip, no npm, no near-cli. It is a
teaching-sized implementation for a testnet demo, not a wallet: the scalar
arithmetic is not constant-time, which does not matter for a key that is
published on purpose.
"""
import base64
import hashlib
import json
import time
import urllib.request

RPCS = ["https://test.rpc.fastnear.com", "https://rpc.testnet.near.org"]
# Ordinary nodes garbage-collect transactions after about five epochs — a few
# days on testnet. Anything that reads an old transaction must ask an archival
# node first, or the evidence quietly becomes unreadable.
ARCHIVAL = ["https://archival-rpc.testnet.fastnear.com",
            "https://archival-rpc.testnet.near.org"]

# ------------------------------------------------------------------ base58
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(raw) - len(raw.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    pad = len(text) - len(text.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * pad + body


# ----------------------------------------------------------------- ed25519
# RFC 8032, section 6, in extended homogeneous coordinates.
_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _recover_x(y, sign):
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, pt):
    acc = (0, 1, 1, 0)
    while s:
        if s & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        s >>= 1
    return acc


def _compress(pt):
    zi = _inv(pt[2])
    x, y = pt[0] * zi % _P, pt[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(raw):
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _hmodq(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little") % _Q


def ed25519_public(seed):
    """32-byte public key for a 32-byte seed."""
    return _compress(_mul(_expand(seed)[0], _G))


def ed25519_sign(seed, msg):
    """64-byte signature of `msg` under the 32-byte `seed`."""
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = _hmodq(prefix, msg)
    R = _compress(_mul(r, _G))
    s = (r + _hmodq(R, pub, msg) * a) % _Q
    return R + s.to_bytes(32, "little")


def ed25519_verify(pub, msg, sig):
    """True when `sig` is a valid signature of `msg` under `pub`."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    A, R = _decompress(pub), _decompress(sig[:32])
    left = _compress(_mul(s, _G))
    right = _compress(_add(R, _mul(_hmodq(sig[:32], pub, msg), A)))
    return left == right


# -------------------------------------------------------------------- keys
class Key:
    """A NEAR ed25519 key pair parsed from its `ed25519:<base58>` form."""

    def __init__(self, secret):
        raw = b58decode(secret.split(":", 1)[1])
        if len(raw) != 64:
            raise ValueError("expected a 64-byte ed25519 secret key")
        self.seed = raw[:32]
        self.public_raw = ed25519_public(self.seed)
        if self.public_raw != raw[32:]:
            raise ValueError("secret key does not match its embedded public key")
        self.public = "ed25519:" + b58encode(self.public_raw)

    def sign(self, msg):
        return ed25519_sign(self.seed, msg)


# ------------------------------------------------------------------- borsh
def _u32(n):
    return n.to_bytes(4, "little")


def _u64(n):
    return n.to_bytes(8, "little")


def _u128(n):
    return n.to_bytes(16, "little")


def _str(s):
    b = s.encode()
    return _u32(len(b)) + b


def function_call(method, args, gas=100 * 10**12, deposit=0):
    body = json.dumps(args).encode()
    return b"\x02" + _str(method) + _u32(len(body)) + body + _u64(gas) + _u128(deposit)


def transfer(yocto):
    return b"\x03" + _u128(yocto)


def add_full_access_key(public_raw):
    # AddKey { public_key, AccessKey { nonce: 0, permission: FullAccess } }
    return b"\x05" + b"\x00" + public_raw + _u64(0) + b"\x01"


def delete_account(beneficiary):
    return b"\x07" + _str(beneficiary)


def signed_transaction(key, signer, receiver, nonce, block_hash, actions):
    """Borsh-encode and sign a transaction; returns (tx hash, signed bytes)."""
    tx = (_str(signer) + b"\x00" + key.public_raw + _u64(nonce) + _str(receiver)
          + b58decode(block_hash) + _u32(len(actions)) + b"".join(actions))
    digest = hashlib.sha256(tx).digest()
    return b58encode(digest), tx + b"\x00" + key.sign(digest)


# --------------------------------------------------------------------- rpc
class RpcError(Exception):
    """An RPC call the node answered with an error. `.data` is the node's own
    structured reason, e.g. {"TxExecutionError": {"InvalidTxError": ...}}."""

    def __init__(self, error):
        self.error = error
        self.data = error.get("data")
        super().__init__(error.get("message") or str(error))


def rpc(method, params, attempts=4, retry_errors=True, endpoints=None):
    """POST to NEAR RPC with retry and endpoint fallback.

    Public endpoints throttle bursts, so back off rather than treating the
    first refusal as a failed claim. Pass retry_errors=False when an error
    answer is itself the result being measured — a rejected transaction.
    """
    last = None
    for endpoint in endpoints or RPCS:
        for attempt in range(attempts):
            try:
                req = urllib.request.Request(
                    endpoint,
                    data=json.dumps({"jsonrpc": "2.0", "id": 1,
                                     "method": method, "params": params}).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=60) as r:
                    body = json.loads(r.read().decode())
            except Exception as e:                      # noqa: BLE001
                last = e
                time.sleep(0.6 * (attempt + 1))
                continue
            if "error" in body:
                if not retry_errors:
                    raise RpcError(body["error"])
                last = RpcError(body["error"])
                time.sleep(0.6 * (attempt + 1))
                continue
            return body["result"]
    raise RuntimeError(f"all RPC endpoints failed: {last}")


def view(contract, method, args=None, finality="final"):
    res = rpc("query", {
        "request_type": "call_function", "finality": finality,
        "account_id": contract, "method_name": method,
        "args_base64": base64.b64encode(json.dumps(args or {}).encode()).decode(),
    })
    return json.loads(bytes(res["result"]).decode())


def transaction(tx_hash, signer):
    """A transaction and its receipts, however old it is."""
    return rpc("tx", [tx_hash, signer], attempts=2, endpoints=ARCHIVAL + RPCS)


def access_keys(account):
    return rpc("query", {"request_type": "view_access_key_list",
                         "finality": "final", "account_id": account})["keys"]


_last_nonce = {}


def send(key, signer, receiver, actions):
    """Sign and broadcast, waiting for the outcome.

    Returns the node's execution result. Raises RpcError when the network
    refuses the transaction outright, which is how an access-key violation
    surfaces: the transaction is never included in a block.

    A stale nonce is retried rather than raised. The published key is shared
    by everyone who tries it, so another sender can land first — that is a
    collision, not a verdict on the transaction.
    """
    for attempt in range(5):
        ak = rpc("query", {"request_type": "view_access_key", "finality": "optimistic",
                           "account_id": signer, "public_key": key.public})
        nonce = max(ak["nonce"], _last_nonce.get(key.public, 0)) + 1
        tx_hash, signed = signed_transaction(
            key, signer, receiver, nonce, ak["block_hash"], actions)
        try:
            result = rpc("broadcast_tx_commit", [base64.b64encode(signed).decode()],
                         attempts=1, retry_errors=False)
        except RpcError as e:
            stale = _invalid_nonce(e.data)
            if stale is None or attempt == 4:
                raise
            _last_nonce[key.public] = stale
            time.sleep(0.7)
            continue
        _last_nonce[key.public] = nonce
        return tx_hash, result


def _invalid_nonce(data):
    """The access key's current nonce, if `data` is an InvalidNonce error."""
    try:
        return data["TxExecutionError"]["InvalidTxError"]["InvalidNonce"]["ak_nonce"]
    except (KeyError, TypeError):
        return None


def events(result):
    """NEP-297 events emitted anywhere in a transaction's receipts."""
    out = []
    for o in result.get("receipts_outcome", []):
        for line in o["outcome"]["logs"]:
            if line.startswith("EVENT_JSON:"):
                out.append(json.loads(line[len("EVENT_JSON:"):]))
    return out
