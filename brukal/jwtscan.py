"""
jwtscan.py — JSON Web Token weakness analysis.

Brukal already EXTRACTED a bearer token at login and carried it on later requests, but
never looked at it. A JWT is a security decision the client can read: the header names
the algorithm, the payload names the principal, and the signature is only as strong as
the key behind it. The most damaging API auth bugs live right there.

Everything here is offline and deterministic — decoding is base64, and recovering a weak
HMAC key is arithmetic over the token's own signing input. No request is sent, so a
cracked key is proved before the target is touched at all. The active follow-up (mint a
token and see whether the server accepts it) lives in AssistSession.confirm_jwt_forgery,
so the network step stays behind the gate like every other action.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

# Keys that show up in real deployments: framework defaults, tutorial copy-paste, and
# the placeholders people mean to replace. Small on purpose — this is a "was the key
# ever chosen?" check, not a cracking rig. A hit is decisive; a miss proves nothing.
COMMON_SECRETS = (
    "secret", "secretkey", "secret_key", "SECRET_KEY", "jwt_secret", "jwtsecret",
    "JWT_SECRET", "password", "passw0rd", "changeme", "change_me", "key", "mykey",
    "private", "privatekey", "supersecret", "super_secret", "s3cr3t", "mysecret",
    "topsecret", "random", "test", "testing", "dev", "development", "debug", "local",
    "admin", "administrator", "root", "default", "example", "demo", "sample",
    "your-256-bit-secret", "your_jwt_secret", "your-secret-key", "shhhhh", "qwerty",
    "123456", "12345678", "1234567890", "abc123", "letmein", "token", "auth", "authkey",
    "signature", "hmac", "app_secret", "appsecret", "client_secret", "api_secret",
    "session_secret", "cookie_secret", "flask", "django", "express", "nodejs", "laravel",
)

_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def find_tokens(text: str, limit: int = 5) -> list[str]:
    """JWTs appearing in a response body, header dump or bundle."""
    out: list[str] = []
    for m in _JWT_RE.finditer(text or ""):
        t = m.group(0)
        if t not in out and decode(t) is not None:
            out.append(t)
            if len(out) >= limit:
                break
    return out


def decode(token: str):
    """(header, payload, signing_input, signature) for a well-formed JWT, else None.
    Pure parsing of untrusted text; never raises."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
        signature = _b64d(parts[2]) if parts[2] else b""
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, f"{parts[0]}.{parts[1]}".encode(), signature


def crack_hmac_secret(token: str, extra_secrets=()) -> str | None:
    """Recover the signing key of an HS256/384/512 token by trying weak candidates
    against its OWN signature. Entirely offline: no request, no side effect, and a hit
    is cryptographic proof rather than a heuristic — the key reproduces the signature."""
    parsed = decode(token)
    if parsed is None:
        return None
    header, _payload, signing_input, signature = parsed
    algo = _HMAC_ALGS.get(str(header.get("alg", "")).upper())
    if algo is None or not signature:
        return None
    for candidate in (*COMMON_SECRETS, *extra_secrets):
        mac = hmac.new(candidate.encode(), signing_input, algo).digest()
        if hmac.compare_digest(mac, signature):
            return candidate
    return None


def sign(header: dict, payload: dict, secret: str) -> str:
    """Mint a token — used to prove a recovered key actually works against the server."""
    algo = _HMAC_ALGS.get(str(header.get("alg", "")).upper(), hashlib.sha256)
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), algo).digest()
    return f"{h}.{p}.{_b64e(sig)}"


def alg_none_variant(token: str) -> str | None:
    """The same claims with the signature stripped and `alg` set to none — accepted by
    any implementation that trusts the header's choice of algorithm."""
    parsed = decode(token)
    if parsed is None:
        return None
    header, payload, _si, _sig = parsed
    h = _b64e(json.dumps({**header, "alg": "none"}, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


# Claims that should never be decided by something the client holds and can rewrite.
_PRIVILEGE_CLAIMS = ("admin", "is_admin", "isadmin", "role", "roles", "scope", "scopes",
                     "permissions", "is_staff", "superuser", "level", "group")
_SECRET_CLAIMS = ("password", "passwd", "pwd", "secret", "api_key", "apikey", "token",
                  "credit_card", "ssn")


def scan_token(token: str, extra_secrets=()) -> list[tuple[str, str, str]]:
    """(severity, label, evidence) for the weaknesses a token reveals about itself.

    A recovered key is CRITICAL and certain: with it an attacker mints any token, so
    every authorisation decision downstream is theirs. The rest are what the token
    discloses about how the system reasons — no request required for any of it."""
    parsed = decode(token)
    if parsed is None:
        return []
    header, payload, _si, signature = parsed
    hits: list[tuple[str, str, str]] = []
    alg = str(header.get("alg", "")).upper()

    if alg in ("NONE", ""):
        hits.append(("critical", "JWT accepts the 'none' algorithm",
                     f"header declares alg={header.get('alg')!r} — the token is unsigned"))
    if not signature and alg not in ("NONE", ""):
        hits.append(("high", "JWT carries no signature",
                     f"alg={alg} but the signature segment is empty"))

    secret = crack_hmac_secret(token, extra_secrets)
    if secret:
        hits.append(("critical", "JWT signed with a guessable secret",
                     f"the {alg} signing key is {secret!r} — recovered offline from the "
                     f"token's own signature, so any token (any user, any role) can be "
                     f"minted"))

    exp = payload.get("exp")
    if exp is None:
        hits.append(("medium", "JWT has no expiry",
                     "no `exp` claim — a stolen token stays valid forever"))
    elif isinstance(exp, (int, float)):
        iat = payload.get("iat")
        if isinstance(iat, (int, float)) and exp - iat > 60 * 60 * 24 * 30:
            days = int((exp - iat) / 86400)
            hits.append(("low", "JWT lifetime is excessive",
                         f"valid for {days} days after issue"))
        elif exp < time.time() - 86400:
            hits.append(("low", "JWT is long expired",
                         "captured token is stale; findings from it may not reproduce"))

    priv = [k for k in payload if str(k).lower() in _PRIVILEGE_CLAIMS]
    if priv:
        hits.append(("low", "JWT carries privilege claims",
                     f"authorisation data in the token ({', '.join(map(str, priv))}) — "
                     f"decisive only if the signature is sound"))
    leaked = [k for k in payload if str(k).lower() in _SECRET_CLAIMS]
    if leaked:
        hits.append(("high", "JWT payload contains sensitive data",
                     f"claims {', '.join(map(str, leaked))} are readable by anyone "
                     f"holding the token — a JWT payload is not encrypted"))
    return hits


CONFIRMED_JWT_LABELS = frozenset({
    "JWT signed with a guessable secret",
    "JWT accepts the 'none' algorithm",
    "JWT carries no signature",
    "JWT payload contains sensitive data",
    "JWT has no expiry",
})
