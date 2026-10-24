"""
ONDC request signing and verification.

Every ONDC message carries an Authorization header proving who sent it and
that the body wasn't changed on the way. A gateway forwarding a search adds
a second header, X-Gateway-Authorization, signed with the gateway's own key.

How a header is made (from ONDC's developer docs and reference code):
  1. digest  = base64( BLAKE2b-512( raw request body ) )
  2. signing string, exactly three lines:
        (created): <unix time>
        (expires): <unix time>
        digest: BLAKE-512=<digest>
  3. signature = base64( Ed25519 sign(signing string) )
  4. Authorization: Signature keyId="<subscriber_id>|<unique_key_id>|ed25519",
        algorithm="ed25519",created="...",expires="...",
        headers="(created) (expires) digest",signature="..."

The receiver looks up the sender's public key (normally in the ONDC registry;
here, a local JSON file) and checks the signature against the body it got.
Change one byte of the body and the check fails.
"""

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CLOCK_SKEW = 5  # seconds of tolerance for clocks that disagree slightly


def digest(body: bytes) -> str:
    return base64.b64encode(hashlib.blake2b(body, digest_size=64).digest()).decode()


def signing_string(created: int, expires: int, body_digest: str) -> str:
    return f"(created): {created}\n(expires): {expires}\ndigest: BLAKE-512={body_digest}"


def _private_key(private_key_b64: str) -> Ed25519PrivateKey:
    raw = base64.b64decode(private_key_b64)
    # ONDC (libsodium) private keys are 64 bytes: 32-byte seed + public key.
    return Ed25519PrivateKey.from_private_bytes(raw[:32])


def make_header(body: bytes, subscriber_id: str, unique_key_id: str, private_key_b64: str,
                created: int | None = None, valid_for: int = 300) -> str:
    created = int(time.time()) if created is None else created
    expires = created + valid_for
    text = signing_string(created, expires, digest(body))
    signature = base64.b64encode(_private_key(private_key_b64).sign(text.encode())).decode()
    return (f'Signature keyId="{subscriber_id}|{unique_key_id}|ed25519",algorithm="ed25519",'
            f'created="{created}",expires="{expires}",headers="(created) (expires) digest",'
            f'signature="{signature}"')


def generate_keypair() -> tuple[str, str]:
    """Returns (private_key_b64, public_key_b64) in ONDC's format."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes_raw()
    public = key.public_key().public_bytes_raw()
    return base64.b64encode(seed + public).decode(), base64.b64encode(public).decode()


def parse_header(header: str) -> dict | None:
    """Turn 'Signature keyId="a|b|c",created="1",...' into a dict. None if unreadable."""
    header = header.strip()
    # ONDC's Python reference code wraps the whole value in quotes: "Signature keyId=...". Only
    # unwrap when the header itself starts with a quote; a blind strip('"') would also eat the
    # closing quote of the last value (signature="...").
    if header.startswith('"') and header.endswith('"'):
        header = header[1:-1]
    if header.startswith("Signature "):
        header = header[len("Signature "):]
    params = dict(re.findall(r'(\w+)="([^"]*)"', header))
    return params or None


# ---- verification -----------------------------------------------------------
# Public keys come from debugger.registry: a local key file and/or the ONDC registry.

@dataclass
class SigProblem:
    code: str
    detail: str


def verify(header: str | None, body: bytes, keys, seen_at: float,
           expected_signer: str | None, label: str = "Authorization") -> list[SigProblem]:
    """Check one signature header. Returns the problems found (empty list = valid).

    keys: a debugger.registry.KeyStore, or a plain dict {"subscriber_id|unique_key_id": public_key}.
    """
    if isinstance(keys, dict):
        from debugger.registry import KeyStore  # here, to avoid a circular import
        keys = KeyStore(local=keys)
    if not header:
        return [SigProblem("missing_signature", f"no {label} header")]

    p = parse_header(header)
    needed = {"keyId", "algorithm", "created", "expires", "signature"}
    if not p or not needed <= p.keys():
        missing = sorted(needed - (p or {}).keys())
        return [SigProblem("bad_signature_header", f"{label} header is missing: {', '.join(missing)}")]

    parts = p["keyId"].split("|")
    if len(parts) != 3:
        return [SigProblem("bad_signature_header",
                           f'{label} keyId must be "subscriber_id|unique_key_id|algorithm", got "{p["keyId"]}"')]
    subscriber, key_id, key_alg = parts
    problems = []

    if key_alg != p["algorithm"] or p["algorithm"] != "ed25519":
        problems.append(SigProblem("bad_signature_header",
            f"{label}: algorithm in keyId ({key_alg}) and algorithm parameter ({p['algorithm']}) "
            f"must both be ed25519"))

    if expected_signer and subscriber != expected_signer:
        problems.append(SigProblem("signer_mismatch",
            f"{label} is signed by {subscriber}, but the message says it's from {expected_signer}"))

    try:
        created, expires = int(p["created"]), int(p["expires"])
    except ValueError:
        return problems + [SigProblem("bad_signature_header", f"{label} created/expires aren't unix timestamps")]
    if created > seen_at + CLOCK_SKEW:
        problems.append(SigProblem("signature_time", f"{label} was created {created - seen_at:.0f}s in the future"))
    if expires < seen_at - CLOCK_SKEW:
        problems.append(SigProblem("signature_time", f"{label} had already expired {seen_at - expires:.0f}s before it arrived"))

    found = keys.get(subscriber, key_id)
    if not found.record:
        return problems + [SigProblem(found.problem or "unknown_key", f"{label}: {found.detail}")]
    rec = found.record

    # A registry key is only valid for a period. Signing with a retired key is a
    # common bug after key rotation.
    if rec.valid_until and seen_at > rec.valid_until.timestamp() + CLOCK_SKEW:
        problems.append(SigProblem("key_validity",
            f"{label} uses key {subscriber}|{key_id}, which the registry says expired on "
            f"{rec.valid_until.isoformat(timespec='seconds')}"))
    if rec.valid_from and seen_at < rec.valid_from.timestamp() - CLOCK_SKEW:
        problems.append(SigProblem("key_validity",
            f"{label} uses key {subscriber}|{key_id}, which isn't valid until "
            f"{rec.valid_from.isoformat(timespec='seconds')}"))

    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(rec.public_key)).verify(
            base64.b64decode(p["signature"]), signing_string(created, expires, digest(body)).encode())
    except (InvalidSignature, ValueError):
        problems.append(SigProblem("signature_invalid",
            f"{label} signature doesn't match: the body was changed after signing, "
            f"or it was signed with a different key than {subscriber}|{key_id} "
            f"(public key from {rec.source})"))
    return problems
