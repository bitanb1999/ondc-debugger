"""
Signing keys for the mock apps.

On first use this generates an Ed25519 key pair for each fake participant and
writes two files to mocks/keys/ (test keys only, never real ones):
  private.json   every mock key, including private keys; the mock registry serves
                 the public parts of this
  registry.json  "subscriber_id|unique_key_id" -> public key, in the format of the
                 debugger's local key file (ONDC_KEYS), if you'd rather not use a registry

mock-seller-a also has an old key, k0, that expired a year ago, for testing the
"still signing with a retired key" bug.
"""

import json
import os
from datetime import datetime, timedelta, timezone

from debugger.signing import generate_keypair

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE = os.path.join(KEY_DIR, "private.json")
REGISTRY = os.path.join(KEY_DIR, "registry.json")

# (subscriber_id, unique_key_id, type, retired?)
PARTICIPANTS = [
    ("mock-buyer.example", "k1", "buyerApp", False),
    ("mock-seller-a.example", "k1", "sellerApp", False),
    ("mock-seller-a.example", "k0", "sellerApp", True),
    ("mock-seller-b.example", "k1", "sellerApp", False),
    ("mock-gateway.example", "g1", "gateway", False),
]


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ensure() -> dict:
    keys = {}
    if os.path.exists(PRIVATE):
        with open(PRIVATE) as f:
            keys = json.load(f)
        if any("|" not in k for k in keys):  # file from an older version of this tool
            keys = {}
    changed = False
    now = datetime.now(timezone.utc)
    for subscriber, key_id, kind, retired in PARTICIPANTS:
        name = f"{subscriber}|{key_id}"
        if name in keys:
            continue
        priv, pub = generate_keypair()
        start, end = (now - timedelta(days=730), now - timedelta(days=365)) if retired \
            else (now - timedelta(days=30), now + timedelta(days=365))
        keys[name] = {"subscriber_id": subscriber, "unique_key_id": key_id, "type": kind,
                      "private_key": priv, "public_key": pub,
                      "valid_from": _iso(start), "valid_until": _iso(end)}
        changed = True
    if changed:
        os.makedirs(KEY_DIR, exist_ok=True)
        with open(PRIVATE, "w") as f:
            json.dump(keys, f, indent=2)
        with open(REGISTRY, "w") as f:
            json.dump({k: v["public_key"] for k, v in keys.items()}, f, indent=2)
    return keys


def identity(subscriber_id: str, key_id: str | None = None) -> tuple[str, str, str]:
    """(subscriber_id, unique_key_id, private_key) for signing as this participant.
    Without key_id, the participant's current (non-retired) key."""
    keys = _ensure()
    if key_id is None:
        key_id = next(k for s, k, _, retired in PARTICIPANTS if s == subscriber_id and not retired)
    k = keys[f"{subscriber_id}|{key_id}"]
    return subscriber_id, k["unique_key_id"], k["private_key"]


def registry_records() -> list[dict]:
    """Every key, in the format ONDC's registry lookup returns (public parts only)."""
    return [{"subscriber_id": v["subscriber_id"], "ukId": v["unique_key_id"], "type": v["type"],
             "country": "IND", "status": "SUBSCRIBED", "signing_public_key": v["public_key"],
             "valid_from": v["valid_from"], "valid_until": v["valid_until"]}
            for v in _ensure().values()]


if __name__ == "__main__":
    _ensure()
    print(f"keys ready: {PRIVATE}")
