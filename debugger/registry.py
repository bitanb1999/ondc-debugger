"""
Where the debugger gets public keys for checking signatures.

Two sources, tried in this order:
  1. A local JSON file (ONDC_KEYS): {"subscriber_id|unique_key_id": "base64 public key"}.
     Useful for test keys, or to override the registry.
  2. The ONDC registry's lookup API (ONDC_REGISTRY), the same place real ONDC
     apps get each other's keys.

How the registry lookup works (from ONDC's developer docs and ONDC's own
buyer-app code, biap-client-node-js):
  POST https://preprod.registry.ondc.org/v2.0/lookup
       {"subscriber_id": "seller.example.com", "country": "IND"}
  The request must carry an Authorization header signed with YOUR OWN
  registered key (same format as normal ONDC messages), so set
  ONDC_SUBSCRIBER_ID, ONDC_UNIQUE_KEY_ID and ONDC_PRIVATE_KEY.
  The reply is a list of records; each has "ukId" and "signing_public_key"
  (plus valid_from, valid_until, status, ...).

Results are cached so a page that refreshes every 3 seconds doesn't hammer
the registry: found keys for an hour, "not found" for 5 minutes, failures for
1 minute. A failure to ask is reported differently from "not registered".

Try a lookup from the command line:
    python -m debugger.registry seller.example.com [unique_key_id]
"""

import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime

import httpx

REGISTRIES = {  # shortcuts for ONDC_REGISTRY
    "preprod": "https://preprod.registry.ondc.org/v2.0/lookup",
    "prod": "https://prod.registry.ondc.org/v2.0/lookup",
    # The older, deprecated endpoints (no Authorization header):
    "preprod-legacy": "https://preprod.registry.ondc.org/ondc/lookup",
    "prod-legacy": "https://prod.registry.ondc.org/lookup",
}

# Subscriber ids are domain names. Refuse to send anything else to the registry:
# the keyId comes from untrusted messages.
SUBSCRIBER_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,255}$")


@dataclass
class KeyRecord:
    public_key: str
    source: str                         # "key file" or the registry URL
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    status: str | None = None


@dataclass
class Lookup:
    record: KeyRecord | None = None
    problem: str | None = None          # "unknown_key" or "registry_error"
    detail: str = ""


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class RegistryClient:
    def __init__(self, url: str, caller: tuple[str, str, str] | None = None, *,
                 country: str = "IND", timeout: float = 5.0,
                 ttl: float = 3600, miss_ttl: float = 300, error_ttl: float = 60,
                 transport: httpx.BaseTransport | None = None):
        self.url = REGISTRIES.get(url, url)
        self.signed = self.url.rstrip("/").endswith("/v2.0/lookup")  # v2 needs a signed request
        self.caller = caller
        self.country = country
        self.timeout = timeout
        self.ttl, self.miss_ttl, self.error_ttl = ttl, miss_ttl, error_ttl
        self.transport = transport
        self._cache: dict[str, tuple[float, list | None, str | None]] = {}
        self._lock = threading.Lock()
        self.calls = 0  # how many requests were actually sent (for tests and the page)

    def describe(self) -> str:
        return f"registry {self.url} ({len(self._cache)} subscribers cached)"

    def _fetch(self, subscriber: str) -> tuple[list | None, str | None]:
        """Returns (records, error). records may be an empty list (not registered)."""
        if self.signed and not self.caller:
            return None, ("the registry's /v2.0/lookup needs a signed request: set ONDC_SUBSCRIBER_ID, "
                          "ONDC_UNIQUE_KEY_ID and ONDC_PRIVATE_KEY to your app's registered keys")
        body = json.dumps({"subscriber_id": subscriber, "country": self.country},
                          separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"}
        if self.signed:
            from debugger.signing import make_header  # here, to avoid a circular import
            headers["Authorization"] = make_header(body, *self.caller)
        self.calls += 1
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                reply = client.post(self.url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            return None, f"couldn't reach the registry at {self.url}: {exc}"

        if reply.status_code == 401:
            return None, ("the registry rejected our lookup request (HTTP 401): check that ONDC_SUBSCRIBER_ID "
                          "and its keys are registered in this environment")
        if reply.status_code == 429:
            return None, "the registry is rate-limiting us (HTTP 429)"
        try:
            data = reply.json()
        except ValueError:
            return None, f"the registry replied HTTP {reply.status_code} with something that isn't JSON"
        if reply.status_code == 404 or data == []:
            return [], None
        if reply.status_code != 200 or not isinstance(data, list):
            text = json.dumps(data)[:200]
            return None, f"unexpected registry reply (HTTP {reply.status_code}): {text}"
        return data, None

    def records_for(self, subscriber: str) -> tuple[list | None, str | None]:
        now = time.monotonic()
        cached = self._cache.get(subscriber)
        if cached and cached[0] > now:
            return cached[1], cached[2]
        with self._lock:  # one request at a time, so parallel page loads don't all ask
            cached = self._cache.get(subscriber)
            if cached and cached[0] > time.monotonic():
                return cached[1], cached[2]
            records, error = self._fetch(subscriber)
            ttl = self.error_ttl if error else (self.ttl if records else self.miss_ttl)
            self._cache[subscriber] = (time.monotonic() + ttl, records, error)
            return records, error

    def lookup(self, subscriber: str, key_id: str) -> Lookup:
        if not SUBSCRIBER_ID.match(subscriber or ""):
            return Lookup(problem="unknown_key", detail=f"'{subscriber[:60]}' isn't a valid subscriber id")
        records, error = self.records_for(subscriber)
        if error:
            return Lookup(problem="registry_error", detail=error)
        for rec in records:
            if not isinstance(rec, dict):
                continue
            if rec.get("subscriber_id") not in (None, subscriber):
                continue  # registries may return near matches
            rec_key_id = rec.get("ukId") or rec.get("unique_key_id") or rec.get("ukid")
            if str(rec_key_id) != key_id:
                continue
            public_key = rec.get("signing_public_key") or (rec.get("key_pair") or {}).get("signing_public_key")
            if public_key:
                return Lookup(KeyRecord(public_key, self.url, _parse_time(rec.get("valid_from")),
                                        _parse_time(rec.get("valid_until")), rec.get("status")))
        others = sorted({str(r.get("ukId") or r.get("unique_key_id") or r.get("ukid"))
                         for r in records if isinstance(r, dict)})
        if others:
            return Lookup(problem="unknown_key",
                          detail=f"{subscriber} is in the registry, but not with key id {key_id} "
                                 f"(registered key ids: {', '.join(others)})")
        return Lookup(problem="unknown_key", detail=f"{subscriber} isn't in the registry at {self.url}")


class KeyStore:
    """Looks a key up in the local file first, then in the registry."""

    def __init__(self, local: dict | None = None, registry: RegistryClient | None = None):
        self.local = local
        self.registry = registry

    def get(self, subscriber: str, key_id: str) -> Lookup:
        if self.local and f"{subscriber}|{key_id}" in self.local:
            return Lookup(KeyRecord(self.local[f"{subscriber}|{key_id}"], "key file"))
        if self.registry:
            return self.registry.lookup(subscriber, key_id)
        return Lookup(problem="unknown_key", detail=f"no public key registered for {subscriber}|{key_id}")

    def describe(self) -> str:
        parts = []
        if self.local is not None:
            parts.append(f"key file ({len(self.local)} keys)")
        if self.registry:
            parts.append(self.registry.describe())
        return " + ".join(parts)


def _caller_from_env() -> tuple[str, str, str] | None:
    values = [os.environ.get(n) for n in ("ONDC_SUBSCRIBER_ID", "ONDC_UNIQUE_KEY_ID", "ONDC_PRIVATE_KEY")]
    return tuple(values) if all(values) else None


_store: tuple[tuple, KeyStore | None] | None = None


def keystore_from_env() -> KeyStore | None:
    """The key sources configured in the environment, or None if signature checks are off.
    Kept between calls so the registry cache survives page refreshes."""
    global _store
    config = tuple(os.environ.get(n) for n in ("ONDC_KEYS", "ONDC_REGISTRY", "ONDC_SUBSCRIBER_ID",
                                               "ONDC_UNIQUE_KEY_ID", "ONDC_PRIVATE_KEY"))
    if _store and _store[0] == config:
        return _store[1]

    keys_path, registry_url = config[0], config[1]
    local = None
    if keys_path and os.path.exists(keys_path):
        with open(keys_path) as f:
            local = json.load(f)
    registry = RegistryClient(registry_url, _caller_from_env()) if registry_url else None
    store = KeyStore(local, registry) if (local is not None or registry) else None
    _store = (config, store)
    return store


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python -m debugger.registry <subscriber_id> [unique_key_id]   (set ONDC_REGISTRY first)")
    if not os.environ.get("ONDC_REGISTRY"):
        sys.exit("set ONDC_REGISTRY to preprod, prod, or a lookup URL")
    client = RegistryClient(os.environ["ONDC_REGISTRY"], _caller_from_env())
    records, error = client.records_for(sys.argv[1])
    if error:
        sys.exit(f"lookup failed: {error}")
    if not records:
        sys.exit(f"{sys.argv[1]} isn't registered at {client.url}")
    for rec in records:
        print(json.dumps({k: rec.get(k) for k in ("subscriber_id", "ukId", "type", "domain", "status",
                                                  "valid_from", "valid_until", "signing_public_key")
                          if k in rec}, indent=2))
    if len(sys.argv) > 2:
        result = client.lookup(sys.argv[1], sys.argv[2])
        if not result.record:
            print(f"not found: {result.detail}")
        elif result.record.valid_until and result.record.valid_until.timestamp() < time.time():
            print(f"key found, but it expired on {result.record.valid_until.isoformat(timespec='seconds')}")
        else:
            print("key found and currently valid")
