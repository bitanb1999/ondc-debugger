"""Registry lookup tests. A fake registry answers in-process, so no network is needed."""

import json
import time

import httpx

from debugger import signing
from debugger.registry import KeyStore, RegistryClient

URL = "https://registry.test/v2.0/lookup"

CALLER_PRIV, CALLER_PUB = signing.generate_keypair()
CALLER = ("my-app.example", "u1", CALLER_PRIV)
SELLER_PRIV, SELLER_PUB = signing.generate_keypair()

RECORDS = {  # what the fake registry knows, in ONDC's response format
    "seller.example": [
        {"subscriber_id": "seller.example", "ukId": "k1", "type": "sellerApp", "status": "SUBSCRIBED",
         "signing_public_key": SELLER_PUB, "valid_from": "2025-01-01T00:00:00.000Z",
         "valid_until": "2030-01-01T00:00:00.000Z"},
        {"subscriber_id": "seller.example", "ukId": "k0", "type": "sellerApp", "status": "SUBSCRIBED",
         "signing_public_key": SELLER_PUB, "valid_from": "2024-01-01T00:00:00.000Z",
         "valid_until": "2025-01-01T00:00:00.000Z"},  # an old, retired key
    ],
}


def fake_registry(status=200, seen=None):
    """A fake /v2.0/lookup that, like the real one, insists on a valid caller signature."""
    def handle(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        problems = signing.verify(request.headers.get("authorization"), request.content,
                                  {"my-app.example|u1": CALLER_PUB}, time.time(), None)
        if problems:
            return httpx.Response(401, json={"error": problems[0].detail})
        if status != 200:
            return httpx.Response(status, json={"error": "boom"})
        body = json.loads(request.content)
        return httpx.Response(200, json=RECORDS.get(body["subscriber_id"], []))
    return httpx.MockTransport(handle)


def client(**kw):
    kw.setdefault("transport", fake_registry())
    return RegistryClient(URL, CALLER, **kw)


def test_finds_key_by_ukId_and_sends_a_signed_request():
    seen = []
    c = client(transport=fake_registry(seen=seen))
    found = c.lookup("seller.example", "k1")
    assert found.record and found.record.public_key == SELLER_PUB
    assert found.record.valid_until.year == 2030
    assert json.loads(seen[0].content) == {"subscriber_id": "seller.example", "country": "IND"}
    assert seen[0].headers["authorization"].startswith('Signature keyId="my-app.example|u1|ed25519"')


def test_unknown_key_id_lists_the_registered_ones():
    found = client().lookup("seller.example", "k9")
    assert found.problem == "unknown_key" and "registered key ids: k0, k1" in found.detail


def test_not_registered():
    found = client().lookup("stranger.example", "k1")
    assert found.problem == "unknown_key" and "isn't in the registry" in found.detail


def test_results_are_cached():
    c = client()
    for _ in range(5):
        c.lookup("seller.example", "k1")
        c.lookup("stranger.example", "k1")   # misses are cached too
    assert c.calls == 2


def test_cache_expires():
    c = client(ttl=0, miss_ttl=0)
    c.lookup("seller.example", "k1"); c.lookup("seller.example", "k1")
    assert c.calls == 2


def test_failures_are_reported_as_registry_errors_not_unknown_keys():
    assert client(transport=fake_registry(status=500)).lookup("seller.example", "k1").problem == "registry_error"

    def down(request):
        raise httpx.ConnectError("connection refused")
    assert client(transport=httpx.MockTransport(down)).lookup("seller.example", "k1").problem == "registry_error"


def test_registry_rejects_a_caller_with_the_wrong_key():
    other_priv, _ = signing.generate_keypair()
    c = RegistryClient(URL, ("my-app.example", "u1", other_priv), transport=fake_registry())
    found = c.lookup("seller.example", "k1")
    assert found.problem == "registry_error" and "401" in found.detail


def test_v2_lookup_without_caller_keys_explains_what_to_set():
    c = RegistryClient(URL, None, transport=fake_registry())
    found = c.lookup("seller.example", "k1")
    assert found.problem == "registry_error" and "ONDC_SUBSCRIBER_ID" in found.detail and c.calls == 0


def test_legacy_lookup_url_sends_no_signature():
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=RECORDS["seller.example"])
    c = RegistryClient("https://registry.test/lookup", None, transport=httpx.MockTransport(handle))
    assert c.lookup("seller.example", "k1").record
    assert "authorization" not in seen[0].headers


def test_junk_subscriber_ids_are_never_sent():
    c = client()
    assert c.lookup("bad id with spaces", "k1").problem == "unknown_key"
    assert c.lookup("x" * 300, "k1").problem == "unknown_key"
    assert c.calls == 0


def test_local_key_file_is_checked_before_the_registry():
    c = client()
    store = KeyStore(local={"seller.example|k1": "LOCALKEY"}, registry=c)
    assert store.get("seller.example", "k1").record.public_key == "LOCALKEY" and c.calls == 0
    assert store.get("seller.example", "k0").record.source == URL


# --- the registry inside signature verification ------------------------------

def signed(body: bytes, key_id: str) -> str:
    return signing.make_header(body, "seller.example", key_id, SELLER_PRIV)


def test_signature_verified_with_registry_key():
    body = b'{"context":{},"message":{}}'
    store = KeyStore(registry=client())
    assert signing.verify(signed(body, "k1"), body, store, time.time(), "seller.example") == []


def test_signing_with_an_expired_registry_key():
    body = b'{"context":{},"message":{}}'
    store = KeyStore(registry=client())
    problems = signing.verify(signed(body, "k0"), body, store, time.time(), "seller.example")
    assert [p.code for p in problems] == ["key_validity"]
    assert "expired on 2025-01-01" in problems[0].detail
