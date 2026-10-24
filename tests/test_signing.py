"""Signature tests, anchored on the worked example in ONDC's developer docs."""

import json

from debugger import signing
from debugger.checks import analyse

# --- ONDC's published example (developer-docs/registry/signing-verification.md)
DOC_BODY = b'{"context":{"domain":"nic2004:60212","country":"IND","city":"Kochi","action":"search","core_version":"0.9.1","bap_id":"bap.stayhalo.in","bap_uri":"https://8f9f-49-207-209-131.ngrok.io/protocol/","transaction_id":"e6d9f908-1d26-4ff3-a6d1-3af3d3721054","message_id":"a2fe6d52-9fe4-4d1a-9d0b-dccb8b48522d","timestamp":"2022-01-04T09:17:55.971Z","ttl":"P1M"},"message":{"intent":{"fulfillment":{"start":{"location":{"gps":"10.108768, 76.347517"}},"end":{"location":{"gps":"10.102997, 76.353480"}}}}}}'
DOC_PRIVATE = "lP3sHA+9gileOkXYJXh4Jg8tK0gEEMbf9yCPnFpbldhrAY+NErqL9WD+Vav7TE5tyVXGXBle9ONZi2W7o144eQ=="
DOC_PUBLIC = "awGPjRK6i/Vg/lWr+0xObclVxlwZXvTjWYtlu6NeOHk="
DOC_DIGEST = "b6lf6lRgOweajukcvcLsagQ2T60+85kRh/Rd2bdS+TG/5ALebOEgDJfyCrre/1+BMu5nA94o4DT3pTFXuUg7sw=="
DOC_SIGNATURE = "cjbhP0PFyrlSCNszJM1F/YmHDVAWsZqJUPzojnE/7TJU3fJ/rmIlgaUHEr5E0/2PIyf0tpSnWtT6cyNNlpmoAQ=="
CREATED, EXPIRES = 1641287875, 1641291475


def test_matches_ondc_documented_example():
    assert signing.digest(DOC_BODY) == DOC_DIGEST
    header = signing.make_header(DOC_BODY, "example-bap.com", "bap1234", DOC_PRIVATE,
                                 created=CREATED, valid_for=EXPIRES - CREATED)
    assert f'signature="{DOC_SIGNATURE}"' in header


def codes(header, body=DOC_BODY, signer="example-bap.com", registry=None, seen=CREATED + 10):
    registry = {"example-bap.com|bap1234": DOC_PUBLIC} if registry is None else registry
    return [p.code for p in signing.verify(header, body, registry, seen, signer)]


def doc_header():
    return signing.make_header(DOC_BODY, "example-bap.com", "bap1234", DOC_PRIVATE,
                               created=CREATED, valid_for=EXPIRES - CREATED)


def test_valid_signature():
    assert codes(doc_header()) == []


def test_tampered_body_fails():
    assert codes(doc_header(), body=DOC_BODY.replace(b"Kochi", b"Delhi")) == ["signature_invalid"]


def test_whitespace_change_fails():
    # Signatures cover exact bytes: re-serialising JSON with spaces breaks them.
    pretty = json.dumps(json.loads(DOC_BODY)).encode()
    assert codes(doc_header(), body=pretty) == ["signature_invalid"]


def test_missing_and_unreadable_headers():
    assert codes(None) == ["missing_signature"]
    assert codes("Bearer abc") == ["bad_signature_header"]


def test_signed_by_someone_else():
    assert codes(doc_header(), signer="another-bap.com") == ["signer_mismatch"]


def test_unknown_key():
    assert codes(doc_header(), registry={}) == ["unknown_key"]


def test_expired_signature():
    assert codes(doc_header(), seen=EXPIRES + 60) == ["signature_time"]


def test_header_wrapped_in_quotes_is_accepted():
    # ONDC's own Python reference code wraps the whole header in quotes.
    assert codes(f'"{doc_header()}"') == []


# --- signatures inside the full analysis, including a gateway hop

def signed_row(id, side, action, body_obj, key, *, gateway_key=None, at=0):
    body = json.dumps(body_obj, separators=(",", ":")).encode()
    sid, kid, priv = key
    row = {
        "id": id, "side": side, "action": action, "message_id": body_obj["context"]["message_id"],
        "ttl": "PT30S", "received_at": f"2026-10-17T12:00:{at:02d}+00:00", "seen_at_unix": None,
        "body": body.decode(), "body_raw": body, "body_is_json": 1,
        "reply_status": 200, "ack": "ACK", "reply": "{}",
        "authorization": signing.make_header(body, sid, kid, priv, created=1792238400 + at - 1),
        "gateway_authorization": None,
    }
    if gateway_key:
        gid, gkid, gpriv = gateway_key
        row["gateway_authorization"] = signing.make_header(body, gid, gkid, gpriv, created=1792238400 + at - 1)
    return row


def test_gateway_forward_needs_both_signatures():
    bap_priv, bap_pub = signing.generate_keypair()
    gw_priv, gw_pub = signing.generate_keypair()
    registry = {"bap.example|k1": bap_pub, "gw.example|g1": gw_pub}
    bap, gw = ("bap.example", "k1", bap_priv), ("gw.example", "g1", gw_priv)
    search = {"context": {"domain": "ONDC:RET10", "action": "search", "core_version": "1.2.0",
                          "bap_id": "bap.example", "bap_uri": "http://b", "transaction_id": "T",
                          "message_id": "M", "timestamp": "x"}, "message": {}}

    good = [signed_row(1, "gateway", "search", search, bap, at=0),
            signed_row(2, "bpp", "search", search, bap, gateway_key=gw, at=1)]
    issues = [i.code for e in analyse(good, keys=registry) for i in e.issues]
    assert not [c for c in issues if "signature" in c], issues

    no_gw_sig = [good[0], signed_row(2, "bpp", "search", search, bap, at=1)]
    issues = [i.code for e in analyse(no_gw_sig, keys=registry) for i in e.issues]
    assert "missing_signature" in issues
