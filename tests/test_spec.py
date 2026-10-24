"""Spec validation tests, using a tiny made-up spec so they don't need downloads."""

from debugger.spec import Spec

TINY_SPEC = {
    "openapi": "3.0.0",
    "info": {"version": "9.9.9"},
    "paths": {"/select": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "required": ["context", "message"],
        "properties": {"context": {"$ref": "#/components/schemas/Context"},
                       "message": {"type": "object", "required": ["order"]}}}}}}}}},
    "components": {"schemas": {"Context": {
        "type": "object", "required": ["domain", "message_id"],
        "properties": {"domain": {"type": "string", "enum": ["nic2004:52110"]},  # outdated, like ONDC's
                       "message_id": {"type": "string"}}}}},
    # The official example uses today's domain code, which the outdated enum rejects.
    "x-examples": {"set": {"select": {"examples": [{"value": {
        "context": {"domain": "ONDC:RET10", "action": "select", "message_id": "m1"},
        "message": {"order": {}}}}]}}},
}


def calibrated():
    s = Spec(name="tiny", version="9.9.9", doc=TINY_SPEC)
    s.calibrate()
    return s


def test_rule_broken_by_official_example_is_skipped():
    s = calibrated()
    assert s.examples_checked == 1 and len(s.known_gaps) == 1
    problems, skipped = s.check("select", {"context": {"domain": "ONDC:RET11", "message_id": "m"},
                                           "message": {"order": {}}})
    assert problems == [] and skipped == 1


def test_real_mistakes_are_still_reported():
    s = calibrated()
    problems, _ = s.check("select", {"context": {"domain": "ONDC:RET10", "message_id": 42}, "message": {}})
    assert any("message_id" in p and "string" in p for p in problems)
    assert any("'order' is a required property" in p for p in problems)


def test_unknown_action_is_not_checked():
    assert calibrated().check("on_confirm", {}) is None
