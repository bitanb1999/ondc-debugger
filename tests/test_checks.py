"""Tests for the pairing rules. Run with:  python -m pytest -q"""

import json
from datetime import datetime, timedelta, timezone

from debugger.checks import analyse, parse_ttl

T0 = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)


def row(id, action, message_id, at_seconds, ttl="PT5S", ack="ACK", status=200, drop=()):
    ctx = {
        "domain": "ONDC:RET10", "action": action, "core_version": "1.2.0",
        "bap_id": "b", "bap_uri": "http://b", "bpp_id": "s", "bpp_uri": "http://s",
        "transaction_id": "T1", "message_id": message_id, "timestamp": "x", "ttl": ttl,
    }
    for f in drop:
        ctx.pop(f, None)
    return {
        "id": id, "side": "bap" if action.startswith("on_") else "bpp",
        "action": action, "message_id": ctx.get("message_id"), "ttl": ttl,
        "received_at": (T0 + timedelta(seconds=at_seconds)).isoformat(),
        "body": json.dumps({"context": ctx, "message": {}}), "body_is_json": 1,
        "reply_status": status, "ack": ack, "reply": "{}",
    }


def codes(exchanges):
    return [[i.code for i in e.issues] for e in exchanges]


def test_parse_ttl():
    assert parse_ttl("PT30S") == timedelta(seconds=30)
    assert parse_ttl("PT1H30M") == timedelta(hours=1, minutes=30)
    assert parse_ttl("P1D") == timedelta(days=1)
    assert parse_ttl("30 seconds") is None
    assert parse_ttl("P") is None


def test_healthy_pair():
    ex = analyse([row(1, "select", "m1", 0), row(2, "on_select", "m1", 1)], now=T0 + timedelta(minutes=1))
    assert codes(ex) == [[]]
    assert ex[0].latency == timedelta(seconds=1)


def test_late_callback():
    ex = analyse([row(1, "select", "m1", 0), row(2, "on_select", "m1", 7)], now=T0 + timedelta(minutes=1))
    assert codes(ex) == [["late_callback"]]


def test_missing_vs_waiting():
    rows = [row(1, "init", "m1", 0)]
    assert codes(analyse(rows, now=T0 + timedelta(seconds=2))) == [["waiting"]]
    assert codes(analyse(rows, now=T0 + timedelta(seconds=9))) == [["missing_callback"]]


def test_callback_without_message_id_is_orphan_and_request_is_missing():
    rows = [row(1, "init", "m1", 0), row(2, "on_init", "m1", 1, drop=["message_id"])]
    ex = analyse(rows, now=T0 + timedelta(minutes=1))
    assert codes(ex) == [["missing_callback"], ["orphan_callback", "missing_field"]]


def test_nack_is_flagged_and_not_expected_to_get_a_callback():
    ex = analyse([row(1, "confirm", "m1", 0, ack="NACK")], now=T0 + timedelta(minutes=1))
    assert codes(ex) == [["nack"]]


def test_action_mismatch():
    r = row(1, "select", "m1", 0)
    body = json.loads(r["body"]); body["context"]["action"] = "init"; r["body"] = json.dumps(body)
    ex = analyse([r, row(2, "on_select", "m1", 1)], now=T0 + timedelta(minutes=1))
    assert "action_mismatch" in codes(ex)[0]


# ---- whole-purchase checks ------------------------------------------------
from debugger.checks import transaction_issues  # noqa: E402


def flow(*steps):
    """steps: (action, request_at, callback_at or None) -> saved rows."""
    rows, n = [], 0
    for action, req_at, cb_at in steps:
        n += 1; rows.append(row(n, action, f"m{n}", req_at))
        if cb_at is not None:
            n += 1; rows.append(row(n, "on_" + action, f"m{n - 1}", cb_at))
    return rows


def txn_codes(rows, after_seconds):
    now = T0 + timedelta(seconds=after_seconds)
    return [i.code for i in transaction_issues(analyse(rows, now=now), now=now)]


def test_complete_purchase_has_no_purchase_issues():
    rows = flow(("search", 0, 1), ("select", 2, 3), ("init", 4, 5), ("confirm", 6, 7))
    assert txn_codes(rows, 600) == []


def test_stopped_partway_only_after_idle_period():
    rows = flow(("search", 0, 1), ("select", 2, 3))
    assert txn_codes(rows, 10) == []                    # still might continue
    assert txn_codes(rows, 120) == ["stopped_partway"]  # idle for 117s


def test_out_of_order_when_init_sent_before_on_select():
    rows = flow(("search", 0, 1), ("select", 2, 5), ("init", 3, 6), ("confirm", 7, 8))
    assert txn_codes(rows, 600) == ["out_of_order"]


def test_skipped_step():
    rows = flow(("search", 0, 1), ("init", 2, 3), ("confirm", 4, 5))
    assert txn_codes(rows, 600) == ["skipped_step"]


# ---- gateway: one search, forwarded to several sellers ----------------------

def bpp_says(r, bpp_id):
    body = json.loads(r["body"]); body["context"]["bpp_id"] = bpp_id; r["body"] = json.dumps(body)
    return r


def test_gateway_fanout_groups_forwards_and_callbacks():
    original = row(1, "search", "m1", 0); original["side"] = "gateway"
    to_a = row(2, "search", "m1", 0.1); to_a["side"] = "bpp"
    to_b = row(3, "search", "m1", 0.1); to_b["side"] = "bpp2"
    answer_a = bpp_says(row(4, "on_search", "m1", 1), "seller-a")
    answer_b = bpp_says(row(5, "on_search", "m1", 2), "seller-b")
    ex = analyse([original, to_a, to_b, answer_a, answer_b], now=T0 + timedelta(minutes=1))
    assert len(ex) == 1 and len(ex[0].forwards) == 2 and len(ex[0].callbacks) == 2
    assert codes(ex) == [[]]


def test_silent_seller_is_reported():
    original = row(1, "search", "m1", 0); original["side"] = "gateway"
    to_a = row(2, "search", "m1", 0.1); to_a["side"] = "bpp"
    to_b = row(3, "search", "m1", 0.1); to_b["side"] = "bpp2"
    answer_a = bpp_says(row(4, "on_search", "m1", 1), "seller-a")
    ex = analyse([original, to_a, to_b, answer_a], now=T0 + timedelta(minutes=1))
    assert codes(ex) == [["seller_no_response"]]
    assert "only 1 answered (seller-a)" in ex[0].issues[0].detail


def test_two_answers_to_one_select():
    rows = [row(1, "select", "m1", 0), row(2, "on_select", "m1", 1), row(3, "on_select", "m1", 2)]
    assert codes(analyse(rows, now=T0 + timedelta(minutes=1))) == [["duplicate_callback"]]
