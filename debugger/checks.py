"""
ONDC debugger: automatic checks.

Takes the saved messages of one transaction and groups them into "exchanges":
one request (e.g. select), any copies a gateway forwarded to sellers, and the
callbacks (on_select) that answered it, all linked by message_id. Then it
flags what went wrong.

Per message
  invalid_json        the body isn't valid JSON at all
  missing_field       a required context field is absent
  action_mismatch     context.action disagrees with the URL it was sent to
  spec_violation      breaks the official ONDC schema for its core_version
  nack / http_error   the receiver rejected it, or couldn't be reached
  missing_signature, bad_signature_header, signer_mismatch, signature_time,
  unknown_key, key_validity, signature_invalid, registry_error
                      problems with the Authorization / X-Gateway-Authorization headers
                      (keys come from a local file and/or the ONDC registry; see registry.py)

Per exchange
  missing_callback    request ACKed, but no callback arrived within the ttl
  waiting             no callback yet, but the ttl hasn't expired (not a bug yet)
  late_callback       a callback arrived after the request's ttl had expired
  seller_no_response  a gateway sent the search to several sellers; some never answered
  duplicate_callback  more than one callback for a request that should get one
  orphan_callback     a callback that matches no request

Per purchase
  stopped_partway, skipped_step, out_of_order
"""

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from debugger import registry, signing, spec

# Fields every message's context should carry. Callbacks must also say which
# seller they came from. This runs alongside the official spec check, because
# some spec versions don't require these (2.0.2 doesn't require transaction_id).
REQUIRED_CONTEXT = ["domain", "action", "core_version", "bap_id", "bap_uri",
                    "transaction_id", "message_id", "timestamp"]
REQUIRED_IN_CALLBACKS = ["bpp_id", "bpp_uri"]

DEFAULT_TTL = timedelta(seconds=30)  # used when a request carries no ttl

# The order a retail purchase goes through. (status, track, cancel and update
# happen after an order exists, so they aren't part of this sequence.)
FLOW = ["search", "select", "init", "confirm"]

# Actions that may legitimately get several callbacks (one per seller).
BROADCAST = {"search"}

# How long a purchase can sit idle before we call it "stopped partway".
STALL_AFTER = timedelta(seconds=float(os.environ.get("STALL_AFTER_SECONDS", "60")))

# The proxy route name the gateway is reached through.
GATEWAY_ROUTE = os.environ.get("GATEWAY_ROUTE", "gateway")

SEVERITY = {  # how bad each problem is, for colouring the page
    "invalid_json": "error", "missing_field": "error", "action_mismatch": "error",
    "spec_violation": "error", "nack": "error", "http_error": "error",
    "missing_signature": "error", "bad_signature_header": "error", "signer_mismatch": "error",
    "signature_time": "error", "signature_invalid": "error",
    "unknown_key": "warning",          # not in your key file, or not in the registry
    "registry_error": "warning",       # couldn't ask the registry, so the signature wasn't checked
    "key_validity": "error",           # signed with a key the registry says has expired
    "missing_callback": "error", "late_callback": "error", "orphan_callback": "error",
    "seller_no_response": "warning",   # in ONDC a seller with nothing to offer may stay silent
    "duplicate_callback": "warning",
    "waiting": "info",
    # Whole-purchase checks. Warnings, because a shopper may simply walk away.
    "stopped_partway": "warning", "skipped_step": "warning", "out_of_order": "warning",
}


@dataclass
class Issue:
    code: str
    detail: str

    @property
    def severity(self) -> str:
        return SEVERITY.get(self.code, "warning")


@dataclass
class Exchange:
    action: str                        # the request's action, e.g. "select"
    message_id: str | None
    request: dict | None = None        # the request as first seen
    forwards: list = field(default_factory=list)   # copies a gateway forwarded to sellers
    callbacks: list = field(default_factory=list)  # every on_<action> that answered it
    ttl: timedelta = DEFAULT_TTL
    issues: list[Issue] = field(default_factory=list)

    @property
    def callback(self) -> dict | None:
        return self.callbacks[0] if self.callbacks else None

    def latency_of(self, callback: dict) -> timedelta | None:
        return _when(callback) - _when(self.request) if self.request else None

    @property
    def latency(self) -> timedelta | None:
        return self.latency_of(self.callback) if self.callback else None

    @property
    def ok(self) -> bool:
        return not any(i.severity == "error" for i in self.issues)


def parse_ttl(value: str | None) -> timedelta | None:
    """Parse an ISO 8601 duration such as 'PT30S', 'PT1M', 'P1D' or 'PT1H30M'."""
    if not value:
        return None
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?", value)
    if not m or not any(m.groups()):
        return None
    d, h, mi, s = m.groups()
    return timedelta(days=int(d or 0), hours=int(h or 0), minutes=int(mi or 0), seconds=float(s or 0))


def _when(row: dict) -> datetime:
    return datetime.fromisoformat(row["received_at"])


def _signature_issues(row: dict, ctx: dict, keys, via_gateway: bool) -> list[Issue]:
    """Check the sender's signature, and the gateway's when the message came through one."""
    body = row.get("body_raw")
    body = bytes(body) if body is not None else row["body"].encode("utf-8")
    seen = row.get("seen_at_unix") or _when(row).timestamp()
    name = row["action"]
    sender = ctx.get("bpp_id") if name.startswith("on_") else ctx.get("bap_id")

    problems = signing.verify(row.get("authorization"), body, keys, seen, sender, "Authorization")
    if via_gateway:  # a forwarded search must also carry the gateway's own signature
        problems += signing.verify(row.get("gateway_authorization"), body, keys, seen, None,
                                   "X-Gateway-Authorization")
    return [Issue(p.code, f"/{name}: {p.detail}") for p in problems]


def _message_issues(row: dict, keys, via_gateway: bool = False) -> list[Issue]:
    """Problems visible from a single message, before any pairing."""
    if not row["body_is_json"]:
        return [Issue("invalid_json", f"/{row['action']} body is not valid JSON")]

    issues = []
    payload = json.loads(row["body"])
    ctx = payload.get("context") or {} if isinstance(payload, dict) else {}

    required = REQUIRED_CONTEXT + (REQUIRED_IN_CALLBACKS if row["action"].startswith("on_") else [])
    missing = [f for f in required if not ctx.get(f)]
    if missing:
        issues.append(Issue("missing_field", f"/{row['action']} context is missing: {', '.join(missing)}"))

    if ctx.get("action") and ctx["action"] != row["action"]:
        issues.append(Issue("action_mismatch",
                            f"sent to /{row['action']} but context.action is '{ctx['action']}'"))

    # Official spec for this message's version, if one is downloaded.
    s = spec.spec_for(ctx.get("core_version"))
    result = s.check(row["action"], payload) if s else None
    if result:
        already = {f"context: '{f}' is a required property" for f in missing}  # don't repeat ourselves
        for problem in result[0]:
            if problem not in already:
                issues.append(Issue("spec_violation", f"/{row['action']} vs ONDC spec {s.version}: {problem}"))

    if row["reply_status"] != 200:
        issues.append(Issue("http_error", f"/{row['action']} got HTTP {row['reply_status']}"))
    elif row["ack"] == "NACK":
        issues.append(Issue("nack", f"/{row['action']} was rejected (NACK): {row['reply'][:200]}"))

    if keys is not None:  # signature checks are on once a key file or registry is configured
        issues += _signature_issues(row, ctx, keys, via_gateway)
    return issues


def analyse(rows: list, now: datetime | None = None, keys=...) -> list[Exchange]:
    """Turn one transaction's saved messages into checked exchanges, in time order."""
    now = now or datetime.now(timezone.utc)
    if keys is ...:  # default: the key file / registry configured in the environment
        keys = registry.keystore_from_env()
    rows = sorted((dict(r) for r in rows), key=_when)
    requests = [r for r in rows if not r["action"].startswith("on_")]
    callbacks = [r for r in rows if r["action"].startswith("on_")]

    # 1. Group requests: the first copy of (action, message_id) is the request;
    #    later copies of the same message are a gateway's forwards to sellers.
    exchanges: list[Exchange] = []
    by_key: dict[tuple, Exchange] = {}
    for req in requests:
        key = (req["action"], req["message_id"]) if req["message_id"] else (req["action"], f"row{req['id']}")
        if key in by_key:
            by_key[key].forwards.append(req)
            continue
        ex = Exchange(action=req["action"], message_id=req["message_id"], request=req)
        ex.ttl = parse_ttl(req["ttl"]) or DEFAULT_TTL
        ex.issues += _message_issues(req, keys)
        by_key[key] = ex
        exchanges.append(ex)

    for ex in exchanges:
        via_gateway = ex.request["side"] == GATEWAY_ROUTE
        for fwd in ex.forwards:
            ex.issues += _message_issues(fwd, keys, via_gateway=via_gateway)

    # 2. Attach callbacks by message_id.
    used = set()
    for ex in exchanges:
        for cb in callbacks:
            if (cb["id"] not in used and cb["message_id"] and cb["message_id"] == ex.message_id
                    and cb["action"] == "on_" + ex.action):
                used.add(cb["id"])
                ex.callbacks.append(cb)

    # 3. Judge each exchange.
    for ex in exchanges:
        for cb in ex.callbacks:
            ex.issues += _message_issues(cb, keys)
            took = ex.latency_of(cb)
            if took > ex.ttl:
                who = json.loads(cb["body"]).get("context", {}).get("bpp_id") if cb["body_is_json"] else None
                ex.issues.append(Issue("late_callback",
                    f"on_{ex.action}{' from ' + who if who else ''} arrived after "
                    f"{took.total_seconds():.1f}s; ttl was {ex.ttl.total_seconds():.0f}s"))

        expired = now - _when(ex.request) > ex.ttl
        if ex.request["ack"] != "ACK":
            pass  # a rejected request isn't expected to get a callback
        elif not ex.callbacks:
            waited = (now - _when(ex.request)).total_seconds()
            if expired:
                ex.issues.append(Issue("missing_callback",
                    f"no on_{ex.action} after {waited:.0f}s (ttl {ex.ttl.total_seconds():.0f}s)"))
            else:
                ex.issues.append(Issue("waiting", f"waiting for on_{ex.action}"))
        elif ex.forwards and expired:
            reached = [f for f in ex.forwards if f["ack"] == "ACK"]
            if len(ex.callbacks) < len(reached):
                answered = sorted({json.loads(c["body"]).get("context", {}).get("bpp_id") or "?"
                                   for c in ex.callbacks if c["body_is_json"]})
                ex.issues.append(Issue("seller_no_response",
                    f"the gateway delivered {ex.action} to {len(reached)} sellers "
                    f"(via {', '.join(f['side'] for f in reached)}); only {len(ex.callbacks)} answered "
                    f"({', '.join(answered)})"))
        if len(ex.callbacks) > 1 and ex.action not in BROADCAST:
            ex.issues.append(Issue("duplicate_callback",
                f"{len(ex.callbacks)} on_{ex.action} callbacks for one {ex.action}"))

    # 4. Callbacks nobody asked for, or that lost their message_id on the way.
    for cb in callbacks:
        if cb["id"] in used:
            continue
        ex = Exchange(action=cb["action"], message_id=cb["message_id"], callbacks=[cb])
        reason = ("it has no message_id" if not cb["message_id"]
                  else f"no {cb['action'][3:]} request has message_id {cb['message_id']}")
        ex.issues.append(Issue("orphan_callback", f"{cb['action']} can't be matched: {reason}"))
        ex.issues += _message_issues(cb, keys)
        exchanges.append(ex)

    exchanges.sort(key=lambda e: _when(e.request or e.callback))
    return exchanges


def transaction_issues(exchanges: list[Exchange], now: datetime | None = None) -> list[Issue]:
    """Checks on the purchase as a whole: did it run in order, and did it finish?"""
    now = now or datetime.now(timezone.utc)
    steps = [e for e in exchanges if e.request and e.action in FLOW]
    if not steps:
        return []
    issues = []

    # 1. Order. Each step needs the previous step's answer before it is sent:
    #    you can't ask for payment terms (init) for a quote (on_select) you never got.
    for ex in steps:
        i = FLOW.index(ex.action)
        if i == 0:
            continue
        prev = FLOW[i - 1]
        sent_at = _when(ex.request)
        earlier = [p for p in steps if p.action == prev and _when(p.request) < sent_at]
        if not earlier:
            issues.append(Issue("skipped_step", f"{ex.action} was sent without a {prev} before it"))
        elif not any(_when(c) <= sent_at for c in earlier[-1].callbacks):
            issues.append(Issue("out_of_order", f"{ex.action} was sent before on_{prev} arrived"))

    # 2. Did it finish? If the furthest step is before confirm and nothing has
    #    happened for a while, the purchase stopped partway.
    furthest = max(FLOW.index(e.action) for e in steps)
    if furthest < len(FLOW) - 1:
        last_activity = max(_when(r) for e in exchanges
                            for r in [e.request, *e.forwards, *e.callbacks] if r)
        idle = now - last_activity
        if idle > STALL_AFTER:
            answered = [FLOW.index(e.action) for e in steps if e.callbacks]
            reached = f"on_{FLOW[max(answered)]}" if answered else f"{FLOW[furthest]} (unanswered)"
            issues.append(Issue("stopped_partway",
                f"no activity for {idle.total_seconds():.0f}s: the purchase reached {reached} "
                f"but never sent {FLOW[furthest + 1]}"))
    return issues
