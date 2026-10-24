"""
Plays the shopper: runs one full purchase, search -> select -> init -> confirm,
signing every request as the mock buyer app.

Usage:
    python -m mocks.run_flow                  # talk to seller A directly
    python -m mocks.run_flow --via-debugger   # route everything through the debugger
    python -m mocks.run_flow --via-gateway    # also send search through the gateway
                                              # (broadcast to every seller); implies --via-debugger
    python -m mocks.run_flow --stop-after select   # walk away partway through

Every message in one purchase shares the same transaction_id; each
request/callback pair shares its own message_id. Those two IDs are what
the debugger uses to stitch the conversation back together.
"""

import argparse
import time
import uuid
from datetime import datetime, timezone

import httpx

from mocks.keys import identity
from mocks.send import encode, headers_for

parser = argparse.ArgumentParser()
parser.add_argument("--via-debugger", action="store_true")
parser.add_argument("--via-gateway", action="store_true")
parser.add_argument("--stop-after", choices=["search", "select", "init"])
parser.add_argument("--faults", default="",
                    help='bugs for the mock sellers to simulate, e.g. "select:late,search:missing@mock-seller-b"')
parser.add_argument("--early", choices=["init"], help="send this step before the previous answer arrives")
args = parser.parse_args()

if args.via_debugger or args.via_gateway:
    BPP_URI = "http://localhost:8000/bpp"          # seller A, through the debugger
    BAP_URI = "http://localhost:8000/bap"          # callbacks come back through the debugger
    GATEWAY = "http://localhost:8000/gateway"
else:
    BPP_URI, BAP_URI, GATEWAY = "http://localhost:8002", "http://localhost:8001", None

ME = identity("mock-buyer.example")
transaction_id = str(uuid.uuid4())


def context(action: str, broadcast: bool = False) -> dict:
    ctx = {
        "domain": "ONDC:RET10",          # retail, grocery
        "action": action,
        "core_version": "1.2.0",
        "bap_id": ME[0],
        "bap_uri": BAP_URI,              # where callbacks must be sent
        "bpp_id": "mock-seller-a.example",
        "bpp_uri": BPP_URI,
        "transaction_id": transaction_id,
        "message_id": str(uuid.uuid4()),
        "city": "std:033",               # Kolkata's STD code
        "country": "IND",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "ttl": "PT5S",                   # the callback must arrive within 5 seconds
    }
    if broadcast:  # a search via the gateway goes to every seller, so it names none
        del ctx["bpp_id"], ctx["bpp_uri"]
    return ctx


order = {"provider": {"id": "P1"}, "items": [{"id": "I1", "quantity": {"count": 1}}]}
steps = [
    ("search", {"intent": {"item": {"descriptor": {"name": "dal"}}}}),
    ("select", {"order": order}),
    ("init", {"order": order}),
    ("confirm", {"order": order}),
]

print(f"transaction_id = {transaction_id}")
with httpx.Client(timeout=10) as client:
    for action, message in steps:
        via_gateway = action == "search" and args.via_gateway
        body = encode({"context": context(action, broadcast=via_gateway), "message": message})
        url = f"{GATEWAY if via_gateway else BPP_URI}/{action}"
        headers = headers_for(body, ME)
        if args.faults:
            headers["X-Mock-Faults"] = args.faults
        reply = client.post(url, content=body, headers=headers)
        status = reply.json().get("message", {}).get("ack", {}).get("status", reply.status_code)
        print(f"[shopper] /{action:<8} -> {status}{'  (via gateway)' if via_gateway else ''}")
        if action == args.stop_after:
            print(f"[shopper] walking away after {action}")
            break
        next_step = steps[[s[0] for s in steps].index(action) + 1][0] if action != "confirm" else None
        if next_step != args.early:
            time.sleep(2)  # give the sellers time to send their callbacks

print("done")
