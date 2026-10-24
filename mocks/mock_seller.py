"""
Mock seller app (a "BPP" in ONDC terms).

What a real seller app does, and what this fake one copies:
  1. Receives a request such as POST /search from a buyer app (or a gateway).
  2. Immediately replies {"message": {"ack": {"status": "ACK"}}}  ("got it").
  3. A little later, makes its OWN signed request back to the buyer app's
     /on_search endpoint with the real answer (the catalog).

Settings (environment variables):
  BPP_ID   who this seller is (default mock-seller-a.example); its key comes from mocks/keys
  BPP_URI  the address it tells buyers to use (default http://localhost:8002)
  FAULTS   test bugs to switch on, e.g. "select:late,confirm:missing,init:bad,search:badsig".
           The same list can also arrive per request in an X-Mock-Faults header; add
           "@<seller name>" to aim a fault at one seller, e.g. "search:missing@mock-seller-b".
      late    callback arrives after the request's ttl
      missing callback is never sent
      bad     callback is sent without context.message_id
      badsig  callback body is changed after signing (signature won't verify)
      badtype callback's context.timestamp is a unix number, not the date-time string the spec requires
      oldkey  callback is signed with the seller's retired key k0 (mock-seller-a only)
"""

import asyncio
import os
import uuid
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, Request

from mocks.keys import identity
from mocks.send import post_signed

BPP_ID = os.environ.get("BPP_ID", "mock-seller-a.example")
BPP_URI = os.environ.get("BPP_URI", "http://localhost:8002")
ME = identity(BPP_ID)
NAME = BPP_ID.split(".")[0]

def parse_faults(text: str) -> dict:
    """'select:late,search:missing@mock-seller-b' -> faults that apply to THIS seller."""
    faults = {}
    for item in (text or "").split(","):
        item, _, target = item.strip().partition("@")
        if ":" in item and (not target or target == NAME):
            action, fault = item.split(":", 1)
            faults[action] = fault
    return faults


FAULTS = parse_faults(os.environ.get("FAULTS", ""))

app = FastAPI(title=f"Mock ONDC seller ({BPP_ID})")

ACK = {"message": {"ack": {"status": "ACK"}}}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def catalog() -> dict:
    return {
        "catalog": {
            "bpp/descriptor": {"name": f"{NAME} store"},
            "bpp/providers": [
                {
                    "id": "P1",
                    "descriptor": {"name": f"{NAME}, Kolkata"},
                    "items": [
                        {"id": "I1", "descriptor": {"name": "Toor dal 1kg"},
                         "price": {"currency": "INR", "value": "160.00"}},
                        {"id": "I2", "descriptor": {"name": "Basmati rice 5kg"},
                         "price": {"currency": "INR", "value": "540.00"}},
                    ],
                }
            ],
        }
    }


def build_answer(action: str, request_message: dict) -> dict:
    """The 'message' part of each on_ callback. Kept minimal on purpose."""
    if action == "search":
        return catalog()
    order = request_message.get("order", {})
    if action == "select":
        return {"order": {**order, "quote": {"price": {"currency": "INR", "value": "160.00"}}}}
    if action == "init":
        return {"order": {**order, "payment": {"type": "ON-ORDER", "status": "NOT-PAID"}}}
    if action == "confirm":
        return {"order": {**order, "id": "ORDER-" + uuid.uuid4().hex[:6].upper(), "state": "Accepted"}}
    return {}


async def send_callback(action: str, body: dict, faults: dict) -> None:
    fault = faults.get(action)
    if fault == "missing":
        print(f"[{NAME}] FAULT: not sending on_{action}")
        return

    await asyncio.sleep(1)  # a real seller needs a moment to look up stock and prices
    if fault == "late":
        print(f"[{NAME}] FAULT: delaying on_{action} past its ttl")
        await asyncio.sleep(6)  # the buyer uses a 5-second ttl

    context = dict(body["context"])  # same transaction_id and message_id
    context.update({"action": f"on_{action}", "bpp_id": BPP_ID, "bpp_uri": BPP_URI, "timestamp": now_iso()})
    if fault == "bad":
        print(f"[{NAME}] FAULT: removing message_id from on_{action}")
        context.pop("message_id", None)
    if fault == "badtype":
        print(f"[{NAME}] FAULT: sending on_{action} with a numeric timestamp")
        context["timestamp"] = int(datetime.now(timezone.utc).timestamp())

    callback = {"context": context, "message": build_answer(action, body.get("message", {}))}
    url = f"{body['context']['bap_uri'].rstrip('/')}/on_{action}"
    signer = ME
    if fault == "oldkey":
        print(f"[{NAME}] FAULT: signing on_{action} with retired key k0")
        signer = identity(BPP_ID, "k0")
    reply = await post_signed(url, callback, signer, tamper=fault == "badsig")
    print(f"[{NAME}] sent on_{action} -> {url}  buyer replied {reply.status_code}")


@app.post("/{action}")
async def receive(action: str, request: Request, background: BackgroundTasks):
    body = await request.json()
    print(f"[{NAME}] got /{action}  transaction_id={body['context'].get('transaction_id')}")
    faults = {**FAULTS, **parse_faults(request.headers.get("x-mock-faults", ""))}
    # Answer "ACK" right away, then do the real work in the background.
    background.add_task(send_callback, action, body, faults)
    return ACK
