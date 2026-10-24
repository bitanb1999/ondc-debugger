"""
Mock ONDC gateway ("BG" in ONDC terms).

Only search goes through a gateway. When a buyer app sends one, the gateway:
  1. checks the buyer's Authorization signature (NACK if it doesn't verify),
  2. replies ACK straight away,
  3. forwards the EXACT same bytes to every seller it knows, keeping the
     buyer's Authorization header and adding its own X-Gateway-Authorization.
Sellers answer with on_search directly to the buyer (bap_uri), not back
through the gateway, which is why one search can produce many on_search.

Settings:
  SELLERS        comma-separated seller base URLs (default http://localhost:8002)
  ONDC_REGISTRY  registry lookup URL used to check the buyer's signature (or ONDC_KEYS: a key file)
"""

import asyncio
import json
import os
import time

import httpx
from fastapi import BackgroundTasks, FastAPI, Request, Response

from debugger.registry import KeyStore, keystore_from_env
from debugger.signing import make_header, verify
from mocks.keys import identity

SELLERS = [s.strip() for s in os.environ.get("SELLERS", "http://localhost:8002").split(",") if s.strip()]
ME = identity("mock-gateway.example")
# Like a real gateway, it checks the buyer's signature with keys from the
# registry (ONDC_REGISTRY) or a key file (ONDC_KEYS). Signs its own lookups as itself.
os.environ.setdefault("ONDC_SUBSCRIBER_ID", ME[0])
os.environ.setdefault("ONDC_UNIQUE_KEY_ID", ME[1])
os.environ.setdefault("ONDC_PRIVATE_KEY", ME[2])

app = FastAPI(title="Mock ONDC gateway")

ACK = {"message": {"ack": {"status": "ACK"}}}


async def broadcast(body: bytes, authorization: str, mock_faults: str | None) -> None:
    subscriber_id, key_id, private_key = ME
    headers = {"Content-Type": "application/json",
               "Authorization": authorization,  # the buyer's signature, untouched
               "X-Gateway-Authorization": make_header(body, subscriber_id, key_id, private_key)}
    if mock_faults:  # test-only header telling the mock sellers which bugs to simulate
        headers["X-Mock-Faults"] = mock_faults
    async with httpx.AsyncClient(timeout=10) as client:
        replies = await asyncio.gather(*(client.post(f"{s.rstrip('/')}/search", content=body, headers=headers)
                                         for s in SELLERS), return_exceptions=True)
    for seller, reply in zip(SELLERS, replies):
        status = reply.status_code if isinstance(reply, httpx.Response) else f"failed: {reply}"
        print(f"[gateway] forwarded search -> {seller}  {status}")


@app.post("/search")
async def search(request: Request, background: BackgroundTasks):
    body = await request.body()
    authorization = request.headers.get("authorization")
    ctx = json.loads(body).get("context", {})

    problems = verify(authorization, body, keystore_from_env() or KeyStore(), time.time(), ctx.get("bap_id"))
    if problems:
        print(f"[gateway] rejected search: {problems[0].detail}")
        nack = {"message": {"ack": {"status": "NACK"}},
                "error": {"type": "POLICY-ERROR", "code": "10001", "message": problems[0].detail}}
        return Response(json.dumps(nack), status_code=401, media_type="application/json")

    background.add_task(broadcast, body, authorization, request.headers.get("x-mock-faults"))
    return ACK
