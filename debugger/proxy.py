"""
ONDC debugger: the recording proxy.

It sits between ONDC apps and forwards every message unchanged:

    buyer   --->  debugger /gateway/search  --->  gateway
    gateway --->  debugger /bpp/search      --->  seller
    buyer   --->  debugger /bpp/<action>    --->  seller
    seller  --->  debugger /bap/<action>    --->  buyer

Each name before the action ("bap", "bpp", "gateway", ...) is a route you
configure. It saves a copy of every message, its signature headers, the reply,
and how long the receiver took, to a SQLite database.

Configure routes with ROUTES (comma-separated name=url pairs):
    ROUTES="bap=http://localhost:8001,bpp=http://localhost:8002" \
        uvicorn debugger.proxy:app --port 8000
BAP_TARGET / BPP_TARGET still work as shortcuts for the "bap" and "bpp" routes.
"""

import json
import os
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request, Response

from debugger import store
from debugger.ui import router as ui_router


def load_routes() -> dict[str, str]:
    routes = {
        "bap": os.environ.get("BAP_TARGET", "http://localhost:8001"),  # the buyer app
        "bpp": os.environ.get("BPP_TARGET", "http://localhost:8002"),  # the seller app
    }
    for pair in os.environ.get("ROUTES", "").split(","):
        if "=" in pair:
            name, url = pair.split("=", 1)
            routes[name.strip()] = url.strip()
    return routes


ROUTES = load_routes()

# Headers that describe the connection itself, not the message. httpx
# recalculates these, so copying them across would cause errors.
SKIP_HEADERS = {"host", "content-length", "connection", "transfer-encoding", "accept-encoding"}

app = FastAPI(title="ONDC transaction debugger")
app.include_router(ui_router)  # the web pages: /, /txn/{id}, /api/transactions/{id}
store.init()


@app.post("/{route}/{action}")
async def forward(route: str, action: str, request: Request):
    if route not in ROUTES:
        return Response(status_code=404, content=f"unknown route '{route}'; configured: {', '.join(ROUTES)}")

    raw = await request.body()
    received_at = datetime.now(timezone.utc)

    # Copy the headers we're allowed to pass on. This keeps ONDC's
    # Authorization signature intact, so the receiver can still verify it.
    headers = {k: v for k, v in request.headers.items() if k.lower() not in SKIP_HEADERS}

    url = f"{ROUTES[route].rstrip('/')}/{action}"
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            upstream = await client.post(url, content=raw, headers=headers)
        status, reply = upstream.status_code, upstream.content
    except httpx.HTTPError as exc:
        # The other app is down or unreachable. Record that too: it's a bug worth seeing.
        status, reply = 502, json.dumps({"error": f"debugger could not reach {url}: {exc}"}).encode()
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

    store.save(
        received_at=received_at,
        side=route,
        action=action,
        body=raw,
        reply_status=status,
        reply=reply,
        elapsed_ms=elapsed_ms,
        authorization=request.headers.get("authorization"),
        gateway_authorization=request.headers.get("x-gateway-authorization"),
    )

    # Hand the receiver's reply back to the sender, exactly as it came.
    return Response(content=reply, status_code=status, media_type="application/json")
