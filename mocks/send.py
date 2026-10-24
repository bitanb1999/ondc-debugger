"""
Sending a signed ONDC message.

The body is serialised ONCE, signed, and those exact bytes are sent. If you
let your HTTP library serialise the JSON for you after signing (httpx's json=,
requests' json=), it may add spaces and the signature breaks. This is one of
the most common ONDC integration bugs.
"""

import json

import httpx

from debugger.signing import make_header


def encode(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def headers_for(body: bytes, identity: tuple[str, str, str]) -> dict:
    subscriber_id, key_id, private_key = identity
    return {"Content-Type": "application/json",
            "Authorization": make_header(body, subscriber_id, key_id, private_key)}


async def post_signed(url: str, message: dict, identity, *, tamper=False) -> httpx.Response:
    body = encode(message)
    headers = headers_for(body, identity)
    if tamper:  # test fault: change the body AFTER signing, like a buggy proxy would
        body = body.replace(b'"context":{', b'"context":{"tampered":true,', 1)
    async with httpx.AsyncClient(timeout=10) as client:
        return await client.post(url, content=body, headers=headers)
