"""
Mock buyer app (a "BAP" in ONDC terms).

It only needs to receive callbacks such as POST /on_search and reply "ACK".
A real buyer app would then show the results to the shopper.
"""

from fastapi import FastAPI, Request

app = FastAPI(title="Mock ONDC buyer (BAP)")

ACK = {"message": {"ack": {"status": "ACK"}}}


@app.post("/{action}")
async def receive_callback(action: str, request: Request):
    body = await request.json()
    ctx = body.get("context", {})
    print(f"[buyer] got /{action}  transaction_id={ctx.get('transaction_id')}")
    return ACK
