"""
Mock ONDC registry: serves public keys for the mock participants.

Behaves like the real registry's lookup endpoints:
  POST /v2.0/lookup   requires an Authorization header signed by a registered
                      participant (HTTP 401 otherwise); body e.g.
                      {"subscriber_id": "mock-seller-a.example", "country": "IND"}
  POST /lookup        the older endpoint, no signature needed
Both return a JSON list of matching records with ukId, signing_public_key,
valid_from, valid_until, status, ...
"""

import json
import time

from fastapi import FastAPI, Request, Response

from debugger.signing import verify
from mocks.keys import registry_records

app = FastAPI(title="Mock ONDC registry")

FILTERS = ("subscriber_id", "type", "country", "domain", "city")


def matching(query: dict) -> list[dict]:
    records = registry_records()
    ukid = query.get("ukId") or query.get("ukid") or query.get("unique_key_id")
    return [r for r in records
            if all(r.get(f) == query[f] for f in FILTERS if f in query and f in r)
            and (not ukid or r["ukId"] == ukid)]


def as_json(data, status=200) -> Response:
    return Response(json.dumps(data), status_code=status, media_type="application/json")


@app.post("/v2.0/lookup")
async def lookup_v2(request: Request):
    body = await request.body()
    keys = {f"{r['subscriber_id']}|{r['ukId']}": r["signing_public_key"] for r in registry_records()}
    problems = verify(request.headers.get("authorization"), body, keys, time.time(), None)
    if problems:
        print(f"[registry] refused lookup: {problems[0].detail}")
        return as_json({"error": {"code": "1015", "message": problems[0].detail}}, 401)
    query = json.loads(body)
    found = matching(query)
    print(f"[registry] v2.0 lookup {query} -> {len(found)} records")
    return as_json(found)


@app.post("/lookup")
async def lookup(request: Request):
    query = await request.json()
    found = matching(query)
    print(f"[registry] lookup {query} -> {len(found)} records")
    return as_json(found)
