# ONDC transaction debugger

A local debugging proxy for apps integrating with [ONDC](https://ondc.org) (the Open Network for Digital Commerce).

ONDC calls are asynchronous: you send `/select`, get an instant `ACK`, and the real answer arrives later as a separate call to your `/on_select`. When something breaks, every log says "200 OK" and you're left guessing which callback was late, missing, malformed or wrongly signed.

This tool sits between buyer apps (BAPs), seller apps (BPPs) and the gateway, records every message, groups each request with the answers it got, and shows each purchase as a timeline with the problems spelled out.

## What it catches

**Each message**

| Check | Meaning |
| --- | --- |
| `spec_violation` | Breaks the official ONDC schema for its `core_version` (see "Spec validation" below) |
| `missing_field` | A core `context` field is absent |
| `action_mismatch` | `context.action` disagrees with the endpoint it was sent to |
| `missing_signature`, `bad_signature_header` | No `Authorization` header, or one that can't be parsed |
| `signature_invalid` | The body was changed after signing, or signed with a different key |
| `signer_mismatch` | Signed by someone other than the message's stated sender |
| `signature_time` | Signature expired, or created in the future |
| `key_validity` | Signed with a key the registry says has expired (common after key rotation) |
| `unknown_key` | The signer's key isn't in the registry or your key file (warning) |
| `registry_error` | Couldn't ask the registry, so the signature wasn't checked (warning) |
| `nack` / `http_error` / `invalid_json` | Rejected, unreachable, or not JSON |

**Each request and its answers**

| Check | Meaning |
| --- | --- |
| `missing_callback` | ACKed, but no `on_` callback within the request's `ttl` |
| `late_callback` | A callback arrived after the `ttl` expired |
| `orphan_callback` | A callback that matches no request (e.g. its `message_id` was lost) |
| `seller_no_response` | The gateway delivered a search to several sellers; some never answered (warning) |
| `duplicate_callback` | Several answers to a request that should get one (warning) |

**The purchase as a whole** (warnings, since a shopper may simply walk away)

| Check | Meaning |
| --- | --- |
| `stopped_partway` | Never reached `confirm`, and idle for `STALL_AFTER_SECONDS` (default 60) |
| `out_of_order` | A step sent before the previous step's answer arrived |
| `skipped_step` | e.g. `init` with no `select` before it |

## How it works

```
buyer   --->  debugger /gateway/search  --->  gateway
gateway --->  debugger /bpp/search      --->  seller A
gateway --->  debugger /bpp2/search     --->  seller B
buyer   --->  debugger /bpp/<action>    --->  seller A
sellers --->  debugger /bap/on_<action> --->  buyer
```

ONDC apps find each other through `bap_uri` and `bpp_uri` in each message's `context`. Point those (and your gateway URL) at the debugger and every hop flows through it, with no code changes to the apps. Bodies and headers are forwarded byte for byte, so signatures still verify at the receiver.

## Try it in one command

```bash
pip install -r requirements.txt
python -m debugger.fetch_spec     # optional: download ONDC's retail specs for validation
python -m mocks.demo              # starts a fake network and runs 5 example purchases
```

Open http://localhost:8000. The demo starts a buyer, two sellers, a gateway, a mock ONDC registry and the debugger (logs in `./logs`), generates test signing keys, and runs: a healthy purchase, one with several bugs, a tampered signature plus a spec violation, an out-of-order purchase whose seller signs with a retired key, and an abandoned one. The debugger gets every public key from the mock registry, the same way it would from ONDC's. Press Ctrl+C to stop.

Run your own purchases against the running network with `python -m mocks.run_flow --via-gateway`, adding bugs with `--faults`, for example `--faults "select:late,search:missing@mock-seller-b"`. Fault types: `late`, `missing`, `bad` (drops `message_id`), `badsig` (body changed after signing), `badtype` (breaks the spec), `oldkey` (signed with seller A's expired key).

## Use it with your own app

```bash
ROUTES="bap=https://your-buyer-app,bpp=https://a-seller-app,gateway=https://preprod.gateway.example" \
ONDC_REGISTRY=preprod \
ONDC_SUBSCRIBER_ID=your-app.example.com ONDC_UNIQUE_KEY_ID=your-ukid ONDC_PRIVATE_KEY=... \
    uvicorn debugger.proxy:app --port 8000
```

1. `ROUTES` maps names to real addresses: a message to `http://<debugger>/<name>/<action>` is forwarded to `<address>/<action>`. Add as many sellers as you like (`bpp2=...`, `bpp3=...`).
2. In your app's messages, set `bap_uri` / `bpp_uri` to `http://<debugger>/bap` / `http://<debugger>/bpp`, and send searches to `http://<debugger>/gateway`.
3. Set `GATEWAY_ROUTE` if your gateway route has another name.

### Where signature keys come from

**From the ONDC registry** (recommended): set `ONDC_REGISTRY` to `preprod`, `prod`, or a full lookup URL. The debugger looks up each signer's `signing_public_key` with the registry's `/v2.0/lookup` API, the same way ONDC apps do, and checks its `valid_from` / `valid_until`.

ONDC's `/v2.0/lookup` only answers requests signed by a registered participant, so the debugger needs **your app's own registry credentials**: `ONDC_SUBSCRIBER_ID`, `ONDC_UNIQUE_KEY_ID` and `ONDC_PRIVATE_KEY` (base64 signing private key). They're only used to sign lookup requests; they're never stored, logged or sent anywhere else. Keep them in your environment or a secrets manager, not in a file you commit. The older unsigned endpoints are available as `preprod-legacy` / `prod-legacy`, but ONDC has deprecated them.

Lookups are cached: found keys for an hour, "not registered" for 5 minutes, failures for 1 minute. So a busy page doesn't hit ONDC's rate limits, and a key rotation shows up within the hour. A registry that can't be reached is reported as `registry_error`, not as a bad signature.

Check your setup before routing traffic:

```bash
ONDC_REGISTRY=preprod ONDC_SUBSCRIBER_ID=... ONDC_UNIQUE_KEY_ID=... ONDC_PRIVATE_KEY=... \
    python -m debugger.registry some-seller.example.com
```

**From a local file:** set `ONDC_KEYS` to a JSON file `{"subscriber_id|unique_key_id": "base64 signing public key"}`. It's checked before the registry, so you can use both, for example to add test participants that aren't registered. With neither set, signature checks are off, and the page says so.

Analysis is also available as JSON at `/api/transactions/<transaction_id>`, handy for CI.

## Spec validation

`python -m debugger.fetch_spec [branch ...]` downloads `build.yaml` from branches of [ONDC-RET-Specifications](https://github.com/ONDC-Official/ONDC-RET-Specifications) into `./specs` (default: retail 1.2.0 and 2.0.2). Messages are validated against the spec matching their `context.core_version`. The specs aren't bundled because that repository has no license.

ONDC's published schemas often disagree with ONDC's own example messages. On the `draft-b2c-1.2.5` branch, only 45 of 377 official examples pass their own schema; on 1.2.0 the `Domain` enum still only allows `nic2004:52110`, not today's `ONDC:RET10`. Strict validation would flag nearly every real message. So each spec is **calibrated** when it loads: all of its official examples are validated, and every schema rule they break is treated as a known spec gap and skipped. Anything else your message breaks is reported. The debugger's own core `context` check runs alongside, because some spec versions don't require fields like `transaction_id`.

This isn't a replacement for ONDC's own [log validation utility](https://github.com/ONDC-Official/log-validation-utility), which applies domain-specific business rules. It's a fast first check that runs locally on every message.

## Run the tests

```bash
python -m pytest -q
```

Signature tests reproduce the worked example from [ONDC's signing documentation](https://github.com/ONDC-Official/developer-docs/blob/main/registry/signing-verification.md) byte for byte.

## Limitations

- Registry lookup follows ONDC's documentation and the request and response format used by ONDC's own reference buyer app (`biap-client-node-js`). It's tested against a mock registry, **not yet against the live preprod or prod registry**. If the live response differs, `python -m debugger.registry <subscriber_id>` shows exactly what came back; please open an issue.
- The deprecated `/vlookup` endpoint isn't supported. ONDC's staging registry has been retired.
- `ttl` and signature times are measured from when the debugger saw each message.
- When a gateway forwards a search, the debugger counts how many sellers answered, but can't always say which silent route belongs to which seller (forwarded searches don't name a seller).
- The purchase order checks follow the retail flow (`search`, `select`, `init`, `confirm`).

## License

MIT
