"""
ONDC debugger: the web pages.

  GET /                          recent transactions, newest first
  GET /txn/{transaction_id}      one transaction as a timeline of exchanges
  GET /api/transactions/{id}     the same analysis as JSON (for scripts and CI)

Everything shown comes from other apps' messages, so every value goes
through html.escape() before it's put on the page.
"""

import json
from datetime import datetime, timezone
from html import escape

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from debugger import registry, spec, store
from debugger.checks import Exchange, Issue, analyse, transaction_issues

router = APIRouter()

CSS = """
:root { --bg:#fbfaf7; --card:#fff; --ink:#1f1e1c; --muted:#6d6a63; --line:#e6e2d9;
        --ok:#2f7d4f; --ok-bg:#e7f3eb; --err:#b3261e; --err-bg:#fbeaea; --warn:#8a5a00; --warn-bg:#fdf1d8;
        --info:#3d5a99; --info-bg:#e9eef9; --bar:#c9c3b6; --mono: ui-monospace, SFMono-Regular, Menlo, monospace; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#181816; --card:#22211e; --ink:#ecebe6; --muted:#a3a097; --line:#3a3833;
          --ok:#7fcf9c; --ok-bg:#1f3327; --err:#f2a39d; --err-bg:#3d1f1d; --warn:#f0c674; --warn-bg:#3a2e14;
          --info:#a9c0f2; --info-bg:#1f2840; --bar:#5a564e; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 system-ui, sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 28px 16px 64px; }
a { color: inherit; }
h1 { font-size: 22px; font-weight: 600; margin: 0 0 4px; }
.sub { color: var(--muted); margin: 0 0 16px; }
.mono { font-family: var(--mono); font-size: 13px; }
.nowrap { white-space: nowrap; }
.status { display:flex; flex-wrap: wrap; gap: 6px 16px; color: var(--muted); font-size: 13px; margin: 0 0 22px; }
.status b { color: var(--ink); font-weight: 600; }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: 0; }
.pill { display:inline-block; padding: 1px 9px; border-radius: 99px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.pill.ok { background: var(--ok-bg); color: var(--ok); }
.pill.error { background: var(--err-bg); color: var(--err); }
.pill.warning { background: var(--warn-bg); color: var(--warn); }
.pill.info { background: var(--info-bg); color: var(--info); }
.purchase { background: var(--warn-bg); color: var(--warn); border-radius: 10px; padding: 12px 16px; margin: 0 0 16px; }
.purchase b { display:block; margin-bottom: 4px; }
.purchase ul { margin: 0; padding-left: 18px; }
.ex { background: var(--card); border: 1px solid var(--line); border-left: 4px solid var(--ok); border-radius: 0 10px 10px 0; padding: 14px 16px; margin-bottom: 12px; }
.ex.error { border-left-color: var(--err); }
.ex.warning { border-left-color: var(--warn); }
.ex.info { border-left-color: var(--info); }
.ex-head { display:flex; flex-wrap: wrap; align-items: baseline; gap: 6px 14px; }
.ex-head b { font-family: var(--mono); font-size: 14px; }
.t { color: var(--muted); font-size: 13px; }
.bars { margin: 12px 0 4px; }
.barrow { display:grid; grid-template-columns: minmax(90px, 200px) 1fr; gap: 10px; align-items: center; margin: 6px 0; }
.who { font-family: var(--mono); font-size: 12px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.track { position: relative; height: 8px; background: var(--line); border-radius: 4px; }
.fill { position: absolute; left: 0; top: 0; bottom: 0; background: var(--bar); border-radius: 4px; }
.fill.late { background: var(--err); }
.ttl { position: absolute; top: -4px; bottom: -4px; width: 2px; background: var(--ink); }
.scale { display:grid; grid-template-columns: minmax(90px, 200px) 1fr; gap: 10px; color: var(--muted); font-size: 12px; }
.scale div { display:flex; justify-content: space-between; }
ul.issues { margin: 10px 0 0; padding-left: 18px; }
ul.issues li { margin: 2px 0; }
ul.issues li.warning { color: var(--warn); }
details { margin-top: 8px; }
summary { cursor: pointer; color: var(--muted); font-size: 13px; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 10px; overflow-x: auto; font: 12px/1.5 var(--mono); white-space: pre-wrap; word-break: break-all; }
.legend { color: var(--muted); font-size: 13px; margin: -4px 0 18px; }
"""


def page(title: str, body: str, refresh: bool = False) -> HTMLResponse:
    meta = '<meta http-equiv="refresh" content="3">' if refresh else ""
    return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">{meta}
<title>{escape(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>""")


def checks_status() -> str:
    """Say which optional checks are on, so nobody mistakes 'not checked' for 'fine'."""
    keys = registry.keystore_from_env()
    sig = (f"<b>on</b>, keys from {escape(keys.describe())}" if keys is not None
           else "<b>off</b> (set ONDC_REGISTRY, or ONDC_KEYS to a public-key file)")
    specs = spec.load_specs()
    sp = (f"<b>{', '.join(sorted(specs))}</b>" if specs
          else "<b>none</b> (run: python -m debugger.fetch_spec)")
    return f"<div class='status'><span>Signature checks: {sig}</span><span>ONDC specs: {sp}</span></div>"


def analysis(transaction_id: str) -> tuple[list[Exchange], list[Issue]]:
    rows = store.transaction(transaction_id)
    if not rows:
        raise HTTPException(404, "No messages for that transaction_id")
    exchanges = analyse(rows)
    return exchanges, transaction_issues(exchanges)


def level_of(issues: list[Issue]) -> str:
    levels = {i.severity for i in issues}
    for level in ("error", "warning", "info"):
        if level in levels:
            return level
    return "ok"


def summary_pill(exchanges: list[Exchange], purchase: list[Issue]) -> str:
    issues = [i for e in exchanges for i in e.issues] + purchase
    n_err = sum(i.severity == "error" for i in issues)
    n_warn = sum(i.severity == "warning" for i in issues)
    if n_err:
        extra = f" + {n_warn} warning{'s' * (n_warn != 1)}" if n_warn else ""
        return f'<span class="pill error">{n_err} problem{"s" * (n_err != 1)}{extra}</span>'
    if n_warn:
        return f'<span class="pill warning">{n_warn} warning{"s" * (n_warn != 1)}</span>'
    if level_of(issues) == "info":
        return '<span class="pill info">in progress</span>'
    return '<span class="pill ok">healthy</span>'


@router.get("/", response_class=HTMLResponse)
def index():
    rows = []
    for t in store.recent_transactions():
        exchanges, purchase = analysis(t["transaction_id"])
        tid = escape(t["transaction_id"])
        rows.append(
            f"<tr><td><a class='mono' href='/txn/{tid}'>{tid}</a></td>"
            f"<td class='t nowrap'>{escape(t['started'][11:19])} UTC</td>"
            f"<td class='mono'>{escape(t['bap_id'] or '-')}</td>"
            f"<td>{t['messages']}</td><td>{summary_pill(exchanges, purchase)}</td></tr>"
        )
    table = ("<table><tr><th>Transaction</th><th>Started</th><th>Buyer app</th>"
             "<th>Messages</th><th>Status</th></tr>" + "".join(rows) + "</table>"
             if rows else "<p class='sub'>No traffic yet. Point your app's bap_uri / bpp_uri at this debugger.</p>")
    return page("ONDC debugger", "<h1>ONDC transaction debugger</h1>"
                "<p class='sub'>Recent transactions, newest first. Refreshes every 3 seconds.</p>"
                + checks_status() + table, refresh=True)


def _bpp(row: dict) -> str:
    try:
        return json.loads(row["body"]).get("context", {}).get("bpp_id") or row["side"]
    except (ValueError, AttributeError):
        return row["side"]


def _raw(row: dict, label: str) -> str:
    try:
        body = json.dumps(json.loads(row["body"]), indent=2, ensure_ascii=False)
    except ValueError:
        body = row["body"]
    headers = "".join(f"{name}: {row.get(key)}\n" for name, key in
                      (("Authorization", "authorization"), ("X-Gateway-Authorization", "gateway_authorization"))
                      if row.get(key))
    return (f"<details><summary>{escape(label)} &middot; via /{escape(row['side'])}/{escape(row['action'])} "
            f"&middot; reply HTTP {row['reply_status']} {escape(row['ack'] or '')}</summary>"
            + (f"<pre>{escape(headers)}</pre>" if headers else "")
            + f"<pre>{escape(body)}</pre><pre>{escape(row['reply'] or '')}</pre></details>")


def render_exchange(ex: Exchange, start: datetime) -> str:
    level = level_of(ex.issues)
    first = ex.request or ex.callback
    offset = (datetime.fromisoformat(first["received_at"]) - start).total_seconds()

    if ex.request and ex.callbacks:
        label = f"<b>{escape(ex.action)}</b> &rarr; <b>on_{escape(ex.action)}</b>"
        timing = (f"{len(ex.callbacks)} answers" if len(ex.callbacks) > 1
                  else f"answered in {ex.latency.total_seconds():.2f}s")
    elif ex.request:
        label = f"<b>{escape(ex.action)}</b> &rarr; <b>?</b>"
        timing = "no answer"
    else:
        label = f"<b>?</b> &rarr; <b>{escape(ex.action)}</b>"
        timing = "unmatched callback"
    if ex.forwards:
        timing += f" &middot; via gateway to {len(ex.forwards)} sellers"

    pill = {"ok": "ok", "info": "in progress", "warning": "warning", "error": "problem"}[level]
    head = (f"<div class='ex-head'>{label}<span class='pill {level}'>{pill}</span>"
            f"<span class='t'>at +{offset:.2f}s &middot; {timing}</span>"
            f"<span class='t mono'>message_id {escape((ex.message_id or 'missing')[:8])}</span></div>")

    # One bar per answer: how long it took, against the ttl (the dark line).
    bars = ""
    if ex.request:
        ttl_s = ex.ttl.total_seconds()
        timings = [(_bpp(cb), ex.latency_of(cb).total_seconds()) for cb in ex.callbacks]
        # Sellers that got the request but haven't answered: show the time waited so far.
        reached = len([f for f in ex.forwards if f["ack"] == "ACK"]) or 1
        silent = max(reached - len(ex.callbacks), 0)
        if silent:
            waited = (datetime.now(timezone.utc) - datetime.fromisoformat(ex.request["received_at"])).total_seconds()
            timings += [("no answer", waited)] * silent
        span = max(ttl_s * 1.5, max(t for _, t in timings) * 1.1, 0.001)
        rows = "".join(
            f"<div class='barrow'><span class='who' title='{escape(who)}'>{escape(who)}</span>"
            f"<div class='track'><div class='fill{' late' if took > ttl_s else ''}' "
            f"style='width:{min(took / span, 1) * 100:.1f}%' title='{took:.2f}s'></div>"
            f"<div class='ttl' style='left:{ttl_s / span * 100:.1f}%'></div></div></div>"
            for who, took in timings)
        bars = (f"<div class='bars'>{rows}<div class='scale'><span></span>"
                f"<div><span>0s</span><span>ttl {ttl_s:.0f}s</span><span>{span:.1f}s</span></div></div></div>")

    issues = "".join(f"<li class='{i.severity}'>{escape(i.detail)}</li>" for i in ex.issues)
    issues = f"<ul class='issues'>{issues}</ul>" if issues else ""

    raw = ""
    if ex.request:
        raw += _raw(ex.request, f"{ex.action} request")
    for fwd in ex.forwards:
        raw += _raw(fwd, f"{ex.action} forwarded by gateway")
    for cb in ex.callbacks:
        raw += _raw(cb, f"{cb['action']} from {_bpp(cb)}")
    return f"<div class='ex {level}'>{head}{bars}{issues}{raw}</div>"


@router.get("/txn/{transaction_id}", response_class=HTMLResponse)
def transaction_page(transaction_id: str):
    exchanges, purchase = analysis(transaction_id)
    rows = store.transaction(transaction_id)
    start = datetime.fromisoformat(rows[0]["received_at"])
    purchase_box = ""
    if purchase:
        items = "".join(f"<li>{escape(i.detail)}</li>" for i in purchase)
        purchase_box = f"<div class='purchase'><b>About the purchase as a whole</b><ul>{items}</ul></div>"
    # Refresh only while something can still change: a callback is awaited, or the
    # purchase hasn't reached confirm and hasn't been declared stopped yet.
    waiting = level_of([i for e in exchanges for i in e.issues]) == "info"
    unfinished = (not any(e.action == "confirm" and e.request for e in exchanges)
                  and not any(i.code == "stopped_partway" for i in purchase))
    still_running = waiting or unfinished
    body = (f"<p><a href='/' class='t'>&larr; all transactions</a></p>"
            f"<h1>Transaction {summary_pill(exchanges, purchase)}</h1>"
            f"<p class='sub mono'>{escape(transaction_id)}</p>"
            + checks_status() + purchase_box +
            "<p class='legend'>Each card is a request with the answers it got. "
            "Bars show how long each answer took; the dark line marks the ttl.</p>"
            + "".join(render_exchange(e, start) for e in exchanges))
    return page("Transaction " + transaction_id[:8], body, refresh=still_running)


@router.get("/api/transactions/{transaction_id}")
def transaction_json(transaction_id: str):
    exchanges, purchase = analysis(transaction_id)

    def issue(i: Issue) -> dict:
        return {"code": i.code, "severity": i.severity, "detail": i.detail}

    return {
        "transaction_id": transaction_id,
        "ok": all(e.ok for e in exchanges) and not any(i.severity == "error" for i in purchase),
        "purchase_issues": [issue(i) for i in purchase],
        "exchanges": [
            {
                "action": e.action,
                "message_id": e.message_id,
                "forwarded_to": [f["side"] for f in e.forwards],
                "callbacks": [{"from": _bpp(c), "latency_seconds": e.latency_of(c).total_seconds()
                               if e.request else None} for c in e.callbacks],
                "ttl_seconds": e.ttl.total_seconds(),
                "issues": [issue(i) for i in e.issues],
            }
            for e in exchanges
        ],
    }
