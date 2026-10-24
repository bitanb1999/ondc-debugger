"""
Saves every message the proxy sees into a SQLite database (one file, no server).

Each row is one HTTP call: either a request (search, select, ...) or a
callback (on_search, on_select, ...).
"""

import json
import os
import sqlite3
from datetime import datetime

DB_PATH = os.environ.get("DEBUGGER_DB", "ondc_debugger.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at     TEXT NOT NULL,   -- when the debugger saw it (UTC)
    side            TEXT NOT NULL,   -- 'bpp' = sent to the seller, 'bap' = sent to the buyer
    action          TEXT NOT NULL,   -- from the URL: search, on_search, ...
    transaction_id  TEXT,            -- the whole purchase
    message_id      TEXT,            -- one request + its callback
    bap_id          TEXT,
    bpp_id          TEXT,
    context_action  TEXT,            -- context.action, should match the URL
    context_time    TEXT,            -- context.timestamp, set by the sender
    ttl             TEXT,            -- context.ttl, e.g. PT30S
    body            TEXT NOT NULL,   -- the full message, exactly as received
    body_is_json    INTEGER NOT NULL,
    reply_status    INTEGER,         -- HTTP status the receiver answered with
    reply           TEXT,            -- the receiver's reply (normally ACK or NACK)
    ack             TEXT,            -- 'ACK', 'NACK' or NULL if unreadable
    elapsed_ms      REAL             -- how long the receiver took to reply
);
CREATE INDEX IF NOT EXISTS idx_txn ON messages(transaction_id);
"""

# Columns added after the first version. init() adds them to older databases.
LATER_COLUMNS = {
    "body_raw": "BLOB",                   # exact bytes received; signatures are checked against these
    "authorization": "TEXT",              # the sender's signature header
    "gateway_authorization": "TEXT",      # the gateway's signature header, if it came via a gateway
    "seen_at_unix": "REAL",               # same moment as received_at, as a number (for signature times)
}


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # rows behave like dicts: row["action"]
    return conn


def init() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(messages)")}
        for name, kind in LATER_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {name} {kind}")


def _parse(raw: bytes):
    """Return the decoded JSON, or None if it isn't valid JSON (that's a bug to show, not hide)."""
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def save(*, received_at: datetime, side: str, action: str, body: bytes,
         reply_status: int, reply: bytes, elapsed_ms: float,
         authorization: str | None = None, gateway_authorization: str | None = None) -> None:
    parsed = _parse(body)
    ctx = parsed.get("context", {}) if isinstance(parsed, dict) else {}
    reply_parsed = _parse(reply)
    try:
        ack = reply_parsed["message"]["ack"]["status"]
    except (TypeError, KeyError):
        ack = None

    with connect() as conn:
        conn.execute(
            """INSERT INTO messages (received_at, side, action, transaction_id, message_id,
                   bap_id, bpp_id, context_action, context_time, ttl, body, body_is_json,
                   reply_status, reply, ack, elapsed_ms,
                   body_raw, authorization, gateway_authorization, seen_at_unix)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                received_at.isoformat(timespec="milliseconds"),
                side,
                action,
                ctx.get("transaction_id"),
                ctx.get("message_id"),
                ctx.get("bap_id"),
                ctx.get("bpp_id"),
                ctx.get("action"),
                ctx.get("timestamp"),
                ctx.get("ttl"),
                body.decode("utf-8", errors="replace"),
                parsed is not None,
                reply_status,
                reply.decode("utf-8", errors="replace"),
                ack,
                elapsed_ms,
                body,
                authorization,
                gateway_authorization,
                received_at.timestamp(),
            ),
        )


def recent_transactions(limit: int = 50) -> list[sqlite3.Row]:
    """Newest purchases first, with when they started and how many messages they have."""
    with connect() as conn:
        return conn.execute(
            """SELECT transaction_id, MIN(received_at) AS started, COUNT(*) AS messages,
                      MAX(bap_id) AS bap_id, MAX(bpp_id) AS bpp_id
               FROM messages WHERE transaction_id IS NOT NULL
               GROUP BY transaction_id ORDER BY started DESC LIMIT ?""",
            (limit,),
        ).fetchall()


def transaction(transaction_id: str) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM messages WHERE transaction_id = ? ORDER BY id", (transaction_id,)
        ).fetchall()
