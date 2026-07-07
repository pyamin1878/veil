#!/usr/bin/env python3
"""Veil relay server.

A deliberately blind message relay: it forwards ciphertext between clients
and never has access to plaintext or private keys. Everything it holds is
in memory — nothing is written to disk.

Zero dependencies. Runs anywhere Python 3.8+ runs:

    python3 server.py [port]

Protocol (all JSON over HTTP, same-origin):
    POST /api/join   {name, pubKey}          -> {id, token}
    GET  /api/events?id=..&token=..          -> SSE stream (roster + messages)
    POST /api/send   {id, token, to, iv, ct} -> {ok}
    POST /api/leave  {id, token}             -> {ok}

SSE events:
    roster  [{id, name, pubKey}, ...]        sent on every join/leave
    message {from, iv, ct, ts}               relayed ciphertext
"""

import json
import queue
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

CLIENT_DIR = Path(__file__).resolve().parent / "client"

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/crypto.js": ("crypto.js", "text/javascript; charset=utf-8"),
}

MAX_BODY = 64 * 1024          # generous cap for a single encrypted message
QUEUE_LIMIT = 512             # per-user pending event cap
HEARTBEAT_SECONDS = 20


class Hub:
    """In-memory registry of connected users and their event queues."""

    def __init__(self):
        self._lock = threading.Lock()
        self._users = {}  # id -> {name, pub_key, token, queue}

    def join(self, name, pub_key):
        user_id = secrets.token_urlsafe(9)
        token = secrets.token_urlsafe(18)
        with self._lock:
            self._users[user_id] = {
                "name": name,
                "pub_key": pub_key,
                "token": token,
                "queue": queue.Queue(maxsize=QUEUE_LIMIT),
            }
        self.broadcast_roster()
        return user_id, token

    def leave(self, user_id):
        with self._lock:
            self._users.pop(user_id, None)
        self.broadcast_roster()

    def authenticate(self, user_id, token):
        with self._lock:
            user = self._users.get(user_id)
            return user is not None and secrets.compare_digest(user["token"], token)

    def get_queue(self, user_id):
        with self._lock:
            user = self._users.get(user_id)
            return user["queue"] if user else None

    def roster(self):
        with self._lock:
            return [
                {"id": uid, "name": u["name"], "pubKey": u["pub_key"]}
                for uid, u in self._users.items()
            ]

    def broadcast_roster(self):
        event = ("roster", self.roster())
        with self._lock:
            queues = [u["queue"] for u in self._users.values()]
        for q in queues:
            self._offer(q, event)

    def relay(self, sender_id, recipient_id, iv, ct):
        """Forward ciphertext untouched. Returns False if recipient unknown."""
        with self._lock:
            recipient = self._users.get(recipient_id)
            if recipient is None:
                return False
            q = recipient["queue"]
        payload = {"from": sender_id, "iv": iv, "ct": ct, "ts": int(time.time() * 1000)}
        self._offer(q, ("message", payload))
        return True

    @staticmethod
    def _offer(q, event):
        try:
            q.put_nowait(event)
        except queue.Full:
            pass  # slow consumer; drop rather than block the whole server


HUB = Hub()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ---- plumbing ----

    def log_message(self, fmt, *args):
        sys.stderr.write("[veil] %s\n" % (fmt % args))

    def send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    # ---- static client ----

    def do_GET(self):
        url = urlparse(self.path)
        if url.path in STATIC_FILES:
            filename, mime = STATIC_FILES[url.path]
            body = (CLIENT_DIR / filename).read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            # The client is fully self-contained; lock everything else out.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:",
            )
            self.end_headers()
            self.wfile.write(body)
        elif url.path == "/api/events":
            self.handle_events(parse_qs(url.query))
        else:
            self.send_json(404, {"error": "not found"})

    # ---- API ----

    def do_POST(self):
        body = self.read_json()
        if body is None:
            return self.send_json(400, {"error": "bad request"})

        if self.path == "/api/join":
            name = str(body.get("name", "")).strip()[:32]
            pub_key = str(body.get("pubKey", ""))
            # An uncompressed P-256 point is 65 bytes -> 88 base64 chars.
            if not name or not (80 <= len(pub_key) <= 96):
                return self.send_json(400, {"error": "name and pubKey required"})
            user_id, token = HUB.join(name, pub_key)
            self.log_message("join: %s (%s)", name, user_id)
            return self.send_json(200, {"id": user_id, "token": token})

        user_id = str(body.get("id", ""))
        token = str(body.get("token", ""))
        if not HUB.authenticate(user_id, token):
            return self.send_json(403, {"error": "not authenticated"})

        if self.path == "/api/send":
            recipient = str(body.get("to", ""))
            iv, ct = str(body.get("iv", "")), str(body.get("ct", ""))
            if not (recipient and iv and ct):
                return self.send_json(400, {"error": "to, iv, ct required"})
            if not HUB.relay(user_id, recipient, iv, ct):
                return self.send_json(404, {"error": "recipient offline"})
            return self.send_json(200, {"ok": True})

        if self.path == "/api/leave":
            HUB.leave(user_id)
            self.log_message("leave: %s", user_id)
            return self.send_json(200, {"ok": True})

        self.send_json(404, {"error": "not found"})

    # ---- SSE ----

    def handle_events(self, params):
        user_id = (params.get("id") or [""])[0]
        token = (params.get("token") or [""])[0]
        if not HUB.authenticate(user_id, token):
            return self.send_json(403, {"error": "not authenticated"})

        q = HUB.get_queue(user_id)
        if q is None:
            return self.send_json(403, {"error": "not authenticated"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        try:
            self._sse("roster", HUB.roster())
            while True:
                try:
                    name, data = q.get(timeout=HEARTBEAT_SECONDS)
                    self._sse(name, data)
                except queue.Empty:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            HUB.leave(user_id)
            self.log_message("disconnected: %s", user_id)
            self.close_connection = True

    def _sse(self, name, data):
        payload = f"event: {name}\ndata: {json.dumps(data)}\n\n"
        self.wfile.write(payload.encode())
        self.wfile.flush()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8420
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    print(f"Veil relay listening on http://localhost:{port}")
    print("The server relays ciphertext only; it cannot read any message.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
