"""A minimal gate: grants hub tiers for codes. Standard library only.

The hub asks a gate who may use its gated providers (hub/app/gate.py,
PROTOCOL.md "Gate"). This is the smallest thing that speaks that contract, and
it is enough to run a hub that only people holding a code can provision on:

    STUB_GATE_TOKEN=<secret> STUB_GATE_CODES="FRIENDS-2026=mailbox" \
        python3 scripts/stub_gate.py
    # then start the hub with
    STONECHAT_GATE_URL=http://127.0.0.1:8478 STONECHAT_GATE_TOKEN=<secret>

Codes are reusable — anyone who has one can redeem it once per identity — and
grants live in memory, so a restart forgets them (and a hub with
STONECHAT_REAP_RETENTION_DAYS set does NOT reap on that: an ID the gate has
never granted anything is left alone). Keep grants somewhere durable before
using this for anything you care about. scripts/e2e.py runs it in-process.

Config (env):
    STUB_GATE_TOKEN  the hub's STONECHAT_GATE_TOKEN (required)
    STUB_GATE_CODES  "CODE=tier,CODE=tier" with tier mailbox or machine
    STUB_GATE_PORT   default 8478
"""

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TIERS = ("mailbox", "machine")


def _norm(code: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", code).upper()


class StubGate:
    def __init__(self, token: str, codes: dict[str, str]):
        self.token = token
        self.codes = {_norm(c): t for c, t in codes.items()}
        self.grants: dict[str, str] = {}      # stonechat_id → tier
        self.revoked: dict[str, str] = {}     # stonechat_id → when
        self.lock = threading.Lock()

    def access(self, stonechat_id: str) -> dict:
        tier = self.grants.get(stonechat_id)
        return {"tier": tier, "status": "active" if tier else None, "until": None,
                "revoked_at": None if tier else self.revoked.get(stonechat_id),
                "notice": None}

    def handle(self, method: str, path: str, auth: str, body: dict) -> tuple[int, dict]:
        if not secrets.compare_digest(auth, f"Bearer {self.token}"):
            return 403, {"detail": "hub token required"}
        m = re.fullmatch(r"/v1/access/([^/]+)(?:/(claim|release))?", path)
        if not m:
            return 404, {"detail": "not found"}
        stonechat_id, action = m.group(1), m.group(2)
        with self.lock:
            if method == "GET" and not action:
                return 200, self.access(stonechat_id)
            if method == "POST" and action == "claim":
                if stonechat_id in self.grants:
                    return 409, {"detail": {"code": "already_granted",
                                            "message": "this account already has access"}}
                tier = None
                presented = _norm(str(body.get("code", "")))
                for code, t in self.codes.items():  # no early exit
                    if secrets.compare_digest(code, presented):
                        tier = t
                if tier not in TIERS:
                    return 404, {"detail": {"code": "invalid_code",
                                            "message": "invalid code"}}
                self.grants[stonechat_id] = tier
                self.revoked.pop(stonechat_id, None)
                return 200, self.access(stonechat_id)
            if method == "POST" and action == "release":
                if self.grants.pop(stonechat_id, None):
                    self.revoked[stonechat_id] = datetime.now(timezone.utc).isoformat()
                return 200, {"released": 1}
        return 405, {"detail": "method not allowed"}

    def serve(self, port: int) -> ThreadingHTTPServer:
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, method: str):
                length = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except ValueError:
                    body = {}
                status, out = gate.handle(method, self.path,
                                          self.headers.get("Authorization", ""),
                                          body if isinstance(body, dict) else {})
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._reply("GET")

            def do_POST(self):
                self._reply("POST")

            def log_message(self, *_):
                pass

        return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def parse_codes(spec: str) -> dict[str, str]:
    codes = {}
    for part in spec.split(","):
        code, _, tier = part.strip().partition("=")
        if code:
            codes[code] = tier.strip() or "mailbox"
    return codes


if __name__ == "__main__":
    token = os.environ.get("STUB_GATE_TOKEN")
    if not token:
        raise SystemExit("set STUB_GATE_TOKEN (the hub's STONECHAT_GATE_TOKEN)")
    port = int(os.environ.get("STUB_GATE_PORT", "8478"))
    server = StubGate(token, parse_codes(os.environ.get("STUB_GATE_CODES", ""))).serve(port)
    print(f"stub gate on http://127.0.0.1:{port}")
    server.serve_forever()
