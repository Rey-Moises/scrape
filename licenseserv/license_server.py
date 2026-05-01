"""
╔══════════════════════════════════════════════════════════════════════╗
║  ProPHBot License Server                                            ║
║  Deploy this to any free server:                                    ║
║    - Railway.app (free tier)                                        ║
║    - Render.com  (free tier)                                        ║
║    - Replit      (free tier)                                        ║
║                                                                     ║
║  ENV VARS to set on your server:                                    ║
║    SECRET_KEY  = any random string (keep private)                   ║
║    ADMIN_PASS  = your admin password for generating keys            ║
╚══════════════════════════════════════════════════════════════════════╝

pip install flask
python license_server.py
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify

app = Flask(__name__)

_db_lock = threading.Lock()
_rate_limit: dict[str, list[float]] = {}

def _rate_limit(max_req: int = 20, window: int = 60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            with _db_lock:
                reqs = [t for t in _rate_limit.get(ip, []) if now - t < window]
                if len(reqs) >= max_req:
                    return jsonify({"error": "Rate limited"}), 429
                reqs.append(now)
                _rate_limit[ip] = reqs
            return f(*args, **kwargs)
        return wrapped
    return decorator

def _check_admin(data: dict) -> bool:
    pw = data.get("admin_pass", "")
    return hmac.compare_digest(pw, ADMIN_PASS)

# ── Config ────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "change_this_in_production_env")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "cappy2026admin")
DB_FILE    = Path("licenses.json")
VERSION    = "1.0"

# ── Tiers ─────────────────────────────────────────────────
TIERS = {
    "script":   {"label": "Script Only",   "price": 9},
    "setup":    {"label": "Setup",         "price": 26},
    "dfy":      {"label": "Done For You",  "price": 60},
}

# ── DB helpers ─────────────────────────────────────────────
def load_db() -> dict:
    with _db_lock:
        if DB_FILE.exists():
            try:
                return json.loads(DB_FILE.read_text())
            except Exception:
                pass
        return {}

def save_db(db: dict):
    with _db_lock:
        tmp = DB_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(db, indent=2))
        tmp.replace(DB_FILE)

# ── Key generation ─────────────────────────────────────────
def generate_key(tier: str, buyer_name: str = "") -> str:
    """
    Format: CW-XXXX-XXXX-XXXX-XXXX
    HMAC-signed so you can verify structure without DB lookup.
    """
    raw     = secrets.token_hex(8).upper()
    payload = f"{tier}:{raw}:{buyer_name}"
    sig     = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:8].upper()
    key     = f"CW-{raw[:4]}-{raw[4:8]}-{sig[:4]}-{sig[4:8]}"
    return key

# ── Routes ─────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"service": "ProPHBot License Server", "version": VERSION})


@app.route("/verify", methods=["POST"])
@_rate_limit(30, 60)
def verify():
    """
    Called by the bot on every startup.
    Body: { "key": "CW-XXXX-...", "machine_id": "abc123" }
    """
    data       = request.get_json(silent=True) or {}
    key        = data.get("key", "").strip().upper()
    machine_id = data.get("machine_id", "unknown")
    bot_ver    = data.get("version", "?")

    if not key:
        return jsonify({"valid": False, "reason": "No key provided"}), 400

    db = load_db()

    if key not in db:
        return jsonify({"valid": False, "reason": "Key not found"}), 403

    record = db[key]

    # Check if revoked
    if record.get("revoked"):
        return jsonify({"valid": False, "reason": "Key has been revoked"}), 403

    # Check expiry (if set)
    if record.get("expires_at"):
        if time.time() > record["expires_at"]:
            return jsonify({"valid": False, "reason": "Key expired"}), 403

    # Machine lock — after first activation, lock to that machine
    if record.get("machine_id") and record["machine_id"] != machine_id:
        # Allow 1 transfer (in case buyer reinstalls)
        transfers = record.get("transfers", 0)
        if transfers >= 1:
            return jsonify({
                "valid":  False,
                "reason": "Key already activated on another machine. "
                          "Contact cappyworks.com to transfer."
            }), 403
        # First transfer — allow but log it
        record["transfers"]  = transfers + 1
        record["machine_id"] = machine_id

    # First activation — lock machine
    if not record.get("machine_id"):
        record["machine_id"]    = machine_id
        record["activated_at"]  = datetime.now().isoformat()
        record["transfers"]     = 0

    # Log usage
    record.setdefault("usage_log", [])
    record["usage_log"].append({
        "ts":         datetime.now().isoformat(),
        "machine_id": machine_id,
        "version":    bot_ver,
    })
    if len(record["usage_log"]) > 100:
        record["usage_log"] = record["usage_log"][-100:]
    record["last_seen"] = datetime.now().isoformat()

    db[key] = record
    save_db(db)

    return jsonify({
        "valid":      True,
        "tier":       record.get("tier", "script"),
        "buyer":      record.get("buyer", ""),
        "activated":  record.get("activated_at", ""),
        "message":    "ProPHBot license verified ✓",
    })


@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    """
    Generate a new license key.
    Body: { "admin_pass": "...", "tier": "script|setup|dfy",
            "buyer": "Name", "order_id": "FVR-123" }
    """
    data = request.get_json(silent=True) or {}

    if not _check_admin(data):
        return jsonify({"error": "Unauthorized"}), 401

    tier     = data.get("tier", "script")
    buyer    = data.get("buyer", "")
    order_id = data.get("order_id", "")

    if tier not in TIERS:
        return jsonify({"error": f"Invalid tier. Choose: {list(TIERS)}"}), 400

    key = generate_key(tier, buyer)
    db  = load_db()
    db[key] = {
        "tier":       tier,
        "buyer":      buyer,
        "order_id":   order_id,
        "created_at": datetime.now().isoformat(),
        "expires_at": None,   # None = never expires
        "revoked":    False,
        "machine_id": None,
        "activated_at": None,
        "transfers":  0,
        "usage_log":  [],
    }
    save_db(db)

    return jsonify({
        "key":      key,
        "tier":     tier,
        "buyer":    buyer,
        "order_id": order_id,
        "message":  f"Key generated for {buyer} ({TIERS[tier]['label']})",
    })


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    """
    Revoke a key (e.g. chargeback, abuse).
    Body: { "admin_pass": "...", "key": "CW-XXXX-..." }
    """
    data = request.get_json(silent=True) or {}

    if not _check_admin(data):
        return jsonify({"error": "Unauthorized"}), 401

    key = data.get("key", "").strip().upper()
    db  = load_db()

    if key not in db:
        return jsonify({"error": "Key not found"}), 404

    db[key]["revoked"] = True
    db[key]["revoked_at"] = datetime.now().isoformat()
    save_db(db)

    return jsonify({"message": f"Key {key} revoked."})


@app.route("/admin/list", methods=["POST"])
def admin_list():
    """List all keys. Body: { "admin_pass": "..." }"""
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"error": "Unauthorized"}), 401
    db = load_db()
    summary = []
    for k, v in db.items():
        summary.append({
            "key":       k,
            "tier":      v.get("tier"),
            "buyer":     v.get("buyer"),
            "activated": v.get("activated_at"),
            "last_seen": v.get("last_seen"),
            "revoked":   v.get("revoked", False),
            "machine":   v.get("machine_id", "not yet"),
        })
    return jsonify({"total": len(summary), "keys": summary})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"ProPHBot License Server v{VERSION} running on :{port}")
    app.run(host="0.0.0.0", port=port, debug=False)