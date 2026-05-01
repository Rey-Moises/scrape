"""
╔══════════════════════════════════════════════════════════════════════╗
║  ProPHBot License Server                                             ║
║  Deploy this to any free server (Railway, Render, Replit)            ║
╚══════════════════════════════════════════════════════════════════════╝
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify
from pymongo import MongoClient

app = Flask(__name__)

# ── Security & Rate Limiting ──────────────────────────────
_db_lock = threading.Lock()
_RATE_LIMIT_CACHE: dict[str, list[float]] = {}  # Collison-free dictionary name

def _rate_limit(max_req: int = 20, window: int = 60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            with _db_lock:
                reqs = [t for t in _RATE_LIMIT_CACHE.get(ip, []) if now - t < window]
                if len(reqs) >= max_req:
                    return jsonify({"error": "Rate limited"}), 429
                reqs.append(now)
                _RATE_LIMIT_CACHE[ip] = reqs
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ── Config ────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "capybaracapybaracapybaracapybara")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "Cappyworks!")
MONGO_URI  = os.environ.get("MONGO_URI", "")
VERSION    = "1.0"

TIERS = {
    "script":   {"label": "Script Only",   "price": 9},
    "setup":    {"label": "Setup",         "price": 26},
    "dfy":      {"label": "Done For You",  "price": 60},
}

def _check_admin(data: dict) -> bool:
    pw = data.get("admin_pass", "")
    return hmac.compare_digest(pw, ADMIN_PASS)

# ── MongoDB Setup ──────────────────────────────────────────
if MONGO_URI:
    try:
        # Initialize connection with explicit TLS settings
        mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=30000,
            tls=True,
            tlsAllowInvalidCertificates=True  # Bypasses the internal SSL handshake error
        )
        mongo_db = mongo_client["prophbot"]
        keys_collection = mongo_db["licenses"]
    except Exception as e:
        print(f"CRITICAL ERROR: Failed to initialize MongoDB Client: {e}")
else:
    print("CRITICAL WARNING: MONGO_URI not set. Database will fail.")
    
def load_db() -> dict:
    """Fetches all keys from MongoDB and formats them as a dictionary."""
    with _db_lock:
        db_dict = {}
        if MONGO_URI:
            for doc in keys_collection.find({}):
                key = doc["_id"]
                del doc["_id"]
                db_dict[key] = doc
        return db_dict

def save_db(db: dict):
    """Upserts keys to MongoDB."""
    with _db_lock:
        if MONGO_URI:
            for key, val in db.items():
                keys_collection.update_one({"_id": key}, {"$set": val}, upsert=True)

# ── Routes ─────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"service": "ProPHBot License Server", "version": VERSION})

@app.route("/verify", methods=["POST"])
@_rate_limit(30, 60)
def verify():
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

    if record.get("revoked"):
        return jsonify({"valid": False, "reason": "Key has been revoked"}), 403

    if record.get("expires_at") and time.time() > record["expires_at"]:
        return jsonify({"valid": False, "reason": "Key expired"}), 403

    if record.get("machine_id") and record["machine_id"] != machine_id:
        transfers = record.get("transfers", 0)
        if transfers >= 1:
            return jsonify({
                "valid":  False,
                "reason": "Key already activated on another machine. Contact cappyworks.com to transfer."
            }), 403
        record["transfers"]  = transfers + 1
        record["machine_id"] = machine_id

    if not record.get("machine_id"):
        record["machine_id"]    = machine_id
        record["activated_at"]  = datetime.now().isoformat()
        record["transfers"]     = 0

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
        "valid":     True,
        "tier":      record.get("tier", "script"),
        "buyer":     record.get("buyer", ""),
        "activated": record.get("activated_at", ""),
        "message":   "ProPHBot license verified ✓",
    })

@app.route("/admin/generate", methods=["POST"])
def admin_generate():
    data = request.get_json(silent=True) or {}
    if not _check_admin(data):
        return jsonify({"error": "Unauthorized"}), 401

    tier     = data.get("tier", "script")
    buyer    = data.get("buyer", "")
    order_id = data.get("order_id", "")

    if tier not in TIERS:
        return jsonify({"error": f"Invalid tier. Choose: {list(TIERS)}"}), 400

    raw     = secrets.token_hex(8).upper()
    payload = f"{tier}:{raw}:{buyer}"
    sig     = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:8].upper()
    key     = f"CW-{raw[:4]}-{raw[4:8]}-{sig[:4]}-{sig[4:8]}"
    
    db  = load_db()
    db[key] = {
        "tier":       tier,
        "buyer":      buyer,
        "order_id":   order_id,
        "created_at": datetime.now().isoformat(),
        "expires_at": None,
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
    data = request.get_json(silent=True) or {}
    if not _check_admin(data): return jsonify({"error": "Unauthorized"}), 401

    key = data.get("key", "").strip().upper()
    db  = load_db()

    if key not in db: return jsonify({"error": "Key not found"}), 404

    db[key]["revoked"] = True
    db[key]["revoked_at"] = datetime.now().isoformat()
    save_db(db)

    return jsonify({"message": f"Key {key} revoked."})

@app.route("/admin/list", methods=["POST"])
def admin_list():
    data = request.get_json(silent=True) or {}
    if not _check_admin(data): return jsonify({"error": "Unauthorized"}), 401
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
