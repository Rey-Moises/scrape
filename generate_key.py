"""
Cappy Works — ProPHBot Key Generator
Run this locally to generate a key WITHOUT the server.
Use when the server is down or for manual key generation.

Usage:
    python generate_key.py --tier script --buyer "John" --order FVR-123
"""
import argparse
import hashlib
import hmac
import secrets

# ── CHANGE THIS TO MATCH YOUR SERVER'S SECRET_KEY ENV VAR ──
SECRET_KEY = "change_this_in_production_env"

TIERS = ["script", "setup", "dfy"]

def generate_key(tier: str, buyer: str = "", order_id: str = "") -> str:
    raw     = secrets.token_hex(8).upper()
    payload = f"{tier}:{raw}:{buyer}"
    sig     = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:8].upper()
    key     = f"CW-{raw[:4]}-{raw[4:8]}-{sig[:4]}-{sig[4:8]}"
    return key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a ProPHBot license key")
    parser.add_argument("--tier",     default="script", choices=TIERS)
    parser.add_argument("--buyer",    default="")
    parser.add_argument("--order",    default="")
    args = parser.parse_args()

    key = generate_key(args.tier, args.buyer, args.order)
    print(f"\n{'='*50}")
    print(f"  Tier:     {args.tier.upper()}")
    print(f"  Buyer:    {args.buyer or '(not set)'}")
    print(f"  Order:    {args.order or '(not set)'}")
    print(f"\n  KEY:  {key}")
    print(f"{'='*50}\n")
    print("Send this key to the buyer. They save it in prophbot.key")
