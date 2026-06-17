#!/usr/bin/env python3
"""Decode the proxy's cloudflared tunnel token (base64url JSON). Prints AccountTag and
TunnelID; the reusable secret is redacted, never printed. The token is not bundled here,
pass it in: decode_argo.py <token>  or  ARGO_AUTH=<token> decode_argo.py"""
import sys, os, json, base64

token = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ARGO_AUTH")
if not token:
    sys.exit("no token: pass it as argv[1] or set ARGO_AUTH")

obj = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
a, t = obj["a"], obj["t"]
print(f"len(token) = {len(token)}")
print('decoded JSON: {' + f'"a":"{a}",')
print(f'               "t":"{t}",')
print('               "s":"<redacted: base64 of the tunnel secret>"}')
print(f"  a (AccountTag) = {a:<38}<- indicator / takedown anchor")
print(f"  t (TunnelID)   = {t:<38}<- indicator / takedown anchor")
print("  s decoded      = <redacted>   (the reusable tunnel secret, a UUID as a 36-byte ASCII string)")
