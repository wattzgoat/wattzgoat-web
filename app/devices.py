import base64
import json

import jwt

# ---------------------------------------------------------------------------
# Device tokens authenticate a METER (not a person) to /api/telemetry.
# Issued the same way jwt.io itself would build one: HS256, a short fixed
# secret. Weak two ways -- the secret is a guessable string if it ever
# leaks, and more importantly, the verifier below trusts whatever
# algorithm the token itself claims in its header and skips signature
# checking entirely when that claim is "none". Insecure JWT exercise
# instance -- flagged in app/api.py's telemetry() when this path is taken.
#
# Note for anyone tempted to "simplify" this with a plain jwt.decode(...,
# algorithms=["HS256", "none"]) call: PyJWT's NoneAlgorithm.verify() is
# hardcoded to always return False, specifically to stop exactly that
# shortcut from working. The branch below deliberately bypasses the
# library for the alg=none case instead of fighting it -- which is also
# the more realistic shape of how this bug shows up in real code.
# ---------------------------------------------------------------------------
DEVICE_JWT_SECRET = "wattzgoat-device-key"


def issue_device_token(meter_code: str) -> str:
    return jwt.encode({"meter_code": meter_code}, DEVICE_JWT_SECRET, algorithm="HS256")


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def verify_device_token(token: str):
    """Returns (meter_code, used_none_alg) -- meter_code is None if the
    token doesn't verify at all."""
    try:
        header_b64, payload_b64, _sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
    except Exception:
        return None, False

    if header.get("alg") == "none":
        try:
            payload = json.loads(_b64url_decode(payload_b64))
            return payload.get("meter_code"), True
        except Exception:
            return None, False

    try:
        payload = jwt.decode(token, DEVICE_JWT_SECRET, algorithms=["HS256"])
        return payload.get("meter_code"), False
    except jwt.InvalidTokenError:
        return None, False
