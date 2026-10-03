import base64
import json

import jwt

from . import flags
from . import hardening

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
        if hardening.is_hardened(flags.JWT_EXERCISE):
            return None, False
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
