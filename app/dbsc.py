import time
import jwt
from jwt.algorithms import ECAlgorithm

# In-memory stores
sessions = {}  # session_id -> {public_key_jwk, challenge, cookie_value, created_at}
pending_registrations = {}  # challenge -> {cookie_value, created_at}


def validate_registration_jwt(token):
    """Validate a DBSC registration JWT.

    Registration JWT format:
      Header: {"alg": "ES256", "typ": "dbsc+jwt", "jwk": {EC public key}}
      Payload: {"jti": "<challenge>", "aud": "<endpoint>", "iat": <timestamp>}

    Returns dict with public_key_jwk and cookie_value, or None on failure.
    """
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "dbsc+jwt" or header.get("alg") != "ES256":
            return None

        jwk_data = header.get("jwk")
        if not jwk_data:
            return None

        public_key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(jwk_data)
        payload = jwt.decode(
            token, public_key, algorithms=["ES256"],
            options={"verify_aud": False, "verify_exp": False},
        )

        challenge = payload.get("jti")
        if not challenge or challenge not in pending_registrations:
            return None

        registration = pending_registrations.pop(challenge)
        if time.time() - registration["created_at"] > 300:
            return None

        return {
            "public_key_jwk": jwk_data,
            "cookie_value": registration["cookie_value"],
        }
    except Exception as e:
        print(f"Registration JWT validation error: {e}")
        return None


def validate_refresh_jwt(token, session):
    """Validate a DBSC refresh JWT against a stored session's public key.

    Refresh JWT format:
      Header: {"alg": "ES256", "typ": "dbsc+jwt"} (no jwk)
      Payload: {"jti": "<challenge>"}

    Returns True on success, None on failure.
    """
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "dbsc+jwt" or header.get("alg") != "ES256":
            return None

        public_key = ECAlgorithm(ECAlgorithm.SHA256).from_jwk(session["public_key_jwk"])
        payload = jwt.decode(
            token, public_key, algorithms=["ES256"],
            options={"verify_aud": False, "verify_exp": False},
        )

        if payload.get("jti") != session.get("challenge"):
            return None

        return True
    except Exception as e:
        print(f"Refresh JWT validation error: {e}")
        return None
