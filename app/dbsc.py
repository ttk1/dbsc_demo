import time

import jwt
from jwt.algorithms import ECAlgorithm

# In-memory stores
sessions = {}  # session_id -> {public_key_jwk, challenge, cookie_value, created_at}
pending_registrations = {}  # challenge -> {cookie_value, created_at}

PENDING_REGISTRATION_TTL = 300  # seconds


def _cleanup_pending_registrations():
    """期限切れの pending_registrations を削除する。"""
    now = time.time()
    expired = [c for c, r in pending_registrations.items()
               if now - r["created_at"] > PENDING_REGISTRATION_TTL]
    for c in expired:
        del pending_registrations[c]


def validate_registration_jwt(token):
    """Validate a DBSC registration JWT (§9.10).

    Returns dict with public_key_jwk and cookie_value, or None on failure.

    --- 仕様と Chrome 145 の差異 ---
    仕様 §9.10 では公開鍵はペイロードの "key" クレームに含まれると定義されている。
    しかし Chrome 145 は JWS ヘッダーの "jwk" パラメータ (RFC 7515) に公開鍵を含める。
    この実装では仕様準拠の "key" を優先しつつ、Chrome 互換でヘッダーの "jwk" にも
    フォールバックする。いずれの場合も、その公開鍵で JWT 署名を検証するため
    セキュリティ上の差異はない（自身の秘密鍵で署名した JWT に含まれる公開鍵を
    取り出して検証するので、改ざんされていれば署名検証が失敗する）。
    """
    _cleanup_pending_registrations()

    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != "dbsc+jwt" or header.get("alg") != "ES256":
            return None

        # 仕様: payload "key" / Chrome 145: header "jwk"
        unverified_payload = jwt.decode(
            token, options={"verify_signature": False},
            algorithms=["ES256"],
        )
        jwk_data = unverified_payload.get("key") or header.get("jwk")
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

        return {
            "public_key_jwk": jwk_data,
            "cookie_value": registration["cookie_value"],
        }
    except Exception as e:
        print(f"Registration JWT validation error: {e}")
        return None


def validate_refresh_jwt(token, session):
    """Validate a DBSC refresh JWT against a stored session's public key.

    Returns True on success, None on failure.

    --- 仕様と Chrome 145 の差異 ---
    仕様 §9.10 ではリフレッシュ JWT のペイロードに "sub" (セッション識別子) が
    MUST とされている。しかし Chrome 145 は "sub" を含めない。
    この実装では "sub" の検証を行わない。セキュリティ上の影響はない：
    リフレッシュ時はヘッダー Sec-Secure-Session-Id でセッションを特定し、
    そのセッションに紐づく公開鍵で JWT 署名を検証する。署名が通る = 正しい
    セッションの秘密鍵を持っているので、"sub" による二重確認は不要。
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
