import secrets
import time

from flask import Flask, jsonify, make_response, render_template, request

from app.dbsc import (
    pending_registrations,
    sessions,
    validate_refresh_jwt,
    validate_registration_jwt,
)

app = Flask(__name__)

COOKIE_NAME = "auth_cookie"
COOKIE_MAX_AGE = 600  # seconds


def _set_auth_cookie(resp, value):
    resp.set_cookie(
        COOKIE_NAME,
        value,
        max_age=COOKIE_MAX_AGE,
        domain="localhost",
        httponly=True,
        samesite="Lax",
    )


def _session_config(session_id):
    return {
        "session_identifier": session_id,
        "refresh_url": "/dbsc/refresh",
        "scope": {
            "origin": "http://localhost:8080",
            "include_site": False,
            "scope_specification": [
                {"type": "include", "domain": "localhost", "path": "/"}
            ],
        },
        "credentials": [
            {
                "type": "cookie",
                "name": COOKIE_NAME,
                "attributes": "Domain=localhost; Path=/; HttpOnly; SameSite=Lax",
            }
        ],
    }


# --- Pages ---


@app.route("/")
def index():
    cookie = request.cookies.get(COOKIE_NAME)
    logged_in = any(s.get("cookie_value") == cookie for s in sessions.values())
    return render_template("index.html", logged_in=logged_in)


# --- Auth ---


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if data.get("username") != "admin" or data.get("password") != "password":
        return jsonify({"error": "Invalid credentials"}), 401

    # Clear any existing sessions
    sessions.clear()

    challenge = secrets.token_urlsafe(32)
    cookie_value = secrets.token_urlsafe(32)

    pending_registrations[challenge] = {
        "cookie_value": cookie_value,
        "created_at": time.time(),
    }

    resp = make_response(jsonify({"status": "ok"}))
    _set_auth_cookie(resp, cookie_value)
    resp.headers["Secure-Session-Registration"] = (
        f'(ES256);path="/dbsc/start";challenge="{challenge}"'
    )
    return resp


@app.route("/logout", methods=["POST"])
def logout():
    cookie = request.cookies.get(COOKIE_NAME)
    for sid in [s for s, d in sessions.items() if d.get("cookie_value") == cookie]:
        del sessions[sid]
    resp = make_response(jsonify({"status": "ok"}))
    resp.delete_cookie(COOKIE_NAME)
    return resp


# --- DBSC Protocol ---


@app.route("/dbsc/start", methods=["POST"])
def dbsc_start():
    token = request.headers.get("Secure-Session-Response", "").strip('"')
    if not token:
        return jsonify({"error": "Missing Secure-Session-Response"}), 400

    result = validate_registration_jwt(token)
    if result is None:
        return jsonify({"error": "Invalid JWT"}), 400

    session_id = secrets.token_urlsafe(16)
    new_challenge = secrets.token_urlsafe(32)

    sessions[session_id] = {
        "public_key_jwk": result["public_key_jwk"],
        "challenge": new_challenge,
        "cookie_value": result["cookie_value"],
        "created_at": time.time(),
    }

    resp = make_response(jsonify(_session_config(session_id)))
    _set_auth_cookie(resp, result["cookie_value"])
    return resp


@app.route("/dbsc/refresh", methods=["POST"])
def dbsc_refresh():
    session_id = request.headers.get("Sec-Secure-Session-Id", "").strip('"')
    token = request.headers.get("Secure-Session-Response", "").strip('"')

    if not session_id or session_id not in sessions:
        return jsonify({"error": "Unknown session"}), 400

    session = sessions[session_id]

    # No JWT or invalid JWT -> send challenge with 403
    if not token or validate_refresh_jwt(token, session) is None:
        new_challenge = secrets.token_urlsafe(32)
        session["challenge"] = new_challenge
        resp = make_response("", 403)
        resp.headers["Secure-Session-Challenge"] = (
            f'"{new_challenge}";id="{session_id}"'
        )
        return resp

    # Valid JWT -> issue new cookie
    cookie_value = secrets.token_urlsafe(32)
    new_challenge = secrets.token_urlsafe(32)
    session["cookie_value"] = cookie_value
    session["challenge"] = new_challenge

    resp = make_response("", 200)
    _set_auth_cookie(resp, cookie_value)
    resp.headers["Secure-Session-Challenge"] = f'"{new_challenge}";id="{session_id}"'
    return resp


# --- Status API ---


@app.route("/api/status")
def api_status():
    cookie = request.cookies.get(COOKIE_NAME)
    for sid, s in sessions.items():
        if s.get("cookie_value") == cookie:
            return jsonify(
                {
                    "authenticated": True,
                    "session_id": sid,
                    "cookie_present": True,
                }
            )
    return jsonify({"authenticated": False, "cookie_present": cookie is not None})


# --- Main ---


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
