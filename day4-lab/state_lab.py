"""Day 4 state lab: the three common ways a web app remembers who you are,
side by side, on ONE local server so you can compare them with curl.

  A  /session/*  server-side session: random id in a cookie, data stays on the server
  B  /cookie/*   Flask signed-cookie session: the data itself lives in the cookie
  C  /jwt/*      JWT bearer token: signed claims the client sends in a header

Safety rules baked in:
  * binds to 127.0.0.1 only, debug off
  * lab users and passwords are fake; the JWT secret is WEAK ON PURPOSE (mission 7)
  * the JWT code is hand-written TEACHING code so you can see the three parts.
    In a real app use a maintained library (PyJWT, jsonwebtoken), never your own.

Run:    python state_lab.py                         -> http://127.0.0.1:5060
Harden: LAB_JWT_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))") python state_lab.py
Expiry: LAB_JWT_TTL=3 python state_lab.py           (tokens live 3 seconds)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

HOST = "127.0.0.1"  # hardcoded: this lab never listens on other interfaces
PORT = int(os.environ.get("LAB_PORT", "5060"))
JWT_SECRET = os.environ.get("LAB_JWT_SECRET", "lab-weak-secret")  # weak on purpose
JWT_TTL = int(os.environ.get("LAB_JWT_TTL", "300"))  # seconds

app = Flask(__name__)
app.secret_key = os.environ.get("LAB_COOKIE_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Fake lab accounts. Passwords are stored as hashes, like a real app would.
USERS: dict[str, dict[str, str]] = {
    "lab-user": {"hash": generate_password_hash("lab-password"), "role": "user"},
    "lab-admin": {"hash": generate_password_hash("lab-admin-password"), "role": "admin"},
}
_DUMMY_HASH = generate_password_hash("never-matches")  # keeps login timing uniform


def authenticate() -> tuple[str, str] | None:
    """AUTHENTICATION: who are you? Returns (username, role) or None."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    user = USERS.get(username)
    ok = check_password_hash(user["hash"] if user else _DUMMY_HASH, password)
    return (username, user["role"]) if user and ok else None


def bad_login():  # type: ignore[no-untyped-def]
    return jsonify(error="Invalid username or password."), 401


def need_login():  # type: ignore[no-untyped-def]
    return jsonify(error="Not authenticated: no valid session or token."), 401


def need_admin():  # type: ignore[no-untyped-def]
    # 403 = we know who you are, but you are not ALLOWED. This is AUTHORIZATION.
    return jsonify(error="Forbidden: admin role required."), 403


@app.get("/")
def index():  # type: ignore[no-untyped-def]
    return jsonify(
        server_side_session=["POST /session/login", "GET /session/me", "GET /session/admin", "POST /session/logout"],
        signed_cookie_session=["POST /cookie/login", "GET /cookie/me", "GET /cookie/admin", "POST /cookie/logout"],
        jwt=["POST /jwt/login", "GET /jwt/me", "GET /jwt/admin", "POST /jwt/logout"],
        users={"lab-user": "role user", "lab-admin": "role admin"},
    )


# ---------------------------------------------------------------- A: server-side
SESSIONS: dict[str, dict[str, Any]] = {}  # sid -> data. The ONLY place the data lives.


def server_session() -> dict[str, Any] | None:
    sid = request.cookies.get("sid")
    return SESSIONS.get(sid) if sid else None


@app.post("/session/login")
def session_login():  # type: ignore[no-untyped-def]
    who = authenticate()
    if not who:
        return bad_login()
    sid = secrets.token_urlsafe(32)  # 256 random bits: nothing inside to decode or forge
    SESSIONS[sid] = {"user": who[0], "role": who[1], "created": int(time.time())}
    resp = jsonify(status="logged in", mechanism="server-side session")
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax", max_age=3600)
    return resp


@app.get("/session/me")
def session_me():  # type: ignore[no-untyped-def]
    s = server_session()
    return jsonify(user=s["user"], role=s["role"], mechanism="server-side session") if s else need_login()


@app.get("/session/admin")
def session_admin():  # type: ignore[no-untyped-def]
    s = server_session()
    if not s:
        return need_login()
    return jsonify(secret="admin-only data") if s["role"] == "admin" else need_admin()


@app.post("/session/logout")
def session_logout():  # type: ignore[no-untyped-def]
    SESSIONS.pop(request.cookies.get("sid", ""), None)  # server forgets: ANY copy of the cookie is now dead
    resp = jsonify(status="logged out (server record deleted)")
    resp.delete_cookie("sid")
    return resp


# ---------------------------------------------------------------- B: signed cookie
@app.post("/cookie/login")
def cookie_login():  # type: ignore[no-untyped-def]
    who = authenticate()
    if not who:
        return bad_login()
    session.clear()
    session["user"], session["role"] = who  # these values are stored INSIDE the cookie
    return jsonify(status="logged in", mechanism="signed cookie session")


@app.get("/cookie/me")
def cookie_me():  # type: ignore[no-untyped-def]
    if "user" not in session:
        return need_login()
    return jsonify(user=session["user"], role=session["role"], mechanism="signed cookie session")


@app.get("/cookie/admin")
def cookie_admin():  # type: ignore[no-untyped-def]
    if "user" not in session:
        return need_login()
    return jsonify(secret="admin-only data") if session.get("role") == "admin" else need_admin()


@app.post("/cookie/logout")
def cookie_logout():  # type: ignore[no-untyped-def]
    session.clear()  # tells THIS browser to drop it. The server keeps no record, so a copy still validates.
    return jsonify(status="logged out (browser told to forget; server holds nothing)")


# ---------------------------------------------------------------- C: JWT (teaching code)
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_sign(claims: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def jwt_verify(token: str, secret: str) -> dict[str, Any]:
    """Return the claims, or raise ValueError. Order matters: check the algorithm
    and signature BEFORE trusting anything inside the token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(b64url_decode(parts[0]))
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise ValueError("unsupported algorithm")  # rejects alg=none and any alg switch
    expected = hmac.new(secret.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(parts[2])):  # constant-time compare
        raise ValueError("bad signature")
    claims = json.loads(b64url_decode(parts[1]))
    if not isinstance(claims, dict):
        raise ValueError("bad claims")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or exp < time.time():
        raise ValueError("token expired")
    return claims


def bearer_claims() -> dict[str, Any] | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt_verify(auth[7:].strip(), JWT_SECRET)
    except ValueError:  # includes JSON, base64 and unicode decode errors
        return None


@app.post("/jwt/login")
def jwt_login():  # type: ignore[no-untyped-def]
    who = authenticate()
    if not who:
        return bad_login()
    now = int(time.time())
    token = jwt_sign({"sub": who[0], "role": who[1], "iat": now, "exp": now + JWT_TTL}, JWT_SECRET)
    return jsonify(access_token=token, token_type="Bearer", expires_in=JWT_TTL)


@app.get("/jwt/me")
def jwt_me():  # type: ignore[no-untyped-def]
    c = bearer_claims()
    if not c:
        resp = need_login()
        resp[0].headers["WWW-Authenticate"] = "Bearer"
        return resp
    return jsonify(user=c["sub"], role=c["role"], mechanism="JWT")


@app.get("/jwt/admin")
def jwt_admin():  # type: ignore[no-untyped-def]
    c = bearer_claims()
    if not c:
        return need_login()
    return jsonify(secret="admin-only data") if c.get("role") == "admin" else need_admin()


@app.post("/jwt/logout")
def jwt_logout():  # type: ignore[no-untyped-def]
    # Nothing to delete: the server stores nothing. The client throws the token away,
    # but a copy stays valid until "exp". That is the price of stateless tokens.
    return jsonify(status="client should discard the token", note="server cannot revoke it before exp")


if __name__ == "__main__":
    if JWT_SECRET == "lab-weak-secret":
        print("WARNING: JWT secret is WEAK ON PURPOSE (mission 7). Set LAB_JWT_SECRET to harden.")
    print(f"State lab on http://{HOST}:{PORT}  (PID {os.getpid()})")
    app.run(host=HOST, port=PORT, debug=False)
