from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
import random
import time
import re
import os
import uuid
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import config
import db

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ================= 1. Session cookie settings (used by /admin only) =================
# The admin panel is opened directly on the backend's own domain, not from the
# GitHub Pages frontend, so it does not need a cross-site cookie. Using "Lax"
# instead of "None" meaningfully reduces CSRF exposure on /admin/* routes.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.permanent_session_lifetime = 60 * 60 * 24 * 7

# ================= 2. CORS (frontend <-> backend) =================
# Regular users authenticate with a bearer token (Authorization header), not
# cookies, so this only needs to allow the token header through for the
# GitHub Pages origin(s). Origins can be extended via config.ALLOWED_ORIGINS
# without touching this file again.
ALLOWED_ORIGINS = getattr(config, "ALLOWED_ORIGINS", ["https://duttaanubhab777-code.github.io"])
CORS(app, supports_credentials=True, origins=ALLOWED_ORIGINS, allow_headers=["Content-Type", "Authorization"])

EMAIL_REGEX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MIN_PASSWORD_LENGTH = 8

db.init_db()

# ================= 3. In-memory stores =================
# These intentionally stay in RAM (not the database) to keep the free-tier
# deployment simple. A server restart clears active sessions and any OTP
# that was mid-flow, which is an acceptable trade-off for a small project —
# but see TOKEN_MAX_AGE_SECONDS below for automatic expiry while the server
# *is* running.
pending_signups = {}          # email -> {name, password_hash, otp, expires_at, attempts, last_sent}
reset_otp_store = {}          # email -> {otp, expires_at, attempts, last_sent}
active_tokens = {}            # token -> {"email": str, "created_at": float, "last_seen": float}
login_attempt_log = {}        # email -> [timestamps of recent failed logins]
admin_login_attempt_log = {}  # ip -> [timestamps of recent failed admin logins]

TOKEN_MAX_AGE_SECONDS = getattr(config, "TOKEN_MAX_AGE_SECONDS", 7 * 24 * 60 * 60)   # 7 days
PRESENCE_ONLINE_WINDOW_SECONDS = getattr(config, "PRESENCE_ONLINE_WINDOW_SECONDS", 90)
LOGIN_MAX_ATTEMPTS = getattr(config, "LOGIN_MAX_ATTEMPTS", 5)
LOGIN_ATTEMPT_WINDOW_SECONDS = getattr(config, "LOGIN_ATTEMPT_WINDOW_SECONDS", 15 * 60)
OTP_MAX_VERIFY_ATTEMPTS = 5


def send_otp_email(to_email, otp, purpose="login"):
    subject = "Your Beyonder AI Verification Code"
    body = (
        f"Hello,\n\nYour one-time verification code for Beyonder AI is:\n\n    {otp}\n\n"
        f"This code will expire in {config.OTP_EXPIRY_SECONDS // 60} minutes.\n\n— Beyonder AI"
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.GMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(config.GMAIL_ADDRESS, config.GMAIL_APP_PASSWORD)
        server.sendmail(config.GMAIL_ADDRESS, [to_email], msg.as_string())


# ================= 4. Presence / token helpers =================

def _prune_expired_tokens():
    now = time.time()
    expired = [t for t, info in active_tokens.items() if now - info["created_at"] > TOKEN_MAX_AGE_SECONDS]
    for t in expired:
        active_tokens.pop(t, None)


def _touch_presence(token):
    if token in active_tokens:
        active_tokens[token]["last_seen"] = time.time()


def get_online_users():
    """Returns {email: last_seen_timestamp} for every user with at least
    one token active within the last PRESENCE_ONLINE_WINDOW_SECONDS."""
    _prune_expired_tokens()
    now = time.time()
    online = {}
    for info in active_tokens.values():
        if now - info["last_seen"] <= PRESENCE_ONLINE_WINDOW_SECONDS:
            email = info["email"]
            if email not in online or info["last_seen"] > online[email]:
                online[email] = info["last_seen"]
    return online


# ================= 5. Rate limiting helpers (login brute-force protection) =================

def _is_rate_limited(log_dict, key, max_attempts, window_seconds):
    now = time.time()
    attempts = [t for t in log_dict.get(key, []) if now - t < window_seconds]
    log_dict[key] = attempts
    return len(attempts) >= max_attempts


def _record_attempt(log_dict, key):
    log_dict.setdefault(key, []).append(time.time())


def _clear_attempts(log_dict, key):
    log_dict.pop(key, None)


# ================= 6. Auth decorators =================

def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token or token not in active_tokens:
            return jsonify({"success": False, "message": "Login required."}), 401

        info = active_tokens[token]
        if time.time() - info["created_at"] > TOKEN_MAX_AGE_SECONDS:
            active_tokens.pop(token, None)
            return jsonify({"success": False, "message": "Session expired. Please log in again."}), 401

        _touch_presence(token)
        request.user_email = info["email"]
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """For human-facing pages — redirects to the admin login screen."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_home"))
        return view(*args, **kwargs)
    return wrapped


def admin_api_required(view):
    """For JSON endpoints used by the dashboard's own JavaScript — returns a
    401 JSON response instead of an HTML redirect, which is what fetch()
    from the dashboard actually needs."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"success": False, "message": "Admin session required."}), 401
        return view(*args, **kwargs)
    return wrapped


@app.template_filter("datetimeformat")
def datetimeformat(value):
    try:
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


@app.template_filter("timeago")
def timeago(value):
    try:
        seconds = max(0, time.time() - value)
    except Exception:
        return "-"
    if seconds < 60:
        return "just now"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes}m ago"
    hours = int(minutes // 60)
    return f"{hours}h ago"


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.teardown_appcontext
def _close_db(exception):
    db.close_db(exception)


# ================= 7. Health check (useful for uptime monitors) =================
@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "time": time.time()})


# ================= AUTH API: LOGIN =================
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "message": "Please enter both email and password."}), 400

    if _is_rate_limited(login_attempt_log, email, LOGIN_MAX_ATTEMPTS, LOGIN_ATTEMPT_WINDOW_SECONDS):
        return jsonify({
            "success": False,
            "message": "Too many failed attempts. Please try again in a few minutes."
        }), 429

    user = db.get_user_by_email(email)
    if not user or not check_password_hash(user["password_hash"], password):
        _record_attempt(login_attempt_log, email)
        db.log_login_attempt(email, client_ip(), success=False)
        return jsonify({"success": False, "message": "Incorrect email or password."}), 401

    _clear_attempts(login_attempt_log, email)
    db.update_last_login(email)
    db.log_login_attempt(email, client_ip(), success=True)

    _prune_expired_tokens()
    token = str(uuid.uuid4())
    now = time.time()
    active_tokens[token] = {"email": email, "created_at": now, "last_seen": now}

    return jsonify({"success": True, "message": "Login successful!", "token": token})


# ================= AUTH API: SIGN UP =================
@app.route("/api/signup/send-otp", methods=["POST"])
def api_signup_send_otp():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name or not email or not password:
        return jsonify({"success": False, "message": "Please fill in all fields."}), 400
    if not EMAIL_REGEX.match(email):
        return jsonify({"success": False, "message": "Please enter a valid email address."}), 400
    if len(password) < MIN_PASSWORD_LENGTH:
        return jsonify({"success": False, "message": f"Password must be at least {MIN_PASSWORD_LENGTH} characters."}), 400
    if db.get_user_by_email(email):
        return jsonify({"success": False, "message": "An account with this email already exists. Please log in."}), 409

    existing = pending_signups.get(email)
    now = time.time()
    if existing and now - existing["last_sent"] < config.OTP_RESEND_COOLDOWN_SECONDS:
        wait = int(config.OTP_RESEND_COOLDOWN_SECONDS - (now - existing["last_sent"]))
        return jsonify({"success": False, "message": f"Please wait {wait} seconds before requesting another code."}), 429

    otp = f"{random.randint(0, 999999):06d}"
    expires_at = now + config.OTP_EXPIRY_SECONDS
    pending_signups[email] = {
        "name": name,
        "password_hash": generate_password_hash(password),
        "otp": otp,
        "expires_at": expires_at,
        "attempts": 0,
        "last_sent": now,
    }
    try:
        send_otp_email(email, otp)
    except Exception:
        return jsonify({"success": False, "message": "Failed to send verification code. Please try again."}), 500

    return jsonify({
        "success": True,
        "message": "Verification code sent. Please check your email.",
        "expires_in": config.OTP_EXPIRY_SECONDS,
        "resend_after": config.OTP_RESEND_COOLDOWN_SECONDS,
    })


@app.route("/api/signup/verify-otp", methods=["POST"])
def api_signup_verify_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    record = pending_signups.get(email)
    if not record:
        return jsonify({"success": False, "message": "No pending signup found. Please start again."}), 400

    # Bug fix: previously the OTP never actually expired here, and there was
    # no limit on verification attempts (a 6-digit code could be brute-forced).
    if time.time() > record["expires_at"]:
        pending_signups.pop(email, None)
        return jsonify({"success": False, "message": "This verification code has expired. Please sign up again."}), 400

    record["attempts"] += 1
    if record["attempts"] > OTP_MAX_VERIFY_ATTEMPTS:
        pending_signups.pop(email, None)
        return jsonify({"success": False, "message": "Too many incorrect attempts. Please sign up again."}), 429

    if otp != record["otp"]:
        return jsonify({"success": False, "message": "Incorrect verification code."}), 400

    db.create_user(record["name"], email, record["password_hash"])
    pending_signups.pop(email, None)
    db.update_last_login(email)

    _prune_expired_tokens()
    token = str(uuid.uuid4())
    now = time.time()
    active_tokens[token] = {"email": email, "created_at": now, "last_seen": now}

    return jsonify({"success": True, "message": "Account created — you're logged in!", "token": token})


# ================= API: ME & LOGOUT =================
@app.route("/api/me")
def api_me():
    token = request.headers.get("Authorization")
    if token and token in active_tokens:
        info = active_tokens[token]
        if time.time() - info["created_at"] <= TOKEN_MAX_AGE_SECONDS:
            _touch_presence(token)
            return jsonify({"logged_in": True, "email": info["email"]})
        active_tokens.pop(token, None)
    return jsonify({"logged_in": False})


@app.route("/api/logout", methods=["POST", "GET"])
def api_logout():
    token = request.headers.get("Authorization")
    if token in active_tokens:
        del active_tokens[token]
    return jsonify({"success": True, "message": "Logged out successfully."})


# ================= CHAT SAVE API =================
@app.route("/api/save-chat", methods=["POST"])
@api_login_required
def save_chat():
    data = request.get_json(silent=True) or {}
    user_message = data.get("user_message", "")
    ai_response = data.get("ai_response", "")

    email = request.user_email
    db.save_chat(email, user_message, ai_response, source="ai")
    return jsonify({"success": True})


# ================= NEW: ADMIN -> USER LIVE MESSAGE CHANNEL =================
@app.route("/api/check-messages", methods=["GET"])
@api_login_required
def api_check_messages():
    """Polled periodically by the frontend so an admin can drop a message
    directly into a specific user's live chat (e.g. a support reply or an
    announcement) without the user needing to do anything."""
    try:
        since_id = int(request.args.get("since_id", 0))
    except (TypeError, ValueError):
        since_id = 0

    rows = db.get_new_admin_messages(request.user_email, since_id)
    messages = [{"id": r["id"], "text": r["ai_response"], "timestamp": r["timestamp"]} for r in rows]
    return jsonify({"success": True, "messages": messages})


# ================= ADMIN PANEL: LOGIN / LOGOUT =================
@app.route("/admin", methods=["GET"])
def admin_home():
    if session.get("is_admin"):
        return render_template(
            "admin_dashboard.html",
            users=db.get_all_users(),
            chats=db.get_all_chats(),
            logs=db.get_all_login_logs(),
            online_count=len(get_online_users()),
        )
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    ip = client_ip()
    if _is_rate_limited(admin_login_attempt_log, ip, LOGIN_MAX_ATTEMPTS, LOGIN_ATTEMPT_WINDOW_SECONDS):
        return render_template("admin_login.html", error="Too many failed attempts. Please try again later.")

    if request.form.get("password", "") == config.ADMIN_PASSWORD:
        _clear_attempts(admin_login_attempt_log, ip)
        session.permanent = True
        session["is_admin"] = True
        return redirect(url_for("admin_home"))

    _record_attempt(admin_login_attempt_log, ip)
    return render_template("admin_login.html", error="Incorrect password.")


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_home"))


@app.route("/admin/delete-user", methods=["POST"])
@admin_required
def admin_delete_user():
    email = request.form.get("email", "")
    if email:
        db.delete_user(email)
    return redirect(url_for("admin_home"))


# ================= NEW: ADMIN JSON APIs (presence, live chat, messaging) =================

@app.route("/admin/api/online-users", methods=["GET"])
@admin_api_required
def admin_api_online_users():
    """Powers the auto-refreshing 'Online Now' panel on the dashboard."""
    online = get_online_users()
    users_by_email = {u["email"]: u["name"] for u in db.get_all_users()}
    result = [
        {
            "email": email,
            "name": users_by_email.get(email, email),
            "last_seen": last_seen,
        }
        for email, last_seen in online.items()
    ]
    result.sort(key=lambda u: u["last_seen"], reverse=True)
    return jsonify({"success": True, "online_users": result, "count": len(result)})


@app.route("/admin/api/user-chats/<path:email>", methods=["GET"])
@admin_api_required
def admin_api_user_chats(email):
    """Returns a specific user's full chat history so the admin can watch
    it live (the dashboard polls this every few seconds while the panel
    for that user is open)."""
    email = email.strip().lower()
    rows = db.get_chats_for_user(email, limit=500)
    chats = [
        {
            "id": r["id"],
            "user_message": r["user_message"],
            "ai_response": r["ai_response"],
            "timestamp": r["timestamp"],
            "source": r["source"],
        }
        for r in rows
    ]
    return jsonify({"success": True, "email": email, "chats": chats})


@app.route("/admin/api/send-message", methods=["POST"])
@admin_api_required
def admin_api_send_message():
    """Lets the admin type a fully custom message and have it appear
    directly inside a specific user's chat, as if it came from Beyonder AI."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    message = (data.get("message") or "").strip()

    if not email or not message:
        return jsonify({"success": False, "message": "Both email and message are required."}), 400
    if not db.get_user_by_email(email):
        return jsonify({"success": False, "message": "No such user exists."}), 404

    new_id = db.save_admin_message(email, message)
    return jsonify({"success": True, "id": new_id})


# ================= AUTH API: FORGOT PASSWORD =================
@app.route("/api/forgot-password/send-otp", methods=["POST"])
def api_forgot_send_otp():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or not EMAIL_REGEX.match(email):
        return jsonify({"success": False, "message": "Please enter a valid email address."}), 400

    user = db.get_user_by_email(email)
    if not user:
        # Deliberately generic — avoids leaking whether an email is registered.
        return jsonify({"success": True, "message": "If this email is registered, a verification code has been sent."})

    existing = reset_otp_store.get(email)
    now = time.time()
    if existing and now - existing["last_sent"] < config.OTP_RESEND_COOLDOWN_SECONDS:
        wait = int(config.OTP_RESEND_COOLDOWN_SECONDS - (now - existing["last_sent"]))
        return jsonify({"success": False, "message": f"Please wait {wait} seconds before requesting another code."}), 429

    otp = f"{random.randint(0, 999999):06d}"
    reset_otp_store[email] = {
        "otp": otp,
        "expires_at": now + config.OTP_EXPIRY_SECONDS,
        "attempts": 0,
        "last_sent": now,
    }
    try:
        send_otp_email(email, otp, purpose="reset")
    except Exception:
        return jsonify({"success": False, "message": "Failed to send verification code. Please try again."}), 500

    return jsonify({
        "success": True,
        "message": "If this email is registered, a verification code has been sent.",
        "expires_in": config.OTP_EXPIRY_SECONDS,
        "resend_after": config.OTP_RESEND_COOLDOWN_SECONDS,
    })


@app.route("/api/forgot-password/reset", methods=["POST"])
def api_forgot_reset():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()
    new_password = data.get("new_password") or ""

    record = reset_otp_store.get(email)
    if not record:
        return jsonify({"success": False, "message": "Please request a verification code first."}), 400
    if time.time() > record["expires_at"]:
        reset_otp_store.pop(email, None)
        return jsonify({"success": False, "message": "This verification code has expired."}), 400

    record["attempts"] += 1
    if record["attempts"] > OTP_MAX_VERIFY_ATTEMPTS:
        reset_otp_store.pop(email, None)
        return jsonify({"success": False, "message": "Too many incorrect attempts. Please request a new code."}), 429

    if otp != record["otp"]:
        return jsonify({"success": False, "message": "Incorrect verification code."}), 400
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return jsonify({"success": False, "message": f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."}), 400

    user = db.get_user_by_email(email)
    if not user:
        reset_otp_store.pop(email, None)
        return jsonify({"success": False, "message": "No account exists with this email."}), 404

    db.update_password(email, generate_password_hash(new_password))
    reset_otp_store.pop(email, None)

    return jsonify({"success": True, "message": "Password updated successfully. Please log in."})


if __name__ == "__main__":
    # debug=True must never run on a public deployment (it exposes the
    # Werkzeug debugger). This now defaults to off and only turns on if
    # you explicitly set FLASK_DEBUG=1 for local development.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=5000)
