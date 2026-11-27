"""Secure university student portal (Lab 5 target: `semgrep scan app_secure.py`).

Features: login with MFA, grades/attendance, assignment upload, lecturer messaging, profile update.
Control IDs in comments (e.g. 6.3.1) are the ASVS IDs used in Lab 1 and Lab 2.
"""
import base64
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import socket
import sqlite3
import struct
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import pyotp
import qrcode
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup, escape
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = Path(__file__).resolve().parent
ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password-for-timing")           # equalises timing when the username does not exist (4.2.1)
csrf = CSRFProtect()
audit_log = logging.getLogger("portal.audit")

MAX_FAILS, LOCK_SECONDS = 5, 15 * 60                         # 6.3.1 / 6.4.1 lockout
CAPTCHA_AFTER_IP_FAILS, IP_FAIL_LIMIT, IP_WINDOW = 3, 20, 300
IDLE_TIMEOUT, ABSOLUTE_TIMEOUT, PRE_MFA_TTL = 30 * 60, 8 * 3600, 300
MAX_UPLOAD = 5 * 1024 * 1024                                 # 5.2.1
UPLOADS_PER_HOUR = 10
ALLOWED_EXT = {"pdf", "txt", "png", "jpg"}
EICAR = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
COMMON_PASSWORDS = frozenset(
    "password password1 password123 123456789012 qwertyuiop12 letmein12345 welcome12345 admin1234567 "
    "iloveyou1234 changeme1234 passw0rd1234 abc123456789 111111111111 123123123123 qwerty123456 "
    "universityuni studentportal".split())                   # offline stand-in for a breached-password list (6.2.12)
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^[0-9+\-\s]{7,20}$")
URL_RE = re.compile(r"https?://[^\s<>\"']+")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,40}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL,
  email TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('student','lecturer')), pw_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '', totp_confirmed INTEGER NOT NULL DEFAULT 0, totp_last_step INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS courses (id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
  lecturer_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS enrolments (student_id INTEGER NOT NULL REFERENCES users(id), course_id INTEGER NOT NULL REFERENCES courses(id),
  PRIMARY KEY (student_id, course_id));
CREATE TABLE IF NOT EXISTS grades (id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id),
  course_id INTEGER NOT NULL REFERENCES courses(id), assessment TEXT NOT NULL, score INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS attendance (student_id INTEGER NOT NULL REFERENCES users(id), course_id INTEGER NOT NULL REFERENCES courses(id),
  total INTEGER NOT NULL, attended INTEGER NOT NULL, PRIMARY KEY (student_id, course_id));
CREATE TABLE IF NOT EXISTS submissions (id INTEGER PRIMARY KEY, course_id INTEGER NOT NULL REFERENCES courses(id),
  student_id INTEGER NOT NULL REFERENCES users(id), original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
  sha256 TEXT NOT NULL, size INTEGER NOT NULL, submitted_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id),
  recipient_id INTEGER NOT NULL REFERENCES users(id), subject TEXT NOT NULL, body TEXT NOT NULL, sent_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, user_id INTEGER, action TEXT NOT NULL,
  ip TEXT, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS login_failures (ip TEXT NOT NULL, ts INTEGER NOT NULL);
"""


# ------------------------------------------------------------------ app factory
def create_app(config=None):
    app = Flask(__name__)
    prod = os.environ.get("PORTAL_ENV", "dev") == "prod"
    app.config.update(
        DATABASE=os.environ.get("PORTAL_DB", str(BASE_DIR / "instance" / "portal.db")),
        UPLOAD_DIR=os.environ.get("PORTAL_UPLOADS", str(BASE_DIR / "instance" / "uploads")),
        SECRET_KEY=os.environ.get("PORTAL_SECRET_KEY") or _load_or_create_secret(),
        MAX_CONTENT_LENGTH=MAX_UPLOAD + 64 * 1024,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=prod,
        SESSION_COOKIE_NAME="portal_session",
        PROD=prod, CLAMAV=os.environ.get("PORTAL_CLAMAV") == "1",
        CLAMAV_HOST=os.environ.get("PORTAL_CLAMAV_HOST", "127.0.0.1"), CLAMAV_PORT=int(os.environ.get("PORTAL_CLAMAV_PORT", "3310")),
    )
    if config:
        app.config.update(config)
    if os.environ.get("PORTAL_BEHIND_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)       # outside the static folder (5.3.1)
    csrf.init_app(app)
    app.jinja_env.filters["linkify"] = linkify
    register_hooks(app)
    register_routes(app)
    with app.app_context():
        get_db().executescript(SCHEMA)
    return app


def _load_or_create_secret():
    path = BASE_DIR / "instance" / "secret_key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32))
    return path.read_text().strip()


# ------------------------------------------------------------------ helpers
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(_app().config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def _app():
    from flask import current_app
    return current_app


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit(action, result="OK", detail="", user_id=None):
    """Timestamped, user-attributed log of security events (Lab 2: repudiation controls)."""
    uid = user_id if user_id is not None else (g.user["id"] if g.get("user") else None)
    ip = request.remote_addr if request else None
    get_db().execute("INSERT INTO audit (ts, user_id, action, ip, result, detail) VALUES (?,?,?,?,?,?)",
                     (utcnow(), uid, action[:64], ip, result[:8], re.sub(r"[\r\n]+", " ", detail)[:255]))
    get_db().commit()
    audit_log.info("user=%s action=%s result=%s ip=%s", uid, action, result, ip)


def safe_filename(name):
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(". ")
    return name[:100] or "file"


def hash_password(pw):
    return ph.hash(pw)


def check_password_policy(pw, username=""):
    """6.2.1 / 6.2.12: length, no common/breached password, no username inside."""
    if len(pw) < 12 or len(pw) > 128:
        return "Password must be 12 to 128 characters."
    if pw.lower() in COMMON_PASSWORDS or len(set(pw)) < 5:
        return "That password is too common."
    if username and username.lower() in pw.lower():
        return "Password must not contain your username."
    return None


def verify_password(user, pw):
    try:
        return ph.verify(user["pw_hash"], pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_user(db, username, full_name, email, role, password):
    problem = check_password_policy(password, username)
    if problem or not USERNAME_RE.match(username) or role not in ("student", "lecturer"):
        raise ValueError(problem or "invalid user")
    cur = db.execute("INSERT INTO users (username, full_name, email, role, pw_hash) VALUES (?,?,?,?,?)",
                     (username, full_name, email, role, hash_password(password)))
    db.commit()
    return cur.lastrowid


def linkify(text):
    """1.2.1 / 1.2.2: output-encode everything; only http(s) URLs become links (no javascript:, data:, etc.)."""
    out, pos = [], 0
    for m in URL_RE.finditer(text or ""):
        out.append(escape(text[pos:m.start()]))
        url = m.group(0).rstrip(".,;:!?)")
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            out.append(Markup('<a href="{}" rel="noopener noreferrer nofollow" target="_blank">{}</a>').format(url, url))
        else:
            out.append(escape(url))
        out.append(escape(m.group(0)[len(url):]))
        pos = m.end()
    out.append(escape((text or "")[pos:]))
    return Markup("").join(out)


def captcha_token(answer, nonce):
    return hmac.new(_app().secret_key.encode(), f"{answer}:{nonce}".encode(), hashlib.sha256).hexdigest()


def new_captcha():
    a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
    nonce = secrets.token_hex(8)
    session["captcha"] = {"nonce": nonce, "tok": captcha_token(a + b, nonce)}       # answer is never readable from the cookie
    return f"What is {a} + {b}?"


def captcha_ok(answer):
    data = session.pop("captcha", None)
    if not data or not str(answer or "").strip().isdigit():
        return False
    return hmac.compare_digest(data["tok"], captcha_token(int(answer), data["nonce"]))


def recent_ip_failures():
    cutoff = int(time.time()) - IP_WINDOW
    return get_db().execute("SELECT COUNT(*) FROM login_failures WHERE ip=? AND ts>?", (request.remote_addr, cutoff)).fetchone()[0]


def register_failure(user):
    """Per-account lockout (6.3.1 / 6.4.1). Same code path whether or not the username exists."""
    db = get_db()
    db.execute("INSERT INTO login_failures (ip, ts) VALUES (?,?)", (request.remote_addr, int(time.time())))
    if user is not None:
        count = user["failed_count"] + 1
        locked = int(time.time()) + LOCK_SECONDS if count >= MAX_FAILS else 0
        db.execute("UPDATE users SET failed_count=?, locked_until=? WHERE id=?", (0 if locked else count, locked, user["id"]))
    db.commit()


def verify_totp(user, code):
    """6.3.3: TOTP with +/-1 step tolerance and single-use codes (replay blocked atomically)."""
    code = str(code or "").strip()
    if not user["totp_secret"] or len(code) != 6 or not code.isdigit():
        return False
    totp = pyotp.TOTP(user["totp_secret"])
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):
        if hmac.compare_digest(totp.at(step * 30), code):
            cur = get_db().execute("UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step<?", (step, user["id"], step))
            get_db().commit()
            return cur.rowcount == 1
    return False


def finish_login(user):
    session.clear()                                           # new session after authentication (7.2.4)
    session.permanent = False
    session.update(uid=user["id"], login_at=time.time(), seen=time.time(), sid=secrets.token_hex(16))
    get_db().execute("UPDATE users SET failed_count=0, locked_until=0 WHERE id=?", (user["id"],))
    get_db().commit()
    audit("login.success", user_id=user["id"])


# ------------------------------------------------------------------ malware / file checks (5.2.x, 5.3.x, 5.4.3)
class UploadError(Exception):
    pass


def validate_upload(filename, data):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT or not data or len(data) > MAX_UPLOAD:
        raise UploadError("File type or size not allowed.")
    ok = {"pdf": data.startswith(b"%PDF-"), "png": data.startswith(b"\x89PNG\r\n\x1a\n"), "jpg": data.startswith(b"\xff\xd8\xff"),
          "txt": b"\x00" not in data and _is_utf8(data)}[ext]
    if not ok:
        raise UploadError("File content does not match its type.")
    if EICAR in data:
        raise UploadError("File rejected by malware scan.")
    if _app().config["CLAMAV"]:
        _clamav_scan(data)


def _is_utf8(data):
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _clamav_scan(data):
    """INSTREAM scan against clamd. Fails secure: an unreachable scanner means the file is refused."""
    cfg = _app().config
    try:
        with socket.create_connection((cfg["CLAMAV_HOST"], cfg["CLAMAV_PORT"]), timeout=10) as s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), 8192):
                chunk = data[i:i + 8192]
                s.sendall(struct.pack("!I", len(chunk)) + chunk)
            s.sendall(struct.pack("!I", 0))
            reply = s.recv(1024)
    except OSError:
        raise UploadError("File rejected by malware scan.")
    if b"OK" not in reply or b"FOUND" in reply:
        raise UploadError("File rejected by malware scan.")


# ------------------------------------------------------------------ hooks (session, headers, errors)
def register_hooks(app):
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid is None:
            return
        now = time.time()
        if now - session.get("seen", 0) > IDLE_TIMEOUT or now - session.get("login_at", 0) > ABSOLUTE_TIMEOUT:
            session.clear()
            return
        row = get_db().execute("SELECT * FROM users WHERE id=? AND active=1", (uid,)).fetchone()
        if row is None:
            session.clear()
            return
        session["seen"] = now
        g.user = row

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        if app.config["PROD"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def err(code, msg):
        def handler(_e):
            return render_template("error.html", code=code, message=msg), code
        return handler

    for code, msg in ((400, "Bad request."), (403, "You are not allowed to do that."), (404, "Page not found."),
                      (413, "That upload is too large."), (429, "Too many attempts. Try again later."),
                      (500, "Something went wrong. Please try again later.")):
        app.register_error_handler(code, err(code, msg))              # no stack traces or internals (4.2.1 / SR error handling)


def login_required(role=None):
    def deco(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login"))
            if role and g.user["role"] != role:
                audit("access.denied", "DENY", request.path)
                abort(403)
            return view(*a, **kw)
        return wrapper
    return deco


# ------------------------------------------------------------------ routes
ROUTES = []


def route(rule, methods=("GET",)):
    """Collects view functions so create_app() can register them (keeps endpoint names equal to function names)."""
    def deco(view):
        ROUTES.append((rule, view.__name__, view, list(methods)))
        return view
    return deco


def register_routes(app):
    for rule, endpoint, view, methods in ROUTES:
        app.add_url_rule(rule, endpoint, view, methods=methods)


# ------------------------------------------------------------------ routes
@route("/")
def home():
    if g.user is None:
        return redirect(url_for("login"))
    return render_template("home.html")

# ---- Story 1: login (6.x, 4.2.1) ----
@route("/login", methods=("GET", "POST",))
def login():
    if g.user:
        return redirect(url_for("home"))
    db = get_db()
    fails = recent_ip_failures()
    if fails >= IP_FAIL_LIMIT:
        audit("login.ratelimited", "DENY")
        abort(429)
    need_captcha = fails >= CAPTCHA_AFTER_IP_FAILS
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()[:40]
        password = request.form.get("password", "")[:128]
        good_captcha = (not need_captcha) or captcha_ok(request.form.get("captcha"))
        user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        locked = user is not None and user["locked_until"] > time.time()
        if user is not None and not locked:
            ok = verify_password(user, password)
        else:
            verify_password({"pw_hash": DUMMY_HASH}, password)                  # same work for unknown or locked accounts
            ok = False
        if ok and good_captcha:
            session.clear()
            session["pre_mfa"] = {"uid": user["id"], "at": time.time(), "tries": 0}
            return redirect(url_for("mfa"))
        register_failure(user if not locked else None)
        audit("login.failure", "FAIL", f"username={username[:40]}" + (" locked" if locked else ""), user_id=user["id"] if user else None)
        flash("Invalid credentials.")                                             # one generic message (4.2.1)
        need_captcha = recent_ip_failures() >= CAPTCHA_AFTER_IP_FAILS
    question = new_captcha() if need_captcha else None
    return render_template("login.html", captcha=question)

@route("/mfa", methods=("GET", "POST",))
def mfa():
    data = session.get("pre_mfa")
    if not data or time.time() - data["at"] > PRE_MFA_TTL:
        session.pop("pre_mfa", None)
        return redirect(url_for("login"))
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=? AND active=1", (data["uid"],)).fetchone()
    if user is None:
        return redirect(url_for("login"))
    enrolling = not user["totp_confirmed"]
    if enrolling and not user["totp_secret"]:
        db.execute("UPDATE users SET totp_secret=? WHERE id=?", (pyotp.random_base32(), user["id"]))
        db.commit()
        user = db.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
    if request.method == "POST":
        data["tries"] += 1
        session["pre_mfa"] = data
        if data["tries"] > 5:
            session.pop("pre_mfa", None)
            audit("mfa.lockout", "DENY", user_id=user["id"])
            return redirect(url_for("login"))
        if verify_totp(user, request.form.get("code")):
            if enrolling:
                db.execute("UPDATE users SET totp_confirmed=1 WHERE id=?", (user["id"],))
                db.commit()
                audit("mfa.enrolled", user_id=user["id"])
            finish_login(user)
            return redirect(url_for("home"))
        audit("mfa.failure", "FAIL", user_id=user["id"])
        flash("Invalid code.")
    qr = None
    if enrolling:
        uri = pyotp.TOTP(user["totp_secret"]).provisioning_uri(name=user["username"], issuer_name="Student Portal")
        buf = io.BytesIO()
        qrcode.make(uri).save(buf, format="PNG")
        qr = base64.b64encode(buf.getvalue()).decode()
    return render_template("mfa.html", enrolling=enrolling, qr=qr, secret=user["totp_secret"] if enrolling else None)

@route("/logout", methods=("POST",))
def logout():
    if g.user:
        audit("logout")
    session.clear()
    return redirect(url_for("login"))

@route("/password", methods=("GET", "POST",))
@login_required()
def change_password():
    if request.method == "POST":
        current, new, again = (request.form.get(k, "")[:128] for k in ("current", "new", "again"))
        problem = check_password_policy(new, g.user["username"])
        if not verify_password(g.user, current):
            register_failure(g.user)
            audit("password.change", "FAIL", "bad current password")
            flash("Could not change the password. Check your details.")
        elif new != again:
            flash("The new passwords do not match.")
        elif problem:
            flash(problem)
        else:
            get_db().execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(new), g.user["id"]))
            get_db().commit()
            audit("password.change")
            session.clear()                                                     # force a fresh login (7.4.3)
            flash("Password changed. Please sign in again.")
            return redirect(url_for("login"))
    return render_template("password.html")

# ---- grades and attendance: a student only ever sees their own (8.2.2 / 8.3.1) ----
@route("/grades")
@login_required("student")
def grades():
    db = get_db()
    rows = db.execute("SELECT c.code, c.title, g.assessment, g.score FROM grades g JOIN courses c ON c.id=g.course_id "
                      "WHERE g.student_id=? ORDER BY c.code, g.id", (g.user["id"],)).fetchall()
    att = db.execute("SELECT c.code, c.title, a.total, a.attended FROM attendance a JOIN courses c ON c.id=a.course_id "
                     "WHERE a.student_id=? ORDER BY c.code", (g.user["id"],)).fetchall()
    return render_template("grades.html", grades=rows, attendance=att)

# ---- Story 2: assignment upload (5.x) ----
@route("/assignments", methods=("GET", "POST",))
@login_required("student")
def assignments():
    db = get_db()
    courses = db.execute("SELECT c.id, c.code, c.title FROM courses c JOIN enrolments e ON e.course_id=c.id "
                         "WHERE e.student_id=? ORDER BY c.code", (g.user["id"],)).fetchall()
    if request.method == "POST":
        upload = request.files.get("file")
        try:
            course_id = int(request.form.get("course_id", ""))
        except ValueError:
            course_id = -1
        if course_id not in {c["id"] for c in courses}:
            abort(400)
        hour_ago = datetime.fromtimestamp(time.time() - 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        recent = db.execute("SELECT COUNT(*) FROM submissions WHERE student_id=? AND submitted_at>?", (g.user["id"], hour_ago)).fetchone()[0]
        if recent >= UPLOADS_PER_HOUR:
            audit("upload.ratelimited", "DENY")
            abort(429)
        if upload is None or not upload.filename:
            flash("Choose a file.")
        else:
            data = upload.stream.read(MAX_UPLOAD + 1)
            name = safe_filename(upload.filename)
            try:
                validate_upload(name, data)
            except UploadError as exc:
                audit("upload.rejected", "DENY", name)
                flash(str(exc))
            else:
                stored = secrets.token_hex(16)                                    # random name, no extension (5.3.2)
                (Path(_app().config["UPLOAD_DIR"]) / stored).write_bytes(data)
                db.execute("INSERT INTO submissions (course_id, student_id, original_name, stored_name, sha256, size, submitted_at) "
                           "VALUES (?,?,?,?,?,?,?)", (course_id, g.user["id"], name, stored, hashlib.sha256(data).hexdigest(), len(data), utcnow()))
                db.commit()
                audit("upload.ok", detail=f"course={course_id} name={name}")
                flash("Assignment submitted.")
                return redirect(url_for("assignments"))
    mine = db.execute("SELECT s.id, s.original_name, s.size, s.submitted_at, c.code FROM submissions s JOIN courses c ON c.id=s.course_id "
                      "WHERE s.student_id=? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
    return render_template("assignments.html", courses=courses, mine=mine, exts=sorted(ALLOWED_EXT))

@route("/submissions")
@login_required("lecturer")
def submissions():
    rows = get_db().execute(
        "SELECT s.id, s.original_name, s.size, s.submitted_at, c.code, u.full_name FROM submissions s "
        "JOIN courses c ON c.id=s.course_id JOIN users u ON u.id=s.student_id WHERE c.lecturer_id=? ORDER BY s.id DESC", (g.user["id"],)).fetchall()
    return render_template("submissions.html", rows=rows)

@route("/files/<int:sub_id>")
@login_required()
def download(sub_id):
    row = get_db().execute("SELECT s.*, c.lecturer_id FROM submissions s JOIN courses c ON c.id=s.course_id WHERE s.id=?", (sub_id,)).fetchone()
    if row is None or g.user["id"] not in (row["student_id"], row["lecturer_id"]):
        audit("file.denied", "DENY", f"id={sub_id}")
        abort(404)                                                                # 404, not 403: do not confirm the id exists
    path = Path(_app().config["UPLOAD_DIR"]) / row["stored_name"]
    audit("file.download", detail=f"id={sub_id}")
    return send_file(path, mimetype="application/octet-stream", as_attachment=True, download_name=row["original_name"])

# ---- Story 3: messaging (1.2.x, 8.2.2) ----
@route("/messages")
@login_required()
def messages():
    if g.user["role"] == "student":                                               # students see what they received
        rows = get_db().execute("SELECT m.id, m.subject, m.sent_at, u.full_name FROM messages m JOIN users u ON u.id=m.sender_id "
                                "WHERE m.recipient_id=? ORDER BY m.id DESC", (g.user["id"],)).fetchall()
    else:                                                                         # lecturers see what they sent
        rows = get_db().execute("SELECT m.id, m.subject, m.sent_at, u.full_name FROM messages m JOIN users u ON u.id=m.recipient_id "
                                "WHERE m.sender_id=? ORDER BY m.id DESC", (g.user["id"],)).fetchall()
    return render_template("messages.html", rows=rows)

@route("/messages/new", methods=("GET", "POST",))
@login_required("lecturer")
def message_new():
    db = get_db()
    students = db.execute("SELECT DISTINCT u.id, u.full_name FROM users u JOIN enrolments e ON e.student_id=u.id "
                          "JOIN courses c ON c.id=e.course_id WHERE c.lecturer_id=? ORDER BY u.full_name", (g.user["id"],)).fetchall()
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        try:
            rid = int(request.form.get("recipient_id", ""))
        except ValueError:
            rid = -1
        if rid not in {s["id"] for s in students}:                               # only own students
            audit("message.denied", "DENY", f"recipient={rid}")
            abort(403)
        if not (1 <= len(subject) <= 120 and 1 <= len(body) <= 2000):
            flash("Subject (max 120) and message (max 2000) are required.")
        else:
            db.execute("INSERT INTO messages (sender_id, recipient_id, subject, body, sent_at) VALUES (?,?,?,?,?)",
                       (g.user["id"], rid, subject, body, utcnow()))
            db.commit()
            audit("message.sent", detail=f"to={rid}")
            flash("Message sent.")
            return redirect(url_for("messages"))
    return render_template("message_new.html", students=students)

@route("/messages/<int:msg_id>")
@login_required()
def message_view(msg_id):
    row = get_db().execute("SELECT m.*, s.full_name AS sender_name, r.full_name AS recipient_name FROM messages m "
                           "JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id WHERE m.id=?", (msg_id,)).fetchone()
    if row is None or g.user["id"] not in (row["sender_id"], row["recipient_id"]):
        abort(404)
    return render_template("message_view.html", m=row)

# ---- Story 4: profile update (7.5.1, 8.2.x) ----
@route("/profile", methods=("GET", "POST",))
@login_required()
def profile():
    if request.method == "POST":
        if not verify_password(g.user, request.form.get("current_password", "")[:128]):    # re-authentication (7.5.1)
            register_failure(g.user)
            audit("profile.update", "FAIL", "re-auth failed")
            flash("Could not update the profile. Check your details.")
            return redirect(url_for("profile"))
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        errors = []
        if not EMAIL_RE.match(email) or len(email) > 254:
            errors.append("Enter a valid email address.")
        if phone and not PHONE_RE.match(phone):
            errors.append("Phone may contain digits, spaces, + and - only (7 to 20 characters).")
        if len(address) > 200 or any(ord(c) < 32 for c in address):
            errors.append("Address is too long or has invalid characters.")
        if errors:
            for e in errors:
                flash(e)
        else:
            changed = [n for n, new, old in (("email", email, g.user["email"]), ("phone", phone, g.user["phone"]),
                                             ("address", address, g.user["address"])) if new != old]
            # only these three fields are ever written, and only for the logged-in user (8.2.2 / 8.3.1)
            get_db().execute("UPDATE users SET email=?, phone=?, address=? WHERE id=?", (email, phone, address, g.user["id"]))
            get_db().commit()
            audit("profile.update", detail="fields=" + ",".join(changed))
            flash("Profile updated.")
            return redirect(url_for("profile"))
    return render_template("profile.html", u=g.user)




app = create_app()


# ------------------------------------------------------------------ CLI: python app_secure.py initdb
def seed_demo():
    """Creates demo accounts with random passwords, printed once. Nothing is hard-coded."""
    db = sqlite3.connect(app.config["DATABASE"])
    db.row_factory = sqlite3.Row
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        print("Database already has users; nothing seeded.")
        return
    accounts = [("alice", "Alice Tan", "alice@student.example", "student"), ("bob", "Bob Lim", "bob@student.example", "student"),
                ("dr.chen", "Dr Chen Wei", "chen@uni.example", "lecturer"), ("dr.kumar", "Dr Kumar Raj", "kumar@uni.example", "lecturer")]
    ids = {}
    print("Demo accounts (shown once):")
    for username, name, email, role in accounts:
        pw = secrets.token_urlsafe(14)
        ids[username] = create_user(db, username, name, email, role, pw)
        print(f"  {role:9} {username:9} {pw}")
    for code, title, lec in (("CT101", "Web Security", "dr.chen"), ("CT102", "Databases", "dr.kumar")):
        db.execute("INSERT INTO courses (code, title, lecturer_id) VALUES (?,?,?)", (code, title, ids[lec]))
    for sid, cid in ((ids["alice"], 1), (ids["alice"], 2), (ids["bob"], 1)):
        db.execute("INSERT INTO enrolments VALUES (?,?)", (sid, cid))
    for sid, cid, assessment, score in ((ids["alice"], 1, "Quiz 1", 86), (ids["alice"], 2, "Midterm", 74), (ids["bob"], 1, "Quiz 1", 65)):
        db.execute("INSERT INTO grades (student_id, course_id, assessment, score) VALUES (?,?,?,?)", (sid, cid, assessment, score))
    for sid, cid, total, att in ((ids["alice"], 1, 12, 11), (ids["alice"], 2, 12, 12), (ids["bob"], 1, 12, 9)):
        db.execute("INSERT INTO attendance VALUES (?,?,?,?)", (sid, cid, total, att))
    db.commit()
    print("Start the app with:  flask --app app_secure run   (MFA is set up on first login)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "initdb":
        seed_demo()
    else:
        app.run(host="127.0.0.1", port=5000)
