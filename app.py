import os, ssl, socket, threading, time, sqlite3, hashlib, binascii, secrets, urllib.parse
from datetime import datetime, timedelta
from email.message import EmailMessage
import smtplib
import json
import urllib.request
import re
import urllib.error


# ------------ Config ------------
DB_PATH = os.environ.get("DB_PATH")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
SESSION_COOKIE_NAME = os.environ.get("SESSION_COOKIE_NAME")
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS"))
TEMPLATES_DIR = os.environ.get("TEMPLATES_DIR")
STATIC_DIR = os.environ.get("STATIC_DIR")

SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT",465))
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

CF_TURN_KEY_ID = os.environ.get("CLOUDFLARE_TURN_KEY_ID")
CF_TURN_API_TOKEN = os.environ.get("CLOUDFLARE_TURN_KEY_API_TOKEN")
CF_TURN_TTL = int(os.environ.get("CLOUDFLARE_TURN_TTL"))

# ------------ DB setup ------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            verify_token TEXT,
            verify_sent_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    try:
        c.execute("ALTER TABLE users ADD COLUMN prefs_json TEXT DEFAULT '{}'")
    except sqlite3.OperationalError:
        pass


    conn.commit()
    conn.close()


init_db()

# ------------ Crypto helpers ------------

def hash_password(password: str):
    salt = os.urandom(16)
    hashed = hashlib.sha256(salt + password.encode("utf-8")).digest()
    return binascii.hexlify(salt).decode(), binascii.hexlify(hashed).decode()


def verify_password(salt_hex: str, hash_hex: str, provided: str) -> bool:
    salt = binascii.unhexlify(salt_hex)
    new_hash = hashlib.sha256(salt + provided.encode("utf-8")).digest()
    return binascii.hexlify(new_hash).decode() == hash_hex


# ------------ User queries ------------

def row_to_user(row):
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "salt": row[3],
        "password_hash": row[4],
        "verified": bool(row[5]),
        "verify_token": row[6],
        "verify_sent_at": row[7],
    }


def get_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, username, email, salt, password_hash, verified, verify_token, verify_sent_at FROM users WHERE username = ?",
        (username,),
    )
    row = c.fetchone()
    conn.close()
    return row_to_user(row)


def get_user_by_email(email: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, username, email, salt, password_hash, verified, verify_token, verify_sent_at FROM users WHERE email = ?",
        (email,),
    )
    row = c.fetchone()
    conn.close()
    return row_to_user(row)


def add_user(username: str, email: str, password: str):
    salt_hex, hash_hex = hash_password(password)
    token = secrets.token_urlsafe(32)
    now_iso = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            """
            INSERT INTO users (username, email, salt, password_hash, verified, verify_token, verify_sent_at)
            VALUES (?, ?, ?, ?, 0, ?, ?)
            """,
            (username, email, salt_hex, hash_hex, token, now_iso),
        )
        conn.commit()
        return True, token
    except sqlite3.IntegrityError:
        return False, None
    finally:
        conn.close()

def get_user_prefs(user_id: int) -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT prefs_json FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row or not row[0]:
        return {}
    try:
        return json.loads(row[0])
    except Exception:
        return {}

def set_user_prefs(user_id: int, prefs: dict) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET prefs_json = ? WHERE id = ?", (json.dumps(prefs), user_id))
    conn.commit()
    ok = c.rowcount > 0
    conn.close()
    return ok


def update_user_password(user_id: int, new_password: str) -> bool:
    salt_hex, hash_hex = hash_password(new_password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET salt = ?, password_hash = ? WHERE id = ?",
        (salt_hex, hash_hex, user_id),
    )
    changed = c.rowcount
    conn.commit()
    conn.close()
    return changed > 0

def create_password_reset(user_id: int, minutes_valid: int = 30):
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    expires_at = (now + timedelta(minutes=minutes_valid)).isoformat()
    created_at = now.isoformat()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO password_resets (user_id, token, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)",
        (user_id, token, expires_at, created_at),
    )
    conn.commit()
    conn.close()
    return token

def get_password_reset(token: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "SELECT id, user_id, token, expires_at, used, created_at FROM password_resets WHERE token = ?",
        (token,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "user_id": row[1],
        "token": row[2],
        "expires_at": row[3],
        "used": bool(row[4]),
        "created_at": row[5],
    }

def mark_password_reset_used(reset_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_id,))
    conn.commit()
    conn.close()

def mark_verified(token: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET verified = 1, verify_token = NULL WHERE verify_token = ?", (token,))
    changed = c.rowcount
    conn.commit()
    conn.close()
    return changed > 0


# ------------ Email ------------

def send_verification_email(email: str, username: str, verify_url: str) -> bool:
    if not email or "@" not in email:
        print("[EMAIL ERROR] Bad recipient:", repr(email))
        return False

    if not SMTP_USER or not SMTP_PASS:
        print("[EMAIL ERROR] Missing SMTP_USER/SMTP_PASS; not sending. URL:", verify_url)
        return False

    em = EmailMessage()
    em["From"] = SMTP_FROM or SMTP_USER
    em["To"] = email
    em["Subject"] = "Verify Your Account"
    em.set_content(
        f"Hi {username},\n\nPlease verify your account by clicking the link below:\n\n{verify_url}\n\n"
        f"If you did not request this, you can ignore this email.\n"
    )

    try:
        print(f"[EMAIL] Trying SMTPS {SMTP_HOST}:{SMTP_PORT} as {SMTP_USER} → {email}")
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=20) as smtp:
            smtp.set_debuglevel(1)  # << see protocol and errors in console
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(em)
        print("[EMAIL] Sent via SMTPS 465")
        return True
    except Exception as e1:
        print("[EMAIL WARN] SMTPS failed:", e1)

    try:
        print(f"[EMAIL] Trying STARTTLS {SMTP_HOST}:587 as {SMTP_USER} → {email}")
        with smtplib.SMTP(SMTP_HOST, 587, timeout=20) as smtp:
            smtp.set_debuglevel(1)
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(em)
        print("[EMAIL] Sent via STARTTLS 587")
        return True
    except Exception as e2:
        print("[EMAIL ERROR] STARTTLS failed:", e2)
        return False

def send_password_reset_email(email: str, username: str, reset_url: str) -> bool:
    if not email or "@" not in email:
        print("[EMAIL ERROR] Bad recipient:", repr(email))
        return False

    if not SMTP_USER or not SMTP_PASS:
        print("[EMAIL ERROR] Missing SMTP creds; not sending. URL:", reset_url)
        return False

    em = EmailMessage()
    em["From"] = SMTP_FROM or SMTP_USER
    em["To"] = email
    em["Subject"] = "Reset Your Password"
    em.set_content(
        f"Hi {username},\n\n"
        f"Click the link below to reset your password (valid for 30 minutes):\n\n"
        f"{reset_url}\n\n"
        f"If you did not request this, you can ignore this email.\n"
    )

    try:
        print(f"[EMAIL] Sending reset → {email}")
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=20) as smtp:
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(em)
        return True
    except Exception as e1:
        print("[EMAIL WARN] SMTPS failed:", e1)

    try:
        print(f"[EMAIL] Trying STARTTLS {SMTP_HOST}:587 → {email}")
        with smtplib.SMTP(SMTP_HOST, 587, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(em)
        return True
    except Exception as e2:
        print("[EMAIL ERROR] STARTTLS failed:", e2)
        return False


# ------------ Cloud Flare ------------
def cf_generate_ice_servers(ttl_seconds: int):
    if not CF_TURN_KEY_ID or not CF_TURN_API_TOKEN:
        raise RuntimeError("Missing CLOUDFLARE_TURN_KEY_ID or CLOUDFLARE_TURN_KEY_API_TOKEN")

    url = f"https://rtc.live.cloudflare.com/v1/turn/keys/{CF_TURN_KEY_ID}/credentials/generate-ice-servers"
    payload = json.dumps({"ttl": int(ttl_seconds)}).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {CF_TURN_API_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "curl/8.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", "ignore")
        raise RuntimeError(f"Cloudflare HTTPError {e.code}: {err_body}") from e

    data = json.loads(body)
    ice = data.get("iceServers") or data.get("ice_servers")
    if not ice:
        raise RuntimeError(f"Cloudflare response missing iceServers: {data}")
    return ice


# ------------ In-memory state ------------

ROOMS = {}  # room_id -> {"key": str, "owner": username, "created_at": iso}
SESSIONS = {}  # sid -> {"data": { ... }, "expires": epoch}


def create_room(owner_username: str):
    room_id = secrets.token_urlsafe(8)
    room_key = secrets.token_urlsafe(16)
    ROOMS[room_id] = {
        "key": room_key,
        "owner": owner_username,
        "created_at": datetime.utcnow().isoformat(),
    }
    return room_id, room_key


def check_room_key(room_id: str, key: str) -> bool:
    room = ROOMS.get(room_id)
    return bool(room and room["key"] == key)


# ------------ HTTP primitives ------------

class HTTPRequest:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.method = "GET"
        self.path = "/"
        self.query = {}
        self.headers = {}
        self.cookies = {}
        self.body = b""
        self.form = {}
        self.files = {}
        self.parse()

    def parse(self):
        try:
            head, body = self.raw.split(b"\r\r\n\r\n", 1)
        except ValueError:
            head, body = self.raw.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in self.raw else (self.raw, b"")
        lines = head.decode("iso-8859-1").splitlines()
        if not lines:
            return
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) >= 2:
            self.method = parts[0]
            url = parts[1]
            if "?" in url:
                path, qs = url.split("?", 1)
                self.path = urllib.parse.unquote(path)
                self.query = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True))
            else:
                self.path = urllib.parse.unquote(url)
        # headers
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                self.headers[k.strip().lower()] = v.strip()
        # cookies
        if "cookie" in self.headers:
            for kv in self.headers["cookie"].split(";"):
                if "=" in kv:
                    ck, cv = kv.strip().split("=", 1)
                    self.cookies[ck] = urllib.parse.unquote(cv)
        # body
        self.body = body
        ctype = self.headers.get("content-type", "")
        if self.method.upper() == "POST" and "application/x-www-form-urlencoded" in ctype:
            self.form = dict(urllib.parse.parse_qsl(self.body.decode("utf-8"), keep_blank_values=True))
        elif self.method.upper() == "POST" and "multipart/form-data" in ctype:
            form, files = _parse_multipart(self.body, ctype)
            self.form = form
            self.files = files
        else:
            self.files = {}



class HTTPResponse:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")

    def to_bytes(self):
        reason = {
            200: "OK",
            201: "Created",
            301: "Moved Permanently",
            302: "Found",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(self.status, "OK")
        lines = [f"HTTP/1.1 {self.status} {reason}"]
        body = self.body
        hdrs = {"Content-Length": str(len(body)), "Server": "PySock/1"}
        hdrs.update(self.headers)
        for k, v in hdrs.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        head = "\r\n".join(lines).encode("iso-8859-1") + b"\r\n"
        return head + body


# ------------ Utilities ------------

def load_template(name: str) -> str:
    path = os.path.join(TEMPLATES_DIR, name)
    if not os.path.isfile(path):
        return "<h1>Missing template: {}</h1>".format(name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def render(name: str, **ctx) -> bytes:
    html = load_template(name)
    # Replace {{var}} and {{ var }} with context values; unknown keys -> empty string
    def _sub(m):
        key = m.group(1).strip()
        return str(ctx.get(key, ""))
    html = re.sub(r"{{\s*([a-zA-Z0-9_]+)\s*}}", _sub, html)
    return html.encode("utf-8")

def _parse_multipart(body: bytes, content_type: str):
    # files_dict[field] = {"filename": str, "content_type": str, "data": bytes}
    form = {}
    files = {}

    if "multipart/form-data" not in content_type or "boundary=" not in content_type:
        return form, files

    boundary = content_type.split("boundary=", 1)[1].strip()
    if boundary.startswith('"') and boundary.endswith('"'):
        boundary = boundary[1:-1]
    boundary_bytes = ("--" + boundary).encode("utf-8")

    parts = body.split(boundary_bytes)
    for part in parts:
        part = part.strip()
        if not part or part == b"--":
            continue
        if part.startswith(b"--"):
            continue

        # split headers / content
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        data = data.rstrip(b"\r\n")

        headers = {}
        for line in head.split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("utf-8","ignore").lower().strip()] = v.decode("utf-8","ignore").strip()

        disp = headers.get("content-disposition", "")
        if "name=" not in disp:
            continue

        # parse content-disposition
        def _get_param(s, key):
            keyeq = key + "="
            i = s.find(keyeq)
            if i < 0:
                return None
            rest = s[i+len(keyeq):]
            if rest.startswith('"'):
                j = rest.find('"', 1)
                return rest[1:j] if j > 0 else rest[1:]
            else:
                # until ; or end
                j = rest.find(";")
                return rest[:j] if j >= 0 else rest

        name = _get_param(disp, "name")
        filename = _get_param(disp, "filename")
        ctype = headers.get("content-type","application/octet-stream")

        if filename:
            files[name] = {"filename": filename, "content_type": ctype, "data": data}
        else:
            form[name] = data.decode("utf-8", "ignore")

    return form, files


def redirect(location: str, cookies=None, status=302) -> HTTPResponse:
    headers = {"Location": location}
    if cookies:
        headers.update({"Set-Cookie": cookies})
    return HTTPResponse(status=status, headers=headers, body=b"")


def cookie_header(name: str, value: str, max_age: int = SESSION_TTL_SECONDS) -> str:
    attrs = [f"{name}={urllib.parse.quote(value)}", f"Max-Age={max_age}", "Path=/", "HttpOnly", "SameSite=Lax", "Secure"]
    return "; ".join(attrs)


# ------------ Sessions ------------

def _new_sid() -> str:
    return secrets.token_urlsafe(32)


def get_session(request: HTTPRequest):
    now = int(time.time())
    sid = request.cookies.get(SESSION_COOKIE_NAME)
    if sid and sid in SESSIONS and SESSIONS[sid]["expires"] > now:
        return sid, SESSIONS[sid]["data"], None
    # create new
    sid = _new_sid()
    SESSIONS[sid] = {"data": {}, "expires": now + SESSION_TTL_SECONDS}
    ck = cookie_header(SESSION_COOKIE_NAME, sid)
    return sid, SESSIONS[sid]["data"], ck


def touch_session(sid: str):
    if sid in SESSIONS:
        SESSIONS[sid]["expires"] = int(time.time()) + SESSION_TTL_SECONDS


# ------------ Router ------------

# Build base URL from request Host unless BASE_URL env is set
def effective_base_url(req: 'HTTPRequest') -> str:
    env = os.environ.get("BASE_URL")
    if env:
        return env.rstrip('/')
    host = req.headers.get('host', 'localhost')

    return f"https://{host}"

class Router:
    def __init__(self):
        self.routes = []  # (method, parts, handler)

    def add(self, method: str, path: str, handler):
        parts = [p for p in path.split("/") if p]
        self.routes.append((method.upper(), parts, handler))

    def match(self, method: str, path: str):
        method = method.upper()
        parts = [p for p in path.split("/") if p]
        for m, patt_parts, handler in self.routes:
            if m != method:
                continue
            params = {}
            if len(parts) != len(patt_parts):
                continue
            ok = True
            for a, b in zip(parts, patt_parts):
                if b.startswith("<") and b.endswith(">"):
                    params[b[1:-1]] = a
                elif a != b:
                    ok = False
                    break
            if ok:
                return handler, params
        return None, {}


router = Router()

# ------------ Handlers ------------

def handle_favicon(req: HTTPRequest):
    path = os.path.join(STATIC_DIR, "favicon.ico")
    if not os.path.isfile(path):
        return HTTPResponse(404, {"Content-Type": "text/plain"}, b"no favicon")
    with open(path, "rb") as f:
        data = f.read()
    return HTTPResponse(200, {"Content-Type": "image/x-icon"}, data)


def serve_static(req: HTTPRequest, file_path: str):
    path = os.path.join(STATIC_DIR, *file_path.split("/"))
    if not os.path.isfile(path):
        return HTTPResponse(404, {"Content-Type": "text/plain"}, b"not found")
    mime = "text/plain"
    if path.endswith(".css"): mime = "text/css"
    if path.endswith(".js"): mime = "application/javascript"
    if path.endswith(".png"): mime = "image/png"
    if path.endswith(".jpg") or path.endswith(".jpeg"): mime = "image/jpeg"
    with open(path, "rb") as f:
        return HTTPResponse(200, {"Content-Type": mime}, f.read())


def home(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    touch_session(sid)
    if sess.get("user"):
        return redirect("/lobby", set_ck)
    body = render("home.html")
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if set_ck:
        hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, body)

def settings(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)
    touch_session(sid)

    user = get_user(sess["user"])
    if not user:
        return redirect("/", set_ck)

    msg_html = ""

    return_to = (req.query.get("return") or req.form.get("return_to") or "/lobby").strip()

    if not return_to.startswith("/"):
        return_to = "/lobby"

    prefs = get_user_prefs(user["id"])
    prefs.setdefault("auto_cam", False)
    prefs.setdefault("auto_mic", False)
    prefs.setdefault("sound", True)

    prefs.setdefault("filters", {})
    prefs["filters"].setdefault("bg_mode", "none")
    prefs["filters"].setdefault("blur_strength", 12)
    prefs["filters"].setdefault("face_filter", "off")
    prefs["filters"].setdefault("bg_src", "")
    prefs["filters"].setdefault("bg_color", "#1f1f1f")

    if req.method == "POST":
        action = (req.form.get("action") or "").strip()

        if action == "save_prefs":
            prefs["auto_cam"] = ("pref_auto_cam" in req.form)
            prefs["auto_mic"] = ("pref_auto_mic" in req.form)
            prefs["sound"] = ("pref_sound" in req.form)

            ok = set_user_prefs(user["id"], prefs)
            return redirect(return_to, set_ck)
        
        elif action == "save_filters":
            prefs.setdefault("filters", {})
            filters = prefs["filters"]

            filters["bg_mode"] = (req.form.get("bg_mode") or "none").strip()

            saved_upload_path = None

            upload = getattr(req, "files", {}).get("bg_upload")
            if upload and upload.get("data"):
                user_folder = os.path.join(STATIC_DIR, "uploads", user["username"])
                os.makedirs(user_folder, exist_ok=True)

                orig = upload.get("filename", "upload.png")
                ext = os.path.splitext(orig)[1].lower()
                if ext not in [".png", ".jpg", ".jpeg", ".webp"]:
                    ext = ".png"

                fname = f"bg_{secrets.token_hex(8)}{ext}"
                out_path = os.path.join(user_folder, fname)

                MAX_BYTES = 3 * 1024 * 1024
                data = upload["data"]
                if len(data) <= MAX_BYTES:
                    with open(out_path, "wb") as f:
                        f.write(data)
                    saved_upload_path = f"/static/uploads/{user['username']}/{fname}"
                    filters["bg_src"] = saved_upload_path

            try:
                filters["blur_strength"] = int(req.form.get("blur_strength") or "12")
            except:
                filters["blur_strength"] = 12

            filters["face_filter"] = (req.form.get("face_filter") or "off").strip()
            filters["bg_color"] = (req.form.get("bg_color") or "#1f1f1f").strip()

            if not saved_upload_path:
                filters["bg_src"] = (req.form.get("bg_src") or "").strip()

            set_user_prefs(user["id"], prefs)
            return redirect(return_to, set_ck)

    # extract for template
    filters = prefs.get("filters", {}) or {}
    bg_mode = filters.get("bg_mode", "none")
    blur_strength = filters.get("blur_strength", 12)
    face_filter = filters.get("face_filter", "off")
    bg_src = filters.get("bg_src", "")
    bg_color = filters.get("bg_color", "#1f1f1f")


    body = render(
        "settings.html",
        msg_html=msg_html,
        username=user["username"],
        email=user["email"],
        verified="yes" if user["verified"] else "no",
        pref_auto_cam_checked="checked" if prefs.get("auto_cam") else "",
        pref_auto_mic_checked="checked" if prefs.get("auto_mic") else "",
        pref_sound_checked="checked" if prefs.get("sound") else "",
        bg_mode=bg_mode,
        blur_strength=blur_strength,
        face_filter=face_filter,
        bg_src=bg_src,
        bg_color=bg_color,
        return_to=return_to,
    )

    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if set_ck:
        hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, body)


def login(req: HTTPRequest):
    if req.method != "POST":
        return HTTPResponse(405, {"Content-Type": "text/plain"}, b"Use POST")
    sid, sess, set_ck = get_session(req)
    username = (req.form.get("username") or "").strip()
    password = req.form.get("password") or ""
    user = get_user(username)
    if user and user["verified"] and verify_password(user["salt"], user["password_hash"], password):
        sess["user"] = username
        touch_session(sid)
        return redirect("/lobby", set_ck)
    if user and not user["verified"]:
        msg = f"Email not verified. <a href='/resend?email={urllib.parse.quote(user['email'])}'>Resend verification email</a>"
        return HTTPResponse(401, {"Content-Type": "text/html"}, msg.encode("utf-8"))
    return HTTPResponse(401, {"Content-Type": "text/plain"}, b"Invalid username or password")

def change_password(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)

    touch_session(sid)

    error_html = ""
    ok_html = ""

    if req.method == "POST":
        current_pw = req.form.get("current_password") or ""
        new_pw = req.form.get("new_password") or ""
        confirm = req.form.get("confirm_password") or ""

        if len(new_pw) < 6:
            error_html = '<div class="error">New password must be at least 6 characters.</div>'
        elif new_pw != confirm:
            error_html = '<div class="error">New password and confirmation do not match.</div>'
        else:
            user = get_user(sess["user"])
            if not user:
                error_html = '<div class="error"> User not found.</div>'
            elif not verify_password(user["salt"], user["password_hash"], current_pw):
                error_html = '<div class="error"> Current password is incorrect.</div>'
            else:
                if update_user_password(user["id"], new_pw):
                    ok_html = (
                        '<div class="panel" style="border-color:#2e6a48;background:#113020;color:#bdf2d3;">'
                        'Password updated successfully.'
                        '</div>'
                    )
                else:
                    error_html = '<div class="error">Failed to update password. Try again.</div>'

    body = render("change_password.html", error_html=error_html, ok_html=ok_html)
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if set_ck:
        hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, body)

def register(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if req.method == "GET":
        body = render("register.html")
        hdrs = {"Content-Type": "text/html; charset=utf-8"}
        if set_ck:
            hdrs["Set-Cookie"] = set_ck
        return HTTPResponse(200, hdrs, body)
    # POST
    username = (req.form.get("username") or "").strip()
    email = (req.form.get("email") or "").strip().lower()
    password = req.form.get("password") or ""
    if not username or not email or not password:
        return HTTPResponse(400, {"Content-Type": "text/plain"}, b"All fields are required")
    ok, token = add_user(username, email, password)
    if not ok:
        return HTTPResponse(400, {"Content-Type": "text/plain"}, b"Username or email already exists")
    verify_url = f"{effective_base_url(req)}/verify?token={urllib.parse.quote(token)}"

    ok = send_verification_email(email, username, verify_url)  # register()
    # or: ok = send_verification_email(user["email"], user["username"], verify_url)  # resend()
    if ok:
        return HTTPResponse(200, {"Content-Type": "text/html"},
                            b"Verification email sent! Please check your inbox.")

    fallback = (f"Email failed to send.<br>"
                f"DEV: click to verify now: <a href='{verify_url}'>{verify_url}</a>")
    return HTTPResponse(200, {"Content-Type": "text/html"}, fallback.encode("utf-8"))


def resend(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if req.method == "GET":
        prefill = req.query.get("email", "")
        body = render("resend.html", email=prefill)
        hdrs = {"Content-Type": "text/html; charset=utf-8"}
        if set_ck:
            hdrs["Set-Cookie"] = set_ck
        return HTTPResponse(200, hdrs, body)
    # POST
    email = (req.form.get("email") or "").strip().lower()
    user = get_user_by_email(email)
    if not user:
        return HTTPResponse(404, {"Content-Type": "text/plain"}, b"No account with that email.")
    if user["verified"]:
        return HTTPResponse(200, {"Content-Type": "text/plain"}, b"This account is already verified. You can log in.")
    new_token = secrets.token_urlsafe(32)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET verify_token = ?, verify_sent_at = ? WHERE id = ?",
              (new_token, datetime.utcnow().isoformat(), user["id"]))
    conn.commit(); conn.close()
    verify_url = f"{effective_base_url(req)}/verify?token={urllib.parse.quote(new_token)}"
    ok = send_verification_email(user["email"], user["username"], verify_url)
    if ok:
        return HTTPResponse(200, {"Content-Type": "text/plain"}, b"Verification email resent! Please check your inbox.")
    return HTTPResponse(500, {"Content-Type": "text/plain"}, b"Could not send email. Please try again later.")


def verify(req: HTTPRequest):
    token = req.query.get("token")
    if not token:
        return HTTPResponse(400, {"Content-Type": "text/plain"}, b"Missing token")
    if mark_verified(token):
        return redirect("/")
    return HTTPResponse(400, {"Content-Type": "text/plain"}, b"Invalid or expired verification link.")


def logout(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    sess.pop("user", None)
    touch_session(sid)
    return redirect("/", set_ck)

def forgot_password(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    touch_session(sid)

    msg_html = ""

    if req.method == "POST":
        email = (req.form.get("email") or "").strip().lower()

        # Always same response (prevents user enumeration)
        msg_html = (
            '<div class="panel" style="border-color:#2e6a48;background:#113020;color:#bdf2d3;">'
            'If the email exists, a reset link was sent.'
            '</div>'
        )

        user = get_user_by_email(email)
        if user:
            token = create_password_reset(user["id"], minutes_valid=30)
            reset_url = f"{effective_base_url(req)}/reset-password?token={urllib.parse.quote(token)}"
            send_password_reset_email(user["email"], user["username"], reset_url)

    body = render("forgot_password.html", msg_html=msg_html)
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if set_ck:
        hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, body)

def reset_password(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    touch_session(sid)

    token = (req.query.get("token") or "").strip()
    msg_html = ""
    form_html = ""

    def render_page(msg_html_in: str, show_form: bool):
        nonlocal msg_html, form_html
        msg_html = msg_html_in
        if show_form:
            form_html = f"""
            <form method="POST" action="/reset-password?token={urllib.parse.quote(token)}">
              <label>New password</label>
              <input type="password" name="new_password" required minlength="6">

              <label>Confirm new password</label>
              <input type="password" name="confirm_password" required minlength="6">

              <div class="actions">
                <button type="submit">Update password</button>
              </div>
            </form>
            """
        else:
            form_html = ""

        body = render("reset_password.html", msg_html=msg_html, form_html=form_html)
        hdrs = {"Content-Type": "text/html; charset=utf-8"}
        if set_ck:
            hdrs["Set-Cookie"] = set_ck
        return HTTPResponse(200, hdrs, body)

    if not token:
        return render_page('<div class="error">Missing token.</div>', False)

    pr = get_password_reset(token)
    if not pr:
        return render_page('<div class="error">Invalid or expired reset link.</div>', False)

    if pr["used"]:
        return render_page('<div class="error">This reset link was already used.</div>', False)

    try:
        expires_at = datetime.fromisoformat(pr["expires_at"])
    except Exception:
        return render_page('<div class="error">Invalid reset data.</div>', False)

    if datetime.utcnow() > expires_at:
        return render_page('<div class="error">This reset link has expired.</div>', False)

    if req.method == "GET":
        return render_page("", True)

    new_pw = req.form.get("new_password") or ""
    confirm = req.form.get("confirm_password") or ""

    if len(new_pw) < 6:
        return render_page('<div class="error">Password must be at least 6 characters.</div>', True)
    if new_pw != confirm:
        return render_page('<div class="error">Passwords do not match.</div>', True)

    if not update_user_password(pr["user_id"], new_pw):
        return render_page('<div class="error">Failed to update password. Try again.</div>', True)

    mark_password_reset_used(pr["id"])

    return render_page(
        '<div class="panel" style="border-color:#2e6a48;background:#113020;color:#bdf2d3;">'
        'Password updated. You can now log in.'
        '</div>',
        False
    )

def api_ice(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)

    room_id = (req.query.get("room") or "").strip()
    print("[ICE] HIT room_id=", room_id, "user=", sess.get("user"),
          "key_id=", CF_TURN_KEY_ID, "ttl=", CF_TURN_TTL, flush=True)

    if not sess.get("user"):
        return HTTPResponse(401, {"Content-Type": "application/json"}, b'{"error":"unauthorized"}')

    if not room_id or room_id not in ROOMS:
        return HTTPResponse(404, {"Content-Type": "application/json"}, b'{"error":"room_not_found"}')

    owner = ROOMS.get(room_id, {}).get("owner")
    joined = set(sess.get("rooms_joined", []))
    if sess["user"] != owner and room_id not in joined:
        return HTTPResponse(403, {"Content-Type": "application/json"}, b'{"error":"forbidden"}')

    touch_session(sid)

    try:
        ice_servers = cf_generate_ice_servers(CF_TURN_TTL)
        print("[ICE] Cloudflare OK servers=", len(ice_servers), flush=True)
    except Exception as e:
        print("[ICE] Cloudflare FAIL:", repr(e), flush=True)
        return HTTPResponse(500, {"Content-Type": "application/json"}, b'{"error":"ice_failed"}')

    out = json.dumps({"iceServers": ice_servers}).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Cache-Control": "no-store"}
    if set_ck:
        hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, out)

def lobby(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)
    body = render("lobby.html", username=sess["user"])
    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if set_ck: hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, body)


def create_room_route(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)
    room_id, room_key = create_room(sess["user"])
    joined = set(sess.get("rooms_joined", []))
    joined.add(room_id)
    sess["rooms_joined"] = list(joined)
    touch_session(sid)
    return redirect(f"/room/{room_id}", set_ck)


def join_room(req: HTTPRequest, room_id: str):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)

    joined = set(sess.get("rooms_joined", []))
    if room_id in joined or ROOMS.get(room_id, {}).get("owner") == sess["user"]:
        return redirect(f"/room/{room_id}", set_ck)

    provided_key = req.query.get("key")
    if provided_key and check_room_key(room_id, provided_key):
        joined.add(room_id)
        sess["rooms_joined"] = list(joined)
        touch_session(sid)
        return redirect(f"/room/{room_id}", set_ck)

    if req.method == "POST":
        provided_key = (req.form.get("key") or "").strip()
        if check_room_key(room_id, provided_key):
            joined.add(room_id)
            sess["rooms_joined"] = list(joined)
            touch_session(sid)
            return redirect(f"/room/{room_id}", set_ck)
        body = render("join.html", room_id=room_id, bad_key=True)
        return HTTPResponse(200, {"Content-Type": "text/html"}, body)

    body = render("join.html", room_id=room_id, bad_key=False)
    return HTTPResponse(200, {"Content-Type": "text/html"}, body)


def join_direct(req: HTTPRequest):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)
    room_id = (req.form.get("room_id") or "").strip()
    key = (req.form.get("key") or "").strip()
    if not room_id or not key:
        return HTTPResponse(400, {"Content-Type": "text/plain"}, b"Room ID and key are required.")
    if not ROOMS.get(room_id):
        return HTTPResponse(404, {"Content-Type": "text/plain"}, b"Room not found.")
    if not check_room_key(room_id, key):
        return HTTPResponse(401, {"Content-Type": "text/plain"}, b"Invalid key.")
    joined = set(sess.get("rooms_joined", []))
    joined.add(room_id)
    sess["rooms_joined"] = list(joined)
    touch_session(sid)
    return redirect(f"/room/{room_id}", set_ck)


def room(req: HTTPRequest, room_id: str):
    sid, sess, set_ck = get_session(req)
    if not sess.get("user"):
        return redirect("/", set_ck)
    room_obj = ROOMS.get(room_id, {})
    owner = room_obj.get("owner")
    joined = set(sess.get("rooms_joined", []))
    if (room_id not in joined) and (owner != sess["user"]):
        return redirect(f"/join/{room_id}", set_ck)
    is_host = owner == sess["user"]
    join_link = None
    room_key = None
    if is_host and room_obj:
        room_key = room_obj.get("key")
        join_link = f"{effective_base_url(req)}/join/{room_id}?key={urllib.parse.quote(room_key)}"
        # Load user prefs
    u = get_user(sess["user"])
    prefs = get_user_prefs(u["id"]) if u else {}
    auto_cam = bool(prefs.get("auto_cam", False))
    auto_mic = bool(prefs.get("auto_mic", False))
    sound = bool(prefs.get("sound", True))
    filters = (prefs.get("filters") or {})
    bg_mode = filters.get("bg_mode", "none")
    blur_strength = filters.get("blur_strength", 12)
    face_filter = filters.get("face_filter", "off")

    body = render(
        "room.html",
        room_id=room_id,
        username=sess["user"],
        is_host=str(is_host).lower(),
        join_link=join_link or "",
        room_key=room_key or "",
        pref_auto_cam=str(auto_cam).lower(),
        pref_auto_mic=str(auto_mic).lower(),
        pref_sound=str(sound).lower(),
        pref_bg_mode=bg_mode,
        pref_blur_strength=str(blur_strength),
        pref_face_filter=face_filter,
        pref_bg_src=filters.get("bg_src", ""),
        pref_bg_color=filters.get("bg_color", "#1f1f1f"),
    )

    hdrs = {"Content-Type": "text/html; charset=utf-8"}
    if set_ck: hdrs["Set-Cookie"] = set_ck
    return HTTPResponse(200, hdrs, body)


# Register routes
router.add("GET", "/", home)
router.add("GET", "/favicon.ico", handle_favicon)
router.add("GET", "/static/<path>", lambda req, path: serve_static(req, path))
router.add("POST", "/login", login)
router.add("GET", "/settings", settings)
router.add("POST", "/settings", settings)
router.add("GET", "/change-password", change_password)
router.add("POST", "/change-password", change_password)
router.add("GET", "/register", register)
router.add("POST", "/register", register)
router.add("GET", "/resend", resend)
router.add("POST", "/resend", resend)
router.add("GET", "/forgot-password", forgot_password)
router.add("POST", "/forgot-password", forgot_password)
router.add("GET", "/reset-password", reset_password)
router.add("POST", "/reset-password", reset_password)
router.add("GET", "/verify", verify)
router.add("GET", "/logout", logout)
router.add("GET", "/api/ice", api_ice)
router.add("GET", "/lobby", lobby)
router.add("POST", "/create-room", create_room_route)
router.add("GET", "/join/<room_id>", join_room)
router.add("POST", "/join/<room_id>", join_room)
router.add("POST", "/join-direct", join_direct)
router.add("GET", "/room/<room_id>", room)


# ------------ Server core ------------

def handle_client(conn):
    try:
        conn.settimeout(5)
        data = b""

        while b"\r\n\r\n" not in data and b"\r\r\n\r\n" not in data:
            try:
                chunk = conn.recv(65536)
            except TimeoutError:
                print("[TIMEOUT] No HTTP request received in 5s, closing client.")
                return
            if not chunk:
                # client closed connection
                return
            data += chunk

        if not data:
            return

        head = data.split(b"\r\n\r\n", 1)[0]
        headers_lower = head.decode("iso-8859-1", "ignore").lower()
        content_length = 0
        for line in headers_lower.splitlines():
            if line.startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except:
                    content_length = 0

        body_received = len(data.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in data else 0

        while body_received < content_length:
            try:
                chunk = conn.recv(65536)
            except TimeoutError:
                print("[TIMEOUT] Body read timed out, closing client.")
                return
            if not chunk:
                break
            data += chunk
            body_received += len(chunk)

        req = HTTPRequest(data)

        # ---- routing ----
        if req.path.startswith("/static/"):
            resp = serve_static(req, req.path[len("/static/"):])
        else:
            handler, params = router.match(req.method, req.path)
            if not handler:
                resp = HTTPResponse(404, {"Content-Type": "text/plain"}, b"Not Found")
            else:
                try:
                    if params:
                        if "path" in params and callable(handler):
                            resp = handler(req, params["path"])
                        elif "room_id" in params:
                            resp = handler(req, params["room_id"])
                        else:
                            resp = handler(req, **params)
                    else:
                        resp = handler(req)
                except Exception as e:
                    print("[ERROR]", e)
                    resp = HTTPResponse(500, {"Content-Type": "text/plain"}, b"Server error")

        conn.sendall(resp.to_bytes())

    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()



def serve(host: str, port: int, certfile: str, keyfile: str):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(128)
    print(f"[SERVE] https://{host}:{port}")

    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            try:
                client, addr = ssock.accept()
            except ssl.SSLError as e:
                print("[TLS HANDSHAKE WARN]", e)   # unknown CA, etc.
                continue
            except OSError as e:
                print("[ACCEPT ERROR]", e)
                continue

            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()


if __name__ == "__main__":
    print("APP.PY STARTED SUCCESSFULLY", flush=True)
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "34535"))
    CERT = os.environ.get("TLS_CERT", "crt/server.crt")
    KEY = os.environ.get("TLS_KEY", "crt/server.key")

    init_db()

    serve(HOST, PORT, CERT, KEY)
