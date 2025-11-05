# app.py (honeypot) - patched version with DH-based key exchange
import os
import logging
from flask import Flask, request, render_template_string, g
import pymysql
import time
import json
import hmac
import hashlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
import secrets
import base64 as _b64

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# -----------------------------
# Diffie-Hellman helpers
# -----------------------------
# Full RFC 3526 2048-bit MODP Group (group 14) prime (canonical hex)
# (This is the full trusted 2048-bit prime)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431"
    "B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42"
    "E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
    16,
)
G = 2

def generate_private_key(bits=256):
    return secrets.randbits(bits)

def public_from_private(priv, p=P, g=G):
    return pow(g, priv, p)

def shared_secret_from_peer(pub_peer, priv, p=P):
    return pow(pub_peer, priv, p)

def int_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")

def derive_aes_key(shared_int: int, length=16) -> bytes:
    sbytes = int_to_bytes(shared_int)
    digest = hashlib.sha256(sbytes).digest()
    return digest[:length]  # AES-128 by default

# -----------------------------
# Config
# -----------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "honeypotuser")
DB_PASS = os.getenv("DB_PASS", "1234")
DB_NAME = os.getenv("DB_NAME", "honeypotdb")

BANNER = os.getenv("BANNER", "Welcome to AASS Web Honeypot")
DASHBOARD_DH_PUBLIC = os.getenv("DASHBOARD_DH_PUBLIC", "http://localhost:5000/dh/public")
DASHBOARD_DH_SUBMIT = os.getenv("DASHBOARD_DH_SUBMIT", "http://localhost:5000/dh/submit")
DASHBOARD_ADD_LOG = os.getenv("DASHBOARD_ADD_LOG", "http://localhost:5000/add_attack_log")

# optional env fallback secret if DH fails
FALLBACK_SECRET = os.getenv("LOG_SECRET_KEY", "yayyisproject123").encode()

INDEX_HTML = """
<!doctype html>
<title>{{banner}}</title>
<h1>{{banner}}</h1>
<p>Try: <a href="/search?query=test">/search?query=...</a> or <a href="/greet?name=Bob">/greet?name=...</a></p>
<form action="/login" method="POST">
  <input name="username" placeholder="username"><input name="password" placeholder="password" type="password">
  <button>Login</button>
</form>
"""

# -----------------------------
# DB helper
# -----------------------------
def get_db():
    if 'db' not in g:
        g.db = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASS,
            db=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
    return g.db

@app.route('/db_test')
def db_test():
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute('SELECT 1;')
            result = cur.fetchone()
        return f"Success: {result}"
    except Exception as e:
        return f"Failure: {str(e)}"

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return render_template_string(INDEX_HTML, banner=BANNER)

# -----------------------------
# DH exchange (honeypot side)
# -----------------------------
_HO_PRIV = generate_private_key(256)
_HO_PUB = public_from_private(_HO_PRIV)
_SHARED_KEY = None  # derived AES/HMAC key (bytes)

def perform_dh_exchange(retries=5, wait=1.0):
    """
    Best-effort DH exchange with dashboard:
      1. GET dashboard public (/dh/public)
      2. derive shared key locally
      3. POST our public to dashboard (/dh/submit) so dashboard can derive the same key
    """
    global _SHARED_KEY
    for attempt in range(retries):
        try:
            app.logger.info("DH: attempting GET %s (attempt %d)", DASHBOARD_DH_PUBLIC, attempt + 1)
            r = requests.get(DASHBOARD_DH_PUBLIC, timeout=2)
            r.raise_for_status()
            j = r.json()
            dashboard_pub_hex = j.get("pub")
            if not dashboard_pub_hex:
                app.logger.warning("DH: dashboard returned no 'pub' field")
                time.sleep(wait)
                continue
            dashboard_pub = int(dashboard_pub_hex, 16)
            shared_int = shared_secret_from_peer(dashboard_pub, _HO_PRIV)
            key = derive_aes_key(shared_int, length=16)
            _SHARED_KEY = key
            app.logger.info("DH: derived shared key (honeypot) base64=%s", _b64.b64encode(key).decode())
            app.logger.info("DH: derived shared key (honeypot)")

            # POST our public back so dashboard can derive the same key
            try:
                payload = {"pub": hex(_HO_PUB)[2:]}
                r2 = requests.post(DASHBOARD_DH_SUBMIT, json=payload, timeout=2)
                app.logger.info("DH: posted our pub to dashboard status=%s", r2.status_code)
            except Exception as e:
                app.logger.warning("DH: failed to POST our pub to dashboard: %s", e)
            return True
        except Exception as e:
            app.logger.info("DH: attempt %d failed: %s", attempt + 1, e)
            time.sleep(wait)
    app.logger.warning("DH: all attempts failed; falling back to env secret")
    return False

# attempt exchange at startup (non-blocking to keep app responsive)
try:
    perform_dh_exchange(retries=5, wait=1.0)
except Exception as ex:
    app.logger.warning("DH exchange startup error: %s", ex)

def get_secret_key() -> bytes:
    """
    Returns the derived shared key if DH succeeded, otherwise fallback env secret.
    Ensure returned key length is 16/24/32 bytes.
    """
    global _SHARED_KEY
    if _SHARED_KEY:
        return _SHARED_KEY
    # fallback: use environment-provided secret
    s = FALLBACK_SECRET
    if len(s) not in (16, 24, 32):
        # if fallback isn't correct length, derive 16-byte from SHA256
        return hashlib.sha256(s).digest()[:16]
    return s

# -----------------------------
# Encryption + signing (uses get_secret_key())
# -----------------------------
def encrypt_and_sign(log_data: dict) -> dict:
    # Add timestamp
    log_data["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    plaintext = json.dumps(log_data).encode()

    key = get_secret_key()
    if len(key) not in (16, 24, 32):
        raise ValueError("Secret key must be 16/24/32 bytes")

    # Generate random IV for AES-CBC
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Base64 encode ciphertext and IV for network transmission
    b64_ciphertext = base64.b64encode(ciphertext).decode()
    b64_iv = base64.b64encode(iv).decode()

    # Compute HMAC-SHA256 over iv + ciphertext (string concatenation of base64s)
    msg = b64_iv + b64_ciphertext
    signature = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()

    return {"iv": b64_iv, "data": b64_ciphertext, "hmac": signature}

def send_log(service, attack_type, message, url):
    payload = encrypt_and_sign({"service": service, "attack_type": attack_type, "message": message})
    try:
        response = requests.post(url, json=payload, timeout=2)
        app.logger.info("Log sent to %s status=%s", url, getattr(response, "status_code", None))
    except Exception as e:
        app.logger.warning("Failed to send log to dashboard: %s", e)

# -----------------------------
# Routes - honeypot behavior
# -----------------------------
# Vulnerable to SQL injection: uses string formatting directly
@app.route('/search')
def search():
    q = request.args.get('query', '')
    src = request.remote_addr
    app.logger.info(f"HONEYPOT_SEARCH src={src} query={q} ua={request.headers.get('User-Agent')}")
    # detect suspicious patterns (basic)
    suspicious = any(token.lower() in q.lower() for token in ["'", "--", "/*", "*/", " or ", " union ", "drop", "select"])
    # send encrypted log for all queries (or only suspicious; adjust as needed)
    if q:
        send_log("search", "SQL Injection" if suspicious else "Search Query", f"{q} from {src}", DASHBOARD_ADD_LOG)

    db = get_db()
    with db.cursor() as cur:
        # INTENTIONAL VULN: do not use parameterized queries in honeypot
        sql = f"SELECT id, title, content FROM articles WHERE title LIKE '%{q}%' LIMIT 10;"
        try:
            cur.execute(sql)
            rows = cur.fetchall()
        except Exception as e:
            # If the articles table doesn't exist, return empty results but still log
            app.logger.info("DB query failed (likely no articles table): %s", e)
            rows = []
    return {"results": rows}

# Reflected XSS (renders input unsanitized)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'friend')
    src = request.remote_addr
    app.logger.info(f"HONEYPOT_GREET src={src} name={name} ua={request.headers.get('User-Agent')}")
    html = f"<h2>Hello, {name}!</h2>"
    # optionally log greets if desired:
    # send_log("greet", "Reflected XSS", f"{name} from {src}", DASHBOARD_ADD_LOG)
    return html

# Fake login that just logs creds (useful for brute force capture)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username','')
    password = request.form.get('password','')
    src = request.remote_addr
    ts = __import__('datetime').datetime.utcnow().isoformat()+"Z"
    app.logger.info(f"HONEYPOT_LOGIN src={src} user={username!r} pass={password!r} ts={ts} ua={request.headers.get('User-Agent')}")
    # send encrypted credential attempt
    send_log("login", "Credential Attempt", f"user={username} pass={password} src={src}", DASHBOARD_ADD_LOG)
    return "Login failed", 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010)
