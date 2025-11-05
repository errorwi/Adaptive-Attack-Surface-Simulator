from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import eventlet
import time
import secrets
import hashlib
import base64
import threading
import hmac
import json
import logging
import base64 as _b64


# Crypto for decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Init
app = Flask(__name__)
socketio = SocketIO(app)

logging.basicConfig(level=logging.INFO)

'''Diffie Hellman key exchange'''

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
    return digest[:length]

'''Diffie Hellman key exchange ends'''

_dh_lock = threading.Lock()
_dh_priv = generate_private_key(256)
_dh_pub = public_from_private(_dh_priv)
_shared_key = None  # bytes - derived AES key

@app.route('/dh/public', methods=['GET'])
def dh_public():
    # return dashboard public key as hex string
    return {"pub": hex(_dh_pub)[2:]}, 200

@app.route('/dh/submit', methods=['POST'])
def dh_submit():
    global _shared_key
    data = request.get_json(force=True)
    peer_hex = data.get("pub")
    if not peer_hex:
        return {"error": "missing pub"}, 400
    try:
        peer_pub = int(peer_hex, 16)
        shared_int = shared_secret_from_peer(peer_pub, _dh_priv)
        key = derive_aes_key(shared_int, length=16)
        with _dh_lock:
            _shared_key = key
        app.logger.info("DH: derived shared key (dashboard) base64=%s", _b64.b64encode(key).decode())
        app.logger.info("DH: derived shared key (dashboard)")
        return {"status": "ok"}, 200
    except Exception as e:
        app.logger.warning("DH submit failed: %s", e)
        return {"error": str(e)}, 400

# (optional) endpoint to show if shared key is ready (for debugging)
@app.route('/dh/status', methods=['GET'])
def dh_status():
    return {"has_shared": _shared_key is not None}, 200

# helper to get dashboard shared key in code
def get_shared_key():
    return _shared_key

log_store = []
mutation_events = []
attack_log_store = []

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/add_log', methods=['POST'])
def add_log():
    log_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "service": request.json.get('service'),
        "attack_type": request.json.get('attack_type'),
        "message": request.json.get('message'),
    }
    log_store.append(log_data)
    socketio.emit('new_log', log_data)
    return {"status": "ok"}

@app.route('/mutation_event', methods=['POST'])
def mutation_event():
    data = request.json
    socketio.emit('mutation_event', data)
    return {"status": "ok"}

# ---- NEW: decrypt & verify encrypted attack log ----
def decrypt_and_verify_encrypted_payload(payload: dict):
    """
    payload: {"iv": "<base64>", "data": "<base64>", "hmac": "<hexdigest>"}
    Returns: dict (decrypted JSON) on success, raises ValueError on failure.
    """
    key = get_shared_key()
    if key is None:
        raise ValueError("No shared DH key established on dashboard")

    # required fields
    b64_iv = payload.get("iv")
    b64_ciphertext = payload.get("data")
    received_hmac = payload.get("hmac")
    if not (b64_iv and b64_ciphertext and received_hmac):
        raise ValueError("Missing fields in payload")

    # Verify HMAC (hexdigest)
    msg = (b64_iv + b64_ciphertext).encode()
    expected_hmac = hmac.new(key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_hmac, received_hmac):
        raise ValueError("HMAC verification failed")

    # decode base64
    try:
        iv = base64.b64decode(b64_iv)
        ciphertext = base64.b64decode(b64_ciphertext)
    except Exception as e:
        raise ValueError(f"Base64 decode error: {e}")

    # Decrypt AES-CBC and unpad
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext_padded, AES.block_size)
    except Exception as e:
        raise ValueError(f"Decryption/unpad error: {e}")

    # parse json
    try:
        data = json.loads(plaintext.decode())
    except Exception as e:
        raise ValueError(f"JSON parse error: {e}")

    return data

@app.route('/add_attack_log', methods=['POST'])
def add_attack_log():
    """
    Expecting encrypted payload:
      { "iv": "...", "data": "...", "hmac": "..." }
    Decrypt + verify then emit/store the resulting dict.
    """
    try:
        payload = request.get_json(force=True)
        # If payload already plaintext dict with 'service' assume unencrypted (backwards compat)
        if isinstance(payload, dict) and 'service' in payload and ('iv' not in payload and 'data' not in payload):
            log_data = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "service": payload.get("service"),
                "attack_type": payload.get("attack_type"),
                "message": payload.get("message"),
            }
        else:
            # encrypted expected
            log_data = decrypt_and_verify_encrypted_payload(payload)
            # ensure timestamp exists or add one if not
            if 'timestamp' not in log_data:
                log_data['timestamp'] = time.strftime("%Y-%m-%d %H:%M:%S")

        attack_log_store.append(log_data)
        app.logger.info("Emitting new_attack_log: %s", log_data)
        socketio.emit('new_attack_log', log_data)
        return {"status": "ok"}, 200

    except ValueError as ve:
        app.logger.warning("Failed to accept encrypted log: %s", ve)
        # Do not leak internals; return reason minimally
        return {"status": "error", "reason": str(ve)}, 400
    except Exception as e:
        app.logger.exception("Unexpected error in /add_attack_log")
        return {"status": "error", "reason": "internal_error"}, 500

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)
