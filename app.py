"""
Kerberos Authentication Protocol Simulator (Web Version)
Run with: python app.py
Visit: http://127.0.0.1:5000
"""

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

DEMO_USERS = {
    "student": hashlib.sha256("cnlab123".encode()).hexdigest(),
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
}
TICKET_LIFETIME_SECONDS = 120
SERVICE_NAME = "Computer Networks Lab Server"
TGS_SECRET = secrets.token_bytes(32)
SERVICE_SECRET = secrets.token_bytes(32)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def sign_ticket(payload: dict, secret: bytes) -> dict:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return {"payload": payload, "signature": signature}


def verify_ticket(ticket: dict, secret: bytes):
    if not isinstance(ticket, dict) or "payload" not in ticket or "signature" not in ticket:
        return False, "Ticket format is invalid."
    body = json.dumps(ticket["payload"], sort_keys=True, separators=(",", ":"))
    expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, ticket["signature"]):
        return False, "Ticket integrity check failed (HMAC mismatch)."
    if ticket["payload"].get("expires_at", 0) < time.time():
        return False, "Ticket has expired."
    return True, "Ticket signature and lifetime are valid."


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/simulate", methods=["POST"])
def simulate():
    data = request.json or {}
    username = (data.get("username") or "student").strip()
    password = data.get("password") or ""
    scenario = data.get("scenario") or "Successful authentication"

    logs = []

    def log(actor, message, tag="normal"):
        stamp = datetime.now().strftime("%H:%M:%S")
        logs.append({"time": stamp, "actor": actor, "message": message, "tag": tag})

    log("SYSTEM", f"Scenario selected: {scenario}", "heading")

    # 1. AS Authentication
    log("CLIENT → AS", f"Authentication request for principal '{username}'.", "heading")
    log("AS", "Looking up the user's stored password verifier.")

    test_password = password
    if scenario == "Incorrect password":
        test_password = password + "_wrong" if password else "wrong-password"

    stored = DEMO_USERS.get(username)
    if stored is None or not hmac.compare_digest(stored, sha256_text(test_password)):
        log("AS → CLIENT", "PREAUTH_FAILED: invalid username or password.", "error")
        return jsonify({
            "status": "ACCESS DENIED: INVALID CREDENTIALS",
            "status_type": "error",
            "logs": logs,
            "tgt": None,
            "service_ticket": None
        })

    log("AS", "Credentials accepted for this educational simulation.", "success")
    now = time.time()
    tgt_payload = {
        "client": username,
        "audience": "TGS",
        "issued_at": now,
        "expires_at": now + TICKET_LIFETIME_SECONDS,
        "session_key": secrets.token_hex(16),
        "ticket_id": secrets.token_hex(8)
    }
    tgt = sign_ticket(tgt_payload, TGS_SECRET)
    log("AS → CLIENT", "AS-REP: TGT issued for the TGS (lifetime: 120s).", "success")

    # 2. TGS Request
    target_requested_service = "Restricted Admin Console" if scenario == "Unauthorized service" else SERVICE_NAME
    log("CLIENT → TGS", f"TGS-REQ: TGT presented for service '{target_requested_service}'.", "heading")

    valid, reason = verify_ticket(tgt, TGS_SECRET)
    if not valid:
        log("TGS", f"TGT rejected: {reason}", "error")
        return jsonify({
            "status": "ACCESS DENIED: TGT REJECTED",
            "status_type": "error",
            "logs": logs,
            "tgt": tgt,
            "service_ticket": None
        })

    log("TGS", "TGT integrity and expiration checks passed.", "success")
    st_payload = {
        "client": username,
        "service": target_requested_service,
        "issued_at": now,
        "expires_at": now + TICKET_LIFETIME_SECONDS,
        "ticket_id": secrets.token_hex(8)
    }
    service_ticket = sign_ticket(st_payload, SERVICE_SECRET)
    log("TGS → CLIENT", "TGS-REP: service ticket issued.", "success")

    # Tampering / Expiry Scenarios
    if scenario == "Expired service ticket":
        service_ticket["payload"]["expires_at"] = time.time() - 10
        log("SYSTEM", "Test setup: service ticket expiry time moved into past.", "error")
    elif scenario == "Tampered service ticket":
        service_ticket["payload"]["service"] = "Restricted Admin Console"
        log("SYSTEM", "Test setup: service payload modified without re-signing HMAC.", "error")

    # 3. Service Access (AP-REQ)
    log("CLIENT → SERVICE", f"AP-REQ: presenting ticket to '{SERVICE_NAME}'.", "heading")
    valid, reason = verify_ticket(service_ticket, SERVICE_SECRET)
    if not valid:
        log("SERVICE", f"Ticket rejected: {reason}", "error")
        return jsonify({
            "status": "ACCESS DENIED: TICKET INVALID",
            "status_type": "error",
            "logs": logs,
            "tgt": tgt,
            "service_ticket": service_ticket
        })

    if service_ticket["payload"].get("service") != SERVICE_NAME:
        log("SERVICE", f"Ticket is for '{service_ticket['payload'].get('service')}', not '{SERVICE_NAME}'.", "error")
        return jsonify({
            "status": "ACCESS DENIED: WRONG SERVICE",
            "status_type": "error",
            "logs": logs,
            "tgt": tgt,
            "service_ticket": service_ticket
        })

    log("SERVICE", f"Ticket verified for client '{username}'.", "success")
    log("SERVICE → CLIENT", "ACCESS GRANTED: protected lab resource is available.", "success")

    return jsonify({
        "status": "ACCESS GRANTED",
        "status_type": "success",
        "logs": logs,
        "tgt": tgt,
        "service_ticket": service_ticket
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
