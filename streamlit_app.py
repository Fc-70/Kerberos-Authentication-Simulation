import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime
import streamlit as st

st.set_page_config(page_title="Kerberos Protocol Simulator", page_icon="🔐", layout="wide")

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


# --- Header & Architecture ---
st.title("🔐 Kerberos Authentication Protocol Simulator")
st.caption("Client → Authentication Server (AS) → Ticket Granting Server (TGS) → Service Server")

cols = st.columns(4)
with cols[0]:
    st.info("**1. Client**\n\nUser / Requester")
with cols[1]:
    st.info("**2. AS**\n\nChecks password & issues TGT")
with cols[2]:
    st.info("**3. TGS**\n\nValidates TGT & issues Service Ticket")
with cols[3]:
    st.info("**4. Service Server**\n\nVerifies Service Ticket & grants access")

st.divider()

# --- Controls in Sidebar ---
with st.sidebar:
    st.header("Simulation Settings")
    username = st.text_input("Username", value="student")
    password = st.text_input("Password", value="cnlab123", type="password")
    scenario = st.selectbox(
        "Scenario",
        [
            "Successful authentication",
            "Incorrect password",
            "Expired service ticket",
            "Tampered service ticket",
            "Unauthorized service",
        ],
    )
    st.caption("Demo users: `student` / `cnlab123`, `admin` / `admin123`")
    run_btn = st.button("🚀 Run Simulation", type="primary", use_container_width=True)

# --- Simulation Logic ---
if run_btn:
    logs = []

    def log(actor, message, level="info"):
        stamp = datetime.now().strftime("%H:%M:%S")
        logs.append((stamp, actor, message, level))

    log("SYSTEM", f"Scenario selected: {scenario}", "system")

    # Step 1: AS
    log("CLIENT → AS", f"Authentication request for principal '{username}'.", "step")
    test_password = password
    if scenario == "Incorrect password":
        test_password = password + "_wrong" if password else "wrong-password"

    tgt = None
    st_ticket = None

    stored = DEMO_USERS.get(username)
    if stored is None or not hmac.compare_digest(stored, sha256_text(test_password)):
        log("AS → CLIENT", "PREAUTH_FAILED: invalid username or password.", "error")
        st.error("❌ ACCESS DENIED: INVALID CREDENTIALS")
    else:
        log("AS", "Credentials accepted for this educational simulation.", "success")
        now = time.time()
        tgt_payload = {
            "client": username,
            "audience": "TGS",
            "issued_at": now,
            "expires_at": now + TICKET_LIFETIME_SECONDS,
            "session_key": secrets.token_hex(16),
            "ticket_id": secrets.token_hex(8),
        }
        tgt = sign_ticket(tgt_payload, TGS_SECRET)
        log("AS → CLIENT", "AS-REP: TGT issued for the TGS (lifetime: 120s).", "success")

        # Step 2: TGS
        target_service = "Restricted Admin Console" if scenario == "Unauthorized service" else SERVICE_NAME
        log("CLIENT → TGS", f"TGS-REQ: TGT presented for service '{target_service}'.", "step")
        valid, reason = verify_ticket(tgt, TGS_SECRET)

        if not valid:
            log("TGS", f"TGT rejected: {reason}", "error")
            st.error("❌ ACCESS DENIED: TGT REJECTED")
        else:
            log("TGS", "TGT integrity and expiration checks passed.", "success")
            st_payload = {
                "client": username,
                "service": target_service,
                "issued_at": now,
                "expires_at": now + TICKET_LIFETIME_SECONDS,
                "ticket_id": secrets.token_hex(8),
            }
            st_ticket = sign_ticket(st_payload, SERVICE_SECRET)
            log("TGS → CLIENT", "TGS-REP: service ticket issued.", "success")

            # Tamper / Expiry
            if scenario == "Expired service ticket":
                st_ticket["payload"]["expires_at"] = time.time() - 10
                log("SYSTEM", "Test setup: ticket expiry moved into past.", "warning")
            elif scenario == "Tampered service ticket":
                st_ticket["payload"]["service"] = "Restricted Admin Console"
                log("SYSTEM", "Test setup: service name modified without re-signing HMAC.", "warning")

            # Step 3: Service Server (AP)
            log("CLIENT → SERVICE", f"AP-REQ: presenting ticket to '{SERVICE_NAME}'.", "step")
            valid, reason = verify_ticket(st_ticket, SERVICE_SECRET)

            if not valid:
                log("SERVICE", f"Ticket rejected: {reason}", "error")
                st.error("❌ ACCESS DENIED: TICKET INVALID")
            elif st_ticket["payload"].get("service") != SERVICE_NAME:
                log("SERVICE", f"Ticket is for '{st_ticket['payload'].get('service')}', not '{SERVICE_NAME}'.", "error")
                st.error("❌ ACCESS DENIED: WRONG SERVICE")
            else:
                log("SERVICE", f"Ticket verified for client '{username}'.", "success")
                log("SERVICE → CLIENT", "ACCESS GRANTED: protected lab resource is available.", "success")
                st.success("🎉 ACCESS GRANTED: Protected Resource Available!")

    # Display Logs and Tickets
    log_col, ticket_col = st.columns([3, 2])
    with log_col:
        st.subheader("📜 Protocol Log")
        for stamp, actor, msg, lvl in logs:
            if lvl == "error":
                st.markdown(f"`[{stamp}]` :red[**[{actor}]** {msg}]")
            elif lvl == "success":
                st.markdown(f"`[{stamp}]` :green[**[{actor}]** {msg}]")
            elif lvl == "warning":
                st.markdown(f"`[{stamp}]` :orange[**[{actor}]** {msg}]")
            elif lvl == "step":
                st.markdown(f"`[{stamp}]` :blue[**[{actor}]** {msg}]")
            else:
                st.markdown(f"`[{stamp}]` **[{actor}]** {msg}")

    with ticket_col:
        st.subheader("🎫 Ticket Inspector")
        if tgt:
            st.caption("Ticket Granting Ticket (TGT)")
            st.json(tgt)
        if st_ticket:
            st.caption("Service Ticket (ST)")
            st.json(st_ticket)
else:
    st.info("👈 Select credentials and scenario from the sidebar and click **Run Simulation**.")
