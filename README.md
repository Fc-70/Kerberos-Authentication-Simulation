# Kerberos Authentication Protocol Simulator (Web)

An interactive, educational web-based simulator modeling the Kerberos network authentication protocol (AS, TGS, and Service Server) built with **Python (Flask)** and **Tailwind CSS**.

---

## 📌 Features

- **3-Phase Kerberos Simulation**:
  1. **AS Exchange**: Client authenticates with the Authentication Server to obtain a Ticket Granting Ticket (TGT).
  2. **TGS Exchange**: Client presents the signed TGT to obtain a Service Ticket.
  3. **AP Exchange**: Client presents the Service Ticket to the Service Server for access authorization.
- **HMAC Ticket Integrity**: Demonstrates cryptographic signatures on tickets using HMAC-SHA256.
- **Interactive Scenarios**:
  - ✅ Successful authentication
  - ❌ Incorrect password
  - ❌ Expired service ticket
  - ❌ Tampered service ticket (HMAC integrity failure)
  - ❌ Unauthorized / wrong service request
- **Live Ticket Inspector**: View real-time JSON payloads of the issued TGT and Service Tickets.
- **Terminal Log Output**: Visualizes message sequences, timestamps, and server responses.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Git

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/kerberos-simulator.git
   cd kerberos-simulator
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```

4. **Open in browser**:
   Visit [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔑 Demo Credentials

| Username | Password   | Role         |
|----------|------------|--------------|
| `student`| `cnlab123` | Student Lab  |
| `admin`  | `admin123` | System Admin |

---

## ⚠️ Disclaimer
This simulator is intended solely for educational computer networking and cybersecurity coursework. It demonstrates protocol logic, ticket lifecycles, and cryptographic integrity, but is not a production-grade Kerberos (RFC 4120) implementation.
