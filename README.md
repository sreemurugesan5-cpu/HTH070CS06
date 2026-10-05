# 🛡️ SOC-FUSION — Signal-Fused Intrusion Detection & Response Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Backend-Flask%20REST%20API-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Chart.js](https://img.shields.io/badge/Analytics-Chart.js-FF6384.svg?logo=chartdotjs&logoColor=white)](https://www.chartjs.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Cybersecurity](https://img.shields.io/badge/Domain-SOC%20%2F%20Threat%20Intelligence-red.svg)](https://mitre.org)
[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/sreemurugesan5-cpu/HTH070CS06)

> **A Next-Generation Security Operations Center (SOC) Platform engineered to solve Level 1 Analyst Alert Fatigue through Temporal Signal Correlation, Host Threat Intelligence Profiling, and Dynamic Telemetry Pivoting.**

---

## 📌 Executive Summary

Modern Security Operations Centers face an overwhelming volume of disjointed alerts: port scans, repeated login failures, and traffic anomalies arrive in isolation, causing **alert fatigue** and delayed responses to multi-stage breaches.

**SOC-FUSION** replaces disjointed alert noise with an intelligent **Signal Fusion Engine**. By clustering atomic network anomalies across sliding temporal windows (60s), the platform correlates low-confidence signals into high-fidelity **Composite Incidents** mapped to the MITRE ATT&CK matrix.

The platform provides a responsive, dark glassmorphic cybersecurity interface with real-time telemetry streaming, dynamic IP threat intelligence dossier inspection, autonomous attack simulations, and multi-chart analytics that dynamically pivot to the selected host.

---

## ✨ Key Architectural Features

### ⚡ 1. Temporal Signal Fusion Engine
- Ingests disparate, low-confidence network signals (`PORT_SCAN`, `AUTH_BURST`, `INVALID_USER_SURGE`, `TRAFFIC_SPIKE`, `DNS_TUNNEL`).
- Correlates multi-source signals occurring within temporal windows into a unified **Composite Incident** (e.g., `INC-001: DISTRIBUTED BRUTE FORCE & ANOMALOUS EGRESS`).
- Calculates dynamic confidence metrics (85%–99%) and CVSS-aligned Risk Scores (0–100).

### 🔍 2. Host Threat Intelligence & Dossier Inspection
- Deep IP search bar allowing immediate query of any internal host (`192.168.1.50`, `10.0.12.8`, `172.16.4.19`) or external WAN entity (`8.8.8.8`, `45.33.32.156`).
- Automatic RFC 1918 private subnet vs. public WAN detection.
- Generates on-demand **Threat Intelligence Dossiers** displaying threat verdicts, event tallies, detected signal matrix, and analyst containment playbooks.

### 📊 3. Dynamic IP Telemetry Pivoting (Real-Time Analytics)
- Selecting or searching an IP dynamically transforms all 4 dashboard analytics charts:
  - **Events Over Time (Line Chart):** Re-plots the time-series frequency curve tailored to that specific IP's attack signature.
  - **Signal Distribution (Horizontal Bar):** Dynamically tallies signal types observed for the queried host.
  - **Top IPs by Risk (Bar Chart):** Highlights the active target in **neon cyan (`#00d2ff`)** with highlighted borders.
  - **Severity Breakdown (Doughnut):** Re-calculates severity distributions for the active scope.

### ⏱️ 4. Attack Timeline & MITRE ATT&CK Progression
- Traces end-to-end intrusion lifecycle across sequential phases:
  - **Reconnaissance** (`SYN_SCAN`, `PORT_SCAN`)
  - **Initial Access & Credential Access** (`FAILED_LOGIN`, `AUTH_BURST`)
  - **Execution & Lateral Movement** (`SMB_BURST`, `SQL_INJECTION`)
  - **Exfiltration & C2** (`DNS_TUNNEL_BURST`, `LARGE_OUTBOUND_CONN`)

### 👥 5. Analyst Capacity & Response Queue Management
- Real-time queue triage with threshold alerts.
- Workload balancing across Tier 1, Tier 2, and Senior Incident Responders.
- Live capacity gauges preventing analyst burnout and SLA breaches.

### 📶 6. Zero-Drop Resilience & Mobile Accessibility
- Client-side exponential backoff retry mechanism for network drops.
- Relative API routing enabling zero-configuration deployment across local networks and secure HTTPS cloud tunnels.

---

## 🏛️ System Architecture

```
[ Network Sensors / Firewalls / EDR ]
                 │
                 ▼
     [ Telemetry Ingestion API ]
                 │
                 ▼
     [ SQLite Threat Telemetry DB ]
                 │
                 ▼
  ┌───────────────────────────────┐
  │   Signal Fusion Engine        │
  │   - 60s Temporal Correlation  │
  │   - Risk Scoring Engine (0-100│
  │   - MITRE Stage Mapper        │
  └──────────────┬────────────────┘
                 │
                 ▼
      [ Flask RESTful API ]
   (/api/stats, /api/logs, /api/incidents, /api/ip/<ip>)
                 │
                 ▼
  ┌────────────────────────────────────────────────────────┐
  │             SOC-FUSION Analyst Dashboard               │
  │  - Real-Time Event Stream       - Signal Fusion Matrix │
  │  - Dynamic Chart.js Analytics   - Attack Progression   │
  │  - IP Threat Intelligence Modal - Queue & Capacity Triage│
  └────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Technology | Details |
| :--- | :--- | :--- |
| **Backend** | Python 3, Flask | Lightweight, asynchronous REST API with CORS enabled |
| **Database** | SQLite3 | Embedded persistent datastore for incidents, logs, and host intelligence |
| **Frontend** | Vanilla JavaScript (ES6+), HTML5 | Zero bulky framework dependencies, sub-millisecond DOM updates |
| **Styling** | Modern CSS3 | Glassmorphism, custom cyber neon accents, responsive mobile/desktop breakpoints |
| **Data Viz** | Chart.js 4.x | Line, doughnut, and horizontal/vertical bar charts with live re-rendering |
| **Deployment** | Cloudflare Tunnel / Localhost | Instant cross-device HTTPS tunneling without port-forwarding |

---

## 🚀 Quickstart Guide

### 1. Clone the Repository
```bash
git clone https://github.com/sreemurugesan5-cpu/HTH070CS06.git
cd HTH070CS06
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
# Or manually: pip install flask flask-cors
```

### 3. Launch the Backend Server
```bash
python backend/app.py
```
*The Flask server starts at `http://127.0.0.1:5000`.*

### 4. Open the SOC Dashboard
Navigate to `http://127.0.0.1:5000` in any web browser.

---

## 📱 Mobile & Remote Access (Cloud Tunneling)

To test the application on mobile phones or external laptops without configuring router port-forwarding:

```bash
# Using Cloudflare Tunnel
cloudflared tunnel --edge-ip-version 4 --protocol http2 --url http://127.0.0.1:5000
```
Open the generated HTTPS URL (`https://<subdomain>.trycloudflare.com`) on any smartphone or tablet. The responsive UI automatically adapts for touch interaction and mobile viewports.

---

## 🧪 Interactive Walkthrough & Demonstration

1. **Simulate a Multi-Stage Attack:**
   - Click the **`⚡ Trigger Attack Simulation`** button in the header.
   - Watch the live event stream ingest high-velocity signals (`PORT_SCAN`, `FAILED_LOGIN`, `TRAFFIC_SPIKE`).
   - Notice the Signal Fusion engine automatically synthesize a high-risk composite incident and escalate it to the analyst queue.

2. **Test Dynamic IP Intelligence:**
   - Type `192.168.1.50` into the search bar or click any host badge.
   - Observe the **IP Intelligence Dossier** modal displaying threat verdicts, event histories, and firewall isolation recommendations.
   - Click **`Filter Dashboard`**:
     - All 4 charts immediately pivot to this host's frequency curve and signal distribution.
     - The **Top IPs** bar chart highlights `192.168.1.50` in **neon cyan**.
   - Click **`✖ Clear IP Filter`** to restore the global SOC fleet overview.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/stats` | `GET` | Retrieves aggregate telemetry counters and trends |
| `/api/logs` | `GET` | Retrieves recent live ingested security events |
| `/api/incidents` | `GET` | Retrieves correlated composite security incidents |
| `/api/queue` | `GET` | Retrieves response queue items and analyst capacity |
| `/api/ip/<ip>` | `GET` | Deep query of threat intelligence, signals, and verdict for a specific host |
| `/api/start-simulation` | `POST` | Triggers an autonomous multi-stage attack simulation |
| `/api/health` | `GET` | Service liveness health check |

---

## 🛡️ License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

**Developed with ❤️ for Modern Cybersecurity Operations & Autonomous Incident Response.**
