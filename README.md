# 🛡️ CyberShield

> **Continuous Zero-Trust Behaviour Analytics (UEBA) & Threat Intelligence Platform**

CyberShield is a next-generation security monitoring web application built with **Python**, **Flask**, and **SQLite**. It moves beyond traditional static perimeter defense by implementing **Continuous Adaptive Risk and Trust Assessment (CARTA)** and **User & Entity Behavior Analytics (UEBA)** with live browser telemetry, self-registration, and real OTP email delivery.

---

## 🌟 Key Features

### 1. 📝 User Registration & Baseline Establishment
* New users self-register via `/register` with their **Username**, **Gmail/Email**, **Mobile No.**, **Password**, and **Baseline Home City**.
* Establishing their initial **Behaviour Fingerprint Baseline** automatically sets up expected location boundaries for geo-anomaly correlation.

### 2. 📍 Real-Time Location & Device Telemetry
* During authentication, CyberShield automatically collects:
  * **Public Network Geolocation** (City, Region, Country via IP lookup).
  * **Real Client Local Time** (HH:MM).
  * **Hardware & Browser Fingerprint** (`User-Agent`).
* Compares current session telemetry against the user's registered baseline using `behaviour_engine.py` to flag **Geo-Anomalies** and **Off-Hours Logins**.

### 3. 📧 Real Email OTP Delivery (Gmail SMTP)
* When a user's trust score drops below **60/100**, CyberShield triggers an adaptive Step-Up verification.
* A single-use 6-digit passcode is dispatched directly to the user's real email address using standard **Gmail SMTP (TLS:587)**.
* Includes an intelligent fallback logger that outputs directly to the VS Code terminal and screen for offline or sandbox evaluation.

### 4. ⛔ 3-Attempt Lockout & Real-Time Warning Alerts
* Maximum permitted authentication attempts is enforced strictly at **3 attempts**.
* Attempts 1 & 2 dispatch instant warning alerts to the account owner's email and in-app notification center.
* Attempt 3 triggers **instant automated account quarantine** (`is_locked = 1`).

### 5. 🗺️ Tactical Dark-Matter Geolocation Map
* High-contrast, zero-API-key **Leaflet.js & CartoDB Dark-Matter Map**.
* Displays a **🟢 Baseline Geofence Pin** vs a **🔴 Detected Access Pin**.
* Draws a dynamic red threat vector line if the login location violates the user's expected baseline geofence.

### 6. 💻 PWA Desktop App Installation
* CyberShield is an installable **Progressive Web App (PWA)** with a Service Worker and `manifest.json`.
* Can be installed directly onto Windows/macOS laptops as a standalone desktop application via the **"Install Desktop App"** button.

### 7. 🚨 Emergency Session Kill Switch
* One-click panic button on the dashboard allowing users to immediately revoke active sessions, restrict trust to 10/100, and lock down sensitive files if suspicious activity is spotted.

### 8. 🔬 Interactive Attack Simulation Sandbox
Enables security evaluators and administrators to inject realistic threat scenarios:
* 💥 **Brute Force Login Storm**
* 🌍 **Impossible Travel (Geo-Anomaly)**
* 📁 **Data Exfiltration**
* ☠️ **Full APT Kill-Chain**
* 🟢 **Normal Verified Routine**

### 9. 🚨 Security Operations Center (SOC) Console
* **Interactive Threat Distribution Chart** powered by Chart.js.
* **Active Defense Actions**: One-click **Quarantine / Account Lockout**, **Unlock**, and **Trust Score Reset**.
* **Live Search & Filter**: Filter events by severity (*Critical*, *Suspicious*, *Normal*) or search by keyword instantly.
* **SIEM Forensic Log Export**: Download complete audit trails in **RFC-4180 CSV** or **JSON** format.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    User([User / Browser]) -->|Registration| RegForm[Self-Registration (/register)]
    RegForm -->|Store Baseline Profile| DB[(SQLite Database)]
    
    User -->|Login with Live Location & Time| FlaskApp[Flask Core (app.py)]
    
    subgraph UEBA & Security Correlation
        UEBA[Behaviour Engine (behaviour_engine.py)]
        Risk[Risk Engine (risk_engine.py)]
        AttackDetect[Sliding-Window Correlation (attack_detector.py)]
    end
    
    FlaskApp --> UEBA
    FlaskApp --> Risk
    FlaskApp --> AttackDetect
    
    subgraph Zero-Trust Enforcement
        MFA[Adaptive Step-Up MFA Gate (Trust < 60)]
        OTPService[Gmail SMTP Service (otp_service.py)]
        Quarantine[Automated Account Lockout]
    end
    
    Risk --> MFA
    MFA --> OTPService
    OTPService -->|Send Passcode| Gmail[User Gmail Inbox]
    Risk --> Quarantine
    
    FlaskApp <--> DB
    
    subgraph SOC Console
        SOC[Admin Dashboard (admin.html)]
        SIEM[Forensic SIEM Export - CSV/JSON]
    end
    
    DB --> SOC
    SOC --> SIEM
```

---

## 🚀 Quick Start Guide (Running in VS Code)

### 1. Prerequisites
Install Flask:
```powershell
pip install flask werkzeug
```

### 2. (Optional) Configure Real Gmail Delivery
If you want CyberShield to send real emails to your Gmail inbox, set your Gmail and Google App Password in your terminal before running:
```powershell
$env:CYBERSHIELD_SMTP_EMAIL = "your-email@gmail.com"
$env:CYBERSHIELD_SMTP_PASSWORD = "your-16-char-app-password"
```
*(Note: If you don't set this, CyberShield will automatically log the OTP to your terminal and display it on-screen for seamless testing without an email setup!)*

### 3. Start the Server
In your VS Code terminal:
```powershell
python app.py
```

### 4. Open in Browser
Open `http://127.0.0.1:5000` in your web browser.

---

## 🔑 Default Accounts & Registration

| Action | Path | Description |
|---|---|---|
| **Register New Account** | `/register` | Sign up with your real email, phone, and home city to test live location & OTP delivery. |
| **Demo User** | Username: `student` / Password: `student123` | Pre-configured user with baseline in Jammu. |
| **SOC Administrator** | Username: `admin` / Password: `admin123` | Access enterprise SOC metrics, chart, and export logs. |
