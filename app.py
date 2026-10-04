from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify
from datetime import datetime
import csv
import io
import random

from database import (
    create_tables,
    log_activity,
    update_trust_score,
    get_trust_score,
    reset_trust_score,
    lock_user,
    unlock_user,
    quarantine_user_honeytoken,
    get_all_users,
    get_user_by_username,
    register_user,
    update_user_login_telemetry,
    get_behaviour_profile,
    get_user_activities,
    get_all_activities,
    get_security_stats,
    verify_user,
    get_policy,
    get_all_policies,
    update_policy,
    add_notification,
    get_user_notifications,
    mark_notifications_read
)

from risk_engine import calculate_risk
from attack_detector import detect_attack_chain
from behaviour_engine import analyze_behaviour, parse_user_agent
from otp_service import send_otp_email

app = Flask(__name__)
app.secret_key = "cybershield-secure-production-key"

# Ensure tables and migrations are initialized
create_tables()


# =========================================================
# REGISTRATION CONTROLLER
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        baseline_location = request.form.get("baseline_location", "").strip() or "Jammu"
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(username) < 3:
            message = "Username must be at least 3 characters long."
        elif "@" not in email or "." not in email:
            message = "Please provide a valid email address."
        elif len(password) < 6:
            message = "Password must be at least 6 characters long."
        elif password != confirm_password:
            message = "Passwords do not match. Please verify."
        else:
            success, msg = register_user(
                username=username,
                email=email,
                phone=phone,
                password=password,
                baseline_location=baseline_location,
                baseline_device=parse_user_agent(request.headers.get("User-Agent", ""))
            )
            if success:
                return redirect(url_for("login", success_msg=f"Account created for {username}! Please sign in."))
            else:
                message = msg

    return render_template("register.html", message=message)


# =========================================================
# LOGIN CONTROLLER (WITH REAL TELEMETRY INGESTION)
# =========================================================

@app.route("/", methods=["GET", "POST"])
def login():
    message = request.args.get("message", "")
    success_msg = request.args.get("success_msg", "")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Real client telemetry captured from form / headers
        real_location = request.form.get("real_location", "").strip() or "Jammu"
        real_time = request.form.get("real_time", "").strip() or datetime.now().strftime("%H:%M")
        real_device = request.form.get("real_device", "").strip() or parse_user_agent(request.headers.get("User-Agent", ""))
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        user, status_msg = verify_user(username, password)

        if user:
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["mfa_verified"] = False  # Reset on fresh login
            session.pop("demo_otp", None)

            # Calculate hours difference from previous authenticated login for Haversine speed
            hours_diff = 1.0
            if user.get("last_login_time"):
                try:
                    last_dt = datetime.strptime(user["last_login_time"], "%Y-%m-%d %H:%M:%S")
                    delta = (datetime.now() - last_dt).total_seconds() / 3600.0
                    hours_diff = max(delta, 0.1)
                except Exception:
                    hours_diff = 1.0

            # Record real login telemetry in database
            now_full_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            update_user_login_telemetry(user["username"], location=real_location, login_time=now_full_str)

            # Telemetry correlation with user's baseline behaviour
            profile = get_behaviour_profile(user["username"])

            if profile:
                b_risk, b_status, b_anomalies = analyze_behaviour(
                    usual_login_time=profile["usual_login_time"],
                    usual_device=profile["usual_device"],
                    usual_location=profile["usual_location"],
                    normal_file_access=profile["normal_file_access"],
                    current_login_time=real_time,
                    current_device=real_device,
                    current_location=real_location,
                    current_file_access=profile["normal_file_access"],
                    client_ip=client_ip,
                    hours_since_last_login=hours_diff
                )
                login_risk = max(5, b_risk)
                threat_level = b_status
            else:
                login_risk = 5
                threat_level = "Normal"
                b_anomalies = []

            activity_note = f"Successful Login ({real_device} from {real_location})"
            if b_anomalies:
                activity_note += f" - {b_anomalies[0]}"

            log_activity(
                username=user["username"],
                activity=activity_note,
                risk_score=login_risk,
                threat_level=threat_level
            )
            update_trust_score(user["username"], login_risk)

            if user["role"] == "admin":
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("dashboard", username=user["username"]))
        else:
            message = status_msg

    return render_template("login.html", message=message, success_msg=success_msg)


# =========================================================
# USER DASHBOARD (WITH ADAPTIVE ZERO-TRUST MFA GATE)
# =========================================================

@app.route("/dashboard/<username>")
def dashboard(username):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("username") != username and session.get("role") != "admin":
        return "Access Denied: You cannot view other users' dashboards.", 403

    trust_score = get_trust_score(username)
    mfa_threshold = int(get_policy("mfa_threshold", 60))

    # Zero-Trust Check: If trust score falls below threshold, enforce Step-Up MFA
    if trust_score < mfa_threshold and not session.get("mfa_verified", False):
        return redirect(url_for("verify_mfa", username=username))

    activities = get_user_activities(username)
    profile = get_behaviour_profile(username)
    user_data = get_user_by_username(username) or {}

    if profile:
        usual_login_time = profile["usual_login_time"]
        usual_device = profile["usual_device"]
        usual_location = profile["usual_location"]
        normal_file_access = profile["normal_file_access"]
    else:
        usual_login_time = "09:00"
        usual_device = "Desktop"
        usual_location = "Jammu"
        normal_file_access = "Low"

    notifications = get_user_notifications(username, limit=10)

    return render_template(
        "dashboard.html",
        username=username,
        user=user_data,
        activities=activities,
        trust_score=trust_score,
        usual_login_time=usual_login_time,
        usual_device=usual_device,
        usual_location=usual_location,
        normal_file_access=normal_file_access,
        notifications=notifications
    )


# =========================================================
# EMERGENCY KILL SWITCH (ACTIVE DEFENSE PROTOCOL)
# =========================================================

@app.route("/emergency-kill/<username>", methods=["POST"])
def emergency_kill(username):
    if "username" not in session or (session.get("username") != username and session.get("role") != "admin"):
        return "Access Denied", 403

    reset_trust_score(username, 10)
    session["mfa_verified"] = False
    session.pop("demo_otp", None)

    add_notification(
        username=username,
        title="🚨 Emergency Protocol Activated",
        message="User manually engaged Emergency Session Kill Switch. Trust restricted to 10/100.",
        severity="critical"
    )
    log_activity(
        username=username,
        activity="EMERGENCY KILL SWITCH ENGAGED (Sessions Revoked & Trust Restricted)",
        risk_score=95,
        threat_level="Critical"
    )

    return redirect(url_for("dashboard", username=username))


# =========================================================
# STEP-UP MFA CHALLENGE (REAL EMAIL / OTP DISPATCH)
# =========================================================

@app.route("/verify-mfa/<username>", methods=["GET", "POST"])
def verify_mfa(username):
    if "username" not in session:
        return redirect(url_for("login"))

    if session.get("username") != username and session.get("role") != "admin":
        return "Access Denied", 403

    user = get_user_by_username(username) or {}
    user_email = user.get("email") or f"{username}@gmail.com"

    trust_score = get_trust_score(username)
    threshold = int(get_policy("mfa_threshold", 60))
    error = ""

    # Generate a new 6-digit OTP and dispatch via Email/SMTP if not yet generated
    if "demo_otp" not in session:
        otp_code = str(random.randint(100000, 999999))
        session["demo_otp"] = otp_code
        send_otp_email(user_email, otp_code, username)

    demo_otp = session.get("demo_otp")

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()

        if entered_otp == demo_otp:
            session["mfa_verified"] = True
            session.pop("demo_otp", None)

            # Log verification event & reward trust recovery (+15 points)
            log_activity(
                username=username,
                activity="Step-Up MFA Challenge Passed (Email Token Confirmed)",
                risk_score=0,
                threat_level="Normal"
            )
            current_score = get_trust_score(username)
            reset_trust_score(username, min(100, current_score + 15))

            return redirect(url_for("dashboard", username=username))
        else:
            error = "Invalid verification code. Please check your email or test token."
            log_activity(
                username=username,
                activity="Step-Up MFA Challenge Failed (Incorrect Passcode)",
                risk_score=35,
                threat_level="Suspicious"
            )
            update_trust_score(username, 35)

    return render_template(
        "mfa.html",
        username=username,
        user_email=user_email,
        trust_score=trust_score,
        threshold=threshold,
        demo_otp=demo_otp,
        error=error
    )


# =========================================================


# =========================================================
# SOC ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        return "Access Denied: SOC Administrator privileges required.", 403

    stats = get_security_stats()
    users = get_all_users()
    activities = get_all_activities(limit=100)
    policies = get_all_policies()

    return render_template(
        "admin.html",
        stats=stats,
        users=users,
        activities=activities,
        policies=policies
    )


# =========================================================
# SOC FORENSIC EXPORT (CSV & SIEM JSON)
# =========================================================

@app.route("/admin/export/csv")
def admin_export_csv():
    if session.get("role") != "admin":
        return "Access Denied", 403

    activities = get_all_activities(limit=1000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Event ID", "Timestamp", "Username", "Security Event", "Risk Score", "Threat Level", "User Trust"])

    for a in activities:
        writer.writerow([
            a.get("id"),
            a.get("timestamp"),
            a.get("username"),
            a.get("activity"),
            a.get("risk_score"),
            a.get("threat_level"),
            a.get("trust_score")
        ])

    csv_data = output.getvalue()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cybershield_audit_log.csv"}
    )


@app.route("/admin/export/json")
def admin_export_json():
    if session.get("role") != "admin":
        return "Access Denied", 403

    activities = get_all_activities(limit=1000)
    return jsonify({
        "system": "CyberShield SOC SIEM Feed",
        "exported_at": datetime.now().isoformat(),
        "total_records": len(activities),
        "events": activities
    })


# =========================================================
# SOC ADMIN RESPONSE ACTIONS
# =========================================================

@app.route("/admin/lock/<username>", methods=["POST"])
def admin_lock(username):
    if session.get("role") != "admin":
        return "Access Denied", 403

    lock_user(username)
    log_activity(
        username=username,
        activity=f"Account Quarantined by SOC Admin ({session.get('username')})",
        risk_score=90,
        threat_level="Critical"
    )
    return redirect(url_for("admin"))


@app.route("/admin/unlock/<username>", methods=["POST"])
def admin_unlock(username):
    if session.get("role") != "admin":
        return "Access Denied", 403

    unlock_user(username)
    log_activity(
        username=username,
        activity=f"Account Unlocked & Restored by SOC Admin ({session.get('username')})",
        risk_score=5,
        threat_level="Normal"
    )
    return redirect(url_for("admin"))


@app.route("/admin/reset-trust/<username>", methods=["POST"])
def admin_reset_trust(username):
    if session.get("role") != "admin":
        return "Access Denied", 403

    reset_trust_score(username, 100)
    log_activity(
        username=username,
        activity=f"Trust Score Reset to 100 by SOC Admin ({session.get('username')})",
        risk_score=0,
        threat_level="Normal"
    )
    return redirect(url_for("admin"))


# =========================================================
# SECURED ENTERPRISE & STUDENT FILE VAULT (WITH HONEYTOKENS)
# =========================================================

HONEYTOKEN_KEYWORDS = [
    "confidential", "salary", "salaries", "keys", "passwords",
    "leaked", "exam_question", "grading_key", "ssh_private", "root_ssh",
    "disciplinary", "firewall_root", "credentials"
]

def is_honeytoken_file(filename: str) -> bool:
    fn_lower = filename.lower()
    return any(k in fn_lower for k in HONEYTOKEN_KEYWORDS)

def generate_document_text(filename: str, username: str) -> tuple[str, str, str, str, str]:
    """
    Returns (title, category, issuer, classification, text_content)
    tailored to the document type.
    """
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if "transcript" in filename.lower():
        title = "Official Academic Transcript — Semester VI"
        category = "Academic & Institutional"
        issuer = "Office of the Registrar & Controller of Examinations"
        classification = "Confidential Student Record"
        content = f"""UNIVERSITY ACADEMIC RECORDS DIVISION
OFFICIAL ACADEMIC TRANSCRIPT — SEMESTER VI
================================================================================
Student Name:            {username.upper()}
Enrollment ID:           CS-2022-8491
Degree Program:          Bachelor of Technology (Computer Science & Engineering)
Major:                   Cybersecurity & Information Assurance
Academic Year:           2025 - 2026
Institutional Standing:  First Class with Distinction (Honors)
--------------------------------------------------------------------------------
COURSE CODE | COURSE TITLE                             | CREDITS | GRADE | POINTS
--------------------------------------------------------------------------------
CS-601      | Cryptography & Network Security          |    4    |   A+  |   10
CS-602      | Continuous Zero-Trust Security Systems   |    4    |   A+  |   10
CS-603      | Distributed Systems & Cloud Security     |    4    |   A   |    9
CS-604      | Machine Learning for Cyber Defense       |    3    |   A+  |   10
CS-605      | Ethical Hacking & Penetration Testing    |    3    |   A+  |   10
CS-606P     | Advanced SOC & Digital Forensics Lab     |    2    |   O   |   10
--------------------------------------------------------------------------------
Semester Credits:        20
Semester GPA (SGPA):     9.80 / 10.00
Cumulative GPA (CGPA):   9.64 / 10.00
Degree Status:           Completed All Core Prerequisites for B.Tech Defense
--------------------------------------------------------------------------------
AUTHENTICATION & INTEGRITY:
Verification Hash:       SHA256: 4e9c7b12d58f331908ae7c2105dae004bf768912e543
Digitally Certified By:  Office of the Registrar
Timestamp:               {now_str}
Status:                  OFFICIAL & CERTIFIED — TAMPER RESISTANT
================================================================================
"""
        return title, category, issuer, classification, content

    elif "tuition" in filename.lower() or "fee" in filename.lower():
        title = "Official Tuition & Institutional Fee Receipt"
        category = "Academic & Institutional"
        issuer = "Finance & Accounts Division / Office of the Bursar"
        classification = "Financial Record"
        content = f"""INSTITUTIONAL BURSAR & FINANCE DIVISION
STUDENT TUITION & SERVICES FEE RECEIPT
================================================================================
Receipt Number:          REC-2025-89421
Student Name:            {username.upper()}
Student ID:              CS-2022-8491
Academic Term:           Spring Semester 2026
Payment Method:          Online NetBanking / Institutional Gateway
Transaction Reference:   TXN-INST-90238471-AXIS
Payment Timestamp:       {now_str}
--------------------------------------------------------------------------------
ITEM DESCRIPTION                              | AMOUNT (USD)  | STATUS
--------------------------------------------------------------------------------
Undergraduate Tuition (Cybersecurity Special) |     $3,400.00 | PAID
Advanced Cyber Defense Lab & Cloud Quota Fee  |       $450.00 | PAID
Library & Research Databases Access Fee       |       $150.00 | PAID
Campus Infrastructure & Health Services       |       $250.00 | PAID
--------------------------------------------------------------------------------
TOTAL AMOUNT PAID:                                  $4,250.00
OUTSTANDING BALANCE:                                    $0.00 (NIL DUES)
--------------------------------------------------------------------------------
Clearance: Authorized for Examination Hall Ticket & Semester Registration
Authorized Signatory: Bursar & Chief Financial Controller
Digital Seal: SHA256: d82e4418af89e0231b54a7c83f9e201b17a659021e3f89a2
================================================================================
"""
        return title, category, issuer, classification, content

    elif "identity" in filename.lower() or "id_card" in filename.lower():
        title = "Institutional Student Identity & Access Card Record"
        category = "Academic & Institutional"
        issuer = "Campus Security & Identity Management Services"
        classification = "Biometric & Access Credential"
        content = f"""CAMPUS SECURITY & IDENTITY MANAGEMENT
DIGITAL STUDENT IDENTITY PROFILE & ACCESS RECORD
================================================================================
Cardholder Name:         {username.upper()}
Role:                    Full-Time Student / Research Scholar
Department:              Computer Science & Engineering
Enrollment Number:       CS-2022-8491
Smart Card RFID UID:     0x8F-9A-23-E1-C4
Biometric Enrollment:    Fingerprint & Facial Geometry VERIFIED
Card Validity:           August 2022 — July 2026
--------------------------------------------------------------------------------
CAMPUS ACCESS CLEARANCES:
- Main Gate & Campus Facilities:        GRANTED (24/7 Access)
- CSE Advanced Computing Laboratories:  GRANTED (Authorized)
- Cyber Defense SOC Testbed:            GRANTED (Student Operator)
- Central Library & Study Halls:        GRANTED
- Residential Block C:                  GRANTED
--------------------------------------------------------------------------------
Zero-Trust Baseline Location: Jammu Campus Geofence
Security Desk Dispatch: +91-191-2400199
================================================================================
"""
        return title, category, issuer, classification, content

    elif "bonafide" in filename.lower() or "enrollment" in filename.lower():
        title = "University Bonafide Enrollment & Character Certificate"
        category = "Academic & Institutional"
        issuer = "Office of the Dean of Student Affairs"
        classification = "Official Attestation"
        content = f"""OFFICE OF THE DEAN OF STUDENT AFFAIRS
BONAFIDE STUDENTSHIP & ENROLLMENT ATTESTATION
================================================================================
Reference ID:            DSA/BONAFIDE/2026/0491
Date of Issuance:        {now_str}

TO WHOMSOEVER IT MAY CONCERN:

This is to certify that {username.upper()} (Enrollment No. CS-2022-8491) is a
bona fide, regular, full-time undergraduate student currently enrolled in the
8th semester of the Bachelor of Technology program in Computer Science and
Engineering at this Institution for the academic session 2025-2026.

According to institutional records, their conduct and character throughout the
course of study have been EXEMPLARY. They are currently leading the capstone
research project titled 'CyberShield: Continuous Zero-Trust UEBA Platform'.

This certificate is granted upon the student's request for academic defense,
internship credentials, and technical project defense.

Dean of Student Affairs:  Prof. R. K. Sharma, Ph.D.
Seal: Institutional Office of Dean Student Welfare
================================================================================
"""
        return title, category, issuer, classification, content

    elif "hostel" in filename.lower():
        title = "Campus Hostel Allotment & Security Clearance Record"
        category = "Academic & Institutional"
        issuer = "Residential Life Administration & Security Board"
        classification = "Institutional Living Record"
        content = f"""CAMPUS RESIDENTIAL LIFE ADMINISTRATION
HOSTEL ALLOTMENT & SECURITY CLEARANCE PASS
================================================================================
Resident Student:        {username.upper()}
Hostel Block:            Block C (Senior Engineering Wing)
Room Number:             Room C-402
Allotment Period:        Academic Year 2025 - 2026
Hostel Warden:           Dr. S. K. Gupta
--------------------------------------------------------------------------------
SECURITY COMPLIANCE STATUS:
- Mess Dues:             NIL (Paid in full)
- Property Damage:       NIL
- Night Curfew Pass:     AUTHORIZED (SOC Lab Extended Research Clearance)
- Emergency Contact:     Verified on Student Profile
--------------------------------------------------------------------------------
Chief Hostel Warden Signature: [DIGITALLY SIGNED & VERIFIED]
================================================================================
"""
        return title, category, issuer, classification, content

    elif "capstone" in filename.lower() or "thesis" in filename.lower():
        title = "CyberShield Zero-Trust UEBA Capstone Project Thesis"
        category = "Student Work & Projects"
        issuer = "Dept of Computer Science — Capstone Review Committee"
        classification = "Student Research Work"
        content = f"""CAPSTONE RESEARCH PROJECT THESIS
CYBERSHIELD: CONTINUOUS ZERO-TRUST USER AND ENTITY BEHAVIOR ANALYTICS (UEBA)
================================================================================
Author / Student:        {username.upper()} (Roll No. CS-2022-8491)
Faculty Project Guide:   Prof. A. Verma, Head of Cybersecurity Research
Academic Department:     Department of Computer Science & Engineering
Degree:                  Bachelor of Technology in Computer Science & Engineering
Submission Date:         Academic Year 2025 - 2026
--------------------------------------------------------------------------------
ABSTRACT:
Traditional boundary perimeter security models ('castle-and-moat') fail when
credentials are stolen or insider privileges are abused. CyberShield implements
the Gartner Continuous Adaptive Risk and Trust Assessment (CARTA) framework:

1. Never Trust, Always Verify: Identity is continually re-evaluated using live
   browser telemetry (device fingerprint, geolocation, access velocity).
2. Mathematical Haversine Distance & Velocity: Calculates great-circle distance
   between logins to flag physical impossibilities (velocity > 800 km/h).
3. Active Cyber Deception: Infiltrates file repositories with Honeytoken Canary
   Traps that immediately quarantine adversaries upon unauthorized access [MITRE T1204].
4. Adaptive Step-Up MFA: Dynamic 6-digit cryptographic OTP gate triggered when
   trust score degrades below the safety threshold (60/100).
5. Sliding-Window Attack Correlation: Identifies multi-stage threats (brute force,
   credential stuffing, data exfiltration) mapped to the MITRE ATT&CK Matrix.

EVALUATION & EXPERIMENTAL RESULTS:
Tested across 37 comprehensive unit & integration tests with 0 external dependencies.
Zero-Trust dynamic trust engine achieved 100% detection rate of impossible travel,
brute force, and honeytoken exfiltration attempts in under 3.5ms evaluation latency.
--------------------------------------------------------------------------------
Project Grade:           Grade 'O' (Outstanding - Recommended for Best Project Award)
Supervisor Sign-Off:     Prof. A. Verma [Approved for Viva Defense]
================================================================================
"""
        return title, category, issuer, classification, content

    elif "lab_manual" in filename.lower() or "experiments" in filename.lower():
        title = "Network Security & Cyber Defense Laboratory Submissions"
        category = "Student Work & Projects"
        issuer = "CSE Department Laboratory Review Board"
        classification = "Laboratory Submissions"
        content = f"""NETWORK SECURITY & DEFENSE LABORATORY MANUAL
STUDENT PRACTICAL ASSIGNMENTS & EXPERIMENTAL CODE
================================================================================
Student Name:            {username.upper()}
Lab Course:              CS-606P Advanced SOC & Digital Forensics Lab
Total Experiments:       10 of 10 Completed & Verified
Lab Supervisor:          Er. N. Chawla
--------------------------------------------------------------------------------
EXPERIMENT INDEX & COMPLETION LOG:
Exp 1:  Packet Sniffing and TLS 1.3 Protocol Dissection using Wireshark [PASS]
Exp 2:  Configuring Stateful Packet Filtering with Linux iptables [PASS]
Exp 3:  Intrusion Detection System Rule Engineering with Snort [PASS]
Exp 4:  ARP Cache Poisoning & Man-in-the-Middle (MITM) Defense [PASS]
Exp 5:  RSA Asymmetric Key Generation, Signing, and Verification [PASS]
Exp 6:  HMAC-SHA256 Token Construction for Zero-Trust Session Management [PASS]
Exp 7:  Haversine Great-Circle Geolocation Calculation in Pure Python [PASS]
Exp 8:  Canary Honeypot Injection in Web Storage Subsystems [PASS]
Exp 9:  Simulating MITRE ATT&CK T1110 Brute Force Lockouts [PASS]
Exp 10: Building an Autonomous SOC Incident Dossier & Alert Stream [PASS]
--------------------------------------------------------------------------------
Total Lab Marks Awarded: 50 / 50 (Grade: A+)
Lab Instructor Verified: Er. N. Chawla
================================================================================
"""
        return title, category, issuer, classification, content

    elif "vulnerability" in filename.lower() or "ethical_hacking" in filename.lower():
        title = "Ethical Hacking & Vulnerability Assessment Report"
        category = "Student Work & Projects"
        issuer = "Institutional Cyber Security Center of Excellence"
        classification = "Security Audit Report"
        content = f"""ETHICAL HACKING & PENETRATION TESTING AUDIT REPORT
CAMPUS TESTBED VULNERABILITY ASSESSMENT & REMEDIATION
================================================================================
Lead Student Auditor:    {username.upper()} (Certified Ethical Hacker Candidate)
Target Scope:            Institutional Sandbox Lab Portal (10.0.4.0/24)
Testing Standard:        OWASP Top 10 (2025 Edition) & NIST SP 800-115
Audit Status:            REMEDIATED & SIGNED OFF
--------------------------------------------------------------------------------
KEY FINDINGS & MITIGATIONS IMPLEMENTED:
1. SQL Injection (A03:2021-Injection):
   - Finding: Login endpoint vulnerable to payload \"' OR 1=1 --\".
   - Remediation: Implemented parameterized SQLite queries using row_factory.
2. Sensitive Data Exposure (A02:2021-Cryptographic Failures):
   - Finding: Passwords stored in plain text.
   - Remediation: Enforced SHA-256 salted password hashing in database.py.
3. Broken Access Control (A01:2021):
   - Finding: Horizontal privilege escalation allowed viewing unauthorized files.
   - Remediation: Implemented role-based session checking and Canary Decoys.
4. Security Misconfiguration (A05:2021):
   - Finding: Absence of rate limiting on authentication routes.
   - Remediation: Configured automated 3-attempt lockout and step-up MFA.
--------------------------------------------------------------------------------
Assessment Score:        High Proficiency — Vulnerability Remediation Confirmed
Verified by:             Prof. K. Sen, Lead Security Auditor
================================================================================
"""
        return title, category, issuer, classification, content

    elif "deeplearning" in filename.lower() or "notebook" in filename.lower():
        title = "Deep Learning Intrusion Detection System (Software 2.0)"
        category = "Student Work & Projects"
        issuer = "Artificial Intelligence & Security Research Group"
        classification = "Research Code & Model Artifact"
        content = f"""SOFTWARE 2.0 AI/ML INTRUSION DETECTION NOTEBOOK
ANOMALY DETECTION USING UNSUPERVISED ISOLATION FORESTS & DEEP MLP
================================================================================
Author:                  {username.upper()}
Frameworks:              Python, NumPy, Scikit-Learn, PyTorch
Dataset:                 NSL-KDD & Real-Time CyberShield Telemetry Vectors
--------------------------------------------------------------------------------
MODEL TRAINING SUMMARY:
- Feature Vector:        [login_hour, haversine_km, velocity_kmh, file_size_kb]
- Total Records:         125,973 network flow instances
- Architecture:          Deep Feedforward Multi-Layer Perceptron (4 -> 64 -> 32 -> 1)
- Loss Function:         Binary Cross-Entropy with Sigmoid Output
- Optimizer:             Adam (lr=0.001, beta1=0.9, beta2=0.999)
- Training Epochs:       50 Epochs | Early stopping patience = 5
--------------------------------------------------------------------------------
PERFORMANCE METRICS:
Accuracy:                99.42%
Precision:               98.91%
Recall (True Positive):  99.15%
False Alarm Rate (FAR):  0.58%
Inference Latency:       0.42 ms per login telemetry vector
--------------------------------------------------------------------------------
Conclusion: Software 2.0 ML model integrates directly into CyberShield UEBA
to complement deterministic Software 1.0 rules with adaptive anomaly boundaries.
================================================================================
"""
        return title, category, issuer, classification, content

    elif "internship" in filename.lower():
        title = "National Cyber Defense Internship Completion Certificate"
        category = "Student Work & Projects"
        issuer = "National Cyber Defense Operations Center (CERT-In Partner)"
        classification = "Industry Certification"
        content = f"""NATIONAL CYBER DEFENSE OPERATIONS CENTER
CERTIFICATE OF INDUSTRIAL INTERNSHIP COMPLETION
================================================================================
This is to certify that: {username.upper()}
Has successfully completed an intensive 6-month cybersecurity internship as:
JUNIOR SOC ANALYST & THREAT HUNTER
Duration:                October 2025 — March 2026
Workplace:               Tier-3 Security Operations Center (24x7 Operations)
--------------------------------------------------------------------------------
KEY RESPONSIBILITIES PERFORMED:
- Real-time SIEM log monitoring and triage across 50,000+ daily endpoints.
- Analysis of MITRE ATT&CK tactics (T1110, T1078, T1048, T1204).
- Development of automated honeypot canary detection scripts.
- Creation of comprehensive CISO forensic incident dossiers.
--------------------------------------------------------------------------------
Performance Rating:      OUTSTANDING (98/100)
Recommendation:          Strongly recommended for senior SOC analyst and
                         cybersecurity engineering roles.
Director of Training:    Col. V. Mehta (Retd.), Head of Operations
================================================================================
"""
        return title, category, issuer, classification, content

    elif is_honeytoken_file(filename):
        title = filename.replace('_', ' ').replace('.xlsx', '').replace('.pdf', '').replace('.pem', '')
        category = "Confidential & Administrative"
        issuer = "Institutional Administration & Security Division"
        classification = "Confidential - Restricted Access"
        content = f"""INSTITUTIONAL ADMINISTRATION & SECURE REPOSITORY
CONFIDENTIAL INTERNAL RECORD
================================================================================
Document Name:           {filename}
Authorized Identity:     {username.upper()}
Security Classification: Confidential - Internal Institutional Access Only
Integrity Checksum:      SHA256: 9b2d881ef40a1b0293e5891a20c34f19a0e882190
Timestamp:               {now_str}

NOTICE:
This internal administrative asset contains restricted institutional data.
All user access and file transfers are cryptographically audited under
institutional security policy.
================================================================================
"""
        return title, category, issuer, classification, content

    else:
        title = filename
        category = "Enterprise Document"
        issuer = "CyberShield Enterprise Repository"
        classification = "Confidential - Internal Use"
        content = f"""CYBERSHIELD ENTERPRISE SECURE DOCUMENT
================================================================================
Document:                {filename}
Authorized User:         {username}
Security Classification: Confidential - Internal Business Only
Integrity Hash:          SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069
Timestamp:               {now_str}
Zero-Trust Clearance:    VERIFIED

This document is certified for authorized inspection under
CyberShield Continuous Adaptive Risk and Trust Assessment (CARTA).
================================================================================
"""
        return title, category, issuer, classification, content


@app.route("/download/file/<filename>")
def download_file(filename):
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    user = get_user_by_username(username)
    if not user:
        return redirect(url_for("login"))

    # Check if this is a Honeytoken Canary Decoy File
    if is_honeytoken_file(filename):
        # Honeytoken trap sprung! Instant zero trust and lockdown
        quarantine_user_honeytoken(username)

        log_activity(
            username=username,
            activity=f"🚨 HONEYTOKEN TRAP SPRUNG: Unauthorized attempt to download decoy asset '{filename}'",
            risk_score=100,
            threat_level="Critical",
            mitre_id="T1204"
        )

        add_notification(
            username=username,
            title="🚨 IMMEDIATE QUARANTINE: Honeytoken Decoy Trap Sprung",
            message=f"Unauthorized access to restricted canary decoy '{filename}' detected. Account quarantined immediately under Zero-Trust Policy.",
            severity="critical"
        )

        session.clear()
        return redirect(url_for("login", message=f"SECURITY BREACH: Account quarantined! Honeytoken decoy '{filename}' triggered automated Zero-Trust lockout. Incident logged to SOC."))

    # Normal verified file download
    log_activity(
        username=username,
        activity=f"Authorized Student & Institution File Download: '{filename}'",
        risk_score=5,
        threat_level="Normal",
        mitre_id="T1078"
    )

    title, category, issuer, classification, file_content = generate_document_text(filename, username)

    return Response(
        file_content,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}.txt"}
    )


# =========================================================
# DOCUMENT PREVIEW API (IN-BROWSER MODAL INSPECTION)
# =========================================================

@app.route("/api/document/preview/<filename>")
def api_document_preview(filename):
    username = session.get("username")
    if not username:
        return jsonify({"success": False, "error": "Authentication required"}), 401

    is_honey = is_honeytoken_file(filename)
    title, category, issuer, classification, content = generate_document_text(filename, username)

    return jsonify({
        "success": True,
        "filename": filename,
        "title": title,
        "category": category,
        "issuer": issuer,
        "classification": classification,
        "is_honeytoken": is_honey,
        "date": datetime.now().strftime("%B %d, %Y"),
        "content": content
    })


# =========================================================
# SOC INTERACTIVE POLICY CONTROL CENTER
# =========================================================

@app.route("/admin/policies/update", methods=["POST"])
def admin_policies_update():
    if session.get("role") != "admin":
        return jsonify({"success": False, "error": "Unauthorized"}), 403

    data = request.get_json() or request.form
    if not data:
        return jsonify({"success": False, "error": "No configuration provided"}), 400

    for key, value in data.items():
        update_policy(key, str(value))

    log_activity(
        username=session.get("username", "admin"),
        activity="Zero-Trust Security Policies reconfigured via SOC Policy Sliders",
        risk_score=0,
        threat_level="Normal",
        mitre_id="T1562"
    )

    return jsonify({"success": True, "message": "Zero-Trust policies updated successfully."})


# =========================================================
# LIVE SOC TELEMETRY STREAM FEED
# =========================================================

@app.route("/api/admin/live-feed")
def admin_live_feed():
    if session.get("role") != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    activities = get_all_activities(limit=15)
    stats = get_security_stats()
    return jsonify({
        "activities": activities,
        "stats": stats,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })


# =========================================================
# FORENSIC INCIDENT REPORT (PRINTABLE CISO DOSSIER)
# =========================================================

@app.route("/admin/incident-report")
def admin_incident_report():
    if session.get("role") != "admin":
        return "Access Denied: SOC Administrator privileges required.", 403

    stats = get_security_stats()
    activities = get_all_activities(limit=100)
    critical_events = [a for a in activities if a.get("threat_level") == "Critical"]
    users = get_all_users()
    locked_users = [u for u in users if u.get("is_locked") == 1]
    policies = get_all_policies()

    act_texts = [a["activity"] for a in reversed(activities)]
    detected_chains = detect_attack_chain(act_texts, window_size=20)

    report_id = f"CS-IR-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"

    return render_template(
        "incident_report.html",
        report_id=report_id,
        stats=stats,
        activities=activities[:25],
        critical_events=critical_events,
        locked_users=locked_users,
        policies=policies,
        detected_chains=detected_chains,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )





# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)