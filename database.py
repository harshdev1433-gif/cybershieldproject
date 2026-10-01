import sqlite3
import os
import shutil
from werkzeug.security import generate_password_hash, check_password_hash

# Vercel serverless: only /tmp is writable. Copy seed DB there on cold start.
if os.environ.get("VERCEL"):
    _tmp_db = "/tmp/cybershield.db"
    if not os.path.exists(_tmp_db):
        _src = os.path.join(os.path.dirname(__file__), "cybershield.db")
        if os.path.exists(_src):
            shutil.copy2(_src, _tmp_db)
    DATABASE = _tmp_db
else:
    DATABASE = "cybershield.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# =========================================================
# CREATE DATABASE TABLES & RUN MIGRATIONS
# =========================================================

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            trust_score INTEGER DEFAULT 100,
            is_locked INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0
        )
    """)

    # ACTIVITIES TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            activity TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'Normal',
            timestamp TEXT DEFAULT (DATETIME('now', 'localtime'))
        )
    """)

    # BEHAVIOUR FINGERPRINT TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behaviour_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            usual_login_time TEXT DEFAULT '09:00',
            usual_device TEXT DEFAULT 'Desktop',
            usual_location TEXT DEFAULT 'Jammu',
            normal_file_access TEXT DEFAULT 'Low'
        )
    """)

    # SECURITY POLICIES TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_policies (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT
        )
    """)

    # NOTIFICATIONS TABLE (IN-APP SECURITY ALERTS)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT DEFAULT 'warning',
            timestamp TEXT DEFAULT (DATETIME('now', 'localtime')),
            is_read INTEGER DEFAULT 0
        )
    """)

    # Default policies (Lockout threshold updated to 3 attempts)
    default_policies = [
        ("mfa_threshold", "60", "Trust score threshold below which Step-Up MFA challenge is enforced"),
        ("auto_quarantine_enabled", "1", "Auto-lock account if maximum failed login attempts are reached"),
        ("max_failed_attempts", "3", "Maximum consecutive failed authentication attempts permitted"),
        ("canary_trap_active", "1", "Arm honeytoken decoy files in enterprise workspace"),
        ("threat_intel_enabled", "1", "Block and score known anonymous proxies and Tor exit nodes")
    ]
    for k, v, desc in default_policies:
        cursor.execute("INSERT OR IGNORE INTO security_policies (key, value, description) VALUES (?, ?, ?)", (k, v, desc))
    
    # Update max_failed_attempts to 3 if previously set to 5
    cursor.execute("UPDATE security_policies SET value = '3' WHERE key = 'max_failed_attempts' AND value = '5'")

    # --- MIGRATIONS FOR EXISTING DATABASES ---
    cursor.execute("PRAGMA table_info(activities)")
    act_cols = [c[1] for c in cursor.fetchall()]
    if "timestamp" not in act_cols:
        cursor.execute("ALTER TABLE activities ADD COLUMN timestamp TEXT")
        cursor.execute("UPDATE activities SET timestamp = DATETIME('now', 'localtime') WHERE timestamp IS NULL")
    if "mitre_id" not in act_cols:
        cursor.execute("ALTER TABLE activities ADD COLUMN mitre_id TEXT DEFAULT 'T1078'")
        cursor.execute("UPDATE activities SET mitre_id = 'T1078' WHERE mitre_id IS NULL")

    cursor.execute("PRAGMA table_info(users)")
    user_cols = [c[1] for c in cursor.fetchall()]
    if "is_locked" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN is_locked INTEGER DEFAULT 0")
    if "failed_attempts" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    if "email" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
        cursor.execute("UPDATE users SET email = 'student@cybershield.local' WHERE username = 'student'")
        cursor.execute("UPDATE users SET email = 'admin@cybershield.local' WHERE username = 'admin'")
    if "phone" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "last_login_time" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN last_login_time TEXT")
    if "last_login_location" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN last_login_location TEXT")

    # DEMO USERS (Create if not exist, with hashed passwords)
    cursor.execute("SELECT id FROM users WHERE username = 'student'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (username, email, phone, password, role, trust_score, is_locked, failed_attempts)
            VALUES ('student', 'student@cybershield.local', '+91-9876543210', ?, 'user', 100, 0, 0)
        """, (generate_password_hash("student123"),))

    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute("""
            INSERT INTO users (username, email, phone, password, role, trust_score, is_locked, failed_attempts)
            VALUES ('admin', 'admin@cybershield.local', '+91-9876543211', ?, 'admin', 100, 0, 0)
        """, (generate_password_hash("admin123"),))

    # DEMO BEHAVIOUR PROFILES
    cursor.execute("""
        INSERT OR IGNORE INTO behaviour_profiles
        (username, usual_login_time, usual_device, usual_location, normal_file_access)
        VALUES ('student', '09:00', 'Desktop (Windows)', 'Jammu', 'Low')
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO behaviour_profiles
        (username, usual_login_time, usual_device, usual_location, normal_file_access)
        VALUES ('admin', '09:00', 'Desktop (Windows)', 'Jammu', 'Low')
    """)

    conn.commit()
    conn.close()


# =========================================================
# USER REGISTRATION & TELEMETRY
# =========================================================

def register_user(username, email, phone, password, baseline_location="Jammu", baseline_device="Desktop"):
    """
    Registers a new user, hashes password, and initializes baseline behaviour profile.
    Returns: (success: bool, message: str)
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists. Please choose another."

    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        return False, "Email address is already registered."

    hashed_pw = generate_password_hash(password)
    cursor.execute("""
        INSERT INTO users (username, email, phone, password, role, trust_score, is_locked, failed_attempts)
        VALUES (?, ?, ?, ?, 'user', 100, 0, 0)
    """, (username, email, phone, hashed_pw))

    # Initialize baseline profile with user's registered home city and primary device
    cursor.execute("""
        INSERT OR REPLACE INTO behaviour_profiles
        (username, usual_login_time, usual_device, usual_location, normal_file_access)
        VALUES (?, '09:00', ?, ?, 'Low')
    """, (username, baseline_device or "Desktop", baseline_location or "Jammu"))

    conn.commit()
    conn.close()

    log_activity(
        username=username,
        activity=f"New User Account Created ({baseline_location})",
        risk_score=0,
        threat_level="Normal"
    )

    return True, "Account created successfully! You can now log in."


def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def update_user_login_telemetry(username, location=None, login_time=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET last_login_location = COALESCE(?, last_login_location),
            last_login_time = COALESCE(?, last_login_time)
        WHERE username = ?
    """, (location, login_time, username))
    conn.commit()
    conn.close()


# =========================================================
# USER AUTHENTICATION & SECURITY
# =========================================================

def verify_user(username, password):
    """
    Verify credentials, handle failed attempts, lockouts, and password hashing.
    Returns: (user_dict_or_None, status_message)
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return None, "Invalid username or password."

    user = dict(row)

    # Check if account is locked / quarantined
    if user.get("is_locked", 0) == 1:
        conn.close()
        return None, "Account is LOCKED by CyberShield security policy. Contact administrator."

    stored_pwd = user["password"]
    is_valid = False

    # Check password (hashed or fallback plaintext for demo migration)
    if stored_pwd.startswith("scrypt:") or stored_pwd.startswith("pbkdf2:"):
        is_valid = check_password_hash(stored_pwd, password)
    else:
        is_valid = (stored_pwd == password)
        # Migrate plaintext password to hash transparently upon valid login
        if is_valid:
            new_hash = generate_password_hash(password)
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user["id"]))
            conn.commit()

    if is_valid:
        # Reset failed attempts on successful login
        cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
        conn.commit()
        conn.close()
        return user, "Success"
    else:
        # Increment failed attempts
        new_failed = user.get("failed_attempts", 0) + 1
        max_failed = int(get_policy("max_failed_attempts", 3))
        should_lock = 1 if new_failed >= max_failed else 0

        cursor.execute("""
            UPDATE users
            SET failed_attempts = ?, is_locked = ?
            WHERE id = ?
        """, (new_failed, should_lock, user["id"]))
        conn.commit()
        conn.close()

        # Log failed attempt activity
        log_activity(
            username=username,
            activity=f"Failed Login Attempt ({new_failed}/{max_failed})",
            risk_score=35 if new_failed >= 2 else 20,
            threat_level="Suspicious" if new_failed >= 2 else "Normal"
        )
        update_trust_score(username, 35 if new_failed >= 2 else 20)

        if should_lock:
            add_notification(
                username=username,
                title="🚨 Account Quarantined (Lockout Enforced)",
                message=f"Your account has been locked after {new_failed} consecutive failed login attempts.",
                severity="critical"
            )
            log_activity(
                username=username,
                activity=f"Account Quarantined: Exceeded {max_failed} failed login attempts",
                risk_score=95,
                threat_level="Critical"
            )
            update_trust_score(username, 95)
            return None, f"Security Alert: Account has been LOCKED due to {max_failed} failed attempts. Contact your SOC admin."

        add_notification(
            username=username,
            title="⚠️ Suspicious Login Attempt Detected",
            message=f"Failed authentication attempt ({new_failed}/{max_failed}) recorded.",
            severity="warning"
        )
        return None, f"Invalid password. Failed attempt {new_failed}/{max_failed}. Account locks at {max_failed} attempts."


# =========================================================
# NOTIFICATION SYSTEM HELPERS
# =========================================================

def add_notification(username, title, message, severity="warning"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO notifications (username, title, message, severity, timestamp, is_read)
        VALUES (?, ?, ?, ?, DATETIME('now', 'localtime'), 0)
    """, (username, title, message, severity))
    conn.commit()
    conn.close()


def get_user_notifications(username, limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, title, message, severity, timestamp, is_read
        FROM notifications
        WHERE username = ?
        ORDER BY id DESC
        LIMIT ?
    """, (username, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_notifications_read(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE notifications SET is_read = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def log_activity(username, activity, risk_score, threat_level, mitre_id=None):
    conn = get_connection()
    cursor = conn.cursor()

    if not mitre_id:
        act_lower = str(activity).lower()
        if "canary" in act_lower or "honeytoken" in act_lower:
            mitre_id = "T1204"  # User Execution / Honeytoken Trap
        elif "brute force" in act_lower or "failed login" in act_lower:
            mitre_id = "T1110"  # Brute Force
        elif "exfiltration" in act_lower or "large file" in act_lower or "download" in act_lower:
            mitre_id = "T1048"  # Exfiltration Over Alternative Protocol
        elif "impossible travel" in act_lower or "geo-anomaly" in act_lower or "location" in act_lower:
            mitre_id = "T1078.003"  # Valid Accounts: Geo Anomaly
        elif "proxy" in act_lower or "tor" in act_lower or "vpn" in act_lower:
            mitre_id = "T1090"  # Proxy: Multi-hop / Anonymization
        elif "kill switch" in act_lower or "quarantine" in act_lower:
            mitre_id = "T1529"  # System Shutdown / Access Revocation
        else:
            mitre_id = "T1078"  # Valid Accounts

    cursor.execute("""
        INSERT INTO activities
        (username, activity, risk_score, threat_level, mitre_id, timestamp)
        VALUES (?, ?, ?, ?, ?, DATETIME('now', 'localtime'))
    """, (username, activity, risk_score, threat_level, mitre_id))

    conn.commit()
    conn.close()


# =========================================================
# DYNAMIC TRUST SCORE MANAGEMENT
# =========================================================

def update_trust_score(username, risk_score):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT trust_score FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        current_score = result["trust_score"]

        # Risk-adjusted penalties & rewards
        if risk_score >= 80:
            change = -25
        elif risk_score >= 60:
            change = -15
        elif risk_score >= 31:
            change = -8
        else:
            # Rebuild trust for normal, safe activities
            change = +3

        new_score = max(0, min(100, current_score + change))

        cursor.execute("UPDATE users SET trust_score = ? WHERE username = ?", (new_score, username))
        conn.commit()

    conn.close()


def get_trust_score(username):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT trust_score FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result["trust_score"]
    return 100


def reset_trust_score(username, score=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET trust_score = ?, failed_attempts = 0 WHERE username = ?", (score, username))
    conn.commit()
    conn.close()


# =========================================================
# ACCOUNT LOCK / QUARANTINE CONTROLS
# =========================================================

def quarantine_user_honeytoken(username):
    """
    Instantly quarantines user and reduces trust to 0 upon triggering a canary trap.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET trust_score = 0, is_locked = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def lock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_locked = 1 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def unlock_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()


def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, email, phone, role, trust_score, is_locked, failed_attempts, last_login_time, last_login_location
        FROM users
        ORDER BY id ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


# =========================================================
# BEHAVIOUR PROFILE MANAGEMENT
# =========================================================

def get_behaviour_profile(username):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT usual_login_time, usual_device, usual_location, normal_file_access
        FROM behaviour_profiles
        WHERE username = ?
    """, (username,))

    result = cursor.fetchone()
    conn.close()

    if result:
        return dict(result)
    return None


def update_behaviour_profile(username, login_time=None, device=None, location=None, file_access=None):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT usual_login_time, usual_device, usual_location, normal_file_access
        FROM behaviour_profiles
        WHERE username = ?
    """, (username,))

    result = cursor.fetchone()

    if result:
        new_login_time = login_time if login_time is not None else result["usual_login_time"]
        new_device = device if device is not None else result["usual_device"]
        new_location = location if location is not None else result["usual_location"]
        new_file_access = file_access if file_access is not None else result["normal_file_access"]

        cursor.execute("""
            UPDATE behaviour_profiles
            SET usual_login_time = ?, usual_device = ?, usual_location = ?, normal_file_access = ?
            WHERE username = ?
        """, (new_login_time, new_device, new_location, new_file_access, username))
    else:
        cursor.execute("""
            INSERT INTO behaviour_profiles (username, usual_login_time, usual_device, usual_location, normal_file_access)
            VALUES (?, ?, ?, ?, ?)
        """, (username, login_time or "09:00", device or "Desktop", location or "Jammu", file_access or "Low"))

    conn.commit()
    conn.close()


# =========================================================
# REPORTING & ANALYTICS QUERIES
# =========================================================

def get_user_activities(username, limit=30):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, activity, risk_score, threat_level, COALESCE(mitre_id, 'T1078') as mitre_id, timestamp
        FROM activities
        WHERE username = ?
        ORDER BY id DESC
        LIMIT ?
    """, (username, limit))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_activities(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.id, a.username, a.activity, a.risk_score, a.threat_level, COALESCE(a.mitre_id, 'T1078') as mitre_id, a.timestamp, u.trust_score
        FROM activities a
        LEFT JOIN users u ON a.username = u.username
        ORDER BY a.id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_security_stats():
    """
    Returns aggregated stats for the admin security dashboard.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM activities")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM activities WHERE threat_level = 'Critical'")
    critical_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM activities WHERE threat_level = 'Suspicious'")
    suspicious_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM activities WHERE threat_level = 'Normal'")
    normal_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users WHERE is_locked = 1")
    locked_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(trust_score) FROM users")
    avg_trust = round(cursor.fetchone()[0] or 0, 1)

    conn.close()

    return {
        "total_events": total_events,
        "critical_events": critical_events,
        "suspicious_events": suspicious_events,
        "normal_events": normal_events,
        "locked_users": locked_users,
        "total_users": total_users,
        "avg_trust": avg_trust
    }


# =========================================================
# SECURITY POLICIES HELPERS
# =========================================================

def get_policy(key, default=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM security_policies WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row["value"]
    return default


def get_all_policies():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value, description FROM security_policies ORDER BY key ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_policy(key, value):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE security_policies SET value = ? WHERE key = ?", (str(value), key))
    conn.commit()
    conn.close()


if __name__ == "__main__":
    create_tables()
    print("CyberShield database migrated and verified successfully!")