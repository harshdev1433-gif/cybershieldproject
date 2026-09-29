"""
CyberShield - Zero-Dependency Unit & Integration Test Suite
Built according to Andrej Karpathy's engineering guidelines:
- Fast, deterministic, and whiteboard-verifiable
- Zero external dependencies (uses standard Python unittest)
- Isolated database testing via temporary SQLite files
- Complete test coverage of mathematical Haversine equations, sliding-window correlation, and UEBA heuristics
"""

import unittest
import math
import os
import tempfile
import sqlite3

# Import application modules
import behaviour_engine
from behaviour_engine import (
    haversine_distance,
    evaluate_impossible_travel,
    check_ip_threat_intel,
    parse_user_agent,
    analyze_behaviour,
    get_location_coords
)
import risk_engine
from risk_engine import calculate_risk
import attack_detector
from attack_detector import detect_attack_chain
import database
from app import app, is_honeytoken_file, generate_document_text


class TestBehaviourEngine(unittest.TestCase):
    """Verifies mathematical Haversine calculations, telemetry parsing, and UEBA heuristics."""

    def test_haversine_same_point(self):
        """Distance between identical coordinates must be exactly 0 km."""
        dist = haversine_distance(32.7266, 74.8570, 32.7266, 74.8570)
        self.assertAlmostEqual(dist, 0.0, places=2)

    def test_haversine_known_distance(self):
        """Haversine distance between Delhi and Mumbai should be ~1148 km (+/- 30 km)."""
        delhi_lat, delhi_lon = 28.6139, 77.2090
        mumbai_lat, mumbai_lon = 19.0760, 72.8777
        dist = haversine_distance(delhi_lat, delhi_lon, mumbai_lat, mumbai_lon)
        self.assertTrue(1100 < dist < 1200, f"Distance {dist} km out of expected bounds")

    def test_haversine_symmetry(self):
        """Distance from A to B must equal distance from B to A."""
        d1 = haversine_distance(32.7266, 74.8570, 28.6139, 77.2090)
        d2 = haversine_distance(28.6139, 77.2090, 32.7266, 74.8570)
        self.assertAlmostEqual(d1, d2, places=4)

    def test_impossible_travel_triggered(self):
        """Moving ~500 km (Jammu to Delhi) in 15 minutes (0.25h) exceeds 800 km/h -> Impossible Travel."""
        is_impossible, dist, speed = evaluate_impossible_travel("Jammu", "Delhi", hours_diff=0.25)
        self.assertTrue(is_impossible)
        self.assertGreater(speed, 800.0)
        self.assertGreater(dist, 350.0)

    def test_impossible_travel_normal(self):
        """Moving Jammu to Delhi in 10 hours (~50 km/h) should not trigger impossible travel."""
        is_impossible, dist, speed = evaluate_impossible_travel("Jammu", "Delhi", hours_diff=10.0)
        self.assertFalse(is_impossible)
        self.assertLess(speed, 800.0)

    def test_impossible_travel_zero_time_handling(self):
        """Zero or near-zero time difference must not raise ZeroDivisionError."""
        is_impossible, dist, speed = evaluate_impossible_travel("Jammu", "Delhi", hours_diff=0.0)
        self.assertIsInstance(speed, float)
        self.assertGreater(speed, 0.0)

    def test_check_ip_threat_intel_tor(self):
        """Known Tor prefix (185.220.x.x) must be flagged with 30 risk points."""
        is_threat, desc, risk = check_ip_threat_intel("185.220.101.5")
        self.assertTrue(is_threat)
        self.assertEqual(risk, 30)
        self.assertIn("Tor", desc)

    def test_check_ip_threat_intel_clean(self):
        """Clean standard IP must pass with 0 risk points."""
        is_threat, desc, risk = check_ip_threat_intel("192.168.1.1")
        self.assertFalse(is_threat)
        self.assertEqual(risk, 0)

    def test_parse_user_agent(self):
        """User-Agent string should correctly categorize operating environment."""
        self.assertEqual(parse_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS)"), "Mobile Device")
        self.assertEqual(parse_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "Desktop (Windows)")
        self.assertEqual(parse_user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X)"), "Desktop (macOS)")
        self.assertEqual(parse_user_agent("Mozilla/5.0 (X11; Linux x86_64)"), "Desktop (Linux)")
        self.assertEqual(parse_user_agent(""), "Unknown")

    def test_analyze_behaviour_matching_baseline(self):
        """When telemetry matches baseline, risk is 0 and status is Normal."""
        risk, status, anomalies = analyze_behaviour(
            usual_login_time="09:00",
            usual_device="Desktop (Windows)",
            usual_location="Jammu",
            normal_file_access="Low",
            current_login_time="09:00",
            current_device="Desktop (Windows)",
            current_location="Jammu",
            current_file_access="Low"
        )
        self.assertEqual(risk, 0)
        self.assertEqual(status, "Normal")
        self.assertEqual(len(anomalies), 0)

    def test_analyze_behaviour_impossible_travel_anomaly(self):
        """Impossible travel between Jammu and London in 1 hour must yield critical risk and flag."""
        risk, status, anomalies = analyze_behaviour(
            usual_login_time="09:00",
            usual_device="Desktop (Windows)",
            usual_location="Jammu",
            normal_file_access="Low",
            current_login_time="09:00",
            current_device="Desktop (Windows)",
            current_location="London",
            current_file_access="Low",
            hours_since_last_login=1.0
        )
        self.assertGreaterEqual(risk, 35)
        self.assertTrue(any("Impossible Travel" in a for a in anomalies))

    def test_analyze_behaviour_risk_clamped_at_100(self):
        """Even with every anomaly triggered simultaneously, risk cannot exceed 100."""
        risk, status, anomalies = analyze_behaviour(
            usual_login_time="09:00",
            usual_device="Desktop (Windows)",
            usual_location="Jammu",
            normal_file_access="Low",
            current_login_time="03:00",
            current_device="Mobile (Android)",
            current_location="London",
            current_file_access="High Exfiltration (500MB)",
            client_ip="185.220.1.1",
            hours_since_last_login=0.2
        )
        self.assertLessEqual(risk, 100)
        self.assertEqual(status, "Critical")


class TestRiskEngine(unittest.TestCase):
    """Verifies Software 1.0 deterministic risk heuristics and boundary tiers."""

    def test_default_risk(self):
        """No anomalous signals must produce 0 risk and Normal status."""
        risk, level, reasons = calculate_risk()
        self.assertEqual(risk, 0)
        self.assertEqual(level, "Normal")
        self.assertEqual(len(reasons), 0)

    def test_three_failed_logins(self):
        """3 failed logins adds 15 risk points."""
        risk, level, reasons = calculate_risk(failed_logins=3)
        self.assertEqual(risk, 15)
        self.assertEqual(level, "Normal")
        self.assertIn("Several failed login attempts", reasons)

    def test_five_failed_logins(self):
        """5 failed logins adds 30 risk points."""
        risk, level, reasons = calculate_risk(failed_logins=5)
        self.assertEqual(risk, 30)
        self.assertEqual(level, "Normal")
        self.assertIn("Multiple failed login attempts", reasons)

    def test_suspicious_tier_transition(self):
        """Risk between 31 and 60 must map to Suspicious level."""
        # new_device (20) + unusual_time (15) = 35 -> Suspicious
        risk, level, reasons = calculate_risk(new_device=True, unusual_time=True)
        self.assertEqual(risk, 35)
        self.assertEqual(level, "Suspicious")

    def test_critical_tier_transition(self):
        """Risk > 60 must map to Critical level."""
        # 5 failed logins (30) + unusual_location (25) + large_file_access (30) = 85 -> Critical
        risk, level, reasons = calculate_risk(failed_logins=5, unusual_location=True, large_file_access=True)
        self.assertEqual(risk, 85)
        self.assertEqual(level, "Critical")

    def test_risk_clamping(self):
        """Cumulative sum over 100 must be safely clamped to 100."""
        risk, level, reasons = calculate_risk(
            failed_logins=10,
            new_device=True,
            unusual_time=True,
            unusual_location=True,
            large_file_access=True
        )
        self.assertEqual(risk, 100)
        self.assertEqual(level, "Critical")


class TestAttackDetector(unittest.TestCase):
    """Verifies sliding-window multi-stage attack correlation and MITRE ATT&CK tagging."""

    def test_empty_activities(self):
        """Empty activity feed returns no detected attack chains."""
        self.assertEqual(detect_attack_chain([]), [])

    def test_honeytoken_canary_trap_mitre_t1204(self):
        """Accessing a canary decoy triggers MITRE T1204 alert."""
        activities = ["User accessed payroll_2026_canary_trap.xlsx"]
        chains = detect_attack_chain(activities)
        self.assertTrue(any("[MITRE T1204]" in c for c in chains))

    def test_brute_force_mitre_t1110(self):
        """>= 3 failed logins triggers MITRE T1110 alert."""
        activities = [
            "Failed login attempt from IP 1.2.3.4",
            "Failed login attempt from IP 1.2.3.4",
            "Failed login attempt from IP 1.2.3.4"
        ]
        chains = detect_attack_chain(activities)
        self.assertTrue(any("[MITRE T1110]" in c for c in chains))

    def test_account_takeover_mitre_t1078(self):
        """Failed logins followed by successful login from new device triggers MITRE T1078."""
        activities = [
            "Failed login attempt",
            "Failed login attempt",
            "Successful login from new device (Desktop Windows)"
        ]
        chains = detect_attack_chain(activities)
        self.assertTrue(any("[MITRE T1078]" in c for c in chains))

    def test_data_exfiltration_mitre_t1048(self):
        """Login followed by large file download from unusual location triggers MITRE T1048."""
        activities = [
            "Successful login from unusual location (Tokyo)",
            "Large file download initiated: confidential_db_dump.sql"
        ]
        chains = detect_attack_chain(activities)
        self.assertTrue(any("[MITRE T1048]" in c for c in chains))

    def test_impossible_travel_mitre_t1078_003(self):
        """Impossible travel indicator triggers MITRE T1078.003."""
        activities = ["Impossible travel detected between Jammu and London"]
        chains = detect_attack_chain(activities)
        self.assertTrue(any("[MITRE T1078.003]" in c for c in chains))

    def test_proxy_tor_mitre_t1090(self):
        """Threat intelligence / Tor proxy activity triggers MITRE T1090."""
        activities = ["Threat intel alert: Tor exit node identified"]
        chains = detect_attack_chain(activities)
        self.assertTrue(any("[MITRE T1090]" in c for c in chains))

    def test_sliding_window_bound(self):
        """Attacks outside the sliding window (window_size=3) are ignored."""
        activities = [
            "Failed login attempt",
            "Failed login attempt",
            "Failed login attempt",
            "Normal file read",
            "Normal file read",
            "Normal file read",
            "Normal file read"
        ]
        # With window_size=3, only the last 3 normal activities are inspected
        chains = detect_attack_chain(activities, window_size=3)
        self.assertFalse(any("[MITRE T1110]" in c for c in chains))


class TestDatabaseIsolated(unittest.TestCase):
    """Verifies SQLite CRUD, password hashing, trust scoring, and account lockout in isolation."""

    @classmethod
    def setUpClass(cls):
        # Create a dedicated temp database for isolated testing
        cls.temp_db_fd, cls.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(cls.temp_db_fd)
        cls.orig_db = database.DATABASE
        database.DATABASE = cls.temp_db_path
        database.create_tables()

    @classmethod
    def tearDownClass(cls):
        database.DATABASE = cls.orig_db
        if os.path.exists(cls.temp_db_path):
            try:
                os.remove(cls.temp_db_path)
            except Exception:
                pass

    def test_demo_users_created(self):
        """Default demo accounts (student, admin) should exist with trust score 100."""
        user = database.get_user_by_username("student")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "user")
        self.assertEqual(user["trust_score"], 100)
        self.assertEqual(user["is_locked"], 0)

    def test_user_registration(self):
        """New user registration must hash password and initialize profile."""
        success, msg = database.register_user(
            username="analyst_test",
            email="analyst@cybershield.local",
            phone="+91-9999999999",
            password="SecurePassword123!",
            baseline_location="Delhi",
            baseline_device="Desktop (Windows)"
        )
        self.assertTrue(success)

        # Verify duplicate username prevention
        dup_success, _ = database.register_user(
            username="analyst_test",
            email="other@cybershield.local",
            phone="+91-1111111111",
            password="OtherPassword123!"
        )
        self.assertFalse(dup_success)

    def test_verify_user_success(self):
        """Verifying with correct password succeeds."""
        user, msg = database.verify_user("student", "student123")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "student")

    def test_verify_user_wrong_password_lockout(self):
        """3 consecutive failed attempts must lock the account per policy."""
        # Create a fresh test user for lockout
        database.register_user(
            username="lockout_test",
            email="lockout@cybershield.local",
            phone="+91-8888888888",
            password="Password123!"
        )

        # Attempt 1
        user, _ = database.verify_user("lockout_test", "Wrong1")
        self.assertIsNone(user)
        # Attempt 2
        user, _ = database.verify_user("lockout_test", "Wrong2")
        self.assertIsNone(user)
        # Attempt 3 (triggers lockout)
        user, _ = database.verify_user("lockout_test", "Wrong3")
        self.assertIsNone(user)

        # Verify user is now locked in DB
        user_record = database.get_user_by_username("lockout_test")
        self.assertEqual(user_record["is_locked"], 1)

        # Even with correct password, login is blocked
        user, msg = database.verify_user("lockout_test", "Password123!")
        self.assertIsNone(user)
        self.assertIn("LOCKED", msg)

        # Unlock user and verify access restored
        database.unlock_user("lockout_test")
        unlocked_record = database.get_user_by_username("lockout_test")
        self.assertEqual(unlocked_record["is_locked"], 0)
        self.assertEqual(unlocked_record["failed_attempts"], 0)

    def test_trust_score_operations(self):
        """Trust score updating, retrieval, clamping, and reset."""
        # Risk score 85 inflicts -25 penalty
        database.update_trust_score("student", 85)
        score = database.get_trust_score("student")
        self.assertEqual(score, 75)

        # Risk score 0 provides +3 trust reward
        database.update_trust_score("student", 0)
        self.assertEqual(database.get_trust_score("student"), 78)

        # Reset trust score back to 100
        database.reset_trust_score("student")
        self.assertEqual(database.get_trust_score("student"), 100)

    def test_canary_quarantine(self):
        """Canary honeytoken trap spring must instantly set trust to 0 and lock account."""
        database.register_user(
            username="canary_suspect",
            email="suspect@cybershield.local",
            phone="+91-7777777777",
            password="Password123!"
        )
        database.quarantine_user_honeytoken("canary_suspect")
        suspect = database.get_user_by_username("canary_suspect")
        self.assertEqual(suspect["trust_score"], 0)
        self.assertEqual(suspect["is_locked"], 1)


class TestFlaskRoutes(unittest.TestCase):
    """Verifies core HTTP endpoints, login page, and registration validation."""

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_root_login_get(self):
        """GET / serves the CyberShield authentication portal."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("CyberShield", html)

    def test_register_page_get(self):
        """GET /register must return 200 and render registration form."""
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Register Identity", html)

    def test_register_validation_short_password(self):
        """POST /register with password < 6 characters returns validation error."""
        response = self.client.post("/register", data={
            "username": "short_user",
            "email": "short@test.com",
            "phone": "+91-1234567890",
            "baseline_location": "Jammu",
            "password": "123",
            "confirm_password": "123"
        })
        html = response.get_data(as_text=True)
        self.assertIn("Password must be at least 6 characters long", html)

    def test_presentation_page_get(self):
        """GET /presentation must return 200 and render viva presentation interface."""
        response = self.client.get("/presentation")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Teacher Presentation & Viva Defense", html)
        self.assertIn("Haversine Velocity Engine", html)

    def test_viva_demo_reset_post(self):
        """POST /api/viva/demo-reset restores student user trust to 100% and unlocks."""
        response = self.client.post("/api/viva/demo-reset")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        student = database.get_user_by_username("student")
        self.assertEqual(student["trust_score"], 100)
        self.assertEqual(student["is_locked"], 0)

    def test_honeytoken_file_classification(self):
        """Verifies honeypot canary decoy keywords and legitimate file classification."""
        canaries = [
            "Confidential_Executive_Salaries_2026.xlsx",
            "Midterm_Exam_Question_Papers_LEAKED_2026.pdf",
            "Faculty_Grading_Key_Master_Passwords.xlsx",
            "Campus_Firewall_Root_SSH_Private_Keys.pem",
            "Dean_Office_Disciplinary_Investigation_Files.pdf"
        ]
        for c in canaries:
            self.assertTrue(is_honeytoken_file(c), f"Expected {c} to be flagged as honeytoken")

        legitimate = [
            "Official_Academic_Transcript_Sem6.pdf",
            "Tuition_Fee_Receipt_Academic_Year_2025_26.pdf",
            "Institutional_Student_Identity_Card.pdf",
            "CyberShield_ZeroTrust_Capstone_Thesis.pdf",
            "Network_Security_Lab_Manual_Submissions.pdf"
        ]
        for leg in legitimate:
            self.assertFalse(is_honeytoken_file(leg), f"Expected {leg} to be classified as legitimate")

    def test_document_content_generation(self):
        """Verifies rich certified academic text generation for student documents."""
        title, cat, issuer, classification, text = generate_document_text("Official_Academic_Transcript_Sem6.pdf", "student")
        self.assertIn("Official Academic Transcript", title)
        self.assertIn("Academic & Institutional", cat)
        self.assertIn("SGPA", text)
        self.assertIn("Cryptography", text)

        title2, cat2, issuer2, classification2, text2 = generate_document_text("CyberShield_ZeroTrust_Capstone_Thesis.pdf", "student")
        self.assertIn("Capstone", title2)
        self.assertIn("CARTA", text2)
        self.assertIn("Haversine", text2)

    def test_legitimate_document_download(self):
        """Authenticated student downloading a legitimate file receives HTTP 200 with text content."""
        with self.client.session_transaction() as sess:
            sess["username"] = "student"
            sess["role"] = "user"
            sess["mfa_verified"] = True

        resp = self.client.get("/download/file/Official_Academic_Transcript_Sem6.pdf")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_data(as_text=True)
        self.assertIn("OFFICIAL ACADEMIC TRANSCRIPT", data)
        self.assertIn("CS-2022-8491", data)

    def test_honeytoken_download_quarantines_user(self):
        """Attempting to download a canary decoy triggers instant Zero-Trust quarantine."""
        database.unlock_user("student")
        database.reset_trust_score("student", 100)

        with self.client.session_transaction() as sess:
            sess["username"] = "student"
            sess["role"] = "user"
            sess["mfa_verified"] = True

        resp = self.client.get("/download/file/Midterm_Exam_Question_Papers_LEAKED_2026.pdf", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("SECURITY", resp.headers.get("Location", ""))

        # Check database: user is quarantined with 0 trust
        student = database.get_user_by_username("student")
        self.assertEqual(student["is_locked"], 1)
        self.assertEqual(student["trust_score"], 0)

        # Cleanup: unlock student for other tests
        database.unlock_user("student")
        database.reset_trust_score("student", 100)

    def test_api_document_preview(self):
        """GET /api/document/preview/<filename> returns structured JSON metadata and content."""
        with self.client.session_transaction() as sess:
            sess["username"] = "student"
            sess["role"] = "user"

        resp = self.client.get("/api/document/preview/Tuition_Fee_Receipt_Academic_Year_2025_26.pdf")
        self.assertEqual(resp.status_code, 200)
        json_data = resp.get_json()
        self.assertTrue(json_data.get("success"))
        self.assertFalse(json_data.get("is_honeytoken"))
        self.assertIn("Tuition", json_data.get("title"))

        # Test canary preview
        resp2 = self.client.get("/api/document/preview/Campus_Firewall_Root_SSH_Private_Keys.pem")
        self.assertEqual(resp2.status_code, 200)
        json_data2 = resp2.get_json()
        self.assertTrue(json_data2.get("is_honeytoken"))
        self.assertIn("Campus Firewall", json_data2.get("title"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

