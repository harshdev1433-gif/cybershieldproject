"""
CyberShield - Attack Chain Correlation Engine
Detects multi-stage attack patterns using sliding-window correlation aligned with MITRE ATT&CK.
"""

def detect_attack_chain(activities, window_size=10):
    """
    Detect suspicious sequences of activities within the recent activity window.
    Activities should be ordered from oldest to newest.
    Returns list of correlated threat chains with MITRE ATT&CK tags.
    """
    if not activities:
        return []

    detected_chains = []

    # Focus on the most recent sliding window of activities
    recent_activities = activities[-window_size:] if len(activities) > window_size else activities
    recent_text = " ".join(recent_activities).lower()
    recent_lower_list = [a.lower() for a in recent_activities]

    # =====================================================
    # Pattern 0 - Honeytoken / Canary Trap Sprung [MITRE T1204]
    # =====================================================
    if "canary" in recent_text or "honeytoken" in recent_text:
        detected_chains.append(
            "[MITRE T1204] Deception Alert: Honeytoken decoy file accessed — unauthorized insider threat"
        )

    # =====================================================
    # Pattern 1 - Brute Force Attack [MITRE T1110]
    # =====================================================
    failed_count = sum(1 for a in recent_lower_list if "failed login" in a)
    if failed_count >= 3:
        detected_chains.append(
            f"[MITRE T1110] Brute Force Attempt: {failed_count} failed login attempts in sliding window"
        )

    # =====================================================
    # Pattern 2 - Possible Credential Compromise [MITRE T1078]
    # =====================================================
    if (
        "failed login" in recent_text
        and "successful login" in recent_text
        and ("new device" in recent_text or "unusual location" in recent_text or "impossible travel" in recent_text)
    ):
        detected_chains.append(
            "[MITRE T1078] Account Takeover Chain: Multiple failed logins followed by access from new device/location"
        )

    # =====================================================
    # Pattern 3 - Data Exfiltration / Insider Threat [MITRE T1048]
    # =====================================================
    if (
        ("successful login" in recent_text or "new device" in recent_text)
        and ("large file" in recent_text or "exfiltration" in recent_text or "download" in recent_text)
        and ("unusual location" in recent_text or "unusual time" in recent_text or "impossible travel" in recent_text)
    ):
        detected_chains.append(
            "[MITRE T1048] Data Exfiltration Chain: Off-hours/off-location access followed by large data download"
        )

    # =====================================================
    # Pattern 4 - Impossible Travel / Geo-Anomaly [MITRE T1078.003]
    # =====================================================
    if "impossible travel" in recent_text or ("unusual location" in recent_text and "new device" in recent_text):
        detected_chains.append(
            "[MITRE T1078.003] Impossible Travel Geo-Anomaly: Device logging in outside physical velocity threshold"
        )

    # =====================================================
    # Pattern 5 - Proxy / Tor Anonymization [MITRE T1090]
    # =====================================================
    if "threat intel" in recent_text or "tor" in recent_text or "proxy" in recent_text:
        detected_chains.append(
            "[MITRE T1090] Anonymous Ingress: Connection routed through known Tor exit node or high-risk proxy"
        )

    # =====================================================
    # Pattern 6 - Multi-Vector High Risk Correlation
    # =====================================================
    suspicious_indicators = [
        "failed login",
        "new device",
        "unusual time",
        "unusual location",
        "impossible travel",
        "large file",
        "canary",
        "tor",
        "proxy"
    ]

    matched_indicators = [ind for ind in suspicious_indicators if ind in recent_text]
    if len(matched_indicators) >= 3 and "[MITRE T1078] Account Takeover Chain" not in " ".join(detected_chains):
        detected_chains.append(
            f"[MITRE T1078+T1110] Multi-Vector Threat: {len(matched_indicators)} distinct anomaly indicators observed ({', '.join(matched_indicators)})"
        )

    # =====================================================
    # Pattern 7 - Simulation Trigger
    # =====================================================
    if "simulation" in recent_text:
        detected_chains.append(
            "Active Security Simulation: Simulated threat scenario active"
        )

    # Remove duplicates while preserving order
    unique_chains = []
    for chain in detected_chains:
        if chain not in unique_chains:
            unique_chains.append(chain)

    return unique_chains