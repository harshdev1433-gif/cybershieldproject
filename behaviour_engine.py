"""
CyberShield - Behaviour Analytics Engine (UEBA)
Analyzes user activity against established behavioural fingerprints.
Includes mathematical Haversine Impossible Travel detection and Threat Intelligence.
"""

import math
from datetime import datetime

# Global coordinate map for major cybersecurity hubs and test regions (lat, lon)
LOCATION_COORDINATES = {
    "jammu": (32.7266, 74.8570),
    "srinagar": (34.0837, 74.7973),
    "delhi": (28.6139, 77.2090),
    "mumbai": (19.0760, 72.8777),
    "bengaluru": (12.9716, 77.5946),
    "hyderabad": (17.3850, 78.4867),
    "chennai": (13.0827, 80.2707),
    "kolkata": (22.5726, 88.3639),
    "pune": (18.5204, 73.8567),
    "chandigarh": (30.7333, 76.7794),
    "london": (51.5074, -0.1278),
    "new york": (40.7128, -74.0060),
    "frankfurt": (50.1109, 8.6821),
    "moscow": (55.7558, 37.6173),
    "tokyo": (35.6762, 139.6503),
    "sydney": (-33.8688, 151.2093),
    "singapore": (1.3521, 103.8198),
    "dubai": (25.2048, 55.2708),
    "amsterdam": (52.3676, 4.9041),
    "paris": (48.8566, 2.3522),
    "berlin": (52.5200, 13.4050)
}

# Known Tor exit nodes and suspicious proxy subnets (Simulated Threat Intel Feed)
SUSPICIOUS_IP_PREFIXES = (
    "185.220.",   # Known Tor Exit Node Cluster
    "198.51.100.", # TEST-NET Anonymizer
    "194.26.",    # Bulletproof Proxy Range
    "45.154.",    # Anonymous Hosting VPN
    "103.251."    # Threat Intel Blacklist ASN
)

def get_location_coords(location_name):
    """
    Resolves a location string to (latitude, longitude).
    Matches substrings (e.g. 'Jammu, India' -> (32.7266, 74.8570)).
    """
    if not location_name:
        return LOCATION_COORDINATES["jammu"]
    
    loc_clean = location_name.lower().strip()
    for city, coords in LOCATION_COORDINATES.items():
        if city in loc_clean:
            return coords
    
    # Default fallback: Jammu coordinates
    return LOCATION_COORDINATES["jammu"]


def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculates great-circle distance between two geographical points using Haversine formula.
    Returns distance in kilometers.
    """
    R = 6371.0 # Mean Earth radius in kilometers
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    
    a = (math.sin(dlat / 2) ** 2 + 
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def evaluate_impossible_travel(loc1, loc2, hours_diff=1.0):
    """
    Evaluates whether travel between two locations violates physical velocity limits.
    Commercial airliner cruise speed is ~800-900 km/h.
    Velocity > 800 km/h is flagged as Impossible Travel.
    """
    lat1, lon1 = get_location_coords(loc1)
    lat2, lon2 = get_location_coords(loc2)

    dist_km = haversine_distance(lat1, lon1, lat2, lon2)
    
    # Avoid zero division
    hours = max(hours_diff, 0.1)
    speed_kmh = dist_km / hours

    is_impossible = dist_km > 350 and speed_kmh > 800
    return is_impossible, round(dist_km, 1), round(speed_kmh, 1)


def check_ip_threat_intel(client_ip):
    """
    Simulated Threat Intelligence feed:
    Checks if client IP originates from known Tor exit nodes or malicious proxies.
    """
    if not client_ip:
        return False, "Clean IP", 0

    ip_str = str(client_ip).strip().lower()
    
    # Test keywords or simulated subnets
    if any(ip_str.startswith(p) for p in SUSPICIOUS_IP_PREFIXES) or "tor" in ip_str or "vpn" in ip_str or "proxy" in ip_str:
        return True, "Known Tor Exit Node / High-Risk Proxy (Threat Intel Match)", 30
    
    return False, "Trusted ISP / Clean IP", 0


def parse_user_agent(user_agent_string):
    """
    Derive simplified device/OS category from User-Agent string.
    """
    if not user_agent_string:
        return "Unknown"
    
    ua = user_agent_string.lower()
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        return "Mobile Device"
    elif "windows" in ua:
        return "Desktop (Windows)"
    elif "macintosh" in ua or "mac os" in ua:
        return "Desktop (macOS)"
    elif "linux" in ua:
        return "Desktop (Linux)"
    return "Desktop"


def analyze_behaviour(
    usual_login_time,
    usual_device,
    usual_location,
    normal_file_access,
    current_login_time,
    current_device,
    current_location,
    current_file_access,
    client_ip=None,
    hours_since_last_login=1.0
):
    """
    Compare current session observations against established baseline.
    Computes mathematical Haversine velocity for Impossible Travel.
    """
    anomalies = []
    behaviour_risk = 0

    # 1. Login Time Check (flag if outside daytime 07:00 - 22:00 or drastically different)
    if current_login_time and usual_login_time:
        try:
            curr_hour = int(current_login_time.split(":")[0])
            usual_hour = int(usual_login_time.split(":")[0])
            if abs(curr_hour - usual_hour) > 3 and (curr_hour < 6 or curr_hour > 22):
                behaviour_risk += 15
                anomalies.append(f"Unusual login time detected: {current_login_time} (Expected ~{usual_login_time})")
        except Exception:
            if current_login_time != usual_login_time:
                behaviour_risk += 10
                anomalies.append(f"Unusual login time: {current_login_time}")

    # 2. Device Check
    if current_device and usual_device:
        curr_d = current_device.lower()
        usual_d = usual_device.lower()
        if curr_d != usual_d and (curr_d not in usual_d and usual_d not in curr_d):
            behaviour_risk += 20
            anomalies.append(f"New/unrecognized device: {current_device} (Baseline: {usual_device})")

    # 3. Mathematical Impossible Travel & Location Geofencing (Haversine Formula)
    if current_location and usual_location:
        curr_loc = current_location.lower().strip()
        usual_loc = usual_location.lower().strip()
        
        if curr_loc not in usual_loc and usual_loc not in curr_loc:
            # Calculate distance and velocity
            is_impossible, dist_km, speed_kmh = evaluate_impossible_travel(
                usual_loc, curr_loc, hours_since_last_login
            )
            
            if is_impossible:
                behaviour_risk += 35
                anomalies.append(
                    f"Impossible Travel: {dist_km} km traversed in {hours_since_last_login:.1f}h "
                    f"({speed_kmh} km/h - exceeds 800 km/h commercial airline threshold)"
                )
            else:
                behaviour_risk += 25
                anomalies.append(f"Unusual location detected: {current_location} (~{dist_km} km from baseline {usual_location})")

    # 4. Threat Intelligence / Tor & Proxy Detection
    if client_ip:
        is_threat, threat_reason, threat_risk = check_ip_threat_intel(client_ip)
        if is_threat:
            behaviour_risk += threat_risk
            anomalies.append(f"Threat Intel Alert: {threat_reason} ({client_ip})")

    # 5. File Access Volume / Pattern Check
    if current_file_access and normal_file_access and current_file_access != normal_file_access:
        behaviour_risk += 20
        anomalies.append(f"Unusual data activity: {current_file_access} (Baseline: {normal_file_access})")

    # Limit risk to [0, 100]
    behaviour_risk = min(behaviour_risk, 100)

    if behaviour_risk == 0:
        status = "Normal"
    elif behaviour_risk <= 40:
        status = "Suspicious"
    else:
        status = "Critical"

    return behaviour_risk, status, anomalies

