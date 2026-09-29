def calculate_risk(
    failed_logins=0,
    new_device=False,
    unusual_time=False,
    unusual_location=False,
    large_file_access=False
):
    risk = 0
    reasons = []

    if failed_logins >= 5:
        risk += 30
        reasons.append("Multiple failed login attempts")
    elif failed_logins >= 3:
        risk += 15
        reasons.append("Several failed login attempts")

    if new_device:
        risk += 20
        reasons.append("New device detected")

    if unusual_time:
        risk += 15
        reasons.append("Unusual login time")

    if unusual_location:
        risk += 25
        reasons.append("Unusual location detected")

    if large_file_access:
        risk += 30
        reasons.append("Large file access detected")

    risk = min(risk, 100)

    if risk <= 30:
        level = "Normal"
    elif risk <= 60:
        level = "Suspicious"
    else:
        level = "Critical"

    return risk, level, reasons