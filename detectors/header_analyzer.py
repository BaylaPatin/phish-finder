import re


def extract_field(header, field):
    pattern = rf"^{field}:\s*(.+)$"
    match = re.search(pattern, header, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def analyze_header(header):
    score = 0
    reasons = []

    from_field = extract_field(header, "From")
    reply_to = extract_field(header, "Reply-To")
    auth = extract_field(header, "Authentication-Results")

    if from_field and reply_to and from_field != reply_to:
        score += 3
        reasons.append("From and Reply-To mismatch")

    if auth:
        auth_lower = auth.lower()
        if "spf=fail" in auth_lower:
            score += 2
            reasons.append("SPF failed")
        if "dkim=fail" in auth_lower:
            score += 2
            reasons.append("DKIM failed")

    return {
        "from": from_field,
        "reply_to": reply_to,
        "score": score,
        "reasons": reasons,
    }