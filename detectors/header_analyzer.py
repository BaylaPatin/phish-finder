import re


def extract_field(header, field):
    pattern = rf"^{field}:\s*(.+)$"
    match = re.search(pattern, header, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def extract_email_address(text):
    if not text:
        return None

    match = re.search(r"<([^>]+)>", text)
    if match:
        return match.group(1).strip().lower()

    match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", text)
    if match:
        return match.group(0).strip().lower()

    return None


def extract_domain(email):
    if not email or "@" not in email:
        return None
    return email.split("@")[-1].lower()


def get_risk_level(score):
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def analyze_header(header):
    score = 0
    reasons = []

    from_field = extract_field(header, "From")
    reply_to_field = extract_field(header, "Reply-To")
    auth_results = extract_field(header, "Authentication-Results")

    from_email = extract_email_address(from_field)
    reply_to_email = extract_email_address(reply_to_field)

    from_domain = extract_domain(from_email)
    reply_to_domain = extract_domain(reply_to_email)

    if from_email and reply_to_email and from_email != reply_to_email:
        score += 2
        reasons.append("From and Reply-To email addresses do not match")

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        score += 3
        reasons.append("From and Reply-To domains do not match")

    if auth_results:
        auth_lower = auth_results.lower()

        if "spf=fail" in auth_lower:
            score += 2
            reasons.append("SPF failed")

        if "dkim=fail" in auth_lower:
            score += 2
            reasons.append("DKIM failed")

        if "dmarc=fail" in auth_lower:
            score += 2
            reasons.append("DMARC failed")

    return {
        "from_field": from_field,
        "reply_to_field": reply_to_field,
        "from_email": from_email,
        "reply_to_email": reply_to_email,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "score": score,
        "risk_level": get_risk_level(score),
        "reasons": reasons,
    }