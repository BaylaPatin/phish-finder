import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "reset",
    "bank",
]


def extract_urls(text):
    pattern = r"https?://[^\s]+"
    return re.findall(pattern, text)


def uses_https(url):
    return url.lower().startswith("https://")


def has_suspicious_keywords(url):
    lowered = url.lower()
    return any(word in lowered for word in SUSPICIOUS_KEYWORDS)


def has_ip_address(url):
    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_long_url(url, threshold=75):
    return len(url) > threshold


def has_many_dots(url, threshold=3):
    parsed = urlparse(url)
    return parsed.netloc.count(".") > threshold


def get_risk_level(score):
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def analyze_url(url):
    score = 0
    reasons = []

    if not uses_https(url):
        score += 1
        reasons.append("URL does not use HTTPS")

    if has_suspicious_keywords(url):
        score += 2
        reasons.append("Contains suspicious keywords")

    if has_ip_address(url):
        score += 3
        reasons.append("URL uses an IP address instead of a domain")

    if is_long_url(url):
        score += 1
        reasons.append("URL is unusually long")

    if has_many_dots(url):
        score += 1
        reasons.append("URL has many dots/subdomains")

    parsed = urlparse(url)
    domain = parsed.netloc

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "risk_level": get_risk_level(score),
        "reasons": reasons,
    }


def analyze_urls_from_text(text):
    urls = extract_urls(text)
    return [analyze_url(url) for url in urls]