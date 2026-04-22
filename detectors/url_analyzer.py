import re
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


def analyze_url(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 1
        reasons.append("URL does not use HTTPS")

    if any(word in url.lower() for word in SUSPICIOUS_KEYWORDS):
        score += 2
        reasons.append("Contains suspicious keywords")

    parsed = urlparse(url)
    domain = parsed.netloc

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "reasons": reasons,
    }


def analyze_urls_from_text(text):
    urls = extract_urls(text)
    return [analyze_url(url) for url in urls]