from detectors.url_analyzer import analyze_urls_from_text, analyze_url
from detectors.header_analyzer import analyze_header


def test_url():
    message = """
    Your account is locked. Verify now:
    http://secure-login-bank-alert.xyz/reset
    """

    print("URL RESULTS FROM MESSAGE:")
    results = analyze_urls_from_text(message)
    for result in results:
        print(result)

    print("\nDIRECT URL TESTS:")
    test_urls = [
        "https://paypal.com",
        "http://192.168.1.10/login",
        "http://verify-account-security-login.example.xyz/reset/password",
        "https://sub.domain.example.com",
    ]

    for url in test_urls:
        print(analyze_url(url))


def test_header():
    header = """From: PayPal <support@paypal.com>
Reply-To: attacker@gmail.com
Authentication-Results: spf=fail dkim=fail
"""

    result = analyze_header(header)
    print("\nHEADER RESULT:")
    print(result)


if __name__ == "__main__":
    test_url()
    test_header()