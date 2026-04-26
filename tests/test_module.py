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
    print("\nHEADER TEST 1:")
    header1 = """From: PayPal <support@paypal.com>
Reply-To: attacker@gmail.com
Authentication-Results: spf=fail dkim=fail dmarc=fail
"""
    print(analyze_header(header1))

    print("\nHEADER TEST 2:")
    header2 = """From: Amazon <support@amazon.com>
Reply-To: support@amazon.com
Authentication-Results: spf=pass dkim=pass dmarc=pass
"""
    print(analyze_header(header2))


if __name__ == "__main__":
    test_url()
    test_header()