from detectors.url_analyzer import analyze_urls_from_text
from detectors.header_analyzer import analyze_header


def test_url():
    message = """
    Your account is locked. Verify now:
    http://secure-login-bank-alert.xyz/reset
    """

    results = analyze_urls_from_text(message)
    print("URL RESULTS:")
    for result in results:
        print(result)


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