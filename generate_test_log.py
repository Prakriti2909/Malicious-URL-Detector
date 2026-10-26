"""Generates TEST_LOG.md: a table of test URLs, expected vs actual verdicts (for the report)."""
from datetime import date

from detector import detect

CASES = [
    # (category, url, expected)
    ("Known safe", "https://www.google.com", "Safe"),
    ("Known safe", "https://github.com", "Safe"),
    ("Known safe", "https://en.wikipedia.org/wiki/Phishing", "Safe"),
    ("Known safe", "https://www.mitwpu.edu.in", "Safe"),
    ("Phishing-style", "https://paypal.com.account-verify.secure-login.info/reset", "Phishing"),
    ("Phishing-style", "http://secure-update-paypal.xyz/login/verify.php", "Phishing"),
    ("Typosquat", "https://arnazon.com/orders", "Not Safe"),
    ("Brand in domain", "https://netflix-billing-update.com/login", "Not Safe"),
    ("IP address", "http://192.168.1.1/login.php", "Phishing"),
    ("URL shortener", "http://bit.ly/3xyz", "Not Safe"),
    ("Contains @", "https://amazon.com@evil-login.com/verify", "Not Safe"),
    ("Very long URL", "https://example.com/" + "a" * 120, "Not Safe"),
    ("Suspicious TLD", "https://free-gift.xyz/claim", "Not Safe"),
    ("Edge: no scheme", "www.google.com", "Safe"),
    ("Edge: malformed", "https://[::1", "Not Safe"),
    ("Edge: unreachable host", "https://this-domain-does-not-exist-12345.com", "Safe/Suspicious (any, no crash)"),
]


def ok(expected, actual):
    if expected == "Not Safe":
        return actual != "Safe"
    if expected.startswith("Safe/Suspicious"):
        return actual in ("Safe", "Suspicious")
    return expected == actual


def main():
    rows, passed = [], 0
    for i, (cat, url, expected) in enumerate(CASES, 1):
        r = detect(url, use_whois=False)
        good = ok(expected, r["verdict"])
        passed += good
        shown = url if len(url) <= 60 else url[:57] + "..."
        rows.append(f"| {i} | {cat} | `{shown}` | {expected} | {r['verdict']} | {r['combined_score']:.2f} | {'PASS' if good else 'FAIL'} |")
    out = [
        "# Test Case Log", "",
        f"Generated {date.today().isoformat()} by `generate_test_log.py` (WHOIS lookup disabled for repeatability).", "",
        "| # | Category | URL | Expected | Actual | Score | Result |",
        "|---|----------|-----|----------|--------|-------|--------|",
        *rows, "", f"**{passed}/{len(CASES)} cases passed.**", "",
    ]
    with open("TEST_LOG.md", "w") as f:
        f.write("\n".join(out))
    print("\n".join(out))


if __name__ == "__main__":
    main()
