# Test Case Log

Generated 2026-10-25 by `generate_test_log.py` (WHOIS lookup disabled for repeatability).

| # | Category | URL | Expected | Actual | Score | Result |
|---|----------|-----|----------|--------|-------|--------|
| 1 | Known safe | `https://www.google.com` | Safe | Safe | 0.06 | PASS |
| 2 | Known safe | `https://github.com` | Safe | Safe | 0.07 | PASS |
| 3 | Known safe | `https://en.wikipedia.org/wiki/Phishing` | Safe | Safe | 0.07 | PASS |
| 4 | Known safe | `https://www.mitwpu.edu.in` | Safe | Safe | 0.00 | PASS |
| 5 | Phishing-style | `https://paypal.com.account-verify.secure-login.info/reset` | Phishing | Phishing | 0.97 | PASS |
| 6 | Phishing-style | `http://secure-update-paypal.xyz/login/verify.php` | Phishing | Phishing | 1.00 | PASS |
| 7 | Typosquat | `https://arnazon.com/orders` | Not Safe | Phishing | 0.69 | PASS |
| 8 | Brand in domain | `https://netflix-billing-update.com/login` | Not Safe | Phishing | 0.84 | PASS |
| 9 | IP address | `http://192.168.1.1/login.php` | Phishing | Phishing | 0.84 | PASS |
| 10 | URL shortener | `http://bit.ly/3xyz` | Not Safe | Phishing | 0.66 | PASS |
| 11 | Contains @ | `https://amazon.com@evil-login.com/verify` | Not Safe | Phishing | 0.66 | PASS |
| 12 | Very long URL | `https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...` | Not Safe | Suspicious | 0.39 | PASS |
| 13 | Suspicious TLD | `https://free-gift.xyz/claim` | Not Safe | Phishing | 0.59 | PASS |
| 14 | Edge: no scheme | `www.google.com` | Safe | Safe | 0.06 | PASS |
| 15 | Edge: malformed | `https://[::1` | Not Safe | Suspicious | 0.50 | PASS |
| 16 | Edge: unreachable host | `https://this-domain-does-not-exist-12345.com` | Safe/Suspicious (any, no crash) | Suspicious | 0.50 | PASS |

**16/16 cases passed.**
