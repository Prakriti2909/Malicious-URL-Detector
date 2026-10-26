"""Rule-based heuristic engine for the Phishing/Malicious URL Detector.

Each check returns (triggered, score, reason). analyze_url() runs every check,
sums the scores and maps the total to a verdict. The list of triggered checks
is surfaced to the user as the explanation.
"""
from urllib.parse import urlparse
from difflib import SequenceMatcher
from datetime import datetime
import re

import tldextract

# Use the suffix list bundled with tldextract (no network fetch at import/run time)
_extract = tldextract.TLDExtract(suffix_list_urls=())

try:  # python-whois is optional at import time so the rest of the app still works
    import whois
except Exception:  # pragma: no cover
    whois = None


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def check_https(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return True, 10, "URL does not use HTTPS"
    return False, 0, "Uses HTTPS"


def check_ip_address(url):
    hostname = urlparse(url).hostname or ""
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, hostname):
        return True, 25, "Host is a raw IP address"
    return False, 0, "Host is a domain name"


def check_url_length(url):
    length = len(url)
    if length > 100:
        return True, 20, f"URL is very long ({length} chars)"
    elif length > 75:
        return True, 10, f"URL is moderately long ({length} chars)"
    return False, 0, f"URL length is normal ({length} chars)"


def check_subdomain_count(url):
    ext = _extract(url)
    if not ext.subdomain:
        return False, 0, "No subdomains"

    count = len(ext.subdomain.split("."))
    if count >= 3:
        return True, 20, f"Excessive subdomains ({count}): {ext.subdomain}"
    elif count == 2:
        return True, 10, f"Multiple subdomains ({count}): {ext.subdomain}"
    return False, 0, f"Normal subdomain count ({count})"


def check_suspicious_chars(url):
    reasons = []
    score = 0

    if "@" in url:
        reasons.append("Contains '@' (can hide real destination)")
        score += 25

    hostname = urlparse(url).hostname or ""
    hyphen_count = hostname.count("-")
    if hyphen_count >= 2:
        reasons.append(f"Domain has {hyphen_count} hyphens")
        score += 15

    if "%" in url:
        reasons.append("Contains URL-encoded characters")
        score += 15

    if reasons:
        return True, score, "; ".join(reasons)
    return False, 0, "No suspicious characters found"


KNOWN_BRANDS = [
    "google", "amazon", "paypal", "apple", "microsoft", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "dropbox", "coinbase", "binance", "adobe", "ebay", "sbi", "hdfcbank",
    "icicibank", "paytm", "flipkart",
]


def check_brand_mimicry(url, brands=KNOWN_BRANDS, threshold=0.75):
    ext = _extract(url)
    domain = ext.domain.lower()
    subdomain = ext.subdomain.lower()

    # 1. Exact brand domain -> fine
    if domain in brands:
        return False, 0, f"Matches known domain for '{domain}'"

    for brand in brands:
        # 2. Brand name used as a subdomain of someone else's domain
        #    e.g. paypal.com.account-verify.info
        if brand in subdomain.split(".") or (subdomain and brand in subdomain):
            return True, 30, (f"Brand '{brand}' appears in the subdomain but the "
                              f"real domain is '{ext.domain}.{ext.suffix}'")
        # 3. Brand name embedded in the domain, e.g. paypal-secure-login.com
        if brand in domain:
            return True, 30, f"Domain contains brand name '{brand}' but isn't '{brand}.com'"
        # 4. Typosquatting, e.g. arnazon.com
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if similarity >= threshold:
            return True, 30, (f"Domain '{domain}' closely resembles brand "
                              f"'{brand}' (similarity {similarity:.2f})")

    return False, 0, "No brand mimicry detected"


SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink",
}


def check_shortener(url):
    ext = _extract(url)
    registered = f"{ext.domain}.{ext.suffix}".lower()
    if registered in SHORTENERS:
        return True, 15, f"URL shortener used ({registered}); real destination is hidden"
    return False, 0, "Not a known URL shortener"


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "zip",
    "work", "loan", "men", "icu", "cyou", "support", "rest", "monster",
}


def check_suspicious_tld(url):
    suffix = _extract(url).suffix.lower().split(".")[-1]
    if suffix in SUSPICIOUS_TLDS:
        return True, 15, f"Top-level domain '.{suffix}' is commonly abused"
    return False, 0, "TLD is not on the suspicious list"


SENSITIVE_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "wallet", "billing", "suspend",
]


def check_sensitive_keywords(url):
    lowered = url.lower()
    found = [k for k in SENSITIVE_KEYWORDS if k in lowered]
    if not found:
        return False, 0, "No sensitive keywords"
    insecure = urlparse(url).scheme != "https"
    if insecure:
        return True, 20, f"Sensitive keywords ({', '.join(found[:4])}) on an insecure (non-HTTPS) connection"
    if len(found) >= 3:
        return True, 10, f"Many sensitive keywords in URL ({', '.join(found[:4])})"
    return False, 0, f"Sensitive keywords present ({', '.join(found)}) but connection is HTTPS"


def check_domain_age(url):
    if whois is None:
        return False, 0, "WHOIS library not available"

    ext = _extract(url)
    domain_name = f"{ext.domain}.{ext.suffix}"

    try:
        info = whois.whois(domain_name)
        creation_data = info.creation_date
        if isinstance(creation_data, list):
            creation_data = creation_data[0]

        if creation_data is None:
            return False, 0, "Domain age unavailable"

        if creation_data.tzinfo is not None:
            creation_data = creation_data.replace(tzinfo=None)

        age_days = (datetime.now() - creation_data).days

        if age_days < 30:
            return True, 30, f"Domain registered very recently ({age_days} days ago)"
        elif age_days < 180:
            return True, 15, f"Domain registered recently ({age_days} days ago)"
        return False, 0, f"Domain age: {age_days} days"

    except Exception as e:
        return False, 0, f"WHOIS lookup unavailable ({type(e).__name__})"


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
OFFLINE_CHECKS = [
    ("HTTPS Check", check_https),
    ("IP Address Check", check_ip_address),
    ("URL Length Check", check_url_length),
    ("Subdomain Count Check", check_subdomain_count),
    ("Suspicious Characters Check", check_suspicious_chars),
    ("Brand Mimicry Check", check_brand_mimicry),
    ("URL Shortener Check", check_shortener),
    ("Suspicious TLD Check", check_suspicious_tld),
    ("Sensitive Keywords Check", check_sensitive_keywords),
]
ONLINE_CHECKS = [("Domain Age Check", check_domain_age)]
ALL_CHECKS = OFFLINE_CHECKS + ONLINE_CHECKS

PHISHING_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 20


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def verdict_from_score(score):
    if score >= PHISHING_THRESHOLD:
        return "Phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Safe"


def analyze_url(url, use_whois=True):
    """Run all heuristic checks. Set use_whois=False to skip the slow network check."""
    url = normalize_url(url)
    checks = ALL_CHECKS if use_whois else OFFLINE_CHECKS
    results = []
    total_score = 0

    for name, check_fn in checks:
        triggered, score, reason = check_fn(url)
        results.append({"name": name, "triggered": triggered, "score": score, "reason": reason})
        total_score += score

    return {
        "url": url,
        "total_score": total_score,
        "verdict": verdict_from_score(total_score),
        "checks": results,
    }


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://192.168.1.1/login.php",
        "https://paypal.com.account-verify.secure-login.info/reset",
        "https://arnazon.com/orders",
        "https://siempreducando.com/",
    ]
    for u in test_urls:
        result = analyze_url(u, use_whois=False)
        print(f"\n{result['url']}")
        print(f"Verdict: {result['verdict']} (score: {result['total_score']})")
        for c in result["checks"]:
            print(f"  {'[!]' if c['triggered'] else '[ok]'} {c['name']}: {c['reason']}")
