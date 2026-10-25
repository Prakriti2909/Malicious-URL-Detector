from urllib.parse import urlparse
import re
import tldextract
from difflib import SequenceMatcher
import whois
from datetime import datetime

def check_https(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return True, 10, "URL does not use HTTPS"
    return  False, 0, "Uses HTTPS"

#test
#print(check_https("http://254827coinbase.com"))

def check_ip_address(url):
    hostname = urlparse(url).hostname or ""
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, hostname):
        return True, 25, "Host is a raw IP address"
    return False, 0, "Host is a domain name"

#test
#print(check_ip_address("http://192.168.1.1/login"))
#print(check_ip_address("https://amazon.com/login"))

def check_url_length(url):
    length = len(url)
    if length > 100:
        return True, 20, f"URL is very long ({length} chars)"
    elif length > 75:
        return True, 10, f"URL is moderately long ({length} chars)"
    return False, 0, f"URL length is normal ({length} chars)"

#test
#print(check_url_length("https://amazon.com/login"))
#print(check_url_length("https://secure-login-update-account-verification.suspicious-site.com/reset?token=" + "a"*40))

def check_subdomain_count(url):
    ext = tldextract.extract(url)
    if not ext.subdomain:
        return False, 0, "No subdomains"

    count = len(ext.subdomain.split("."))
    if count >= 3:
        return True, 20, f"Excessive subdomains ({count}): {ext.subdomain}"
    elif count == 2:
        return True, 10, f"Multiple subdomains ({count}): {ext.subdomain}"
    return False, 0, f"Normal subdomain count ({count})"

#test
#print(check_subdomain_count("https://mail.google.com"))
#print(check_subdomain_count("https://paypal.com.account-verify.secure-login.info"))


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
        score +=15

    if reasons: 
        return True, score, "; ".join(reasons)
    return False, 0, "No suspicious characters found"

#test
#print(check_suspicious_chars("https://amazon.com@evil-login.com/verify"))
#print(check_suspicious_chars("https://secure-paypal-account-update.com"))
#print(check_suspicious_chars("https://amazon.com/products/item123"))

from difflib import SequenceMatcher

KNOWN_BRANDS = ["google", "amazon", "paypal", "apple", "microsoft", "netflix", "facebook", "instagram"]

def check_brand_mimicry(url, brands=KNOWN_BRANDS, threshold=0.75):
    ext = tldextract.extract(url)
    domain = ext.domain.lower()

    for brand in brands:
        if domain == brand:
            return False, 0, f"Matches known domain for '{brand}"
        if brand in domain and domain != brand:
            return True, 30, f"Domain contains brand name '{brand}' but isn't '{brand}.com'"
        similarity = SequenceMatcher(None, domain, brand).ratio()
        if similarity >= threshold and domain != brand:
            return True, 30, f"Domain '{domain}' closely resembles brand '{brand}' (similarity {similarity:.2f})"

    return False, 0, "No brand mimicry detected"

#test
#print(check_brand_mimicry("https://amazon.com/orders"))
#print(check_brand_mimicry("https://arnazon.com/orders"))
#print(check_brand_mimicry("https://paypal-secure-verify-account.com/login"))

def check_domain_age(url):
    ext = tldextract.extract(url)
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

        if age_days <30:
            return True, 30, f"Domain registered very recently ({age_days} days ago)"
        elif age_days < 180:
            return True, 15, f"Domain registered recently ({age_days} days ago)"
        return False, 0, f"Domain age: {age_days} days"

    except Exception as e:
        return False, 0, f"WHOIS lookup failed: {e}"
    


ALL_CHECKS = [
    ("HTTPS Check", check_https),
    ("IP Address Check", check_ip_address),
    ("URL Length Check", check_url_length),
    ("Subdomain Count Check", check_subdomain_count),
    ("Suspicious Characters Check", check_suspicious_chars),
    ("Brand Mimicry Check", check_brand_mimicry),
    ("Domain Age Check", check_domain_age)
]

def analyze_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    results = []
    total_score = 0

    for name, check_fn in ALL_CHECKS:
        triggered, score, reason = check_fn(url)
        results.append({"name": name, "triggered": triggered, "reason": reason})
        total_score += score

    if total_score >= 50:
        verdict = "Phishing"
    elif total_score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"url": url, "total_score": total_score, "verdict": verdict, "checks": results}

#test
#result = analyze_url("https://siempreducando.com/")
#print(result["verdict"], result["total_score"])
#for c in result["checks"]:
#    print(c["triggered"], c["name"], "-", c["reason"])

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=python",
        "http://192.168.1.1/login.php",
        "https://paypal.com.account-verify.secure-login.info/reset",
        "https://arnazon.com/orders",
        "https://siempreducando.com/",
    ]
    for url in test_urls:
        result = analyze_url(url)
        print(f"\n{result['url']}")
        print(f"Verdict: {result['verdict']} (score: {result['total_score']})")
        for c in result["checks"]:
            print(f"  {'⚠️' if c['triggered'] else '✅'} {c['name']}: {c['reason']}")
