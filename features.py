"""Lexical / structural feature extraction for the ML classifier.

All features are derived from the URL string alone so they can be computed
instantly for thousands of training URLs (no network calls).
"""
import re
from urllib.parse import urlparse

import tldextract

from url_heuristics import (
    KNOWN_BRANDS, SENSITIVE_KEYWORDS, SHORTENERS, SUSPICIOUS_TLDS, normalize_url,
)

_extract = tldextract.TLDExtract(suffix_list_urls=())

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_digits", "num_slashes",
    "num_question", "num_equals", "num_ampersand", "num_percent",
    "has_at", "has_ip", "uses_https", "num_subdomains", "domain_hyphens",
    "domain_digits", "digit_ratio", "letter_ratio", "has_brand_in_domain",
    "has_brand_in_subdomain_or_path", "is_shortener", "suspicious_tld",
    "num_sensitive_keywords", "has_port", "double_slash_in_path", "tld_length",
]

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def extract_features(url):
    url = normalize_url(url)
    # 'https://example.com' and 'https://example.com/' are the same page; make them
    # produce identical features so a missing trailing slash can't change the verdict.
    if not urlparse(url).path and "?" not in url and "#" not in url:
        url += "/"
    parsed = urlparse(url)
    ext = _extract(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    lowered = url.lower()
    n = max(len(url), 1)

    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    registered = f"{ext.domain}.{ext.suffix}".lower()
    tld = ext.suffix.lower().split(".")[-1] if ext.suffix else ""
    sub_and_path = (ext.subdomain + "/" + path).lower()

    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 1

    return [
        len(url), len(host), len(path), len(query),
        url.count("."), url.count("-"), url.count("_"), digits, url.count("/"),
        url.count("?"), url.count("="), url.count("&"), url.count("%"),
        int("@" in url), int(bool(_IPV4.match(host))), int(parsed.scheme == "https"),
        len(ext.subdomain.split(".")) if ext.subdomain else 0,
        host.count("-"), sum(c.isdigit() for c in host),
        digits / n, letters / n,
        int(any(b in ext.domain.lower() and ext.domain.lower() != b for b in KNOWN_BRANDS)),
        int(any(b in sub_and_path for b in KNOWN_BRANDS) and ext.domain.lower() not in KNOWN_BRANDS),
        int(registered in SHORTENERS), int(tld in SUSPICIOUS_TLDS),
        sum(k in lowered for k in SENSITIVE_KEYWORDS),
        has_port, int("//" in path), len(tld),
    ]
