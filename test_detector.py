"""Run with:  pytest -q"""
import pytest

from detector import detect
from features import FEATURE_NAMES, extract_features
from url_heuristics import (
    check_brand_mimicry, check_https, check_ip_address, check_sensitive_keywords,
    check_shortener, check_subdomain_count, check_suspicious_chars,
    check_suspicious_tld, check_url_length, KNOWN_BRANDS,
)


def test_known_brands_list_is_not_fused():
    # regression: missing commas used to fuse 'microsoft' 'netflix' 'facebook'
    for b in ("microsoft", "netflix", "facebook"):
        assert b in KNOWN_BRANDS


def test_https():
    assert check_https("http://example.com")[0] is True
    assert check_https("https://example.com")[0] is False


def test_ip_address():
    assert check_ip_address("http://192.168.1.1/login")[0] is True
    assert check_ip_address("https://amazon.com/login")[0] is False


def test_url_length():
    assert check_url_length("https://a.com/" + "x" * 120)[1] == 20
    assert check_url_length("https://a.com")[0] is False


def test_subdomains():
    assert check_subdomain_count("https://paypal.com.account-verify.secure-login.info")[0] is True
    assert check_subdomain_count("https://mail.google.com")[0] is False


def test_suspicious_chars():
    assert check_suspicious_chars("https://amazon.com@evil.com")[0] is True
    assert check_suspicious_chars("https://my-cool-shop-now.com")[0] is True
    assert check_suspicious_chars("https://amazon.com/products")[0] is False


def test_brand_mimicry():
    assert check_brand_mimicry("https://amazon.com")[0] is False
    assert check_brand_mimicry("https://arnazon.com")[0] is True
    assert check_brand_mimicry("https://paypal-secure-login.com")[0] is True
    assert check_brand_mimicry("https://paypal.com.evil-site.info")[0] is True
    assert check_brand_mimicry("https://netflix-help.com")[0] is True


def test_shortener_and_tld_and_keywords():
    assert check_shortener("https://bit.ly/abc")[0] is True
    assert check_shortener("https://example.com")[0] is False
    assert check_suspicious_tld("https://win-prize.xyz")[0] is True
    assert check_suspicious_tld("https://example.com")[0] is False
    assert check_sensitive_keywords("http://example.com/login")[0] is True
    assert check_sensitive_keywords("https://example.com/login")[0] is False


def test_feature_vector_shape_and_slash_invariance():
    assert len(extract_features("https://example.com")) == len(FEATURE_NAMES)
    assert extract_features("https://example.com") == extract_features("https://example.com/")


@pytest.mark.parametrize("url", ["https://www.google.com", "https://github.com", "https://www.mitwpu.edu.in"])
def test_known_safe(url):
    assert detect(url, use_whois=False)["verdict"] == "Safe"


@pytest.mark.parametrize("url", [
    "http://192.168.1.1/login.php",
    "https://paypal.com.account-verify.secure-login.info/reset",
    "http://secure-update-paypal.xyz/login/verify.php",
])
def test_known_phishing_style(url):
    assert detect(url, use_whois=False)["verdict"] == "Phishing"


def test_typosquat_not_safe():
    assert detect("https://arnazon.com/orders", use_whois=False)["verdict"] != "Safe"


@pytest.mark.parametrize("url", ["", "   ", "not a url", "http://", "https://[::1", "a" * 3000, "ftp://example.com"])
def test_edge_cases_do_not_crash(url):
    if not url.strip():
        pytest.skip("empty input is handled by the UI")
    result = detect(url, use_whois=False)
    assert result["verdict"] in ("Safe", "Suspicious", "Phishing")


def test_app_pages_render():
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file("app.py", default_timeout=60).run()
    assert not at.exception
    at.text_input(key="url_input").set_value("http://192.168.1.1/login.php")
    at.button[-1].click().run()   # the Analyze button is the last button on the page
    assert not at.exception
    assert any("Phishing" in m.value for m in at.markdown)
