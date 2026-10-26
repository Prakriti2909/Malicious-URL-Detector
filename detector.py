"""Signal integration: combines the rule-based heuristic score and the ML model's
phishing probability into one explainable verdict (Safe / Suspicious / Phishing)."""
import os
from functools import lru_cache
from urllib.parse import urlparse

import joblib
import pandas as pd
import tldextract

from features import FEATURE_NAMES, extract_features
from url_heuristics import SHORTENERS, analyze_url, normalize_url

_HERE = os.path.dirname(os.path.abspath(__file__))
_extract = tldextract.TLDExtract(suffix_list_urls=())

# Weights and thresholds for the combined score (0..1). Calibrated on example URLs
# during testing; see README / methodology page.
HEURISTIC_WEIGHT = 0.5
ML_WEIGHT = 0.5
HEURISTIC_CAP = 80          # heuristic score that counts as "maximum risk"
PHISHING_AT = 0.55
SUSPICIOUS_AT = 0.30
TRUSTED_ML_CAP = 0.15       # ML probability is capped for allow-listed popular domains


@lru_cache(maxsize=1)
def _load_model():
    path = os.path.join(_HERE, "model.joblib")
    if not os.path.exists(path):
        return None
    return joblib.load(path)


@lru_cache(maxsize=1)
def _load_trusted():
    path = os.path.join(_HERE, "trusted_domains.txt")
    if not os.path.exists(path):
        return frozenset()
    with open(path) as f:
        return frozenset(line.strip().lower() for line in f if line.strip())


def ml_probability(url):
    """Probability (0..1) that the URL is phishing, or None if no model is available."""
    bundle = _load_model()
    if bundle is None:
        return None
    row = pd.DataFrame([extract_features(url)], columns=FEATURE_NAMES)
    return float(bundle["model"].predict_proba(row)[0][1])


def is_trusted(url):
    ext = _extract(url)
    registered = f"{ext.domain}.{ext.suffix}".lower()
    if registered in SHORTENERS:      # popular, but they hide the real destination
        return False
    return registered in _load_trusted()


def verdict_from_combined(score):
    if score >= PHISHING_AT:
        return "Phishing"
    if score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Safe"


def detect(url, use_whois=True):
    """Full analysis of one URL. Returns a dict with verdict, scores and explanations."""
    url = normalize_url(url)
    try:
        urlparse(url).hostname  # raises ValueError for malformed hosts such as 'https://[::1'
    except ValueError:
        return {
            "url": url, "verdict": "Suspicious", "combined_score": 0.5, "heuristic_score": 0,
            "heuristic_verdict": "Safe", "ml_probability": None, "trusted_domain": False,
            "triggered": [{"name": "URL Format Check", "triggered": True, "score": 0,
                           "reason": "URL is malformed and could not be parsed"}],
            "all_checks": [], "notes": ["Malformed URLs cannot be analyzed reliably; treat with caution."],
        }
    heur = analyze_url(url, use_whois=use_whois)
    prob = ml_probability(url)
    trusted = is_trusted(url)

    heur_norm = min(heur["total_score"], HEURISTIC_CAP) / HEURISTIC_CAP
    notes = []

    if prob is None:
        combined = heur_norm
        notes.append("ML model file not found; verdict uses heuristic rules only.")
        effective_prob = None
    else:
        effective_prob = min(prob, TRUSTED_ML_CAP) if trusted else prob
        if trusted and prob > TRUSTED_ML_CAP:
            notes.append("Domain is in the trusted top-10,000 list, so the ML signal was capped.")
        combined = HEURISTIC_WEIGHT * heur_norm + ML_WEIGHT * effective_prob

    # A heuristic flag should never be diluted to "Safe" by the ML side.
    verdict = verdict_from_combined(combined)
    if heur["verdict"] != "Safe" and verdict == "Safe":
        verdict = "Suspicious"

    return {
        "url": url,
        "verdict": verdict,
        "combined_score": round(combined, 3),
        "heuristic_score": heur["total_score"],
        "heuristic_verdict": heur["verdict"],
        "ml_probability": None if prob is None else round(prob, 3),
        "trusted_domain": trusted,
        "triggered": [c for c in heur["checks"] if c["triggered"]],
        "all_checks": heur["checks"],
        "notes": notes,
    }
