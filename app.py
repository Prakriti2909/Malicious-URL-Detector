import json
import os
from datetime import datetime

import pandas as pd
import streamlit as st

from detector import detect

st.set_page_config(page_title="Phishing / Malicious URL Detector", page_icon="🛡️", layout="centered")

HERE = os.path.dirname(os.path.abspath(__file__))
COLORS = {"Safe": "#1a7f37", "Suspicious": "#b7791f", "Phishing": "#c62828"}
ICONS = {"Safe": "✅", "Suspicious": "⚠️", "Phishing": "🚨"}
EXAMPLES = {
    "Legit: google.com": "https://www.google.com",
    "IP address login": "http://192.168.1.1/login.php",
    "Brand in subdomain": "https://paypal.com.account-verify.secure-login.info/reset",
    "Typosquat: arnazon": "https://arnazon.com/orders",
    "Shortened link": "http://bit.ly/3xyz",
}

if "history" not in st.session_state:
    st.session_state.history = []
if "url_input" not in st.session_state:
    st.session_state.url_input = ""


def remember(result):
    st.session_state.history.insert(0, {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "URL": result["url"],
        "Verdict": result["verdict"],
        "Score": result["combined_score"],
    })
    del st.session_state.history[50:]


def verdict_banner(result):
    v = result["verdict"]
    st.markdown(
        f"<div style='padding:16px;border-radius:10px;background:{COLORS[v]};color:white;"
        f"font-size:1.4rem;font-weight:600'>{ICONS[v]} {v}"
        f"<span style='font-size:0.95rem;font-weight:400'> &nbsp;· risk score {result['combined_score']:.2f} / 1.00</span></div>",
        unsafe_allow_html=True,
    )


def explain(result):
    verdict_banner(result)
    st.write("")
    c1, c2 = st.columns(2)
    c1.metric("Heuristic risk points", result["heuristic_score"])
    ml = result["ml_probability"]
    c2.metric("ML phishing probability", "n/a" if ml is None else f"{ml:.0%}")
    for note in result["notes"]:
        st.info(note)

    st.subheader("Why this verdict")
    if result["triggered"]:
        for c in result["triggered"]:
            st.markdown(f"- **{c['name']}** (+{c['score']}): {c['reason']}")
    else:
        st.markdown("No heuristic red flags were triggered.")
    with st.expander("See all checks"):
        for c in result["all_checks"]:
            st.markdown(f"{'⚠️' if c['triggered'] else '✅'} **{c['name']}**: {c['reason']}")


# ----------------------------------------------------------------------------- pages
def page_analyze():
    st.title("🛡️ URL Safety Checker")
    st.caption("Paste a link to see whether it looks safe, suspicious or like phishing, and why.")

    st.write("Try an example:")
    cols = st.columns(len(EXAMPLES))
    for col, (label, url) in zip(cols, EXAMPLES.items()):
        if col.button(label, use_container_width=True):
            st.session_state.url_input = url

    url = st.text_input("URL to check", key="url_input", placeholder="https://example.com/login")
    use_whois = st.checkbox("Include domain-age (WHOIS) lookup — slower, may be unavailable", value=False)

    if st.button("Analyze", type="primary") and url.strip():
        with st.spinner("Analyzing..."):
            result = detect(url, use_whois=use_whois)
        remember(result)
        explain(result)
    st.caption("This tool gives a risk estimate, not a guarantee. Never enter credentials on a site you don't trust.")


def page_batch():
    st.title("Batch check")
    st.caption("One URL per line.")
    text = st.text_area("URLs", height=180, placeholder="https://example.com\nhttp://192.168.1.1/login")
    if st.button("Analyze all", type="primary"):
        urls = [u.strip() for u in text.splitlines() if u.strip()][:100]
        if not urls:
            st.warning("Enter at least one URL.")
            return
        rows = []
        bar = st.progress(0.0)
        for i, u in enumerate(urls, 1):
            r = detect(u, use_whois=False)
            remember(r)
            rows.append({
                "URL": r["url"], "Verdict": f"{ICONS[r['verdict']]} {r['verdict']}",
                "Risk score": r["combined_score"], "Heuristic pts": r["heuristic_score"],
                "ML prob": r["ml_probability"],
                "Flags": "; ".join(c["name"] for c in r["triggered"]),
            })
            bar.progress(i / len(urls))
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Download CSV", df.to_csv(index=False), "url_results.csv", "text/csv")
        st.caption("Batch mode skips the slow WHOIS lookup. Maximum 100 URLs per run.")


def page_history():
    st.title("Recent activity")
    if not st.session_state.history:
        st.write("No URLs analyzed yet in this session.")
        return
    st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True, hide_index=True)
    if st.button("Clear history"):
        st.session_state.history = []
        st.rerun()


def page_methodology():
    st.title("Methodology")
    st.markdown(
        """
**Hybrid detection.** Every URL is scored two ways and the results are combined:

1. **Rule-based heuristics** — ten checks (HTTPS, IP-address host, URL length, subdomain count,
   suspicious characters, brand mimicry/typosquatting, URL shorteners, suspicious TLDs, sensitive keywords,
   domain age). Each adds risk points and produces a plain-language reason.
2. **Machine-learning classifier** — a Random Forest trained on 29 URL features
   (lexical and structural) to estimate the probability a URL is phishing.

**Combined score** = 0.5 × heuristic risk (capped at 80 points) + 0.5 × ML probability.
≥ 0.55 → *Phishing*, ≥ 0.30 → *Suspicious*, otherwise *Safe*. Any heuristic flag keeps the verdict at least *Suspicious*.
Domains in the top-10,000 most popular list have their ML probability capped, because the model is
trained on URL text only and can over-flag normal deep links on well-known sites.
        """
    )
    path = os.path.join(HERE, "metrics.json")
    if os.path.exists(path):
        with open(path) as f:
            m = json.load(f)
        st.subheader("Model evaluation (held-out test set)")
        st.write(f"{m['dataset_size']:,} URLs total, {m['test_size']:,} held out for testing. Selected model: **{m['selected_model']}**.")
        rows = []
        for name, r in m["results"].items():
            rows.append({"Model": name, "Accuracy": r["accuracy"], "Precision": r["precision"],
                         "Recall": r["recall"], "F1": r["f1"]})
        st.dataframe(pd.DataFrame(rows).style.format({k: "{:.3f}" for k in ["Accuracy", "Precision", "Recall", "F1"]}),
                     hide_index=True, use_container_width=True)
        if m.get("top_features"):
            st.write("Most influential features")
            st.bar_chart(pd.DataFrame(m["top_features"], columns=["feature", "importance"]).set_index("feature"))
    st.subheader("Limitations")
    st.markdown(
        """
- Analyzes the URL string, domain registration and SSL scheme only — **not** the page content.
- Accuracy figures come from one public dataset (PhishTank phishing URLs vs. a benign URL list plus
  top-ranked domains); real-world accuracy on new attack styles will be lower.
- The benign dataset has unusual path structure, so the ML signal is less reliable on long paths of legitimate sites,
  which is why the trusted-domain cap exists.
- WHOIS data can be missing or rate-limited.
        """
    )


PAGES = {"Analyze URL": page_analyze, "Batch check": page_batch, "History": page_history, "Methodology": page_methodology}
choice = st.sidebar.radio("Navigate", list(PAGES))
PAGES[choice]()
