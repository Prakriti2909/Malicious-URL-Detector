# Phishing / Malicious URL Detector
https://malicious-url-detector-46ugt3ej7k9qhhwfmlwnb8.streamlit.app/

A web app that checks whether a URL looks **Safe, Suspicious or Phishing** and explains why.
It combines rule-based heuristics with a Random Forest classifier trained on public phishing data.

Mini Project, MIT World Peace University, School of CSE (Prakriti Shree Patel, Rashi Wagh).

## Features
- Single-URL analysis with a colour-coded verdict and a list of triggered checks
- Batch mode (up to 100 URLs, CSV download), session history, methodology/metrics page
- 10 heuristic checks: HTTPS, IP host, URL length, subdomains, suspicious characters, brand mimicry /
  typosquatting, URL shorteners, suspicious TLDs, sensitive keywords, domain age (WHOIS)
- 29-feature ML model (Random Forest vs Logistic Regression compared; best is saved)

## Run locally
```bash
pip install -r requirements.txt
streamlit run app.py
```

## Project layout
| File | Purpose |
|------|---------|
| `url_heuristics.py` | Rule-based checks and heuristic score |
| `features.py` | URL to numeric feature vector for the ML model |
| `train_model.py` | Downloads data, trains/evaluates models, writes `model.joblib` and `metrics.json` |
| `detector.py` | Combines heuristic score + ML probability into the final verdict |
| `app.py` | Streamlit interface |
| `test_detector.py` | pytest suite (`pytest -q`) |
| `generate_test_log.py` | Produces `TEST_LOG.md` for the report |
| `trusted_domains.txt` | Top-10,000 popular domains (caps the ML signal for known sites) |

## Retrain the model
```bash
python train_model.py     # downloads ~20 MB of public data into ./data (git-ignored)
```
Data: PhishTank verified phishing URLs and a public benign URL list (via
`shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques`), plus the top-ranked domains from
`zer0h/top-1000000-domains`. The benign list alone is heavily biased (94% HTTP, only long deep-path URLs),
so it is mixed with homepage-style URLs of top domains and the HTTPS rate is equalised across classes.

## Deploy (Streamlit Community Cloud)
1. Push this repo to GitHub (`model.joblib` and `trusted_domains.txt` must be committed).
2. Go to https://share.streamlit.io, sign in with GitHub, click **Create app**.
3. Pick this repository, branch `main`, main file `app.py`, then **Deploy**.
4. Copy the public URL into your report and put it at the top of this README.

## Limitations
- URL-level analysis only; page content is not inspected.
- Metrics come from one dataset snapshot (2020-era PhishTank); real-world accuracy on new attacks will be lower.
- The ML model is less reliable on long paths of legitimate sites, hence the trusted-domain cap.
- WHOIS lookups can fail or be rate limited.
