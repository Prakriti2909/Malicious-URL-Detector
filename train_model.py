"""Train and evaluate the phishing URL classifier.

Usage:  python train_model.py

Data: public labelled URL lists (benign list + PhishTank verified-online phishing list).
They are downloaded into ./data on first run. Outputs: model.joblib, metrics.json.
"""
import json
import os
import urllib.request

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_NAMES, extract_features

BASE = "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/"
FILES = {"benign": "1.Benign_list_big_final.csv", "phish": "2.online-valid.csv"}
DATA_DIR = "data"
SAMPLE_PER_CLASS = 10000
SEED = 42


def download(name):
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        print(f"Downloading {name} ...")
        urllib.request.urlretrieve(BASE + name, path)
    return path


TOP_DOMAINS_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains"
TOP_DOMAINS_FILE = "top-1000000-domains.txt"
TOP_N = 100000          # only use the 100k most popular domains as "benign"
HTTPS_RATE = 0.47       # match the phishing set's HTTPS rate so the scheme is not a shortcut


def _rescheme(url, rng, https_rate=HTTPS_RATE):
    """Replace the scheme with a random one (removes the dataset's scheme bias)."""
    rest = url.split("://", 1)[-1]
    return ("https://" if rng.random() < https_rate else "http://") + rest


def build_benign(n, rng):
    """Benign class = half real benign-list URLs, half top-ranked domain URLs.

    The raw benign list is almost all long deep-path HTTP URLs, so a model trained on it
    learns 'short URL / bare domain = phishing'. Mixing in homepage-style URLs of top
    domains and equalising the scheme rate removes that shortcut.
    """
    import random
    rnd = random.Random(rng)
    benign_list = pd.read_csv(download(FILES["benign"]), header=None, names=["url"])["url"].dropna().drop_duplicates()
    benign_list = benign_list.sample(n // 2, random_state=rng).tolist()
    benign_list = [_rescheme(u, rnd) for u in benign_list]

    if not os.path.exists(os.path.join(DATA_DIR, TOP_DOMAINS_FILE)):
        os.makedirs(DATA_DIR, exist_ok=True)
        print("Downloading top-domain list ...")
        urllib.request.urlretrieve(TOP_DOMAINS_URL, os.path.join(DATA_DIR, TOP_DOMAINS_FILE))
    with open(os.path.join(DATA_DIR, TOP_DOMAINS_FILE)) as f:
        domains = [line.strip() for line in f.readlines()[:TOP_N] if line.strip()]
    domains = rnd.sample(domains, n - len(benign_list))

    # real paths (host stripped) borrowed from the benign list, for non-homepage URLs
    paths = [u.split("://", 1)[-1].split("/", 1)[-1] for u in benign_list if "/" in u.split("://", 1)[-1]]
    top_urls = []
    for d in domains:
        host = ("www." if rnd.random() < 0.5 else "") + d
        path = "" if rnd.random() < 0.4 else "/" + rnd.choice(paths)
        top_urls.append(_rescheme("x://" + host + (path or "/"), rnd))
    return benign_list + top_urls


def load_urls():
    phish = pd.read_csv(download(FILES["phish"]))["url"].dropna().drop_duplicates()
    phish = phish.sample(min(SAMPLE_PER_CLASS, len(phish)), random_state=SEED)
    benign = build_benign(SAMPLE_PER_CLASS, SEED)
    df = pd.concat([
        pd.DataFrame({"url": benign, "label": 0}),
        pd.DataFrame({"url": phish, "label": 1}),
    ], ignore_index=True)
    return df.sample(frac=1, random_state=SEED).reset_index(drop=True)


def main():
    df = load_urls()
    print(f"Dataset: {len(df)} URLs ({(df.label == 1).sum()} phishing, {(df.label == 0).sum()} benign)")
    X = pd.DataFrame([extract_features(u) for u in df.url], columns=FEATURE_NAMES)
    y = df.label
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)

    candidates = {
        "Random Forest": RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000)),
    }

    results, fitted = {}, {}
    for name, model in candidates.items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        results[name] = {
            "accuracy": accuracy_score(y_test, pred),
            "precision": precision_score(y_test, pred),
            "recall": recall_score(y_test, pred),
            "f1": f1_score(y_test, pred),
            "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        }
        fitted[name] = model
        print(f"{name}: " + ", ".join(f"{k}={v:.4f}" for k, v in results[name].items() if k != "confusion_matrix"))

    best = max(results, key=lambda k: results[k]["f1"])
    print(f"Selected model: {best}")

    importances = []
    if best == "Random Forest":
        importances = sorted(zip(FEATURE_NAMES, fitted[best].feature_importances_), key=lambda t: -t[1])
        importances = [(n, float(v)) for n, v in importances[:10]]

    joblib.dump({"model": fitted[best], "feature_names": FEATURE_NAMES, "model_name": best}, "model.joblib", compress=3)
    with open("metrics.json", "w") as f:
        json.dump({
            "selected_model": best,
            "dataset_size": int(len(df)),
            "train_size": int(len(X_train)),
            "test_size": int(len(X_test)),
            "results": results,
            "top_features": importances,
        }, f, indent=2)
    print("Saved model.joblib and metrics.json")


if __name__ == "__main__":
    main()
