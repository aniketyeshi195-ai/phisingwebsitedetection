import joblib
import pandas as pd
import re
import ipaddress
from urllib.parse import urlparse


def extract_features(url):
    url = str(url).strip()

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0

    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    special = sum(not c.isalnum() for c in url)

    suspicious_words = [
        "login", "verify", "account", "secure",
        "update", "password", "bank", "confirm",
        "signin", "wallet"
    ]

    return {
        "url_length": len(url),
        "domain_length": len(host),
        "is_ip": is_ip,
        "is_https": int(parsed.scheme.lower() == "https"),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "ampersand_count": url.count("&"),
        "digit_count": digits,
        "letter_count": letters,
        "digit_ratio": digits / max(len(url), 1),
        "special_ratio": special / max(len(url), 1),
        "subdomain_count": max(len(host.split(".")) - 2, 0),
        "path_length": len(path),
        "query_length": len(query),
        "percent_count": url.count("%"),
        "suspicious_word_count": sum(
            word in url.lower() for word in suspicious_words
        ),
        "double_slash_in_path": int("//" in path),
    }


saved = joblib.load("url_model.pkl")
model = saved["model"]
feature_names = saved["features"]

urls = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
]

for url in urls:
    features = extract_features(url)
    X = pd.DataFrame([features]).reindex(
        columns=feature_names,
        fill_value=0
    )

    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]

    print("\nURL:", url)
    print("Prediction:", prediction)
    print("Phishing probability:", round(probabilities[0] * 100, 2), "%")
    print("Legitimate probability:", round(probabilities[1] * 100, 2), "%")