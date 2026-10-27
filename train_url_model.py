import re
import ipaddress
import joblib
import pandas as pd

from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


DATASET = "PhiUSIIL_Phishing_URL_Dataset.csv"


def extract_features(url):
    url = str(url).strip()
    parsed = urlparse(url if "://" in url else "http://" + url)

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

    features = {
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

    return features


print("Loading dataset...")
df = pd.read_csv(DATASET)

df = df.dropna(subset=["URL", "label"])
df = df[df["label"].isin([0, 1])].copy()

print("Dataset records:", len(df))
print("Labels:")
print(df["label"].value_counts().sort_index())

print("\nExtracting features directly from URLs...")
X = pd.DataFrame(
    [extract_features(url) for url in df["URL"]]
)
y = df["label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training model...")
model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print(
    "\nTest accuracy:",
    round(accuracy_score(y_test, predictions) * 100, 2),
    "%"
)
print("\nClassification report:")
print(classification_report(y_test, predictions))

joblib.dump(
    {
        "model": model,
        "features": list(X.columns)
    },
    "url_model.pkl"
)

print("\nNew URL model saved as url_model.pkl")