import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

DATASET = "PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")
df = pd.read_csv(DATASET)

print("Dataset shape:", df.shape)
print("\nClass distribution:")
print(df["label"].value_counts())

# Numeric features only; exclude identifiers and target
X = df.drop(columns=["FILENAME", "URL", "Domain", "TLD", "Title", "label"])
X = X.select_dtypes(include=["number"])

y = df["label"]

# Replace missing/infinite values if present
X = X.replace([float("inf"), float("-inf")], float("nan"))
X = X.fillna(X.median())

print("\nFeatures used:", len(X.columns))
print("Splitting data...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training model...")
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\nTest accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("\nClassification report:")
print(classification_report(y_test, predictions))

joblib.dump(
    {"model": model, "features": list(X.columns)},
    "model.pkl"
)

print("\nModel saved as model.pkl")