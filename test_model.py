import joblib

data = joblib.load("model.pkl")

model = data["model"]
features = data["features"]

print("Model loaded successfully!")
print("Number of features:", len(features))
print("Features:", features)

print("\nModel classes:", model.classes_)