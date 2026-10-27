import pandas as pd

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

print("Label distribution:")
print(df["label"].value_counts().sort_index())

print("\nSample URLs by label:")
for label in sorted(df["label"].unique()):
    print(f"\nLabel {label}:")
    print(df.loc[df["label"] == label, "URL"].head(5).to_string(index=False))