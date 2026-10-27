import pandas as pd

file_path = "PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(file_path, nrows=10)

print("All column names:")
for column in df.columns:
    print(repr(column))

print("\nLabel column exists:", "label" in df.columns)

if "label" in df.columns:
    print("\nLabel values:")
    print(df["label"].value_counts())