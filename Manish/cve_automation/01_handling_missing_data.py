import pandas as pd

file_path = "data.xlsx"
df = pd.read_excel(file_path)


print("Dataset Info:")
print(df.info())

print("\nMissing values per column:")
print(df.isnull().sum())


#dropping rows with any of the below mentioned values
critical_columns = ["Endpoint name", "application", "version"]
df = df.dropna(subset=critical_columns)

# Fill missing values for non-critical fields
df["manufactrurer"] = df["manufactrurer"].fillna("Unknown")
df["os"] = df["os"].fillna("Unknown OS")
df["logged in user"] = df["logged in user"].fillna("Not Assigned")
df["gender"] = df["gender"].fillna("Unknown")

# Verify missing data after cleaning
print("Missing values after cleaning:")
print(df.isnull().sum())

# Save cleaned data
df.to_excel("data_missing_fixed.xlsx", index=False)

print("\nMissing data handled successfully.")
print("Rows with missing Endpoint name OR application OR version were dropped.")
print("Cleaned file saved as data_missing_fixed.xlsx")