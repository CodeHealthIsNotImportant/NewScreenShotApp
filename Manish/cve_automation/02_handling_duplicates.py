import pandas as pd

df = pd.read_excel("data_missing_fixed.xlsx")

# Columns that define uniqueness
duplicate_columns = [
    "Endpoint name",
    "logged in user",
    "application",
    "version"
]

# Identifying duplicate rows
duplicates = df[df.duplicated(subset=duplicate_columns, keep="first")]

# Remove duplicates
df_deduplicated = df.drop_duplicates(
    subset=duplicate_columns,
    keep="first"
)

# Save removed duplicates for audit
duplicates.to_excel("removed_duplicates.xlsx", index=False)

# Save final deduplicated data
df_deduplicated.to_excel("data_deduplicated.xlsx", index=False)

# Output stats
print(f"Total rows before deduplication: {len(df)}")
print(f"Duplicate rows removed: {len(duplicates)}")
print(f"Rows after deduplication: {len(df_deduplicated)}")

print("\nDeduplication completed successfully.")
print("Files created:")
print("- data_deduplicated.xlsx")
print("- removed_duplicates.xlsx")
