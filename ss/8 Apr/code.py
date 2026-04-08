import pandas as pd

# read file
df = pd.read_csv("input.csv")

# convert types
df["CVSS Score"] = pd.to_numeric(df["CVSS Score"], errors="coerce")
df["Publish Date"] = pd.to_datetime(df["Publish Date"], errors="coerce")

# sort so best row comes first in each group
df_sorted = df.sort_values(
    by=["CVSS Score", "Publish Date"],
    ascending=[False, False]
)

# keep first row per group
final_df = df_sorted.drop_duplicates(
    subset=[
        "Site Name",
        "Device Hostname",
        "OS Version",
        "Severity"
    ],
    keep="first"
)

# save output
final_df.to_csv("final_filtered.csv", index=False)

print(final_df.head())