import pandas as pd

# Read Excel file
df = pd.read_excel("input.xlsx")


# Convert columns to proper datatype
df["CVSS Score"] = pd.to_numeric(df["CVSS Score"], errors="coerce")
df["Publish Date"] = pd.to_datetime(df["Published Date"], errors="coerce")

# Sort by highest CVSS first, then latest publish date
df_sorted = df.sort_values(
    by=["CVSS Score", "Published Date"],
    ascending=[False, False]
)

# Keep best row for each device/severity combination
final_df = df_sorted.drop_duplicates(
    subset=[
        "Site Name",
        "Device Hostname",
        "OS Version",
        "Severity"
    ],
    keep="first"
)
#		Software	Version	CVE ID	Severity	CVSS Score	Published Date	Description

# Save output to Excel
final_df.to_excel("final_filtered.xlsx", index=False)

print("Done bro, file saved as final_filtered.xlsx")
print(final_df.head())  