import pandas as pd

# Load files
file1 = pd.read_csv("MDR_endpoints_CrowdStrike.csv")
file2 = pd.read_csv("mdrdata.csv")

# Create temporary cleaned columns for matching
file1["Tags_clean"] = file1["Tags"].str.strip().str.lower()
file1["Hostname_clean"] = file1["Hostname"].str.strip().str.lower()

file2["SiteName_clean"] = file2["Site Name"].str.strip().str.lower()
file2["DeviceHostname_clean"] = file2["Device Hostname"].str.strip().str.lower()

# Merge using cleaned columns
merged = pd.merge(
    file1,
    file2,
    left_on=["Tags_clean", "Hostname_clean"],
    right_on=["SiteName_clean", "DeviceHostname_clean"],
    how="inner"
)

# Drop temporary columns
merged = merged.drop(columns=["Tags_clean","Hostname_clean","SiteName_clean","DeviceHostname_clean"])

# Save result
merged.to_csv("Final_Endpoints2.csv", index=False)

print("Matching completed. Output saved to matched_output.csv")