import pandas as pd

# Load files
file1 = pd.read_csv("MDR_endpoints_CrowdStrike.csv")
file2 = pd.read_csv("mdrdata.csv")

# Clean text to avoid mismatch issues
file1["Tags"] = file1["Tags"].str.strip().str.lower()
file1["Hostname"] = file1["Hostname"].str.strip().str.lower()

file2["Site Name"] = file2["Site Name"].str.strip().str.lower()
file2["Device Hostname"] = file2["Device Hostname"].str.strip().str.lower()

# Merge based on conditions
merged = pd.merge(
    file1,
    file2,
    left_on=["Tags", "Hostname"],
    right_on=["Site Name", "Device Hostname"],
    how="inner"
)

# Save output
merged.to_csv("matched_output.csv", index=False)

print("Matching completed. Output saved to matched_output.csv")