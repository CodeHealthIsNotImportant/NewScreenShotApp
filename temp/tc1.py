import pandas as pd

# Load the two CSV files
df1 = pd.read_csv("sheet1.csv")
df2 = pd.read_csv("sheet2.csv")

# Normalize column names (optional but recommended)
df1.columns = df1.columns.str.strip()
df2.columns = df2.columns.str.strip()

# Rename columns if needed (make sure both have same column name)
# Example: if one file has 'MAC Address' and other 'Mac Address'
df1 = df1.rename(columns={"MAC Address": "MAC"})
df2 = df2.rename(columns={"MAC Address": "MAC"})

# Perform inner join on MAC
result = pd.merge(df1, df2, on="MAC", how="inner")

# Save result to new CSV
result.to_csv("matched_mac_addresses.csv", index=False)

print("Done! Matching MAC addresses saved to matched_mac_addresses.csv")