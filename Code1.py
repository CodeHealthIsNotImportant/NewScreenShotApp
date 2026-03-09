import pandas as pd

#print("hello")
# 1. Read CSV into dataframe
#df = pd.read_csv("CrowdStrikeEndpoints.csv")
df = pd.read_excel("CrowdStrikeEndpoints.xlsx")
# 2. Listing unique tags
unique_tags = df["Tags"].dropna().unique()
print("Unique Tags:")
print(unique_tags)

# 3. Same Site at one place
df_sorted = df.sort_values(by="Tags")

# 4. MDR sites  
MDR_Sites = {"Hollywood_Grande", "Hollywood_Volume","The_Hollywood_Roosevelt","Malibu_Beach_Inn","Rountree_Consulting","San_Ysidro_Ranch","FalconGroupingTags/San_Ysidro_Ranch","Sunset_Tower_Hotel","Sydell_Miami","The_Core_Club_Fifth"} 

# Filtering  MDR_Sites
mdr_df = df_sorted[df_sorted["Tags"].isin(MDR_Sites)]

# 5. Export to CSV
mdr_df.to_csv("MDR_endpoints_CrowdStrike.csv", index=False)

print("Filtered CSV created: MDR_endpoints_CrowdStrike.csv")

