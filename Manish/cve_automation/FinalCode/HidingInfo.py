import pandas as pd

df=pd.read_csv('mdrdata.csv',encoding='cp1252')
# df.insert(0, "S.No", range(1, len(df) + 1))

mdr_df = df.drop(
    columns=[
        "Site Name",
        "Device Hostname",
        "Device Description",
    ]
)
print("*"*40)
print("Initial: ",mdr_df.shape)
print("Removing duplicates")
mdr_df=mdr_df.drop_duplicates(
 subset=[
        "Software",
        "Version"
    ]
)
print("Final: ",mdr_df.shape)
mdr_df.to_csv('FeedData.csv', index=False)
# private_df = pd.read_csv("private_data.csv")
# final_df = pd.merge(
#     mdr_df,
#     private_df,
#     on=["Software", "Version"],   
#     how="inner"                 
# )
# final_df.to_csv("mdrdata_with_vulnerabilities.csv", index=False)