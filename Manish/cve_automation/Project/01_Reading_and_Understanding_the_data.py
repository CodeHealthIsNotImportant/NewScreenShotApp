import pandas as pd
df=pd.read_csv("./data.csv",encoding="cp1252")
# #print(pd.__version__)
print(df.head())
print(df.info())
print(df.columns)
# # for col in df.columns:
# #     print(type(col))
print(df.describe())

print("*"*40)

# result1=df.groupby("Site Name")
# #print(result1)
# # for x,y in result1:
# #     print("printing x")
# #     print(x)
# #     print("printing y")
# #     print(y)
# #     print()


# #result1.getgroup("give your name")
# #result1.min()

# mdrSites=set()

# print("Inside the loop")
# for sitename,temp in  result1:
#     #mdrSites.add(row[])
#     #for row
#     #print(row.info())
#     #print(type(row))
#     #break
#     mdrSites.add(sitename)

# print(sorted(mdrSites))
# #print(len(mdrSites))

# mdrSites={'Hollywood Grande (Formerly: Thompson)','The Core Club Fifth Ave, Inc.','San Ysidro Ranch','Hollywood Volume (Formerly: Tommie)','Rountree Consulting','Sydell Group - Miami','Malibu Beach Inn','Sunset Tower Hotel','Sydell Group - UK'}



# import pandas as pd

# df = pd.read_csv("./data.csv", encoding="cp1252")

# mdrSites = {
#     'Hollywood Grande (Formerly: Thompson)',
#     'The Core Club Fifth Ave, Inc.',
#     'San Ysidro Ranch',
#     'Hollywood Volume (Formerly: Tommie)',
#     'Rountree Consulting',
#     'Sydell Group - Miami',
#     'Malibu Beach Inn',
#     'Sunset Tower Hotel',
#     'Sydell Group - UK'
# }

# # Filter rows where Site Name is in mdrSites
# mdr_df = df[df["Site Name"].isin(mdrSites)]

# print(mdr_df.head())
# print(mdr_df.shape)



df_clean = (
    df
    .dropna(subset=["Software", "Version"])
    .loc[
        (df["Software"].str.strip() != "") &
        (df["Version"].str.strip() != "")
    ]
)

print(df_clean.info())

print("Original rows:", df.shape[0])
print("After cleaning:", df_clean.shape[0])
#result1=df.groupby("Site Name")
df_clean.to_csv("cleaneddata.csv", index=False)

site_groups_data = df_clean.groupby("Site Name")
#site_groups_data.to_csv('groupeddata.csv',index=False)

