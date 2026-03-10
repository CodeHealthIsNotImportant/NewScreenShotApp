import pandas as pd

df = pd.read_csv("./data.csv", encoding="cp1252")

mdrSites = {
    'Hollywood Grande (Formerly: Thompson)',
    'The Core Club Fifth Ave, Inc.',
    'San Ysidro Ranch',
    'Hollywood Volume (Formerly: Tommie)',
    'Rountree Consulting',
    'Sydell Group - Miami',
    'Malibu Beach Inn',
    'Sunset Tower Hotel',
    'Sydell Group - UK'
}

# Filter rows where Site Name is in mdrSites
mdr_df = df[df["Site Name"].isin(mdrSites)]

mdr_df.to_csv('newdata.csv',index=False)
print(mdr_df.head())
print(mdr_df.shape)