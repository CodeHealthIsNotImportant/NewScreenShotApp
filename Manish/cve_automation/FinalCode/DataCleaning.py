import pandas as pd
#df=pd.read_csv("data.csv",encoding="cp1252")
df=pd.read_excel('data.xlsx')
#getting the detaiails of data 
print("-"*60)
print("The head")
print(df.head())
print("The columns of the data")
print(df.columns)
print("the information of the data")
df.info()
print("Describing the data")
print(df.describe())
print("-"*60)

#Removing the missing elements
print("Removing the missing elements")
initialRows=df.shape[0]
df.dropna(subset=["Software","Version"],inplace=True)
finalRows=df.shape[0]
print("Initial Rows: ",initialRows," Final rows: ",finalRows)
print("-"*60)

#Setting the data 
print("Setting the data")
df = df.sort_values(by="Site Name").reset_index(drop=True)
print("-"*60)

#Removing the duplicates
print("Removing the duplicates")
distinct_rows=df.drop_duplicates(
    subset=[
        "Site Name",
        "Device Hostname",
        "Device Description",
        "Software",
        "Version"
    ]
)
print("Initial: ", df.shape[0])
print("Final:  " ,distinct_rows.shape[0])

print("-"*60)
#Filtering mdr sites
mdrSites = {
    'Hollywood Grande (Formerly: Thompson)',
    'The Core Club Fifth Ave, Inc.',
    'San Ysidro Ranch',
    'Hollywood Volume (Formerly: Tommie)',
    'Rountree Consulting',
    'Sydell Group - Miami',
    'Malibu Beach Inn',
    'Sunset Tower Hotel',
    'The Hollywood Roosevelt'
}
mdr_df=distinct_rows[distinct_rows["Site Name"].isin(mdrSites)]
print("-"*60)
#Converting to CSV
print("MDR sites Filtered")
mdr_df.to_csv('mdrdata.csv',index=False)
print(f"Exported {mdr_df.shape[0]} rows to mdrdata.csv")
print("-"*60)

