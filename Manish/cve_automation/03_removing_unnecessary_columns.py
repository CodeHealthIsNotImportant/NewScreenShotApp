import pandas as pd

df = pd.read_excel("data_deduplicated.xlsx")

df = df.drop(columns=["gender"])


df.to_excel("data_impportant_columns.xlsx", index=False)

print("Column 'gender' removed successfully.")
print("Final cleaned file saved as data_final.xlsx")