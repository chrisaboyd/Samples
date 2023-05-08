import pandas as pd

csv_path = "/Users/christopherboyd/gitrepos/Samples/file.csv"
df = pd.read_csv(csv_path)
#print(df)

for index,row in df.iterrows():
    print (row['col1'] * row['col2'])

#   col1  col2
#0     2     4
#1     6     8
