import pandas as pd


"""# Lecture avec xpath explicite
df = pd.read_xml("https://www.w3schools.com/xml/cd_catalog.xml")

print(df)"""


"""df = pd.read_csv("https://people.sc.fsu.edu/~jburkardt/data/csv/hw_200.csv")
print(df.head())"""


df = pd.read_html("https://www.w3schools.com/html/html_tables.asp")
print(df)