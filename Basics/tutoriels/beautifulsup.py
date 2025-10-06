import requests
from bs4 import BeautifulSoup

xml_data = requests.get("https://www.w3schools.com/xml/note.xml")

# Parse the XML content with BeautifulSoup
soup = BeautifulSoup(xml_data.content, "xml")

# Display the formatted XML structure
print(soup.find("from").text)



