import csv

import requests
from bs4 import BeautifulSoup
import json

"""response = requests.get("https://wttr.in/Dakar?format=j1")
r = dict(response.json())
weather = r["current_condition"][0]
print(weather)
with open("weather.csv", "w") as file:
    fields = ["temp_C", "feelslike_C", "windspeedKmph", "weatherDesc", 'visibility', 'observation_time', 'precipInches', 'winddir16Point', 'precipMM', 'weatherCode', 'winddirDegree', 'humidity', 'uvIndex', 'weatherIconUrl', 'visibilityMiles', 'cloudcover', 'windspeedMiles', 'FeelsLikeC', 'localObsDateTime', 'pressureInches', 'temp_F', 'pressure', 'FeelsLikeF']
    writer = csv.DictWriter(file, fieldnames=fields)
    csv.DictWriter.writeheader(writer)
    writer.writerow(weather)"""

"""response = requests.get("https://api.github.com/users/ghost775-art")
data = dict(response.json())

with open("octocat.json", "w") as file:
    json.dump(data, file, indent=4)
"""

response = requests.get("https://quotes.toscrape.com/")
with open("quotes.html", "w", encoding="utf-8") as f:
    f.write(response.text)