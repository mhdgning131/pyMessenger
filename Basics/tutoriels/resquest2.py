import requests

url = "https://quotes.toscrape.com"

response = requests.get(url)
print(response.status_code)
print(response.headers["Content-Type"])
print(response.json())