import requests
#import pandas as pd  # plus pratique que csv module brut

def get_response(endpoint, params, URL):
    url = URL + endpoint
    resp = requests.get(url, params=params)
    if resp.status_code == 200:
        return resp.json()
    else:
        print("Request unsuccessful")
        return None


# Endpoint API correct
url = "https://api.coingecko.com/api/v3"

response = get_response("/simple/price", {"ids": "bitcoin,tether", "vs_currencies": "usd"}, url)
print(response)

# Parameters
"""params = {
    "ids": "bitcoin,ethereum",
    "vs_currencies": "usd"
}"""

# Request
"""resp = requests.get(url)
resp.raise_for_status()  # pour lever une erreur si problème
data = resp.json()"""


