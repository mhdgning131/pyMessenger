import requests


def main():
    response = requests.get("https://api.artic.edu/api/v1/artworks/search")
    content = response.json()
    for artwork in content["data"]:
        print(f"* {artwork['title']}")


main()