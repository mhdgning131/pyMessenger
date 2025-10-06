from bs4 import BeautifulSoup

with open("index.html", "r", encoding="utf-8") as file:
    soup = BeautifulSoup(file, 'html.parser')
    print(soup.find("title").text.strip())
    print(soup.find(id="titre").text.strip())

    produits = []
    produits_html = soup.select("li.product")

    for produit in produits_html:
        nom = produit.find("h2").text.strip()
        paragraphes = produit.find_all("p")
        prix = (paragraphes[0].text.strip()) if len(paragraphes) > 0 else "Prix non trouvé"
        description = paragraphes[1].text.strip() if len(paragraphes) > 1 else "Description non trouvée"
        
        produits.append({
            "nom": nom,
            "prix": prix.replace("Prix: ", "").replace("€", ""),
            "description": description
        })

    for produit in produits:
        prix = int(produit["prix"]) * 1.2
        produit["prix"] = f"{prix}$"

        print()
        print(f'Nom: {produit["nom"]}')
        print(f'Prix: {produit["prix"]}')
        print(f'Description: {produit["description"]}')
        


    