# Définition de la classe de base "batiment"
class batiment:
    def __init__(self, nom, adresse, etage):
        # Initialisation des attributs de base
        self.nom = nom
        self.adresse = adresse
        self.etage = etage

    # Accesseur pour le nom
    def get_nom(self):
        return self.nom

    # Accesseur pour l'adresse
    def get_adresse(self):
        return self.adresse

    # Accesseur pour le nombre d'étages
    def get_etage(self):
        return self.etage

    # Mutateur (setter) pour changer le nom
    def changement_nom(self, nouveau_nom):
        self.nom = nouveau_nom

    # Mutateur pour changer l'adresse
    def changement_adresse(self, nouveau_adresse):
        self.adresse = nouveau_adresse

    # Mutateur pour changer le nombre d'étages
    def changement_etage(self, nouveau_etage):
        self.etage = nouveau_etage

    # Affichage des informations de base d’un bâtiment
    def __str__(self):
        return f"Nom_batiment: {self.nom}\nAdresse: {self.adresse}\nEtage: {self.etage}"


# Classe "immeuble" qui hérite de "batiment"
class immeuble(batiment):
    def __init__(self, nom, adresse, etage, nbre_appartement):
        # Appel du constructeur parent
        super().__init__(nom, adresse, etage)
        self.nbre_appartement = nbre_appartement

    # Accesseur pour le nombre d'appartements
    def get_nbre_appartement(self):
        return self.nbre_appartement

    # Mutateur pour modifier le nombre d'appartements
    def change_nbre_appartement(self, nouveaux_apparts):
        self.nbre_appartement = nouveaux_apparts

    # Mutateurs spécifiques à l’immeuble (duplicata des méthodes de base)
    def change_nom_immeuble(self, nouveau_nom):
        self.nom = nouveau_nom

    def change_adresse_immeuble(self, nouveau_adresse):
        self.adresse = nouveau_adresse

    def change__nbre_etage_immeuble(self, nouveau_etage):
        self.etage = nouveau_etage

    # Redéfinition de __str__ pour afficher aussi les appartements
    def __str__(self):
        return f"---->Immeuble-_-:\n{super().__str__()}\nNombre d'appartement: {self.nbre_appartement}"


# Classe "supermarche" qui hérite aussi de "batiment"
class supermarche(batiment):
    def __init__(self, nom, adresse, etage, nbre_rayon):
        super().__init__(nom, adresse, etage)
        self.nbre_rayon = nbre_rayon

    def get_nbre_rayon(self):
        return self.nbre_rayon

    def change_nbre_rayon(self, nouveaux_rayons):
        self.nbre_rayon = nouveaux_rayons

    def change_nom_supermarche(self, nouveau_nom):
        self.nom = nouveau_nom

    def change_adresse_supermarche(self, nouveau_adresse):
        self.adresse = nouveau_adresse

    def change__nbre_etage_supermarche(self, nouveau_etage):
        self.etage = nouveau_etage

    def __str__(self):
        return f"----->Supermarche-_-:\n{super().__str__()}\nNombre de rayon: {self.nbre_rayon}"


# Classe "banque" qui hérite également de "batiment"
class banque(batiment):
    def __init__(self, nom, adresse, etage, nbre_coffre):
        super().__init__(nom, adresse, etage)
        self.nbre_coffre = nbre_coffre

    def get_nbre_coffre(self):
        return self.nbre_coffre

    def change_nbre_coffre(self, nouveaux_coffres):
        self.nbre_coffre = nouveaux_coffres

    def change_nom_banque(self, nouveau_nom):
        self.nom = nouveau_nom

    def change_adresse_banque(self, nouveau_adresse):
        self.adresse = nouveau_adresse

    def change__nbre_etage_banque(self, nouveau_etage):
        self.etage = nouveau_etage

    def __str__(self):
        return f"--->Banque -_-:\n{super().__str__()}\nNombre de coffre: {self.nbre_coffre}"