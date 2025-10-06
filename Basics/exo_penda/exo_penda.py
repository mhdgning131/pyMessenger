try:
    number = int(input("Entrer un nombre: "))
    if number < 0: 
        raise ValueError("entrer un nombre positif")
    print(f"Le double de {number} est {number*2}")
except ValueError as e:
    if str(e) == "entrer un nombre positif":
        print(f"Error: {e}")
    else:
        print("Invalid input")
finally:
    print("Fin du programme")