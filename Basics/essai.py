import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import linregress

# --- Données ---
X = np.array([3, 4, 6, 7, 9, 10, 9, 11, 12, 13, 15, 4])
Y = np.array([8, 9, 10, 13, 15, 14, 13, 16, 13, 19, 6, 19])

# --- Étape 1 : Nuage de points ---
plt.scatter(X, Y, color='blue', label='Données originales')
plt.xlabel('Algèbre linéaire (X)')
plt.ylabel('Analyse de données (Y)')
plt.title('Nuage de points')
plt.grid(True)
plt.show()

# --- Étape 2 : Régression linéaire complète ---
slope, intercept, r_value, p_value, std_err = linregress(X, Y)
print("Régression complète :")
print(f"y = {intercept:.2f} + {slope:.2f}x")
print(f"Coefficient de corrélation r = {r_value:.3f}")
print(f"Coefficient de détermination R^2 = {r_value**2:.3f}")

# Tracé de la droite sur le nuage
plt.scatter(X, Y, color='blue', label='Données originales')
plt.plot(X, intercept + slope*X, color='red', label='Droite de régression')
plt.xlabel('Algèbre linéaire (X)')
plt.ylabel('Analyse de données (Y)')
plt.title('Régression avec tous les points')
plt.legend()
plt.grid(True)
plt.show()

# --- Étape 3 : Supprimer points atypiques ---
mask = ~((X == 15) & (Y == 6)) & ~((X == 4) & (Y == 19))
X_clean = X[mask]
Y_clean = Y[mask]

slope_clean, intercept_clean, r_value_clean, _, _ = linregress(X_clean, Y_clean)
print("\nRégression sans points atypiques :")
print(f"y = {intercept_clean:.2f} + {slope_clean:.2f}x")
print(f"Coefficient de corrélation r = {r_value_clean:.3f}")
print(f"Coefficient de détermination R^2 = {r_value_clean**2:.3f}")

# Tracé nuage et droite sans points atypiques
plt.scatter(X_clean, Y_clean, color='green', label='Données sans atypiques')
plt.plot(X_clean, intercept_clean + slope_clean*X_clean, color='red', label='Droite de régression')
plt.xlabel('Algèbre linéaire (X)')
plt.ylabel('Analyse de données (Y)')
plt.title('Régression sans points atypiques')
plt.legend()
plt.grid(True)
plt.show()
