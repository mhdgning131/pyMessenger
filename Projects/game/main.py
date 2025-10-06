from package1 import Warrior, Player
# Example usage
warrior = Warrior("Aragorn", 80, 100, 3)
player = Player("player1", 80, 10)
player1 = Player("player1", 80, 10)

print(player)
print()
player.attack_warrior(warrior)
print()
print(player1)
print()
print(warrior)