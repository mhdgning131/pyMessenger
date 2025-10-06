from .player import Player


class Warrior(Player):
    def __init__(self, username, health, attack, shield):
        super().__init__(username, health, attack)
        self.shield = int(shield)

    def __str__(self):
        return f"{super().__str__()} \nShield: {self.shield}"
    
    def get_attack(self):
        return super().get_attack()
    
    def get_health(self):
        return super().get_health()
    
    def get_username(self):
        return super().get_username()

    def get_shield_point(self):
        return self.shield
    
    def set_shield(self, points):
        if not isinstance(points, int):
            raise TypeError("Shield points should be integer")
        elif points < 0:
            raise ValueError("Shield points should be (>= 0) a non-negative integer")
        self.shield = points

    def damage_warrior(self, damage):
        if not isinstance(damage, int):
            raise TypeError("Damage should be integer")
        elif damage <= 0:
            raise ValueError("Damage should be (> 0) a positive integer")
        
        if self.shield > 0:
            self.shield -= 1
            damage = 0
        self.health -= damage

        if self.health < 0:
            self.health = 0

    def attack_warrior(self, target_warrior):
        if not isinstance(target_warrior, Warrior):
            raise TypeError("target_warrior should be Warrior")
        target_warrior.damage_warrior(self.attack) 
     
    