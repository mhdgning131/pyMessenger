class Player():
    def __init__(self, username, health, attack):
        self.username = str(username)
        self.health = int(health)
        self.attack = int(attack)

    def __str__(self):
        return f"Player: {self.username}\nHealth: {self.health}\nAttack: {self.attack}"
    
    # defining getters
    def get_username(self):
        return self.username

    def get_health(self):
        return self.health

    def get_attack(self):
        return self.attack
    
    # defining setters
    def set_username(self, name):
        self.username = str(name)

    def set_health(self, health):
        if not isinstance(health, int):
            raise TypeError("Health should be an int") 
        if health < 0:
                raise ValueError("Health should be positive")
        self.health = int(health)
    
    def damage(self, damage):
        try:
            damage = int(damage)
            if damage < 0:
                raise ValueError("Damage should be positive")
            
            if damage > self.health:
                print(f"-{damage}")
                self.health = 0
            else:
                print(f"-{damage}")
                self.health -= damage
        except ValueError:
            raise ValueError("Damage should be a positive integer")
        except TypeError:
            raise TypeError("Damage should be an integer")
        
    def attack_player(self, target_player):
        if not isinstance(target_player, Player):
            raise TypeError("Damage should be a Player")
        target_player.damage(self.attack)
        
    def attack_warrior(self, target_warrior):
        target_warrior.damage_warrior(self.attack)
