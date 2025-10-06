import pytest
from package1 import Player, Warrior

def test_player_init_and_str():
    p = Player("Alice", 100, 20)
    assert p.username == "Alice"
    assert p.health == 100
    assert p.attack == 20
    assert str(p) == "Player: Alice\nHealth: 100\nAttack: 20"

def test_player_getters():
    p = Player("Bob", 80, 15)
    assert p.get_username() == "Bob"
    assert p.get_health() == 80
    assert p.get_attack() == 15

def test_player_setters():
    p = Player("Carol", 50, 10)
    p.set_health(40)
    assert p.health == 40
    
def test_player_setters_invalid():
    p = Player("Dave", 60, 12)
    with pytest.raises(TypeError):
        p.set_health("bad")
    with pytest.raises(ValueError):
        p.set_health(-1)

def test_warrior_init_and_str():
    w = Warrior("Eve", 120, 30, 5)
    assert w.username == "Eve"
    assert w.health == 120
    assert w.attack == 30
    assert w.shield == 5
    assert "Shield: 5" in str(w)

def test_warrior_getters():
    w = Warrior("Frank", 90, 22, 3)
    assert w.get_username() == "Frank"
    assert w.get_health() == 90
    assert w.get_attack() == 22
    assert w.get_shield_point() == 3

def test_warrior_set_shield():
    w = Warrior("Grace", 100, 20, 2)
    w.set_shield(10)
    assert w.shield == 10

def test_warrior_set_shield_invalid():
    w = Warrior("Heidi", 100, 20, 2)
    with pytest.raises(TypeError):
        w.set_shield("bad")
    with pytest.raises(ValueError):
        w.set_shield(-1)

def test_warrior_damage_warrior_with_shield():
    w = Warrior("Ivan", 50, 10, 2)
    w.damage_warrior(5)
    assert w.shield == 1
    assert w.health == 50  # shield absorbs damage

def test_warrior_damage_warrior_no_shield():
    w = Warrior("Judy", 50, 10, 0)
    w.damage_warrior(5)
    assert w.shield == 0
    assert w.health == 45

def test_warrior_damage_warrior_invalid():
    w = Warrior("Ken", 50, 10, 1)
    with pytest.raises(TypeError):
        w.damage_warrior("bad")
    with pytest.raises(ValueError):
        w.damage_warrior(0)
    with pytest.raises(ValueError):
        w.damage_warrior(-3)

def test_warrior_attack_warrior():
    w1 = Warrior("Leo", 40, 10, 1)
    w2 = Warrior("Mia", 30, 5, 0)
    w1.attack_warrior(w2)
    assert w2.health == 20  # Mia had no shield, so health reduced by 10

def test_warrior_attack_warrior_with_shield():
    w1 = Warrior("Nina", 40, 10, 1)
    w2 = Warrior("Oscar", 30, 5, 2)
    w1.attack_warrior(w2)
    assert w2.shield == 1  # shield absorbs attack
    assert w2.health == 30

def test_warrior_attack_warrior_invalid():
    w = Warrior("Paul", 40, 10, 1)
    with pytest.raises(TypeError):
        w.attack_warrior("not_a_warrior")