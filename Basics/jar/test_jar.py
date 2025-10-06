import pytest
from jar import Jar

def test_init():
    jar = Jar()
    assert jar.capacity == 12
    assert jar.size == 0

    jar2 = Jar(5)
    assert jar2.capacity == 5
    assert jar2.size == 0

def test_str():
    jar = Jar()
    assert str(jar) == ""
    jar.deposit(1)
    assert str(jar) == "🍪"
    jar.deposit(11)
    assert str(jar) == "🍪" * 12

def test_deposit():
    jar = Jar(3)
    jar.deposit(1)
    assert jar.size == 1
    jar.deposit(2)
    assert jar.size == 3
    with pytest.raises(ValueError):
        jar.deposit(1)  # Exceeds capacity

def test_withdraw():
    jar = Jar(5)
    jar.deposit(5)
    jar.withdraw(2)
    assert jar.size == 3
    jar.withdraw(3)
    assert jar.size == 0
    with pytest.raises(ValueError):
        jar.withdraw(1)  # Not enough cookies

def test_deposit_zero_negative():
    jar = Jar()
    with pytest.raises(ValueError):
        jar.deposit(13)  # Exceeds default capacity

def test_withdraw_zero_negative():
    jar = Jar()
    with pytest.raises(ValueError):
        jar.withdraw(1)  # Withdraw from empty jar

def test_capacity_property():
    jar = Jar(7)
    assert jar.capacity == 7

def test_size_property():
    jar = Jar()
    assert jar.size == 0
    jar.deposit(5)
    assert jar.size == 5