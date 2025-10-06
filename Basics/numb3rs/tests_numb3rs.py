from numb3rs import validate

def test_ip():
    assert validate("192.168.1.1")
    assert validate("1.1.1.1")

def test_false_ip():
    assert not validate("274.76.12.13")
    assert not validate("27.476.12.13")
    assert not validate("256.256.256.256")
    assert not validate("123.456.78.90")
    assert not validate("192.168.1")
    assert not validate("192.168.1.1.1")

def test_str():
    assert not validate("cat.dog.bird.fish")
    assert not validate("hello.world.1.1")