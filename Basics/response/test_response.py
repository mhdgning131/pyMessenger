from response import validate

def test_valide():
    assert(validate("username@gmail.com")) == "Valid"
    assert(validate("momo@outlook.com")) == "Valid"
    assert(validate("mimo@unchk.edu.sn")) == "Valid"

def test_invalid():
    assert(validate("username@gmailcom")) == "Invalid"
    assert(validate("usernamegmail.com")) == "Invalid"
    assert(validate("usernamegmailcom")) == "Invalid"
    assert(validate("@")) == "Invalid"
    assert(validate("username")) == "Invalid"
    assert(validate("9")) == "Invalid"