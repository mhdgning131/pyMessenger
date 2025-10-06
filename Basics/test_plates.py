# Python
from plates import is_valid


def test_valid_basic():
    assert is_valid("CS") is True           # minimum length, letters only
    assert is_valid("HELLO") is True        # letters only
    assert is_valid("CS50") is True         # numbers at the end, first number not 0
    assert is_valid("AB123") is True        # numbers at the end
    assert is_valid("ABCDE1") is True       # max length with one trailing digit
    assert is_valid("AbCdE9") is True       # mixed case allowed
    assert is_valid("AAA222") is True       # all numbers at end


def test_length_constraints():
    assert is_valid("A") is False           # too short
    assert is_valid("ABCDEFG") is False     # too long


def test_first_two_letters():
    assert is_valid("1ABCDE") is False
    assert is_valid("A1BCDE") is False
    assert is_valid("-ABCDE") is False
    assert is_valid("C5") is False          # second char not a letter


def test_alphanumeric_only():
    # Disallowed punctuation/space
    assert is_valid("AB.CD") is False
    assert is_valid("AB,CD") is False
    assert is_valid("AB;CD") is False
    assert is_valid("AB:CD") is False
    assert is_valid("AB?CD") is False
    assert is_valid("AB!CD") is False
    assert is_valid("AB CD") is False


def test_numbers_only_at_end():
    assert is_valid("CS50P") is False
    assert is_valid("AB1CDE") is False
    assert is_valid("A2B3") is False
    assert is_valid("AAA22A") is False      # letter after number


def test_no_leading_zero_in_numbers():
    assert is_valid("AB0") is False
    assert is_valid("XY01") is False        # first digit is 0 even with more digits after
    assert is_valid("AB000") is False
    assert is_valid("AB0001") is False      # first digit in the numeric part is 0


def test_return_type_is_bool():
    assert isinstance(is_valid("CS50"), bool)
    assert isinstance(is_valid("A"), bool)