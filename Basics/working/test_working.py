import pytest
from working import convert

def test_convert_basic():
    assert convert("9 AM to 5 PM") == "09:00 to 17:00"
    assert convert("12 PM to 12 AM") == "12:00 to 00:00"
    assert convert("1 PM to 3 PM") == "13:00 to 15:00"
    assert convert("12 AM to 12 PM") == "00:00 to 12:00"

def test_convert_with_minutes():
    assert convert("9:30 AM to 5:15 PM") == "09:30 to 17:15"
    assert convert("12:01 AM to 12:59 PM") == "00:01 to 12:59"
    assert convert("11:59 PM to 12:01 AM") == "23:59 to 00:01"

def test_convert_invalid_format():
    with pytest.raises(ValueError):
        convert("9AM-5PM")
    with pytest.raises(ValueError):
        convert("09:00 to 17:00")
    with pytest.raises(ValueError):
        convert("13 PM to 2 PM")
    with pytest.raises(ValueError):
        convert("9:60 AM to 5:00 PM")
    with pytest.raises(ValueError):
        convert("9:00 XM to 5:00 PM")
    with pytest.raises(ValueError):
        convert("")

def test_convert_edge_cases():
    assert convert("12 AM to 1 AM") == "00:00 to 01:00"
    assert convert("12 PM to 1 PM") == "12:00 to 13:00"
    assert convert("11 AM to 12 PM") == "11:00 to 12:00"
    assert convert("11 PM to 12 AM") == "23:00 to 00:00"