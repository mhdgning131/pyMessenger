import pytest
from um import count

@pytest.mark.parametrize("text, expected", [
    ("um", 1),
    ("Um", 1),
    ("UM", 1),
    ("hello um world", 1),
    ("um um", 2),
    ("um? um! um.", 3),
    ("yummy", 0),
    ("album", 0),
    ("um, um, um", 3),
    ("Um, I think, um, you know, um...", 3),
    ("The word 'um' is common.", 1),
    ("umbrella", 0),
    ("Umbridge", 0),
    ("um um um um", 4),
    ("", 0),
    ("um-um", 2),
    ("um's", 1),
    ("um um? um! um.", 4),
    ("Um... um... um...", 3),
])
def test_count(text, expected):
    assert count(text) == expected