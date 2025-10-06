"""
# The use of conditionals
def compare(value1, value2):
    if value1 > value2:
        print(f"{value1} is greater than {value2}")

    elif value1 > value2:
        print(f"{value1} is less than {value2}")

    else:
        print("They are equal")

def equality(value1, value2):
    if value1 > value2 or  value1 < value2:
        print("they are not equal")
    else:
        print("they are equal")
    
"""

def equality(value1, value2):
    if value1 == value2:
        print("they are equal")
    else:
        print("they are not equal")

def main():
    A = int(input("Type a value: "))
    B = int(input("Type another value: "))
    equality(A, B)

main()