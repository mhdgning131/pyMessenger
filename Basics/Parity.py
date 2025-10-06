"""
x = int(input("What's x? "))

if x % 2 == 0:
     print("Even")
else: 
    print("Odd")
"""

"""
# Better version of the same programme
def is_even(n):
    if n % 2 == 0:
        return True
    else:
        return False
"""

# Or we can do it in a Pythonique way
def is_even(n):
    return True if n % 2 == 0 else False # Or " return n % 2 == 0

def main():
    x = int(input("What's x? "))
    if is_even(x):
        print("Even")
    else:
        print("Odd")

main()