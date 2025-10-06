import re

pattern = r"[\w\.-]+@[\w\.]+\w+\.\w+"
email = input("Enter your email: ")

if re.fullmatch(pattern, email, re.IGNORECASE):
    print("Valid")
else:
    print("Invalid")
