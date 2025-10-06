# ask user for their name 
name = input("What is your name? ")

"""
# Remove whitespace from str
name = name.strip()

# Capitalize the first letter of the user's input
# we can use title() that do the same thing on each word 
name = name.capitalize()

"""

#we improve the line 6 and 10 by doing on the same line
name = name.strip().title()

#Split user's name into first name and last name
first, middle, last = name.split(" ")

# say hello to user
print(f"hello, {first}")