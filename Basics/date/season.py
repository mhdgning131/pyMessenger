from datetime import date
import inflect 
import sys
import re

p = inflect.engine()

def main():
    print(get_date(input("Date of Birth: ")))

def get_date(s):
    if matches := re.search(r"^([1-2]\d{3})-(0\d|1[0-2])-(0\d|1\d|2\d|30?1?)$", s):
        age = date.today() - date(int(matches.group(1)), int(matches.group(2)), int(matches.group(3)))
        return f"{p.number_to_words(age.days * 24 * 60, andword="").capitalize()} minutes"
    sys.exit("Invalid input")

if __name__ == "__main__":
    main()