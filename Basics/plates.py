def main():
    plate = input("Plate: ")
    print(is_valid(plate))


def is_valid(s):
    invalid_characters = "., ;:?!"
    for letter in s:
        if letter in invalid_characters:
            return "Invalid"
    if len(s) < 2 or len(s) > 6:
        return "Invalid"

    if not (s[:2].isalpha()):
        return "Invalid"
    # Ensure numbers appear only at the end
    has_number = False
    for i, letter in enumerate(s):
        if letter.isdigit():
            if letter == '0' and not has_number:  # The first number must not be '0'
                return "Invalid"
            has_number = True
        elif has_number:  # If a letter appears after a number, it's invalid
            return "Invalid"

    return "Valid"

if __name__ == "__main__":
    main()
