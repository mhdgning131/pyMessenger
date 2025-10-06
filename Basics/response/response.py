import validators

def main():
    print(f"{validate(input("What's your email address? "))}")

# Validate an email
def validate(s):
    """
    i could also use the re.match(^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$, s)
    """
    if validators.email(s):
        return "Valid"
    return "Invalid"

if __name__ == "__main__":
    main()