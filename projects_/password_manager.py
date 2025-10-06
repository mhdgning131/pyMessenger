import re
import csv

# ===================== CRYPTO IMPORTS =====================
from Crypto.Cipher import AES          # AES encryption algorithm
from Crypto.Random import get_random_bytes  # Secure random generator
import base64                          # For converting binary data <-> text
# ==========================================================

# ⚠️ IMPORTANT: This is the encryption key.
# - Must be 16, 24, or 32 bytes long (AES-128, AES-192, AES-256).
# - Here it is hardcoded for simplicity, but in real life you should load it
#   from an environment variable or derive it from a master password.
KEY = b"this_is_16_bytes"


def encrypt_password(password: str, key: bytes = KEY) -> str:
    """
    Encrypts a password using AES in EAX mode.
    Returns a base64 string that combines nonce + ciphertext.
    """
    cipher = AES.new(key, AES.MODE_EAX)             # Create AES cipher with key in EAX mode
    nonce = cipher.nonce                            # Random nonce (unique per encryption)
    ciphertext, tag = cipher.encrypt_and_digest(    # Encrypt + compute authentication tag
        password.encode("utf-8")
    )
    # Concatenate nonce + ciphertext, encode as base64 for safe storage in CSV
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_password(encrypted: str, key: bytes = KEY) -> str:
    """
    Decrypts a base64 string back into the original password.
    The base64 string contains nonce + ciphertext.
    """
    raw = base64.b64decode(encrypted)               # Decode base64 back to raw bytes
    nonce = raw[:16]                                # First 16 bytes = nonce
    ciphertext = raw[16:]                           # Remaining bytes = ciphertext
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) # Recreate AES cipher with same key + nonce
    return cipher.decrypt(ciphertext).decode("utf-8")
    # Decrypt ciphertext -> original password string


def _prompt_choice(max_option: int, prompt: str = "Choose an option: ") -> int:
    while True:
        choice = input(prompt).strip()
        if not choice.isdigit():
            print("Invalid option")
            continue
        value = int(choice)
        if 0 <= value <= max_option:
            return value
        print("Invalid option")


def main_menu():
    print()
    print("===== Password manager =====")
    print("1. add")
    print("2. view")
    print("3. delete")
    print("4. edit")
    print("0. quit")
    print()
    return _prompt_choice(4)


def view_menu():
    print()
    print("1. view one")
    print("2. View all")
    print("0. quit")
    print()
    return _prompt_choice(2)


def add_menu():
    print()
    print("1. add one")
    print("2. add more than one")
    print("0. quit")
    print()
    return _prompt_choice(2)


def del_menu():
    print()
    print("1. delete one")
    print("2. delete all")
    print("0. quit")
    print()
    return _prompt_choice(2)


def edit_menu():
    print()
    print("1. edit")
    print("0. quit")
    print()
    return _prompt_choice(1)


def passw():
    while True:
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s])\S{8,}$'
        password = input("password: ")
        if re.fullmatch(pattern, password):
            break
    return password


def add_pass(amount: int = 1):
    for i in range(amount):
        print()
        print(f"password {i+1}")
        with open("passwords.csv", 'a', newline='') as file:
            csv_writer = csv.writer(file)
            while True:
                repeated = False
                account_name = input('Account name: ')
                with open("passwords.csv", 'r', newline='') as f:
                    csv_reader = csv.reader(f)
                    for row in csv_reader:
                        if not row or len(row) < 1:
                            continue
                        if account_name.lower() == row[0].lower():
                            print("This name already exist")
                            repeated = True
                            break
                if not repeated:
                    break

            password = passw()

            # 🔒 Encrypt password before saving
            csv_writer.writerow([account_name, encrypt_password(password)])
            print("Added successfully")


def view_pass(account_name=None):
    with open("passwords.csv", 'r') as file:
        csv_reader = csv.reader(file)
        if account_name is None:
            print()
            for line in csv_reader:
                # 🔓 Decrypt password before showing
                print(f"{line[0]}   {decrypt_password(line[1])}")
        else:
            not_found = True
            for line in csv_reader:
                if line[0].lower() == account_name.lower():
                    not_found = False
                    print()
                    # 🔓 Decrypt password before showing
                    print(f"{line[0]}   {decrypt_password(line[1])}")
            if not_found:
                print("This account was not found")


def del_pass(account_name=None):
    if account_name is None:
        with open("passwords.csv", 'w', newline= '') as file:
            csv_writer = csv.writer(file)
        print("Deleted successfully")
    else:
        with open("passwords.csv", 'r') as file:
            csv_reader = csv.reader(file)
            passwords = []
            found = False
            for line in csv_reader:
                if line[0].lower() == account_name.lower():
                    found = True
                    continue
                passwords.append(line)

        if found:
            with open("passwords.csv", 'w', newline= '') as file:
                csv_writer = csv.writer(file)
                for password in passwords:
                    csv_writer.writerow(password)
            print("Deleted successfully")
        else:
            print("This account was not found")


def edit_pass(account_name: str):
    with open("passwords.csv", 'r') as file:
        csv_reader = csv.reader(file)
        passwords = []
        found = False
        for line in csv_reader:
            if line[0].lower() == account_name.lower():
                found = True
                # 🔒 Encrypt new password before saving
                line[1] = encrypt_password(passw())
            passwords.append(line)

    if found:
        with open("passwords.csv", 'w', newline='') as file:
            csv_writer = csv.writer(file)
            for password in passwords:
                csv_writer.writerow(password)
        print("Edited successfully")
    else:
        print("This account was not found")


def main():
    while True:
        choice0 = main_menu()
        if choice0 == 0:
            break
        elif choice0 == 1:
            while True:
                choice = add_menu()
                if choice == 0:
                    break
                elif choice == 1:
                    add_pass()
                elif choice == 2:
                    while True:
                        try:
                            amount = int(input("How many: "))
                            add_pass(amount)
                            break
                        except ValueError:
                            pass
        elif choice0 == 2:
            while True:
                choice = view_menu()
                if choice == 0:
                    break
                elif choice == 1:
                    account_name = input("Which one: ")
                    view_pass(account_name)
                elif choice == 2:
                    view_pass()
        elif choice0 == 3:
            while True:
                choice = del_menu()
                if choice == 0:
                    break
                elif choice == 1:
                    account_name = input("Which one: ")
                    del_pass(account_name)
                elif choice == 2:
                    del_pass()
        elif choice0 == 4:
            while True:
                choice = edit_menu()
                if choice == 0:
                    break
                else:
                    account_name = input("Which one: ")
                    edit_pass(account_name)


if __name__ == "__main__":
    main()
