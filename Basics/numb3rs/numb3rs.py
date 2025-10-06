import re


def main():
    print(validate(input("IPv4 Address: ")))

def validate(ip):
    pattern = r"^((25[0-5]|2[0-4][0-9]|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4][0-9]|1\d\d|[1-9]?\d)$"
    return bool(re.fullmatch(pattern, ip))

if __name__ == "__main__":
    main()
