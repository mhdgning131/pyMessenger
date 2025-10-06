import re
import sys


def main():
    print(count(input("Text: ")))


def count(s):
    pattern = r"\bum\b"
    return len(re.findall(pattern, s, re.IGNORECASE))


if __name__ == "__main__":
    main()