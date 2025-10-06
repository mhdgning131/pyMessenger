import sys

def main():
    if len(sys.argv) <= 1:
        print("Too few command-line arguments")
        sys.exit(1)
    elif len(sys.argv) > 2:
        print("Too many command-line arguments")
        sys.exit(1)
    elif not(sys.argv[1].endswith(".py")):
        print("Not a Python file")
        sys.exit(1)
    else:
        print(f"There is {count_lines(sys.argv[1])}")


def count_lines(file):
    n = 0
    try:
        with open(file, "r") as f:
            for line in f:
                line = line.lstrip()
                if line.startswith("#") or line == "":
                    continue
                n += 1
            return n
    except FileNotFoundError:
        print("File does not exist")
        sys.exit(1)

main()