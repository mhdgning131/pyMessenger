import re
import sys

def main():
    print(convert(input("Hours: ")))


def convert(s):
    # Pattern 12-hour format only: e.g. "9 AM to 5 PM" or "9:30 AM to 5:15 PM"
    pattern_12 = r"^(\d{1,2})(?::(\d{2}))? (AM|PM) to (\d{1,2})(?::(\d{2}))? (AM|PM)$"
    match_12 = re.match(pattern_12, s)

    if match_12:
        h1, m1, p1, h2, m2, p2 = match_12.groups()

        # Default missing minutes to 00
        m1 = int(m1) if m1 else 0
        m2 = int(m2) if m2 else 0
        h1 = int(h1)
        h2 = int(h2)

        # Check if time values are valid
        check_time(h1, m1, is_12h=True)
        check_time(h2, m2, is_12h=True)

        t1 = to_24(h1, m1, p1.upper())
        t2 = to_24(h2, m2, p2.upper())
        return f"{t1} to {t2}"

    else:
        raise ValueError("Invalid format")


def to_24(hour, minute, period):
    if hour < 1 or hour > 12 or minute < 0 or minute > 59:
        raise ValueError("Invalid 12-hour time")

    if period == "AM":
        hour = 0 if hour == 12 else hour
    elif period == "PM":
        hour = hour if hour == 12 else hour + 12

    return f"{hour:02}:{minute:02}"


def check_time(hour, minute, is_12h=False):
    if is_12h:
        if not (1 <= hour <= 12 and 0 <= minute <= 59):
            raise ValueError("Invalid 12-hour time")
    else:
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError("Invalid 24-hour time")


if __name__ == "__main__":
    main()
