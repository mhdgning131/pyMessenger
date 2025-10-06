score = int(input("Score: "))

"""
if score >= 90 and score <= 100:
    print("Grade: A")
elif score >= 80 and score < 90:
    print("Grade: B")
elif score >= 70 and score < 80:
    print("Grade: C")
elif score >= 60 and score < 70:
    print("Grade: D")
else:
    print("Grade: F")

"""

# Instead we can also do this and have the same result
if 90 <= score:
    print("Grade: A")
elif 80 <= score :
    print("Grade: B")
elif 70 <= score:
    print("Grade: C")
elif 60 <= score:
    print("Grade: D")
else:
    print("Grade: F")
