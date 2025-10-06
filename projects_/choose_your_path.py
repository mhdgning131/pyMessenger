name = input("What is your name? ")
print(f"Hello {name.capitalize()}")
print("In this game your gonna choose your path")
print("This is gonna be like an adventure game you're gonna make decisions that will decide of your fate")
print("Choose wisely")
while True :
    answer = input("You still wanna play, don't you? (yes/no): ").lower().strip()
    if answer == 'yes':
        Continue = True
        break
    else:
        Continue = False
        break

if not Continue:
    print("Scary ass boy. You're LOOSER!")
    quit()

print("So now, let's start. Good luck!")
print()

print("You're are a basketball player in college")
print("Tonight there is a big party in my house and i invited you")
print("1. You come")
print("2. You dont")
while True:
    answer = input("Choose wisely: (1 or 2)").lower().strip()
    if answer == 1:
        ...
    else:
        ...
