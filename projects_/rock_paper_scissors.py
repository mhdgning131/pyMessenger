import random

name = input("What's you name: ")
print(f"hello {name} Welcome")
allowed = ["rock", "paper", "scissors"]

print("We gonna play rock paper scissors")
print("You are only allowed to use: rock, paper or scissors")

user_points = 0
computer_points = 0

while user_points < 3 and computer_points < 3:
    computer_choice = random.choice(allowed)
    choice = input("Choose one: ").lower()

    if choice not in allowed:
        print("Choose between: rock, paper or scissors")
    elif computer_choice == choice:
        print(f"computer : {computer_choice}")
        print("Tied '_'")
    elif (computer_choice == "rock" and choice == "paper") or (computer_choice == "scissors" and choice == "rock") or computer_choice == "paper" and choice == "scissors":
        print(f"computer : {computer_choice}")
        print("you win -_-")
        user_points+=1
    else:
        print(f"computer : {computer_choice}")
        print("got yah :)")
        computer_points+=1

print(f"final score: You {user_points} vs {computer_points} Computer")
