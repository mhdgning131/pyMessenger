import random

Try = 7
number = random.randint(0, 100)

while True:
    try:
        print("you have 7 try") if (Try == 7) else print(f"You {Try} try left")
        guess = input("Guess a number between 0-100: ").strip()
        if guess.isdigit():
            if int(guess) < 0 or int(guess) > 100:
                raise ValueError
        else:
            raise TypeError

        if number == int(guess):
            quit("congratulations you got it")
        else:
            Try -= 1
            if Try == 0:
                quit("looser")
            print("go higher") if number > int(guess) else print("go lower")

    except TypeError:
        print("We using numbers here")
        pass
    except ValueError:
        print("Don't go outside the range")
        pass
    except EOFError:
        quit("You quit")
