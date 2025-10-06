import random
import time

def roll_() -> int:
    return random.randint(1, 6)


def number_player() -> int:
    while True:
        num_player = input("How many player are going to play? ")
        if (num_player.isdigit()) and (int(num_player) in range(2, 5)):
            return int(num_player)
        else:
            print("Choose a number between 2-4")
            pass

num_player = number_player()
players_scores = [0 for _ in range(num_player)]

while max(players_scores) < 50:
    for player in range(num_player):
        while True:
            play = input("type 'P' to play or 'Q' to quit: ").lower()
            time.time(300)
            if play == 'p' or play == 'q':
                break
        if play == 'p':
            value = roll_()
            if value == 1:
                players_scores[player] = 0
            else:
                players_scores[player]+=value
        else:
            break
        print(f"Your current score is {players_scores[player]}")