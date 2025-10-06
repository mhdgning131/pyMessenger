import random

name = input("What's your name: ")
print(f"Hello {name}")
print("Welcome to my QuestionForOneMillion")

questions = [
        ("What is the capital city of France?", "Paris"),
        ("What is the chemical symbol for gold?", "Au"),
        ("In what year did the Titanic sink?", "1912"),
        ("Which planet is the largest in our solar system?", "Jupiter"),
        ("Who wrote the novel '1984'?", "George Orwell"),
        ("What is the square root of 144?", "12"),
        ("What is the hardest natural substance on Earth?", "Diamond"),
        ("How many degrees are in a right angle?", "90"),
        ("What gas do plants primarily absorb for photosynthesis?", "Carbon dioxide"),
        ("What is the smallest prime number?", "2"),
    ]
score= 0
random.shuffle(questions)
for i in range(10):
    question, right_answer = questions[i]
    answer = input(f"question {i+1}: {question} ")

    if answer.lower() != right_answer.lower():
        print("Wrong answer -_-")
    else:
        print("Right answer :)")
        score += 1

print(f"You have scored {score}/10")