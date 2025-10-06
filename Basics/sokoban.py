def main():
    history = []

    while True:
        action = input("Action: ")

        if action == "undo":
            undone = history.pop()
            print(f"Undone: '{undone}'")
        elif action == "restart":
            history.clear()
        else:
            history.append(action)

        print(history)

main()
