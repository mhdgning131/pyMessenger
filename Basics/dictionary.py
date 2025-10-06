students = [
        {"name": "Hermione", "House": "Gryffindor", "Patronus": "Otter"},
        {"name": "Harry", "House": "Gryffindor", "Patronus": "Stag"},
        {"name": "Ron", "House": "Gryffindor", "Patronus": "Jack Russell terrier"},
        {"name": "Draco", "House": "Slytherin", "Patronus": None}
]

for student in students:
    print(student["name"], student["House"], student["Patronus"], sep=", ")