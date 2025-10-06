results=["Mario","Luigi"]

results.append("Princess")
results.append("Yoshi")
results.append("Koopa Troopa")
results.append("Toad")

print(results)

results.append(["Bowser","Donkey Kong Jr."])
results.remove(["Bowser","Donkey Kong Jr."])
results.extend(["Bowser","Donkey Kong Jr."])

print(results)

results.remove("Bowser")

print(results)

results.insert(0,"Bowser")

print(results)

print(results.index("Mario"))

results.reverse()

print(results)
