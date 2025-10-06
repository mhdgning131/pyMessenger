class Food:
    base_hearts = 1

    def __init__(self, ingredients):
        self.ingredients = ingredients
        self.hearts = Food.calculate_hearts(ingredients)

    @classmethod
    def calculate_hearts(cls, ingredients):
        hearts = cls.base_hearts
        for ingredient in ingredients:
            if "hearty" in ingredient.lower():
                hearts += 2
            else:
                hearts += 1
        return hearts

    @classmethod
    def from_nothing(cls, hearts):
        food = cls(ingredients=[])
        food.hearts = hearts
        return food


def main():
    mushroom_skewer = Food(ingredients=["Mushroom", "Hearty Mushroom"])
    print(f"This Mushroom Skewer heals {mushroom_skewer.hearts} hearts! 💕")

    Food.base_hearts = 2
    mushroom_skewer = Food(ingredients=["Mushroom", "Hearty Mushroom"])
    print(f"This Mushroom Skewer heals {mushroom_skewer.hearts} hearts! 💕")

    mushroom_skewer = Food.from_nothing(hearts=2)
    print(f"This Mushroom Skewer heals {mushroom_skewer.hearts} hearts! 💕")


main()
