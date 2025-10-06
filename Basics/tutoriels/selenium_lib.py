from selenium import webdriver
from selenium.webdriver.common.by import By

# 1. Open Chrome
driver = webdriver.Chrome()

# 2. Go to a page that needs JavaScript
driver.get("https://quotes.toscrape.com/js/")

# 3. Get all quotes (they are loaded by JavaScript)
quotes = driver.find_elements(By.CLASS_NAME, "text")

for q in quotes:
    print(q.text)

# 4. Close the browser
driver.quit()

