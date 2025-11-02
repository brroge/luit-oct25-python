# Ask the question
age = int(input("HOW OLD ARE YOU?\n"))

# The function to calculate decades and years
decades = age //10
years = age % 10

# Print the result
print("You are " + str(decades) + 
      " decades and " + str(years) + " years old.")