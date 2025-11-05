import random

# Ask how many names we need
count = int(input("How many EC2 names do you want?\n"))

# Ask for department
dept = input("Enter your department name:\n")

# Loop that many times
for i in range(count):
    
    # Make random number 100-999
    num = random.randint(100, 999)

    # Make a random letter a-z
    letter = chr(random.randint(97, 122))

    # Build EC2 name
    name = dept + "-ec2-" + letter + str(num)

    # Print the name
    print(name)
