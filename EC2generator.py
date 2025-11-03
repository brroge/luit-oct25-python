import random

# Ask for the department
department = input("Enter your department name:\n")

# Ask how many EC2 names 
number = int(input("How many EC2 names do you want?\n"))

for i in range(number):
    
    # generate random number
    num = random.randint(100, 999)

    # generate random letter
    letter = chr(random.randint(97, 122))  # a-z

    # combine to make EC2 name
    ec2_name = department + "-ec2-" + letter + str(num)

    print(ec2_name)
