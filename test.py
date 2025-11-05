import random
import string

def generate_ec2_names():
    print("=== EC2 Random Name Generator ===")
    
    while True:
        try:
            num_instances = int(input("How many EC2 instance names do you want to generate? "))
            if num_instances <= 0:
                print("Please enter a positive number.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")
    
    dept_name = input("Enter your department name (e.g., finance, devops, hr): ").strip().lower()
    
    ec2_names = set()
    while len(ec2_names) < num_instances:
        random_letters = ''.join(random.choices(string.ascii_lowercase, k=3))
        random_numbers = ''.join(random.choices(string.digits, k=4))
        ec2_name = f"{dept_name}-ec2-{random_letters}{random_numbers}"
        ec2_names.add(ec2_name)
    
    print("\nGenerated EC2 Instance Names:")
    for name in ec2_names:
        print(name)
    
    print("\n✅ Done! Copy these names to tag your EC2 instances.")

if __name__ == "__main__":
    generate_ec2_names()
