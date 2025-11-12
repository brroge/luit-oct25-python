import os, sys
# Create a list of missing files
REQUIRED = ["README.md", ".gitignore"]

# Create a loop to check for missing files
missing = [f for f in REQUIRED if not os.path.isfile(f)]

# if missing show message 
if missing:
    print("MISSING FILES:")
    for f in missing:
        print(f"- {f}")
    sys.exit(1)
sys.exit(0)
