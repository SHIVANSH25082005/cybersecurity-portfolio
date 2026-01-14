password = input("Enter a password to check its strength: ")

length_ok = False
upper_ok = False
lower_ok = False
digit_ok = False
special_ok = False

# Length check
if len(password) >= 8:
    length_ok = True

# Character checks
for char in password:
    if char.isupper():
        upper_ok = True
    elif char.islower():
        lower_ok = True
    elif char.isdigit():
        digit_ok = True

# Special character check
special_characters = "!@#$%^&*()-_+=?"

for char in password:
    if char in special_characters:
        special_ok = True

# Scoring
score = 0

if length_ok:
    score += 1
if upper_ok:
    score += 1
if lower_ok:
    score += 1
if digit_ok:
    score += 1
if special_ok:
    score += 1

# Final output
if score <= 2:
    print("PASSWORD STRENGTH: WEAK")
elif score == 3 or score == 4:
    print("PASSWORD STRENGTH: MODERATE")
else:
    print("PASSWORD STRENGTH: STRONG")
