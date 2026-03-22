import secrets
import string

LENGTH    = 16
UPPERCASE = True
DIGITS    = True
SYMBOLS   = True

charset = string.ascii_lowercase
print(f"charset value: {charset}")
if UPPERCASE: charset += string.ascii_uppercase
print(f"uppercase value: {charset}")
if DIGITS:    charset += string.digits
print(f"digits value: {charset}")
if SYMBOLS:   charset += string.punctuation
print(f"symbols value: {charset}")

password = "".join(secrets.choice(charset) for _ in range(LENGTH))

print(f"Generated password: {password}")