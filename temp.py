import os
import string
import sqlite3
import hashlib

LENGTH    = 16
UPPERCASE = True
DIGITS    = True
SYMBOLS   = True

charset = string.ascii_lowercase
if UPPERCASE: charset += string.ascii_uppercase
if DIGITS:    charset += string.digits
if SYMBOLS:   charset += string.punctuation

# ── Database Setup ──────────────────────────────────────────
conn   = sqlite3.connect("passwords.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        hash       TEXT    NOT NULL UNIQUE,
        created_at DATETIME DEFAULT (datetime('now'))
    )
""")
cursor.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_passwords_hash
    ON passwords (hash)
""")
conn.commit()

# ── Functions ───────────────────────────────────────────────
def generate_password():
    return "".join(charset[byte % len(charset)] for byte in os.urandom(LENGTH))

def manual_password():
    return input("Enter your password: ")

def check_and_store(password):
    pw_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()

    cursor.execute("SELECT 1 FROM passwords WHERE hash = ? LIMIT 1", (pw_hash,))

    if cursor.fetchone():
        print(f"Password : {password}")
        print(f"SHA-256  : {pw_hash}")
        print(f"Status   : ❌ Hash already exists — password not stored")
    else:
        cursor.execute("INSERT INTO passwords (hash) VALUES (?)", (pw_hash,))
        conn.commit()
        print(f"Password : {password}")
        print(f"SHA-256  : {pw_hash}")
        print(f"Status   : ✅ Hash stored in DB — plaintext never saved")

# ── Main ─────────────────────────────────────────────────────
print("\n[1] Auto-generate password")
print("[2] Enter password manually")
choice = input("\nChoose an option (1 or 2): ").strip()

if choice == "1":
    password = generate_password()
    check_and_store(password)
elif choice == "2":
    password = manual_password()
    check_and_store(password)
else:
    print("Invalid option. Please enter 1 or 2.")
1
conn.close()