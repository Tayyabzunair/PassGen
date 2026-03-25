import os
import string
import hashlib
from supabase import create_client

SUPABASE_URL = "https://nnrcjsotishiyxtuhwgk.supabase.co"
SUPABASE_KEY = "eyJ.pasteyourkeyhere.eyJ"

LENGTH    = 16
UPPERCASE = True
DIGITS    = True
SYMBOLS   = True

charset = string.ascii_lowercase
if UPPERCASE: charset += string.ascii_uppercase
if DIGITS:    charset += string.digits
if SYMBOLS:   charset += string.punctuation

# ── Supabase Client ─────────────────────────────────────────
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── OS Entropy → Password → SHA-256 → Check → Store ─────────
while True:
    password = "".join(charset[byte % len(charset)] for byte in os.urandom(LENGTH))
    pw_hash  = hashlib.sha256(password.encode("utf-8")).hexdigest()

    existing = supabase.table("passwords").select("id").eq("hash", pw_hash).execute()

    if existing.data:
        print("Hash already exists — regenerating...")
    else:
        supabase.table("passwords").insert({"hash": pw_hash}).execute()
        print(f"Password : {password}")
        print(f"SHA-256  : {pw_hash}")
        print(f"Status   : ✅ Hash stored in Supabase — plaintext never saved")
        break