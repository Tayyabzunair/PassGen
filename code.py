"""
Password Generator with SHA-256 Hashing + SQLite Uniqueness Check
------------------------------------------------------------------
Pipeline:
  OS entropy → secrets module → password → SHA-256 hash → DB check → store if unique → return
"""

import sqlite3
import hashlib
import secrets
import string
import os

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
DB_FILE = "passwords.db"

DEFAULT_LENGTH    = 16
DEFAULT_UPPERCASE = True
DEFAULT_DIGITS    = True
DEFAULT_SYMBOLS   = True

MAX_RETRIES = 10   # max attempts before giving up (collision loop guard)

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def init_db(db_path: str = DB_FILE) -> sqlite3.Connection:
    """
    Create (or open) the SQLite DB and ensure the password_hashes table exists.
    A UNIQUE constraint on the hash column gives O(1) duplicate detection via index.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_hashes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            hash       TEXT    NOT NULL UNIQUE,   -- UNIQUE constraint + auto-index
            created_at DATETIME DEFAULT (datetime('now'))
        )
    """)

    # Explicit index for even faster lookup (SQLite auto-creates one for UNIQUE,
    # but this makes the intent crystal-clear and is a no-op if it already exists)
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_password_hashes_hash
        ON password_hashes (hash)
    """)

    conn.commit()
    return conn


# ─────────────────────────────────────────────
# CRYPTO: PASSWORD GENERATION + HASHING
# ─────────────────────────────────────────────

def build_charset(
    uppercase: bool = DEFAULT_UPPERCASE,
    digits: bool    = DEFAULT_DIGITS,
    symbols: bool   = DEFAULT_SYMBOLS,
) -> str:
    """Assemble the character pool from which passwords are drawn."""
    charset = string.ascii_lowercase
    if uppercase:
        charset += string.ascii_uppercase
    if digits:
        charset += string.digits
    if symbols:
        charset += string.punctuation
    return charset


def generate_password(length: int = DEFAULT_LENGTH, charset: str = None) -> str:
    """
    Generate a cryptographically strong random password.
    Uses secrets.choice() which is backed by os.urandom() (OS entropy).
    """
    if charset is None:
        charset = build_charset()
    if not charset:
        raise ValueError("Character set cannot be empty.")

    # secrets.choice uses os.urandom() internally — cryptographic quality
    return "".join(secrets.choice(charset) for _ in range(length))


def sha256_hash(password: str) -> str:
    """Return the hex-encoded SHA-256 hash of the password (UTF-8 encoded)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────
# DB OPERATIONS
# ─────────────────────────────────────────────

def hash_exists(conn: sqlite3.Connection, pw_hash: str) -> bool:
    """Return True if this hash is already stored (O(1) via UNIQUE index)."""
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM password_hashes WHERE hash = ? LIMIT 1", (pw_hash,))
    return cursor.fetchone() is not None


def store_hash(conn: sqlite3.Connection, pw_hash: str) -> None:
    """Insert the hash into the DB. Raises IntegrityError on duplicate (safety net)."""
    cursor = conn.cursor()
    cursor.execute("INSERT INTO password_hashes (hash) VALUES (?)", (pw_hash,))
    conn.commit()


# ─────────────────────────────────────────────
# CORE PIPELINE
# ─────────────────────────────────────────────

def get_unique_password(
    conn:      sqlite3.Connection,
    length:    int  = DEFAULT_LENGTH,
    uppercase: bool = DEFAULT_UPPERCASE,
    digits:    bool = DEFAULT_DIGITS,
    symbols:   bool = DEFAULT_SYMBOLS,
) -> str:
    """
    Full pipeline:
      OS entropy → password → SHA-256 → DB check → store if unique → return
    Retries up to MAX_RETRIES times if a collision is detected.
    """
    charset = build_charset(uppercase, digits, symbols)

    for attempt in range(1, MAX_RETRIES + 1):
        password = generate_password(length, charset)
        pw_hash  = sha256_hash(password)

        if hash_exists(conn, pw_hash):
            print(f"  [attempt {attempt}] Hash collision detected — regenerating...")
            continue

        # New unique password — store its hash and return
        store_hash(conn, pw_hash)
        return password

    raise RuntimeError(
        f"Could not generate a unique password after {MAX_RETRIES} attempts. "
        "Consider increasing the password length or expanding the character set."
    )


# ─────────────────────────────────────────────
# DB STATS HELPER
# ─────────────────────────────────────────────

def get_stats(conn: sqlite3.Connection) -> dict:
    """Return basic statistics about the stored hashes."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM password_hashes")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT created_at FROM password_hashes ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    last_created = last_row[0] if last_row else "N/A"

    return {"total_hashes_stored": total, "last_generated_at": last_created}


# ─────────────────────────────────────────────
# MAIN / DEMO
# ─────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  🔐 Secure Password Generator")
    print("  Pipeline: OS entropy → SHA-256 → DB uniqueness check")
    print("=" * 55)

    # 1. Initialize DB
    conn = init_db()
    print(f"\n✅ Database ready: {os.path.abspath(DB_FILE)}\n")

    # 2. Generate 5 unique passwords as a demo
    configs = [
        {"length": 16, "uppercase": True,  "digits": True,  "symbols": True},
        {"length": 20, "uppercase": True,  "digits": True,  "symbols": False},
        {"length": 12, "uppercase": False, "digits": True,  "symbols": True},
        {"length": 24, "uppercase": True,  "digits": False, "symbols": True},
        {"length": 32, "uppercase": True,  "digits": True,  "symbols": True},
    ]

    for i, cfg in enumerate(configs, 1):
        print(f"[{i}] Generating password — length={cfg['length']}, "
              f"upper={cfg['uppercase']}, digits={cfg['digits']}, symbols={cfg['symbols']}")

        password = get_unique_password(conn, **cfg)
        pw_hash  = sha256_hash(password)

        print(f"    Password : {password}")
        print(f"    SHA-256  : {pw_hash[:32]}...{pw_hash[-8:]}")
        print(f"    Status   : ✅ Unique — stored in DB\n")

    # 3. Show DB stats
    stats = get_stats(conn)
    print("-" * 55)
    print(f"📊 DB Stats:")
    print(f"   Total hashes stored : {stats['total_hashes_stored']}")
    print(f"   Last generated at   : {stats['last_generated_at']}")
    print("-" * 55)

    conn.close()


if __name__ == "__main__":
    main()