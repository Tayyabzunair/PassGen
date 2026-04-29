# entropyX

A cryptographically secure password generator with uniqueness enforcement via SHA-256 hashing and Supabase storage. Available as both a Python CLI script and a cross-browser extension (Chrome + Firefox).

---

## How It Works

```
OS entropy → password → SHA-256 → Supabase check → store if unique → return
```

1. Password is generated using OS entropy (`os.urandom` / `crypto.getRandomValues`)
2. Password is hashed with SHA-256
3. Hash is checked against Supabase — if it exists, regenerate
4. If unique, only the hash is stored — plaintext never touches the database

---

## Project Structure

```
securepass/
├── generate_password.py        # Python CLI script
├── extension/
│   ├── manifest.json           # Chrome + Firefox MV3
│   ├── popup.html              # Extension UI
│   ├── popup.js                # Extension logic
│   └── icons/
│       └── icon48.png
└── README.md
```

---

## Setup

### Supabase

Create a table in your Supabase project via the SQL Editor:

```sql
CREATE TABLE passwords (
    id         BIGSERIAL PRIMARY KEY,
    hash       TEXT      NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE UNIQUE INDEX idx_passwords_hash ON passwords (hash);
```

Then grab your **Project URL** and **Anon Key** from Project Settings → API.

---

### Python Script

```bash
pip install supabase
```

Set your credentials at the top of `generate_password.py`:

```python
SUPABASE_URL = "https://your-project.supabase.co"
SUPABASE_KEY = "your-anon-key"
```

Run it:

```bash
python3 generate_password.py
```

---

### Browser Extension

Set your credentials at the top of `extension/popup.js`:

```js
const SUPABASE_URL = "https://your-project.supabase.co";
const SUPABASE_KEY = "your-anon-key";
```

**Chrome:**
1. Go to `chrome://extensions`
2. Enable Developer mode
3. Click Load unpacked → select the `extension/` folder

**Firefox:**
1. Go to `about:debugging` → This Firefox
2. Click Load Temporary Add-on → select any file in `extension/`

---

## Tech Stack

| Layer | Technology |
|---|---|
| CLI | Python 3 |
| Entropy | `os.urandom` / `crypto.getRandomValues` |
| Hashing | SHA-256 (`hashlib` / `crypto.subtle`) |
| Database | Supabase (PostgreSQL) |
| Extension | JavaScript, HTML, CSS — MV3 |

---

## Security Notes

- Plaintext passwords are **never stored** — only their SHA-256 hashes
- All randomness comes from OS-level entropy
- The UNIQUE index on the hash column ensures O(1) duplicate detection