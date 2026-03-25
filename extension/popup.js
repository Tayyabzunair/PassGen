// ── Config ───────────────────────────────────────────────────
const SUPABASE_URL = "https://nnrcjsotishiyxtuhwgk.supabase.co";
const SUPABASE_KEY = "eyJ.pasteyourkeyhere.eyJ"; // Replace with your actual Supabase anon key

const LENGTH    = 16;
const UPPERCASE = true;
const DIGITS    = true;
const SYMBOLS   = true;

// ── Character Set ────────────────────────────────────────────
function buildCharset() {
  let charset = "abcdefghijklmnopqrstuvwxyz";
  if (UPPERCASE) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (DIGITS)    charset += "0123456789";
  if (SYMBOLS)   charset += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  return charset;
}

// ── OS Entropy → Password ────────────────────────────────────
function generatePassword(charset) {
  const randomBytes = new Uint8Array(LENGTH);
  crypto.getRandomValues(randomBytes);                   // OS entropy
  return Array.from(randomBytes)
    .map(byte => charset[byte % charset.length])
    .join("");
}

// ── SHA-256 Hash ─────────────────────────────────────────────
async function sha256(password) {
  const encoded = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Supabase: Check if hash exists ───────────────────────────
async function hashExists(pwHash) {
  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/passwords?hash=eq.${pwHash}&select=id&limit=1`,
    {
      headers: {
        "apikey":        SUPABASE_KEY,
        "Authorization": `Bearer ${SUPABASE_KEY}`,
      }
    }
  );
  const data = await res.json();
  return data.length > 0;
}

// ── Supabase: Store hash ──────────────────────────────────────
async function storeHash(pwHash) {
  await fetch(`${SUPABASE_URL}/rest/v1/passwords`, {
    method: "POST",
    headers: {
      "apikey":        SUPABASE_KEY,
      "Authorization": `Bearer ${SUPABASE_KEY}`,
      "Content-Type":  "application/json",
      "Prefer":        "return=minimal"
    },
    body: JSON.stringify({ hash: pwHash })
  });
}

// ── UI Helpers ───────────────────────────────────────────────
function setStatus(msg, type = "") {
  const el = document.getElementById("status");
  el.textContent = msg;
  el.className = `status ${type}`;
}

function setLoading(on) {
  const btn = document.getElementById("btnGenerate");
  btn.disabled = on;
  btn.classList.toggle("loading", on);
}

// ── Main Pipeline ─────────────────────────────────────────────
async function run() {
  setLoading(true);
  setStatus("Generating...", "loading");

  const pwBox    = document.getElementById("pwBox");
  const pwValue  = document.getElementById("pwValue");
  const hashValue = document.getElementById("hashValue");

  pwBox.className    = "pw-box";
  pwValue.className  = "pw-value placeholder";
  pwValue.textContent = "Generating...";
  hashValue.className = "hash-value";
  hashValue.textContent = "—";

  try {
    const charset  = buildCharset();
    let password, pwHash, exists;

    // Loop until unique (practically always first try)
    do {
      password = generatePassword(charset);
      pwHash   = await sha256(password);
      setStatus("Checking uniqueness in Supabase...", "loading");
      exists   = await hashExists(pwHash);
      if (exists) setStatus("Hash collision — regenerating...", "loading");
    } while (exists);

    // Store the unique hash
    setStatus("Storing hash...", "loading");
    await storeHash(pwHash);

    // Update UI
    pwValue.textContent  = password;
    pwValue.className    = "pw-value";
    pwBox.className      = "pw-box success";
    hashValue.textContent = pwHash;
    hashValue.className  = "hash-value active";
    setStatus("✅ Unique — hash stored. Plaintext never saved.", "success");

  } catch (err) {
    pwValue.textContent  = "Error occurred";
    pwValue.className    = "pw-value placeholder";
    pwBox.className      = "pw-box error";
    setStatus(`❌ ${err.message}`, "error");
  }

  setLoading(false);
}

// ── Init ──────────────────────────────────────────────────────
document.getElementById("btnGenerate").addEventListener("click", run);
