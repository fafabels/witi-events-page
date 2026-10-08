// ============================================================
//  functions/_utils/password.js
//  Password hashing + verification for the Workers runtime.
//
//  WHY NOT BCRYPT / ARGON2:
//  Cloudflare Workers has no Node `crypto` module and cannot run
//  native addons, so `bcrypt` / `argon2` are not available. The
//  runtime DOES ship WebCrypto (crypto.subtle), which gives us
//  PBKDF2 -- a standard, slow-by-iteration KDF. That is what we
//  use here, so there is no npm dependency to install.
//
//  HASH FORMAT (single string, self-describing):
//      pbkdf2$sha256$<iterations>$<salt-b64>$<hash-b64>
//
//  Storing the params alongside the hash means you can raise the
//  iteration count later and old hashes still verify.
//
//  The users.password column is plain TEXT, which fits this fine.
// ============================================================

// 210,000 is the OWASP 2023 floor for PBKDF2-HMAC-SHA256.
// Higher = slower for an attacker, but also slower per login.
const ITERATIONS = 210_000;
const HASH = "SHA-256";
const KEY_BITS = 256;
const SALT_BYTES = 16;

// --- base64 <-> bytes -------------------------------------------
function bytesToB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64ToBytes(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// Constant-time-ish comparison. Avoids leaking how many leading
// bytes matched via early-return timing.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- core -------------------------------------------------------
async function derive(password, salt, iterations) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: HASH },
    key,
    KEY_BITS,
  );
  return new Uint8Array(bits);
}

/**
 * Hash a plaintext password for storage.
 * @param {string} password
 * @returns {Promise<string>} the storable hash string
 */
export async function hashPassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("password must be a non-empty string");
  }
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(password, salt, ITERATIONS);
  return `pbkdf2$${HASH}$${ITERATIONS}$${bytesToB64(salt)}$${bytesToB64(hash)}`;
}

/**
 * Check a plaintext password against a stored hash.
 * Returns a boolean -- never throws on a malformed stored value,
 * because a corrupt row should mean "login denied", not a 500.
 * @param {string} password
 * @param {string} stored  the string produced by hashPassword()
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, stored) {
  if (typeof password !== "string" || typeof stored !== "string") {
    return false;
  }

  const parts = stored.split("$");
  if (parts.length !== 5) return false;

  const [scheme, hashName, iterStr, saltB64, hashB64] = parts;
  if (scheme !== "pbkdf2" || hashName !== HASH) return false;

  const iterations = Number.parseInt(iterStr, 10);
  if (!Number.isInteger(iterations) || iterations <= 0) return false;

  let salt, expected;
  try {
    salt = b64ToBytes(saltB64);
    expected = b64ToBytes(hashB64);
  } catch {
    return false; // malformed base64
  }

  const actual = await derive(password, salt, iterations);
  return timingSafeEqual(actual, expected);
}

// ============================================================
//  Session tokens
// ============================================================

/**
 * 32 random bytes, hex-encoded. This is what goes in the cookie
 * and in the sessions table -- never the user's name or id, so a
 * tampered cookie can't select an arbitrary account the way
 * `session=1` can.
 * @returns {string}
 */
export function generateSessionToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Hash a session token before storing it.
 * Storing the raw token would mean a leaked DB dump is a pile of
 * ready-to-use logins. SHA-256 is fine here (unlike for passwords)
 * because the token is already 256 bits of random -- there is
 * nothing to brute-force.
 * @param {string} token
 * @returns {Promise<string>}
 */
export async function hashSessionToken(token) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return bytesToB64(new Uint8Array(digest));
}

// How long a login lasts. Keep in sync with the cookie Max-Age
// in api/auth/login.js.
export const SESSION_TTL_SECONDS = 60 * 60 * 24; // 24 hours
