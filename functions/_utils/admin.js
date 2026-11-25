// ============================================================
//  functions/_utils/admin.js
//  Shared helpers for the admin credential store.
//
//  The store is a D1 database bound as `witi_users` (see
//  wrangler.toml). Two tables, created by schema.sql:
//
//      admin_credentials  one row per admin name + password HASH
//      admin_sessions     one row per logged-in browser
//
//  Passwords are PBKDF2-SHA256 hashes with a per-admin random
//  salt, never plaintext -- a leaked database must not hand out
//  logins.
//
//  The login cookie holds a random token; the database stores only
//  its SHA-256, so the cookie cannot be forged or read back, and
//  deleting an admin deletes their sessions too.
//
//  Files/folders in functions/ whose names start with "_" are
//  not routed to a URL by Cloudflare Pages, so this is a plain
//  module you can import from any endpoint.
// ============================================================

// Exactly what the D1 binding is called in wrangler.toml:
//   [[d1_databases]]
//       binding = "witi_users"
const DB_BINDING = "witi_users";

export const SESSION_COOKIE = "witi_admin";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours
const PBKDF2_ITERATIONS = 100000;

// No length rule: an admin may use any password they like. The
// only requirement is that it is not empty -- an empty password
// would mean "anyone can log in as this admin".

// --- Responses --------------------------------------------------
export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function db(env) {
  const database = env?.[DB_BINDING];
  if (!database) {
    throw new Error(
      `D1 binding "${DB_BINDING}" is missing. Check wrangler.toml.`,
    );
  }
  return database;
}

export function now() {
  return Math.floor(Date.now() / 1000);
}

// --- Base64 helpers --------------------------------------------
export function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- Input rules -------------------------------------------------
// "David" and "david" are the same admin: names are matched
// case-insensitively via the stored name_key = lower(name).
export function normalizeName(raw) {
  const name = String(raw ?? "")
    .trim()
    .replace(/\s+/g, " ");
  if (!name) return { error: "Enter a name." };
  if (name.length > 32) {
    return { error: "A name must be 32 characters or fewer." };
  }
  if (!/^[A-Za-z0-9 ._-]+$/.test(name)) {
    return {
      error:
        "A name may only use letters, numbers, spaces, dots, dashes or underscores.",
    };
  }
  return { name };
}

export function validatePassword(raw) {
  const password = String(raw ?? "");
  if (password.length === 0) {
    return { error: "Enter a password." };
  }
  return { password };
}

export function nameKey(name) {
  return String(name).toLowerCase();
}

// --- Password hashing ------------------------------------------
async function pbkdf2(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return {
    algo: "pbkdf2-sha256",
    iterations: PBKDF2_ITERATIONS,
    salt: bytesToBase64(salt),
    hash: bytesToBase64(hash),
  };
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// `row` is an admin_credentials row.
export async function verifyPassword(password, row) {
  if (!row?.password_salt || !row?.password_hash) return false;
  const actual = await pbkdf2(
    password,
    base64ToBytes(row.password_salt),
    Number(row.password_iters) || PBKDF2_ITERATIONS,
  );
  return constantTimeEqual(actual, base64ToBytes(row.password_hash));
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return bytesToHex(new Uint8Array(digest));
}

// --- Credential CRUD --------------------------------------------
export async function getAdmin(env, name) {
  return db(env)
    .prepare("SELECT * FROM admin_credentials WHERE name_key = ?1")
    .bind(nameKey(name))
    .first();
}

// Upsert: creates the admin, or replaces their password if the
// name already exists. Returns { row, replaced }.
export async function saveAdmin(env, name, password) {
  const existing = await getAdmin(env, name);
  const hashed = await hashPassword(password);
  const ts = now();

  await db(env)
    .prepare(
      `INSERT INTO admin_credentials
         (name, name_key, password_algo, password_iters,
          password_salt, password_hash, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
       ON CONFLICT (name_key) DO UPDATE SET
         name           = excluded.name,
         password_algo  = excluded.password_algo,
         password_iters = excluded.password_iters,
         password_salt  = excluded.password_salt,
         password_hash  = excluded.password_hash,
         updated_at     = excluded.updated_at`,
    )
    .bind(
      name,
      nameKey(name),
      hashed.algo,
      hashed.iterations,
      hashed.salt,
      hashed.hash,
      ts,
    )
    .run();

  const row = await getAdmin(env, name);
  return { row, replaced: Boolean(existing) };
}

export async function deleteAdmin(env, adminId) {
  // ON DELETE CASCADE takes the admin's sessions with it.
  await db(env)
    .prepare("DELETE FROM admin_credentials WHERE admin_id = ?1")
    .bind(adminId)
    .run();
}

// Names and dates only -- the hash columns never leave the server.
export async function listAdmins(env) {
  const { results } = await db(env)
    .prepare(
      `SELECT admin_id, name, created_at, updated_at
         FROM admin_credentials
        ORDER BY name COLLATE NOCASE ASC`,
    )
    .all();
  return (results || []).map((row) => ({
    name: row.name,
    createdAt: new Date(row.created_at * 1000).toISOString(),
  }));
}

// --- Sessions ---------------------------------------------------
function readCookie(request, name) {
  const header = request.headers.get("Cookie");
  if (!header) return null;
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]).trim() || null;
  } catch {
    return null;
  }
}

export async function createSession(env, adminId) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = bytesToHex(tokenBytes);
  const tokenHash = await sha256Hex(token);
  const ts = now();

  await db(env)
    .prepare(
      `INSERT INTO admin_sessions (token_hash, admin_id, created_at, expires_at)
       VALUES (?1, ?2, ?3, ?4)`,
    )
    .bind(tokenHash, adminId, ts, ts + SESSION_TTL_SECONDS)
    .run();

  // Opportunistic cleanup; a failure here must not break login.
  try {
    await db(env)
      .prepare("DELETE FROM admin_sessions WHERE expires_at < ?1")
      .bind(ts)
      .run();
  } catch {
    // ignore
  }

  return { token, maxAge: SESSION_TTL_SECONDS };
}

// Resolves the session cookie to { admin_id, name }, or null.
export async function readSession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;

  const tokenHash = await sha256Hex(token);
  const row = await db(env)
    .prepare(
      `SELECT c.admin_id, c.name
         FROM admin_sessions s
         JOIN admin_credentials c ON c.admin_id = s.admin_id
        WHERE s.token_hash = ?1
          AND s.expires_at > ?2`,
    )
    .bind(tokenHash, now())
    .first();

  if (!row) return null;
  return { adminId: row.admin_id, name: row.name };
}

export async function destroySession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return;
  const tokenHash = await sha256Hex(token);
  await db(env)
    .prepare("DELETE FROM admin_sessions WHERE token_hash = ?1")
    .bind(tokenHash)
    .run();
}

export function sessionCookie(request, token, maxAge) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export function clearSessionCookie(request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
