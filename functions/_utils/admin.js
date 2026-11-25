// ============================================================
//  functions/_utils/admin.js
//  Shared helpers for the admin credential store.
//
//  The store itself is a Cloudflare KV namespace bound as
//  WITI_ADMINS (see wrangler.toml). One key per admin:
//
//      key   : admin:david
//      value : {"name":"david","password":{...hash...},"createdAt":"..."}
//
//  The VALUE is a PBKDF2 hash, never the plaintext password.
//  KV is readable by anything holding the account's API token
//  and by anyone who can open the Cloudflare dashboard, so a
//  plaintext password sitting in there would leak every admin
//  login. A hash still lets us answer "does this match?" without
//  ever storing the answer itself.
//
//  Files/folders in functions/ whose names start with "_" are
//  not routed to a URL by Cloudflare Pages, so this is a plain
//  module you can import from any endpoint.
// ============================================================

// Exactly what the KV binding is called in wrangler.toml:
//   [[kv_namespaces]]
//       binding = "WITI_ADMINS"
const KV_BINDING = "WITI_ADMINS";

// Every credential key lives under this prefix so listing is a
// single `list({ prefix })` call and so internal keys (like the
// session-signing secret) can never collide with an admin name.
export const ADMIN_PREFIX = "admin:";

// The rule from the brief: a password must be exactly 12 chars.
export const PASSWORD_LENGTH = 12;

const SECRET_KEY = "__session_secret__";
export const SESSION_COOKIE = "witi_admin";
const SESSION_TTL_SECONDS = 60 * 60 * 8; // 8 hours
const PBKDF2_ITERATIONS = 100000;

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

function kv(env) {
  const namespace = env?.[KV_BINDING];
  if (!namespace) {
    throw new Error(
      `KV binding "${KV_BINDING}" is missing. Check wrangler.toml.`,
    );
  }
  return namespace;
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

function toBase64Url(text) {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value) {
  let s = value.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
}

// --- Input rules -------------------------------------------------
// "David" and "david" are the same admin: names are matched
// case-insensitively (the KV key is lowercased).
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
  if (password.length !== PASSWORD_LENGTH) {
    return {
      error: `A password must be exactly ${PASSWORD_LENGTH} characters.`,
    };
  }
  return { password };
}

export function keyFor(name) {
  return ADMIN_PREFIX + name.toLowerCase();
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

export async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const actual = await pbkdf2(
    password,
    base64ToBytes(record.salt),
    Number(record.iterations) || PBKDF2_ITERATIONS,
  );
  return constantTimeEqual(actual, base64ToBytes(record.hash));
}

// --- Credential CRUD --------------------------------------------
export async function getAdmin(env, name) {
  const raw = await kv(env).get(keyFor(name));
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null; // corrupt entry -> treat as "no such admin"
  }
}

export async function saveAdmin(env, name, password) {
  const record = {
    name,
    password: await hashPassword(password),
    createdAt: new Date().toISOString(),
  };
  await kv(env).put(keyFor(name), JSON.stringify(record), {
    // Metadata lets the admin page list names without reading
    // every value (which would need one GET per admin).
    metadata: { name: record.name, createdAt: record.createdAt },
  });
  return record;
}

export async function deleteAdmin(env, name) {
  await kv(env).delete(keyFor(name));
}

export async function listAdmins(env) {
  const result = await kv(env).list({ prefix: ADMIN_PREFIX });
  return (result.keys || [])
    .map((key) => ({
      name: key.metadata?.name || key.name.slice(ADMIN_PREFIX.length),
      createdAt: key.metadata?.createdAt || null,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

// --- Session cookie ---------------------------------------------
// The cookie is a signed payload: <payload>.<hmac>. It holds no
// password and cannot be edited -- change one character of the
// payload and the signature no longer matches.
async function getSecret(env) {
  const namespace = kv(env);
  let secret = await namespace.get(SECRET_KEY);
  if (!secret) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    secret = bytesToBase64(bytes);
    await namespace.put(SECRET_KEY, secret);
  }
  return secret;
}

async function sign(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data),
  );
  return new Uint8Array(signature);
}

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

export async function createSession(env, name) {
  const secret = await getSecret(env);
  const payload = toBase64Url(
    JSON.stringify({
      name,
      exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
    }),
  );
  const signature = bytesToBase64(await sign(secret, payload));
  return {
    token: `${payload}.${toBase64Url(signature)}`,
    maxAge: SESSION_TTL_SECONDS,
  };
}

export async function readSession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;

  const split = token.lastIndexOf(".");
  if (split < 1) return null;
  const payload = token.slice(0, split);
  const signature = token.slice(split + 1);

  const secret = await getSecret(env);
  const expected = bytesToBase64(await sign(secret, payload));
  if (
    !constantTimeEqual(
      base64ToBytes(fromBase64Url(signature)),
      base64ToBytes(expected),
    )
  ) {
    return null;
  }

  let data;
  try {
    data = JSON.parse(fromBase64Url(payload));
  } catch {
    return null;
  }
  if (!data?.name || !data?.exp) return null;
  if (data.exp < Math.floor(Date.now() / 1000)) return null;

  // The credential may have been deleted since the cookie was
  // issued -- deleting an admin must end their session.
  const record = await getAdmin(env, data.name);
  if (!record) return null;

  return { name: record.name };
}

export function sessionCookie(request, token, maxAge) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export function clearSessionCookie(request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
