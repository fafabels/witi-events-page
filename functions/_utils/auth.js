// ============================================================
//  functions/_utils/auth.js
//  Shared access-control helper.
//
//  Files/folders in functions/ that start with "_" are NOT
//  routed to a URL by Cloudflare Pages, so this is a plain
//  module you can import from any endpoint.
//
//      import { requireAdmin } from "../_utils/auth.js";
//
//      export async function onRequestGet({ request, env }) {
//        const { user, error } = await requireAdmin(request, env);
//        if (error) return error;   // already a ready-to-return Response
//        // ...user is a guaranteed admin from here on
//      }
//
//  Why this lives on the server and not in index.html:
//  the browser is untrusted. Anyone can open devtools, edit the
//  JS, and set their own role. The session cookie travels with
//  every request, so only the server can be the referee.
// ============================================================

import { hashSessionToken } from "./password.js";

// The only two roles the schema allows (see schema.sql):
//   access TEXT NOT NULL DEFAULT 'user' CHECK (access IN ('user','admin'))
export const ROLES = Object.freeze({
  USER: "user",
  ADMIN: "admin",
});

// Exactly what the DB binding is called in wrangler.toml:
//   [[d1_databases]]
//       binding = "witi_users"
export const DB_BINDING = "witi_users";

// --- Responses --------------------------------------------------
export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// --- Session cookie parsing -------------------------------------

const SESSION_COOKIE_NAME = "session";

/**
 * Pull the session token out of the request's Cookie header.
 * Returns null when the header is absent, malformed, or empty.
 * @param {Request} request
 * @returns {string|null}
 */
function readSessionToken(request) {
  const header = request.headers.get("Cookie");
  if (!header) return null;

  // Match "session=<value>" at the start or right after a "; ".
  const match = header.match(/(?:^|;\s*)session=([^;]*)/);
  if (!match) return null;

  let token;
  try {
    token = decodeURIComponent(match[1]);
  } catch {
    return null; // malformed percent-encoding
  }

  return token ? token.trim() : null;
}

/**
 * Is there a well-formed session cookie on this request at all?
 * Cheap check that touches no database -- useful for routing.
 * @param {Request} request
 * @returns {boolean}
 */
export function hasSessionCookie(request) {
  return readSessionToken(request) !== null;
}

// ============================================================
//  getCurrentUser
//  Reads the session cookie and resolves it to a real user row.
//  Returns the user record, or null when not logged in.
//
//  The cookie holds a RANDOM 64-char token, not a user id. We
//  hash it and join through `sessions`, so a hand-written cookie
//  (e.g. session=1) matches no row and is simply rejected.
//
//  Every failure path returns null rather than throwing -- a
//  corrupt cookie is "not logged in", not a 500.
// ============================================================
export async function getCurrentUser(request, env) {
  // 1. No cookie -> definitely not logged in. Skip the DB entirely.
  const token = readSessionToken(request);
  if (!token) return null;

  // 2. The binding must exist; that IS a configuration error, so
  //    it throws loudly instead of silently logging everyone out.
  const db = env?.[DB_BINDING];
  if (!db) {
    throw new Error(
      `D1 binding "${DB_BINDING}" is missing. Check wrangler.toml.`,
    );
  }

  // 3. Look the session up by the HASH of the token. Expiry is
  //    enforced in SQL, so a stale row can never authenticate even
  //    if the cleanup sweep has not run yet.
  const now = Math.floor(Date.now() / 1000);
  const tokenHash = await hashSessionToken(token);

  // The account settings page also needs the student id and the
  // gmail, so they travel with the identity. This object is only ever
  // used on the SERVER -- /api/me decides which of these fields reach
  // the browser.
  const user = await db
    .prepare(
      `SELECT u.user_id, u.name, u.student_id, u.gmail, u.access
         FROM sessions s
         JOIN users u ON u.user_id = s.user_id
        WHERE s.token_hash = ?
          AND s.expires_at > ?
        LIMIT 1`,
    )
    .bind(tokenHash, now)
    .first();

  return user ?? null;
}

// ============================================================
//  Session cookie
//  Shared by login, signup, logout and the account endpoints so the
//  attributes can never drift apart (a cookie written without
//  `Path=/` is invisible to half the site).
//
//  `Secure` cookies are only stored by the browser over HTTPS, so on a
//  local http:// dev server the browser would silently drop the
//  session and every later request would look logged out. We keep
//  `Secure` in production (any https:// origin) and relax it only for
//  http:// localhost / 127.0.0.1 -- or for any origin when the dev
//  server is started with --var SESSION_COOKIE_INSECURE:1 (see
//  schema.sql).
// ============================================================
function isLocalHttp(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:") return false;
    return (
      u.hostname === "localhost" ||
      u.hostname === "127.0.0.1" ||
      u.hostname === "[::1]"
    );
  } catch {
    return false;
  }
}

/**
 * Build a `Set-Cookie` value for the session token.
 * @param {string} token
 * @param {number} maxAge seconds; 0 clears the cookie (logout)
 * @param {string} url the request URL
 * @param {object} [env] the Pages env (checks SESSION_COOKIE_INSECURE)
 */
export function buildSessionCookie(token, maxAge, url, env) {
  // HttpOnly  -> JS cannot read it (blocks XSS token theft)
  // Secure    -> HTTPS only (relaxed for local http testing)
  // SameSite  -> Lax stops the cookie riding along on cross-site POSTs
  // Path      -> sent to the whole site
  const parts = [
    `session=${token}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${maxAge}`,
  ];

  const insecureDev = String(env?.SESSION_COOKIE_INSECURE ?? "") === "1";
  if (!insecureDev && !isLocalHttp(url)) parts.splice(2, 0, "Secure");

  return parts.join("; ");
}

// ============================================================
//  isAdmin(user)  -- the comparison you asked for.
//
//  A single, case-insensitive equality check against ROLES.ADMIN.
//  It answers only "is this person an admin?" If you need the
//  opposite, use !isAdmin(user) rather than writing a second
//  function -- two definitions of "who is an admin" is exactly
//  how auth bugs get introduced.
// ============================================================
export function isAdmin(user) {
  if (!user || typeof user.access !== "string") return false;
  return user.access.trim().toLowerCase() === ROLES.ADMIN;
}

// Convenience: the positive counterpart, for readable call sites
// like `if (isUser(user))` when an endpoint is user-facing.
export function isUser(user) {
  return !isAdmin(user);
}

// ============================================================
//  Guard helpers
//  Each returns { user, error }. If `error` is set, it is a
//  finished Response -- just `return error;`.
//
//    requireUser   -> 401 if not logged in
//    requireAdmin  -> 401 if not logged in, 403 if not an admin
// ============================================================

export async function requireUser(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user) {
    return { user: null, error: json({ error: "Not authenticated." }, 401) };
  }
  return { user, error: null };
}

export async function requireAdmin(request, env) {
  const { user, error } = await requireUser(request, env);
  if (error) return { user: null, error };

  if (!isAdmin(user)) {
    return {
      user: null,
      error: json({ error: "Admins only." }, 403),
    };
  }
  return { user, error: null };
}
