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

// ============================================================
//  getCurrentUser
//  Reads the session cookie and resolves it to a real user row.
//  Returns the user record, or null when not logged in.
//
//  The cookie holds a RANDOM 64-char token, not a user id. We
//  hash it and join through `sessions`, so a hand-written cookie
//  (e.g. session=1) matches no row and is simply rejected.
// ============================================================
export async function getCurrentUser(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return null;

  const sessionToken = decodeURIComponent(match[1]);
  if (!sessionToken) return null;

  const db = env[DB_BINDING];
  if (!db) {
    // Fail loudly instead of throwing a confusing "undefined.prepare".
    throw new Error(
      `D1 binding "${DB_BINDING}" is missing. Check wrangler.toml.`,
    );
  }

  const tokenHash = await hashSessionToken(sessionToken);
  const now = Math.floor(Date.now() / 1000);

  // Expiry is enforced in SQL, so a stale row can never authenticate
  // even if the cleanup sweep has not run yet.
  return await db
    .prepare(
      `SELECT u.user_id, u.name, u.access
         FROM sessions s
         JOIN users u ON u.user_id = s.user_id
        WHERE s.token_hash = ?
          AND s.expires_at > ?`,
    )
    .bind(tokenHash, now)
    .first();
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
