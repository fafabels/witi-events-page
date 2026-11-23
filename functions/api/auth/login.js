// ============================================================
//  functions/api/auth/login.js
//  POST /api/auth/login
//
//  Body (JSON):  { name, studentId, password }
//
//  These three fields match the login form in
//  public/static/login/login.html -- it has no email input, so
//  `name` is the identifier and `studentId` must also match.
//
//  On success:
//    - creates a row in `sessions`
//    - sets an HttpOnly session cookie
//    - returns { ok, access } so the client can redirect
//
//  On failure: a single "Invalid name or password." message with
//  401, regardless of WHICH part was wrong. Distinct messages
//  ("no such user" vs "bad password") let an attacker enumerate
//  valid accounts.
// ============================================================

import {
  json,
  DB_BINDING,
  ROLES,
  buildSessionCookie,
} from "../../_utils/auth.js";
// Open mode keeps a copy of this form on the site purely so the
// single admin can still get in -- see the check in onRequestPost.
import { isStrictMode, entryPage } from "../../_utils/settings.js";
import {
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
  SESSION_TTL_SECONDS,
} from "../../_utils/password.js";

// A real hash to compare against when the user does not exist, so
// the "no such user" path costs the same time as "wrong password".
// Format: pbkdf2$SHA-256$<iters>$<salt-b64>$<hash-b64>.
//
// The iteration count MUST stay <= 100000: production Workers
// WebCrypto rejects anything higher (NotSupportedError), which would
// turn a missing-user login into a 500. Keep this in step with
// ITERATIONS in _utils/password.js.
const DUMMY_HASH =
  "pbkdf2$SHA-256$100000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const GENERIC_ERROR = "Invalid name or password.";

function normalize(raw) {
  return String(raw ?? "").trim();
}

// The cookie is built by buildSessionCookie in _utils/auth.js, so the
// attributes are identical to the ones logout clears.

export async function onRequestPost({ request, env }) {
  const db = env[DB_BINDING];
  if (!db) {
    return json({ error: "Server misconfigured." }, 500);
  }

  const strict = await isStrictMode(env);

  // 1. Parse the body.
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const name = normalize(body.name);
  const studentId = normalize(body.studentId ?? body.student_id);
  const password = typeof body.password === "string" ? body.password : "";

  if (!name || !password) {
    return json({ error: GENERIC_ERROR }, 401);
  }

  // 2. Look the user up by name. If studentId was supplied, it must
  //    also match -- name alone is not a secret.
  const user = await db
    .prepare(
      `SELECT user_id, name, student_id, password, access
         FROM users
        WHERE name = ?`,
    )
    .bind(name)
    .first();

  if (!user) {
    // Burn equivalent time, then fail identically.
    await verifyPassword(password, DUMMY_HASH);
    return json({ error: GENERIC_ERROR }, 401);
  }

  // 3. studentId is a second factor here. If the client sent one
  //    and it does not match this account, refuse.
  if (studentId && studentId !== user.student_id) {
    return json({ error: GENERIC_ERROR }, 401);
  }

  // 4. Verify the password against the stored PBKDF2 hash.
  const ok = await verifyPassword(password, user.password);
  if (!ok) {
    return json({ error: GENERIC_ERROR }, 401);
  }

  // 5. In open mode the student flow is not part of the site, but the
  //    admin still needs a way in to flip the switch back and to post
  //    content -- so admin accounts may log in, everyone else may not.
  //    (The check runs AFTER the password so a wrong password still
  //    gives the same generic answer.)
  if (!strict && user.access !== ROLES.ADMIN) {
    return json(
      { error: "Student logins are disabled while the site is in open mode." },
      403,
    );
  }

  // 6. Issue a session. Store only the HASH of the token.
  const token = generateSessionToken();
  const tokenHash = await hashSessionToken(token);
  const now = Math.floor(Date.now() / 1000);

  await db
    .prepare(
      `INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
       VALUES (?, ?, ?, ?)`,
    )
    .bind(tokenHash, user.user_id, now, now + SESSION_TTL_SECONDS)
    .run();

  // 7. Opportunistic cleanup of this user's stale sessions. Cheap,
  //    and keeps the table from growing forever.
  await db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now).run();

  const access = user.access === ROLES.ADMIN ? ROLES.ADMIN : ROLES.USER;

  return new Response(
    JSON.stringify({
      ok: true,
      access,
      name: user.name,
      redirect:
        access === ROLES.ADMIN
          ? "/static/admin/admin.html"
          : entryPage(strict),
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json",
        "Set-Cookie": buildSessionCookie(
          token,
          SESSION_TTL_SECONDS,
          request.url,
          env,
        ),
      },
    },
  );
}
