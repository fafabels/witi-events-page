// ============================================================
//  functions/api/auth/signup.js
//  POST /api/auth/signup
//
//  Body (JSON): { name, studentId, email, password }
//  These match the signup form in public/static/signup/signup.html.
//
//  Creates a normal 'user' account. NEVER an admin -- see the
//  allowlist note below. Auto-logs-in the new account by issuing
//  a session, so signup flows straight through to the main page.
//
//  Rules enforced here (the browser-side checks in signup.html are
//  a convenience, not a security boundary -- anyone can skip them):
//    - studentId must be in student_master_list (you're a real student)
//    - studentId and email must not already be registered
//    - password must meet the strength rule
//    - password is hashed with PBKDF2 before storage
// ============================================================

import {
  json,
  DB_BINDING,
  ROLES,
  buildSessionCookie,
} from "../../_utils/auth.js";
import {
  hashPassword,
  generateSessionToken,
  hashSessionToken,
  SESSION_TTL_SECONDS,
} from "../../_utils/password.js";

// Mirrors the regex in signup.html so client and server agree.
const PASSWORD_RULE = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

const NAME_MIN = 2;
const NAME_MAX = 100;

function normalize(raw) {
  return String(raw ?? "").trim();
}

// The cookie is built by buildSessionCookie in _utils/auth.js, so the
// attributes are identical to the ones login and logout write.

export async function onRequestPost({ request, env }) {
  const db = env[DB_BINDING];
  if (!db) {
    return json({ error: "Server misconfigured." }, 500);
  }

  // 1. Parse the body.
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const name = normalize(body.name).replace(/\s+/g, " ");
  const studentId = normalize(body.studentId ?? body.student_id);
  const email = normalize(body.email ?? body.gmail).toLowerCase();
  const password = typeof body.password === "string" ? body.password : "";

  // 2. Validate the name.
  if (name.length < NAME_MIN || name.length > NAME_MAX) {
    return json(
      { error: `Name must be between ${NAME_MIN} and ${NAME_MAX} characters.` },
      422,
    );
  }

  // 3. Validate the student id against the official roster. This is
  //    the check that stops anyone from inventing an ID.
  if (!studentId) {
    return json({ error: "Student ID is required." }, 422);
  }

  const onRoster = await db
    .prepare("SELECT name FROM student_master_list WHERE student_id = ?")
    .bind(studentId)
    .first();

  if (!onRoster) {
    return json(
      { error: "That student ID is not on the school roster." },
      403,
    );
  }

  // 4. Validate the email shape (form already has a pattern, but the
  //    browser can be bypassed).
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "Please enter a valid email address." }, 422);
  }

  // 5. Validate password strength server-side.
  if (!PASSWORD_RULE.test(password)) {
    return json(
      {
        error:
          "Password must be at least 8 characters, include one uppercase letter, one number, and one special character.",
      },
      422,
    );
  }

  // 6. Reject duplicates explicitly, so the user gets a clear reason
  //    rather than a raw UNIQUE-constraint failure.
  const existing = await db
    .prepare(
      `SELECT student_id, gmail FROM users
        WHERE student_id = ? OR gmail = ?`,
    )
    .bind(studentId, email)
    .first();

  if (existing) {
    if (existing.student_id === studentId) {
      return json(
        { error: "That student ID is already registered. Try logging in." },
        409,
      );
    }
    return json(
      { error: "That email is already registered. Try logging in." },
      409,
    );
  }

  // 7. Hash and insert.
  //
  //    NOTE ON `access`: this is hardcoded to 'user'. The request body
  //    is deliberately NEVER read for a role, because trusting a
  //    client-supplied "access" field would let anyone sign themselves
  //    up as an admin. To create the first admin, promote a row by hand:
  //        UPDATE users SET access='admin' WHERE gmail='you@gmail.com';
  //
  //    Hashing uses WebCrypto. On a non-secure origin (plain http on a
  //    LAN IP rather than localhost) `crypto.subtle` is undefined and
  //    this throws -- an opaque 500 with an empty body. Surfacing it
  //    as a 500 with a readable message beats "Signup failed."
  let passwordHash;
  try {
    passwordHash = await hashPassword(password);
  } catch (err) {
    console.error("password hashing failed:", err);
    return json({ error: "Server could not hash the password." }, 500);
  }

  let result;
  try {
    result = await db
      .prepare(
        `INSERT INTO users (name, password, student_id, gmail, access)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(name, passwordHash, studentId, email, ROLES.USER)
      .run();
  } catch (err) {
    // Distinguish the expected duplicate race from a genuine schema /
    // integrity failure. Reporting a missing table or a failed CHECK
    // as "already registered" sent us chasing the wrong bug.
    const detail = String(err?.message ?? err);
    if (/UNIQUE constraint failed/i.test(detail)) {
      return json(
        { error: "That student ID or email was just registered." },
        409,
      );
    }
    console.error("signup insert failed:", err);
    return json({ error: "Could not create the account." }, 500);
  }

  // 8. Auto-login: issue a session so the client can go straight in.
  //
  //    `last_row_id` is what D1 puts in `meta` for an INSERT, but we
  //    fall back to a lookup when the driver does not supply it -- an
  //    undefined id here would otherwise bind a value that matches no
  //    users row and trip the sessions -> users foreign key.
  const userId =
    result?.meta?.last_row_id ||
    (
      await db
        .prepare("SELECT user_id FROM users WHERE gmail = ?")
        .bind(email)
        .first()
    )?.user_id;

  //    A failure here must NOT turn an already-created account into a
  //    500 and a confusing "Signup failed." The account exists; the
  //    user can simply log in. So the insert is guarded and `token`
  //    stays null when it does not succeed.
  let token = null;
  if (userId) {
    const candidate = generateSessionToken();
    const tokenHash = await hashSessionToken(candidate);
    const now = Math.floor(Date.now() / 1000);
    try {
      await db
        .prepare(
          `INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(tokenHash, userId, now, now + SESSION_TTL_SECONDS)
        .run();
      token = candidate;
    } catch (err) {
      console.error("session insert failed after signup:", err);
    }
  }

  return new Response(
    JSON.stringify({
      ok: true,
      access: ROLES.USER,
      name,
      redirect: "/static/user/main_page.html",
    }),
    {
      status: 201,
      headers: {
        "content-type": "application/json",
        ...(token
          ? {
              "Set-Cookie": buildSessionCookie(
                token,
                SESSION_TTL_SECONDS,
                request.url,
                env,
              ),
            }
          : {}),
      },
    },
  );
}
