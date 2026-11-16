// ============================================================
//  functions/api/user/account.js
//  The account settings section of the page.
//
//    GET  /api/user/account   -> the logged-in user's own details
//    POST /api/user/account   -> request an email change
//    PUT  /api/user/account   -> change the password
//
//  Every verb starts with requireUser, so an anonymous request gets a
//  flat 401 and never sees anyone's details. The page hides the
//  sections while logged out, but that is only UX -- this file is
//  where access is actually decided.
//
//  GET returns the fields that came from the signup form:
//    { name, gmail, student_id, access, pending_email }
//  The password hash is NEVER included.
//
//  POST body: { currentPassword, newEmail }
//  PUT  body: { currentPassword, newPassword, confirmPassword }
// ============================================================

import {
  requireUser,
  json,
  DB_BINDING,
  buildSessionCookie,
  ROLES,
} from "../../_utils/auth.js";
import {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  hashSessionToken,
  SESSION_TTL_SECONDS,
} from "../../_utils/password.js";

// Mirrors the rules in signup.html / auth/signup.js.
const PASSWORD_RULE =
  /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const EMAIL_RULE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Same window as a session; the mailed link is useless after a day.
const EMAIL_CHANGE_TTL_SECONDS = 60 * 60 * 24;

function normalize(raw) {
  return String(raw ?? "").trim();
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// The table lives in schema.sql, but a database that was created
// before this feature existed has no such table. CREATE TABLE IF NOT
// EXISTS is a no-op once it is there.
async function ensureEmailTable(db) {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS email_change_requests (
         token_hash  TEXT    PRIMARY KEY,
         user_id     INTEGER NOT NULL,
         new_email   TEXT    NOT NULL,
         created_at  INTEGER NOT NULL,
         expires_at  INTEGER NOT NULL
       )`,
    )
    .run();
}

function hasEmailProvider(env) {
  // Resend's HTTP API, or Cloudflare Email Routing's send_email
  // binding. Either one is enough to deliver the confirmation link.
  return Boolean(env?.RESEND_API_KEY) || Boolean(env?.EMAIL);
}

async function sendConfirmationEmail(env, { to, confirmUrl }) {
  const subject = "Confirm your new WITI Bulletin email";
  const text =
    `Open this link to finish changing your WITI Bulletin email to ${to}:\n\n` +
    `${confirmUrl}\n\n` +
    "If you did not ask for this, ignore this email -- nothing changes " +
    "until the link is opened. The link expires in 24 hours.";

  // 1. Resend (https://resend.com) -- plain HTTP, works on Pages.
  if (env?.RESEND_API_KEY) {
    const from = env.MAIL_FROM || "WITI Bulletin <onboarding@resend.dev>";
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ from, to: [to], subject, text }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`Resend rejected the message: ${res.status} ${detail}`);
    }
    return;
  }

  // 2. Cloudflare Email Routing send_email binding.
  if (env?.EMAIL) {
    await env.EMAIL.send({
      to,
      from: {
        email: env.MAIL_FROM || "noreply@witi.pages.dev",
        name: "WITI Bulletin",
      },
      subject,
      text,
    });
    return;
  }

  throw new Error("No email provider is configured.");
}

export async function onRequestGet({ request, env }) {
  const { user, error } = await requireUser(request, env);
  if (error) return error;

  const db = env[DB_BINDING];
  if (!db) return json({ error: "Server misconfigured." }, 500);

  // The session lookup only carries a few columns; read the full row
  // so the page can show exactly what was entered at signup.
  const row = await db
    .prepare(
      `SELECT name, gmail, student_id, access
         FROM users
        WHERE user_id = ?`,
    )
    .bind(user.user_id)
    .first();

  if (!row) return json({ error: "Account not found." }, 404);

  await ensureEmailTable(db);
  const now = Math.floor(Date.now() / 1000);
  const pending = await db
    .prepare(
      `SELECT new_email
         FROM email_change_requests
        WHERE user_id = ? AND expires_at > ?
        ORDER BY created_at DESC
        LIMIT 1`,
    )
    .bind(user.user_id, now)
    .first();

  return json({
    name: row.name,
    gmail: row.gmail,
    student_id: row.student_id,
    access: row.access === ROLES.ADMIN ? ROLES.ADMIN : ROLES.USER,
    pending_email: pending?.new_email ?? null,
    email_configured: hasEmailProvider(env),
  });
}

// --- POST: request an email change ------------------------------
// Nothing is written to `users` here. The new address is parked in
// email_change_requests until the link mailed to it is opened
// (/api/user/confirm-email), so a typo can never lock the owner out.
export async function onRequestPost({ request, env }) {
  const { user, error } = await requireUser(request, env);
  if (error) return error;

  const db = env[DB_BINDING];
  if (!db) return json({ error: "Server misconfigured." }, 500);

  const body = await readJson(request);
  if (!body) return json({ error: "Invalid JSON body." }, 400);

  const newEmail = normalize(body.newEmail ?? body.email).toLowerCase();
  const currentPassword =
    typeof body.currentPassword === "string" ? body.currentPassword : "";

  if (!EMAIL_RULE.test(newEmail)) {
    return json({ error: "Please enter a valid email address." }, 422);
  }
  if (!currentPassword) {
    return json({ error: "Enter your current password to continue." }, 422);
  }

  const account = await db
    .prepare("SELECT user_id, gmail, password FROM users WHERE user_id = ?")
    .bind(user.user_id)
    .first();

  if (!account) return json({ error: "Account not found." }, 404);

  // Re-authenticate: a borrowed open browser must not be able to
  // move the account to an attacker's inbox.
  const ok = await verifyPassword(currentPassword, account.password);
  if (!ok) return json({ error: "That password is not correct." }, 401);

  if (newEmail === String(account.gmail).toLowerCase()) {
    return json({ error: "That is already your email address." }, 422);
  }

  const taken = await db
    .prepare("SELECT user_id FROM users WHERE gmail = ? AND user_id != ?")
    .bind(newEmail, user.user_id)
    .first();
  if (taken) {
    return json({ error: "That email is already registered." }, 409);
  }

  await ensureEmailTable(db);

  // One pending request per account: drop the older ones.
  await db
    .prepare("DELETE FROM email_change_requests WHERE user_id = ?")
    .bind(user.user_id)
    .run();

  const token = generateSessionToken();
  const tokenHash = await hashSessionToken(token);
  const now = Math.floor(Date.now() / 1000);

  await db
    .prepare(
      `INSERT INTO email_change_requests
         (token_hash, user_id, new_email, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(
      tokenHash,
      user.user_id,
      newEmail,
      now,
      now + EMAIL_CHANGE_TTL_SECONDS,
    )
    .run();

  const confirmUrl = new URL("/api/user/confirm-email", request.url);
  confirmUrl.searchParams.set("token", token);

  if (!hasEmailProvider(env)) {
    // No mail provider wired up yet. Without a delivered link the
    // change can never complete, so say so plainly instead of
    // pretending an email went out. (The request row is harmless.)
    await db
      .prepare("DELETE FROM email_change_requests WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
    return json(
      {
        error:
          "Email delivery is not set up on this server yet, so the " +
          "confirmation email cannot be sent. Set RESEND_API_KEY (and " +
          "optionally MAIL_FROM) to enable email changes.",
      },
      503,
    );
  }

  try {
    await sendConfirmationEmail(env, {
      to: newEmail,
      confirmUrl: confirmUrl.toString(),
    });
  } catch (err) {
    console.error("confirmation email failed:", err);
    await db
      .prepare("DELETE FROM email_change_requests WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
    return json(
      { error: "The confirmation email could not be sent. Try again later." },
      502,
    );
  }

  return json({
    ok: true,
    pending_email: newEmail,
    message:
      `A confirmation link was sent to ${newEmail}. ` +
      "Open it to finish the change.",
  });
}

// --- PUT: change the password -----------------------------------
export async function onRequestPut({ request, env }) {
  const { user, error } = await requireUser(request, env);
  if (error) return error;

  const db = env[DB_BINDING];
  if (!db) return json({ error: "Server misconfigured." }, 500);

  const body = await readJson(request);
  if (!body) return json({ error: "Invalid JSON body." }, 400);

  const currentPassword =
    typeof body.currentPassword === "string" ? body.currentPassword : "";
  const newPassword =
    typeof body.newPassword === "string" ? body.newPassword : "";
  const confirmPassword =
    typeof body.confirmPassword === "string" ? body.confirmPassword : "";

  if (!currentPassword) {
    return json({ error: "Enter your current password." }, 422);
  }
  if (newPassword !== confirmPassword) {
    return json({ error: "The new passwords do not match." }, 422);
  }
  if (!PASSWORD_RULE.test(newPassword)) {
    return json(
      {
        error:
          "Password must be at least 8 characters, include one uppercase " +
          "letter, one number, and one special character.",
      },
      422,
    );
  }

  const account = await db
    .prepare("SELECT password FROM users WHERE user_id = ?")
    .bind(user.user_id)
    .first();
  if (!account) return json({ error: "Account not found." }, 404);

  const ok = await verifyPassword(currentPassword, account.password);
  if (!ok) return json({ error: "That password is not correct." }, 401);

  if (currentPassword === newPassword) {
    return json(
      { error: "The new password must be different from the old one." },
      422,
    );
  }

  let newHash;
  try {
    newHash = await hashPassword(newPassword);
  } catch (err) {
    console.error("password hashing failed:", err);
    return json({ error: "Server could not hash the password." }, 500);
  }

  await db
    .prepare("UPDATE users SET password = ? WHERE user_id = ?")
    .bind(newHash, user.user_id)
    .run();

  // Invalidate every other session of this account (a changed
  // password should end logins that knew the old one), then hand the
  // current browser a fresh cookie so it stays logged in.
  await db
    .prepare("DELETE FROM sessions WHERE user_id = ?")
    .bind(user.user_id)
    .run();

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

  return new Response(
    JSON.stringify({ ok: true, message: "Password updated." }),
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
