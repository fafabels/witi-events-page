// ============================================================
//  functions/api/user/confirm-email.js
//  GET /api/user/confirm-email?token=<...>
//
//  The link in the confirmation email lands here. Only this step
//  writes the new address to `users`, which is what makes the change
//  actually confirmed by whoever owns the new inbox.
//
//  No session is required: the link may be opened on a phone that is
//  not logged in. The token itself is the proof -- it is 256 bits of
//  random, mailed to the new address and stored only as a SHA-256.
//
//  Responds with a tiny HTML page (it is opened by clicking a link,
//  not by fetch), then the user can go back to Settings.
// ============================================================

import { DB_BINDING } from "../../_utils/auth.js";
import { hashSessionToken } from "../../_utils/password.js";

const BACK_LINK = "/static/user/main.html#account";

function page(title, message, status) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} - WITI Bulletin</title>
<style>
  body { margin:0; min-height:100dvh; display:grid; place-items:center;
         font-family: 'Playfair Display', Georgia, serif; background:#eef0f8; }
  .card { background:#fff; padding:36px 40px; border-radius:16px; max-width:460px;
          box-shadow:0 10px 30px rgba(0,0,0,.12); text-align:center; }
  h1 { font-size:24px; margin:0 0 12px; color:#1d1d6e; }
  p { margin:0 0 20px; line-height:1.5; color:#333; }
  a { color:#2f2fd7; }
</style>
</head>
<body>
  <div class="card">
    <h1>${title}</h1>
    <p>${message}</p>
    <p><a href="${BACK_LINK}">Back to account settings</a></p>
  </div>
</body>
</html>`;

  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

export async function onRequestGet({ request, env }) {
  const db = env[DB_BINDING];
  if (!db) return page("Something went wrong", "Server misconfigured.", 500);

  const token = new URL(request.url).searchParams.get("token");
  if (!token) {
    return page(
      "Invalid link",
      "This confirmation link is missing its token.",
      400,
    );
  }

  const tokenHash = await hashSessionToken(token);
  const now = Math.floor(Date.now() / 1000);

  const pending = await db
    .prepare(
      `SELECT user_id, new_email
         FROM email_change_requests
        WHERE token_hash = ? AND expires_at > ?`,
    )
    .bind(tokenHash, now)
    .first();

  if (!pending) {
    return page(
      "Link expired",
      "This confirmation link is invalid or has expired. Request the " +
        "email change again from account settings.",
      400,
    );
  }

  // UNIQUE(gmail) may reject an address that was registered while this
  // link sat in an inbox. Report that instead of a 500.
  try {
    await db
      .prepare("UPDATE users SET gmail = ? WHERE user_id = ?")
      .bind(pending.new_email, pending.user_id)
      .run();
  } catch (err) {
    console.error("email confirmation failed:", err);
    await db
      .prepare("DELETE FROM email_change_requests WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
    return page(
      "Could not change the email",
      "That address is already registered to another account.",
      409,
    );
  }

  // One-shot link.
  await db
    .prepare("DELETE FROM email_change_requests WHERE token_hash = ?")
    .bind(tokenHash)
    .run();

  const safeEmail = String(pending.new_email).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

  return page("Email confirmed", `Your email is now <strong>${safeEmail}</strong>.`, 200);
}
